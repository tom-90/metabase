(ns metabase.sso.oidc.oss.api-test
  (:require
   [clj-http.client :as http]
   [clojure.string :as str]
   [clojure.test :refer :all]
   [metabase.api.macros :as api.macros]
   [metabase.sso.oidc.discovery :as oidc.discovery]
   [metabase.sso.oidc.oss.api]
   [metabase.sso.oidc.tokens :as oidc.tokens]
   [metabase.test :as mt]
   [metabase.test.fixtures :as fixtures]
   [metabase.util.encryption :as encryption]
   [ring.util.codec :as codec]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(use-fixtures :once (fixtures/initialize :db :test-users))

(def ^:private test-secret
  (encryption/secret-key->hash "Orw0AAyzkO/kPTLJRxiyKoBHXa/d6ZcO+p+gpZO/wSQ="))

(def ^:private discovery-doc
  {:authorization_endpoint "https://provider.example.com/authorize"
   :token_endpoint         "https://provider.example.com/token"
   :jwks_uri               "https://provider.example.com/jwks"})

(def ^:private claims
  {:sub         "user-123"
   :iss         "https://provider.example.com"
   :aud         "test-client-id"
   :email       "oidc-user@metabase.test"
   :given_name  "Oh"
   :family_name "Idc"
   :roles       ["analyst"]})

(def ^:private handler
  (api.macros/ns-handler 'metabase.sso.oidc.oss.api))

(defn- GET
  "Call an `/api/oidc-oss` endpoint directly, in this thread, so `with-dynamic-fn-redefs` applies.
  `query-params` are string-keyed like Ring's, and the return value is the raw Ring response."
  [uri query-params & {:as request}]
  (let [result (promise)]
    (handler (merge {:request-method :get
                     :uri            uri
                     :query-params   query-params
                     :headers        {"user-agent" "OIDC test"}
                     :remote-addr    "127.0.0.1"}
                    request)
             (partial deliver result)
             (partial deliver result))
    (let [response @result]
      (if (instance? Throwable response)
        (throw response)
        response))))

(defmacro ^:private with-oidc-configured!
  "Configure OIDC the way a deployment would — env vars plus an encryption key — and stub out the
  identity provider's discovery document, token endpoint, and ID token."
  [& body]
  `(with-redefs [encryption/default-secret-key test-secret]
     (mt/with-temp-env-var-value! [mb-oidc-client-id     "test-client-id"
                                   mb-oidc-client-secret "test-client-secret"
                                   mb-oidc-issuer-uri    "https://provider.example.com"]
       (mt/with-dynamic-fn-redefs [oidc.discovery/discover-oidc-configuration (constantly discovery-doc)
                                   http/post                                 (constantly
                                                                              {:status 200
                                                                               :body   {:id_token     "id-token"
                                                                                        :access_token "access-token"}})
                                   oidc.tokens/validate-id-token             (constantly
                                                                              {:valid? true :claims claims})]
         ~@body))))

(defn- query-param
  [url param]
  (get (codec/form-decode (second (str/split url #"\?" 2))) param))

(deftest login-not-configured-test
  (testing "the endpoints stay inert until OIDC is configured"
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"OIDC authentication is not configured"
                          (GET "/login" {})))
    (is (thrown-with-msg? clojure.lang.ExceptionInfo
                          #"OIDC authentication is not configured"
                          (GET "/callback" {"code" "x" "state" "y"})))))

(deftest login-redirects-to-provider-test
  (with-oidc-configured!
    (let [response (GET "/login" {"redirect" "/collection/root"})]
      (testing "we redirect to the provider's authorization endpoint"
        (is (= 302 (:status response)))
        (is (str/starts-with? (get-in response [:headers "Location"])
                              "https://provider.example.com/authorize")))
      (testing "and hand the browser the encrypted state cookie the callback checks"
        (is (some? (get-in response [:cookies "metabase.OIDC_STATE" :value])))))))

(deftest login-rejects-offsite-redirect-test
  (testing "an open redirect isn't allowed to ride along through the state cookie"
    (with-oidc-configured!
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"Invalid redirect URL"
                            (GET "/login" {"redirect" "https://evil.example.com/"}))))))

(defn- login+callback!
  "Walk the whole flow: start login, then hand the state cookie and code back to the callback the way
  the browser would. `callback-params` overrides the query params the provider sends back."
  [& {:keys [redirect callback-params cookies]}]
  (let [login-response (GET "/login" (cond-> {} redirect (assoc "redirect" redirect)))
        state          (query-param (get-in login-response [:headers "Location"]) "state")]
    (GET "/callback"
      (merge {"code" "auth-code" "state" state} callback-params)
      :cookies (or cookies (select-keys (:cookies login-response) ["metabase.OIDC_STATE"])))))

(deftest callback-logs-user-in-test
  (with-oidc-configured!
    (mt/with-model-cleanup [:model/User]
      (let [response (login+callback! :redirect "/collection/root")]
        (testing "the browser is sent on to where it was headed, with a session cookie"
          (is (= 302 (:status response)))
          (is (= "/collection/root" (get-in response [:headers "Location"])))
          (is (some? (get-in response [:cookies "metabase.SESSION" :value]))))
        (testing "and the state cookie is cleared so it can't be replayed"
          (is (= 0 (get-in response [:cookies "metabase.OIDC_STATE" :max-age]))))
        (testing "the user is provisioned from the ID token claims"
          (let [user (t2/select-one [:model/User :first_name :last_name :sso_source :is_active]
                                    :email "oidc-user@metabase.test")]
            (is (=? {:first_name "Oh" :last_name "Idc" :is_active true}
                    user))
            (is (= "oidc" (name (:sso_source user))))))))))

(deftest callback-syncs-groups-test
  (with-oidc-configured!
    (mt/with-model-cleanup [:model/User]
      (mt/with-temp-env-var-value! [mb-oidc-group-sync "true"]
        (try
          (login+callback!)
          (testing "logging in creates a group for the role in the ID token and joins the user to it"
            (let [user-id  (t2/select-one-pk :model/User :email "oidc-user@metabase.test")
                  group-id (t2/select-one-pk :model/PermissionsGroup :name "analyst")]
              (is (some? group-id))
              (is (t2/exists? :model/PermissionsGroupMembership :user_id user-id :group_id group-id))))
          (finally
            (t2/delete! :model/PermissionsGroup :name "analyst")))))))

(deftest callback-rejects-tampered-state-test
  (with-oidc-configured!
    (mt/with-model-cleanup [:model/User]
      (testing "a state parameter that doesn't match the cookie is refused"
        (is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #"State parameter does not match"
                              (login+callback! :callback-params {"state" "not-the-state-we-issued"}))))
      (testing "and so is a callback with no state cookie at all"
        (is (thrown-with-msg? clojure.lang.ExceptionInfo
                              #"state cookie is invalid, expired, or missing"
                              (login+callback! :cookies {"metabase.OIDC_STATE" nil}))))
      (is (false? (t2/exists? :model/User :email "oidc-user@metabase.test"))))))

(deftest callback-passes-provider-errors-through-test
  (with-oidc-configured!
    (testing "when the provider says no, we surface its reason instead of pretending otherwise"
      (is (thrown-with-msg? clojure.lang.ExceptionInfo
                            #"User denied access"
                            (login+callback! :callback-params {"code"              nil
                                                               "error"             "access_denied"
                                                               "error_description" "User denied access"}))))))
