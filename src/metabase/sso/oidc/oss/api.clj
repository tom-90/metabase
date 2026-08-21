(ns metabase.sso.oidc.oss.api
  "`/api/oidc-oss` endpoints: the browser-facing half of OIDC login on the OSS edition.

  `/login` starts the authorization code flow and `/callback` finishes it. Both are
  unauthenticated by design — they are how you get a session in the first place. See
  [[metabase.sso.oidc.oss.config]] for configuration."
  (:require
   [java-time.api :as t]
   [metabase.api.macros :as api.macros]
   [metabase.auth-identity.core :as auth-identity]
   [metabase.request.core :as request]
   [metabase.sso.oidc.oss.config :as oidc.oss.config]
   [metabase.sso.oidc.oss.groups :as oidc.oss.groups]
   [metabase.sso.oidc.state :as oidc.state]
   [metabase.system.core :as system]
   [metabase.util.i18n :refer [tru]]
   [metabase.util.log :as log]
   [ring.util.response :as response]))

(set! *warn-on-reflection* true)

(def ^:private callback-path "/api/oidc-oss/callback")

(defn- oidc-request
  "The Ring request, plus everything the OSS OIDC provider needs to talk to the identity provider."
  [request]
  (assoc request :oidc-config (oidc.oss.config/provider-config (str (system/site-url) callback-path))))

(defn- check-enabled!
  []
  (when-not (oidc.oss.config/enabled?)
    (throw (ex-info (tru "OIDC authentication is not configured on this instance.")
                    {:status-code 400}))))

(defn- fail!
  "Turn a failed provider result into an error response, preferring whatever the provider had to say
  over our own generic `message`."
  [message result status-code]
  (log/errorf "OIDC login failed: %s (%s)" (:message result) (:error result))
  (throw (ex-info (or (not-empty (str (:message result))) (str message))
                  {:status-code status-code
                   :errors      {:_error (or (:error result) message)}})))

#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema]}
(api.macros/defendpoint :get "/login"
  "Start OIDC login by redirecting the browser to the identity provider. `redirect` is where the
  browser lands once login completes, and must be relative or same-origin."
  [_route-params
   {:keys [redirect]} :- [:map
                          [:redirect {:optional true} [:maybe :string]]]
   _body
   request]
  (check-enabled!)
  (let [result (auth-identity/authenticate :provider/oidc (oidc-request request))]
    (if (= :redirect (:success? result))
      ;; the state and nonce we just generated go into an encrypted cookie, which `/callback`
      ;; validates the identity provider's response against
      (oidc.state/wrap-oidc-redirect result request :oidc (or (not-empty redirect) "/")
                                     {:browser-id (:browser-id request)})
      (fail! (tru "Could not start OIDC login") result 500))))

;; the callback's query params are named by the identity provider, so `error_description` is not ours
;; to kebab-case
#_{:clj-kondo/ignore [:metabase/validate-defendpoint-has-response-schema
                      :metabase/validate-defendpoint-query-params-use-kebab-case]}
(api.macros/defendpoint :get "/callback"
  "Finish OIDC login: exchange the authorization code the identity provider sent for tokens, create
  or update the user, sync their groups, and hand the browser a session cookie."
  [_route-params
   query-params :- [:map
                    [:code  {:optional true} [:maybe :string]]
                    [:state {:optional true} [:maybe :string]]
                    [:error {:optional true} [:maybe :string]]
                    ;; snake_case because that is what the OIDC spec calls it
                    [:error_description {:optional true} [:maybe :string]]]
   _body
   request]
  (check-enabled!)
  (let [result (auth-identity/login! :provider/oidc
                                     (merge (oidc-request request)
                                            {:device-info (request/device-info request)}
                                            ;; an allow-list, so a hand-crafted callback URL can't
                                            ;; talk its way past the state cookie checks
                                            (select-keys query-params [:code :state :error :error_description])))]
    (if (:success? result)
      (do
        (oidc.oss.groups/sync-groups-from-claims! (:user result) (:claims result))
        (request/set-session-cookies request
                                     (-> (response/redirect (or (:redirect-url result) "/"))
                                         oidc.state/clear-oidc-state-cookie)
                                     (:session result)
                                     (t/zoned-date-time (t/zone-id "GMT"))))
      (fail! (tru "OIDC login failed") result 401))))
