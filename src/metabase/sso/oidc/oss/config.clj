(ns metabase.sso.oidc.oss.config
  "Configuration for OIDC login in the OSS edition, read from environment variables.

  Upstream Metabase only exposes OIDC login as a paid feature. This module wires the OSS OIDC
  provider ([[metabase.sso.providers.oidc]]) up to a pair of unauthenticated endpoints
  ([[metabase.sso.oidc.oss.api]]) so that a self-hosted OSS instance can log people in against
  any OIDC identity provider, and mirror the roles it sends onto Metabase groups
  ([[metabase.sso.oidc.oss.groups]]).

  Configuration lives entirely in environment variables — there is no admin UI and nothing is
  stored in the app db:

  | Variable                 | Meaning                                                                       |
  |--------------------------|-------------------------------------------------------------------------------|
  | `MB_OIDC_CLIENT_ID`      | OAuth2 client id (required)                                                   |
  | `MB_OIDC_CLIENT_SECRET`  | OAuth2 client secret (required)                                               |
  | `MB_OIDC_ISSUER_URI`     | Issuer URI; the rest of the endpoints come from OIDC discovery (required)     |
  | `MB_OIDC_SCOPES`         | Space- or comma-separated scopes (default `openid email profile`)              |
  | `MB_OIDC_ROLES_CLAIM`    | ID token claim holding the roles, `.` separated when nested (default `roles`) |
  | `MB_OIDC_GROUP_SYNC`     | `true` to make the roles claim the source of truth for group membership       |

  `MB_ENCRYPTION_SECRET_KEY` must also be set: the OIDC state cookie is encrypted with it."
  (:require
   [clojure.string :as str]
   [metabase.config.core :as config]
   [metabase.settings.core :refer [defsetting]]
   [metabase.util :as u]
   [metabase.util.i18n :refer [deferred-tru]]))

(set! *warn-on-reflection* true)

(defn- setting-str
  [k]
  (some-> (config/config-str k) str/trim not-empty))

(defn client-id
  "OAuth2 client id, from `MB_OIDC_CLIENT_ID`."
  []
  (setting-str :mb-oidc-client-id))

(defn client-secret
  "OAuth2 client secret, from `MB_OIDC_CLIENT_SECRET`."
  []
  (setting-str :mb-oidc-client-secret))

(defn issuer-uri
  "OIDC issuer URI, from `MB_OIDC_ISSUER_URI`. Endpoints are resolved from it by discovery."
  []
  (setting-str :mb-oidc-issuer-uri))

(def ^:private default-scopes ["openid" "email" "profile"])

(defn scopes
  "Scopes to request from the identity provider, from `MB_OIDC_SCOPES`."
  []
  (or (when-let [s (setting-str :mb-oidc-scopes)]
        (not-empty (into [] (remove str/blank?) (str/split s #"[,\s]+"))))
      default-scopes))

(defn enabled?
  "Whether OSS OIDC login has been configured. Endpoints and the login button are inert until it is."
  []
  (boolean (and (client-id) (client-secret) (issuer-uri))))

;; lives here rather than in `metabase.sso.settings` (where the linter wants settings) to keep this
;; fork's footprint in upstream files small. `metabase.sso.settings/sso-source-enabled?` reads it by
;; name, and the frontend uses it to decide whether to offer the SSO button.
#_{:clj-kondo/ignore [:metabase/defsetting-namespace]}
(defsetting oidc-oss-enabled
  (deferred-tru "Is OIDC login configured on this instance? Configured with env vars only.")
  :type       :boolean
  :visibility :public
  :setter     :none
  :getter     enabled?
  :doc        false
  :export?    false)

(defn provider-config
  "Config map for the OSS OIDC provider, shaped like `:metabase.sso.oidc.schema/oidc-configuration`.

  `redirect-uri` must be the absolute URL of the callback endpoint, and has to be identical on the
  authorization request and the token exchange."
  [redirect-uri]
  {:client-id     (client-id)
   :client-secret (client-secret)
   :issuer-uri    (issuer-uri)
   :redirect-uri  redirect-uri
   :scopes        (scopes)})

(def ^:private default-roles-claim "roles")

(defn roles-claim-path
  "Path of the ID token claim holding the user's roles, as a vector of keywords for `get-in`.

  `MB_OIDC_ROLES_CLAIM` is split on `.`, so a Keycloak-style `realm_access.roles` becomes
  `[:realm_access :roles]`."
  []
  (mapv keyword (str/split (or (setting-str :mb-oidc-roles-claim) default-roles-claim) #"\.")))

(defn group-sync?
  "Whether group memberships are synced from the roles claim on every login, from
  `MB_OIDC_GROUP_SYNC`.

  Off unless explicitly turned on: switching it on hands the identity provider sole authority over
  who is in which group -- including who is an admin -- which is not something to end up with by
  accident."
  []
  (contains? #{"true" "yes" "1"}
             (u/lower-case-en (or (setting-str :mb-oidc-group-sync) ""))))
