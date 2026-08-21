(ns metabase.sso.oidc.oss.groups
  "Mirror the roles an OIDC identity provider sends onto Metabase permissions groups.

  A role becomes a group of the same name, created on first sight, and the roles in the token are
  the whole truth: memberships the user has in any other group are removed. That includes
  Administrators, so whoever runs the identity provider decides who administers Metabase.

  Roles are read from the ID token claims, so the identity provider has to be configured to include
  them there — an access token or a userinfo call is not consulted."
  (:require
   [clojure.string :as str]
   [metabase.sso.common :as sso.common]
   [metabase.sso.oidc.oss.config :as oidc.oss.config]
   [metabase.util :as u]
   [metabase.util.log :as log]
   [toucan2.core :as t2]))

(set! *warn-on-reflection* true)

(defn- role-name
  "One role name, from one element of the roles claim."
  [v]
  (cond
    (string? v)  (not-empty (str/trim v))
    (keyword? v) (name v)
    (some? v)    (str v)))

(defn- role-names
  "Role names from whatever the roles claim holds. A list holds one role per element -- spaces and
  all, since a role is free to be called \"Data Analysts\" -- while a bare string is split on commas
  and whitespace, the way a scope list is written."
  [v]
  (cond
    (or (sequential? v) (set? v)) (keep role-name v)
    (string? v)                   (remove str/blank? (map str/trim (str/split v #"[,\s]+")))
    (some? v)                     [(str v)]))

(defn- group-name->id
  "Lower-cased group name -> id, for every group there is. Group names are unique case-insensitively,
  and including the magic groups means a role named \"Administrators\" lands people in that group
  rather than colliding with its name."
  []
  (into {}
        (map (juxt (comp u/lower-case-en :name) :id))
        (t2/select [:model/PermissionsGroup :id :name])))

(defn- group-id!
  "Id of the group called `group-name`, creating it if this role hasn't been seen before. A fresh
  group starts with no permissions at all (see the `after-insert` hook on `:model/PermissionsGroup`),
  so creating one grants nobody anything until an admin says otherwise."
  [existing group-name]
  (or (get existing (u/lower-case-en group-name))
      (try
        (u/prog1 (t2/insert-returning-pk! :model/PermissionsGroup {:name group-name})
          (log/infof "Created Metabase group %s for OIDC role of the same name" (pr-str group-name)))
        (catch Exception e
          ;; two logins can race to create the same group; the loser reuses the winner's group
          (or (t2/select-one-pk :model/PermissionsGroup :%lower.name (u/lower-case-en group-name))
              (throw e))))))

(defn- sync-groups!
  [user roles]
  (let [existing  (group-name->id)
        group-ids (mapv (partial group-id! existing) (distinct roles))]
    (log/debugf "Syncing OIDC groups for user %s from roles %s" (u/the-id user) (pr-str roles))
    ;; the two-arity sync is authoritative over every group except All Users and All Tenant Users,
    ;; which is what makes the roles claim the only source of truth
    (sso.common/sync-group-memberships! user group-ids)))

(defn sync-groups-from-claims!
  "Make `user`'s group memberships match the roles in the ID token `claims`, creating a group for any
  role that doesn't have one yet and dropping every membership no role accounts for.

  A no-op unless `MB_OIDC_GROUP_SYNC` is on. Never throws: a group that can't be created or a
  membership that can't be changed is logged rather than costing someone their login."
  [user claims]
  (when (and user (oidc.oss.config/group-sync?))
    (try
      (let [claim-path (oidc.oss.config/roles-claim-path)]
        (if-some [roles (get-in claims claim-path)]
          (sync-groups! user (role-names roles))
          ;; a claim that isn't there at all means MB_OIDC_ROLES_CLAIM points at the wrong place, or
          ;; the provider was never set up to send roles. Reading that as "no roles" would strip
          ;; every group from everyone who logs in, so leave memberships alone and say so.
          (log/warnf "OIDC login had no %s claim, skipping group sync"
                     (str/join "." (map name claim-path)))))
      (catch Exception e
        (log/errorf "Error syncing OIDC group memberships: %s" (ex-message e))))))
