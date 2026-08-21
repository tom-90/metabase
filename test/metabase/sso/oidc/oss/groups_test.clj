(ns metabase.sso.oidc.oss.groups-test
  (:require
   [clojure.test :refer :all]
   [metabase.permissions.core :as perms]
   [metabase.sso.oidc.oss.groups :as oidc.oss.groups]
   [metabase.test :as mt]
   [metabase.test.fixtures :as fixtures]
   [metabase.util :as u]
   [toucan2.core :as t2]))

(use-fixtures :once (fixtures/initialize :db))

(defn- group-names
  "Names of the PermissionsGroups `user` currently belongs to."
  [user]
  (when-let [group-ids (seq (t2/select-fn-set :group_id :model/PermissionsGroupMembership :user_id (u/the-id user)))]
    (t2/select-fn-set :name :model/PermissionsGroup :id [:in group-ids])))

(defn- cleanup-groups!
  [& names]
  (t2/delete! :model/PermissionsGroup :name [:in names]))

(defmacro ^:private with-group-sync!
  [& body]
  `(mt/with-temp-env-var-value! [mb-oidc-group-sync "true"]
     ~@body))

(deftest ^:parallel role-names-test
  (testing "a list holds one role per element, keeping names that contain spaces intact"
    (are [claim expected] (= expected
                             (#'oidc.oss.groups/role-names claim))
      ["analyst" "editor"]   ["analyst" "editor"]
      ["Data Analysts"]      ["Data Analysts"]
      ["  padded  "]         ["padded"]
      ["analyst" "" nil]     ["analyst"]
      #{"analyst"}           ["analyst"]
      [:analyst]             ["analyst"]))
  (testing "a bare string is delimited, the way a scope list is written"
    (are [claim expected] (= expected
                             (#'oidc.oss.groups/role-names claim))
      nil               nil
      ""                []
      "analyst"         ["analyst"]
      "analyst editor"  ["analyst" "editor"]
      "analyst, editor" ["analyst" "editor"])))

(deftest group-sync-is-off-by-default-test
  (mt/with-temp [:model/User user {}]
    (testing "handing the identity provider authority over groups has to be opted into"
      (oidc.oss.groups/sync-groups-from-claims! user {:roles ["OIDC Ought Not Exist"]})
      (is (= #{"All Users"}
             (group-names user)))
      (is (false? (t2/exists? :model/PermissionsGroup :name "OIDC Ought Not Exist"))))))

(deftest creates-groups-from-roles-test
  (with-group-sync!
    (mt/with-temp [:model/User user {}]
      (try
        (testing "a role with no group yet gets one"
          (oidc.oss.groups/sync-groups-from-claims! user {:roles ["OIDC Analysts" "OIDC Editors"]})
          (is (= #{"All Users" "OIDC Analysts" "OIDC Editors"}
                 (group-names user))))
        (testing "a new group is an ordinary group with no permissions, so creating it grants nothing"
          (let [group-id (t2/select-one-pk :model/PermissionsGroup :name "OIDC Analysts")]
            (is (nil? (t2/select-one-fn :magic_group_type :model/PermissionsGroup :id group-id)))
            (is (false? (t2/select-one-fn :is_superuser :model/User (u/the-id user))))
            (is (empty? (t2/select-fn-set :perm_value :model/DataPermissions
                                          {:where [:and
                                                   [:= :group_id group-id]
                                                   [:not-in :perm_value ["no" "no-self-service" "blocked" "unrestricted-database-only"]]]})))))
        (testing "the second login reuses the groups instead of duplicating them"
          (oidc.oss.groups/sync-groups-from-claims! user {:roles ["OIDC Analysts" "OIDC Editors"]})
          (is (= 1 (t2/count :model/PermissionsGroup :name "OIDC Analysts")))
          (is (= #{"All Users" "OIDC Analysts" "OIDC Editors"}
                 (group-names user))))
        (finally
          (cleanup-groups! "OIDC Analysts" "OIDC Editors"))))))

(deftest removes-groups-no-role-accounts-for-test
  (with-group-sync!
    (mt/with-temp [:model/PermissionsGroup by-hand {:name "OIDC Added By Hand"}
                   :model/User             user    {}]
      (try
        (perms/add-user-to-group! user by-hand)
        (testing "the roles claim is the whole truth: memberships nobody has a role for go away"
          (oidc.oss.groups/sync-groups-from-claims! user {:roles ["OIDC Analysts"]})
          (is (= #{"All Users" "OIDC Analysts"}
                 (group-names user))))
        (testing "including every group, when the claim is there but empty"
          (oidc.oss.groups/sync-groups-from-claims! user {:roles []})
          (is (= #{"All Users"}
                 (group-names user))))
        (finally
          (cleanup-groups! "OIDC Analysts"))))))

(deftest existing-group-is-matched-case-insensitively-test
  (with-group-sync!
    (mt/with-temp [:model/PermissionsGroup group {:name "OIDC Finance"}
                   :model/User             user  {}]
      (testing "group names are unique case-insensitively, so a differently-cased role reuses the group"
        (oidc.oss.groups/sync-groups-from-claims! user {:roles ["oidc finance"]})
        (is (= #{"All Users" "OIDC Finance"}
               (group-names user)))
        (is (= 1 (t2/count :model/PermissionsGroup :%lower.name "oidc finance")))
        (is (t2/exists? :model/PermissionsGroupMembership
                        :user_id (u/the-id user)
                        :group_id (u/the-id group)))))))

(deftest administrators-role-grants-admin-test
  (with-group-sync!
    (mt/with-temp [:model/User user {}]
      (testing "a role named after the Administrators group makes someone an admin"
        (oidc.oss.groups/sync-groups-from-claims! user {:roles [(:name (perms/admin-group))]})
        (is (true? (t2/select-one-fn :is_superuser :model/User (u/the-id user)))))
      (testing "and losing the role takes it away again"
        (oidc.oss.groups/sync-groups-from-claims! user {:roles []})
        (is (false? (t2/select-one-fn :is_superuser :model/User (u/the-id user))))))))

(deftest missing-claim-leaves-memberships-alone-test
  (with-group-sync!
    (mt/with-temp [:model/PermissionsGroup group {:name "OIDC Keep Me"}
                   :model/User             user  {}]
      (perms/add-user-to-group! user group)
      (testing "a claim that isn't in the token means the claim is misconfigured, not that the user
               has no roles -- stripping their groups over a typo would be worse than doing nothing"
        (mt/with-temp-env-var-value! [mb-oidc-roles-claim "realm_access.roles"]
          (oidc.oss.groups/sync-groups-from-claims! user {:roles ["OIDC Analysts"]})
          (is (= #{"All Users" "OIDC Keep Me"}
                 (group-names user))))))))
