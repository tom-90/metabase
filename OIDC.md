# OIDC login (OSS edition)

Upstream Metabase only offers OIDC login as a paid feature. This fork adds an OIDC login flow to
the OSS edition, on top of the OIDC provider that already ships in `src/metabase/sso/`, and maps
the roles the identity provider sends onto Metabase groups.

## Configuration

Everything is configured with environment variables. Nothing is stored in the app db and there is
no admin UI — set these on the container and restart.

| Variable                   | Required | Default                | Meaning                                                                     |
| -------------------------- | -------- | ---------------------- | --------------------------------------------------------------------------- |
| `MB_OIDC_CLIENT_ID`        | yes      |                        | OAuth2 client id                                                            |
| `MB_OIDC_CLIENT_SECRET`    | yes      |                        | OAuth2 client secret                                                        |
| `MB_OIDC_ISSUER_URI`       | yes      |                        | Issuer URI; every other endpoint comes from its discovery document          |
| `MB_ENCRYPTION_SECRET_KEY` | yes      |                        | The OIDC state cookie is encrypted with it                                  |
| `MB_SITE_URL`              | yes      |                        | Used to build the callback URL, so it has to match what the provider knows  |
| `MB_OIDC_SCOPES`           | no       | `openid email profile` | Space- or comma-separated scopes                                            |
| `MB_OIDC_ROLES_CLAIM`      | no       | `roles`                | ID token claim holding the user's roles; `.` separated for a nested claim   |
| `MB_OIDC_GROUP_SYNC`       | no       | `false`                | `true` makes the roles claim the source of truth for groups (see below)     |

Register `https://your-metabase.example.com/api/oidc-oss/callback` as the redirect URI with your
identity provider.

Login is inert until the three required OIDC variables are set: the endpoints return a 400 and the
login page shows no SSO button.

## Groups from roles

With `MB_OIDC_GROUP_SYNC=true`, the roles in the ID token become the user's Metabase groups on every
login:

- A role is matched to the group of the same name, case-insensitively.
- A role with no group yet gets one created. New groups have **no permissions at all** until an admin
  grants some, so a new role can't grant access by appearing.
- Every other membership is removed. The token is the whole truth.

Nothing else is configured — there is no mapping table. To put people in a group, give them a role of
that name; to rename what a group is called in Metabase, rename the role.

Roles are read from the **ID token**, so the identity provider has to be configured to put them
there — an access token or a userinfo call is not consulted. Point `MB_OIDC_ROLES_CLAIM` at wherever
your provider puts them; in Keycloak that is

```
MB_OIDC_ROLES_CLAIM=resource_access.metabase.roles   # client roles, for the client named "metabase"
MB_OIDC_ROLES_CLAIM=realm_access.roles               # realm roles
```

and either way the matching mapper (Client scopes → roles → Mappers) needs *Add to ID token* turned
on. Client roles are usually what you want: only the roles you defined for Metabase come through,
rather than every realm role the provider hands out.

A role name may contain spaces when the claim is a list (`["Data Analysts"]` is one role). A claim
that is a bare string is split on commas and whitespace instead, the way a scope list is written.

### Admin access comes from the identity provider too

`Administrators` is an ordinary group as far as this is concerned: a role called `Administrators`
makes someone a Metabase admin, and an admin who logs in *without* that role is demoted. Before
turning group sync on, either create that role and assign it, or keep an admin account that doesn't
log in through OIDC. Metabase refuses to demote the last remaining admin, so you cannot lock yourself
out completely, but you can demote everyone else.

### When roles go missing

If the claim named by `MB_OIDC_ROLES_CLAIM` is absent from the token entirely, the sync is skipped
and a warning logged — that is a misconfiguration, and reading it as "this user has no roles" would
strip everyone's groups. A claim that is present but empty *is* honoured: that user genuinely has no
roles and ends up in no groups.

## Signing in

People who land on a Metabase page while signed out are redirected to the identity provider
automatically. Reaching the login page deliberately — after signing out, say — shows a "Sign in with
SSO" button instead, so signing out doesn't immediately sign you back in.

To sign in with a password while OIDC is on (recovering a locked-out admin, for instance), use
`/auth/login?disable_sso=true`.

## Where the code lives

Rebasing this fork onto a newer upstream release means re-applying:

| File                                                     | Change                                                             |
| -------------------------------------------------------- | ------------------------------------------------------------------ |
| `src/metabase/sso/oidc/oss/`                             | New. Config, group sync, and the `/api/oidc-oss` endpoints           |
| `test/metabase/sso/oidc/oss/`                            | New. Tests for both                                                 |
| `src/metabase/api_routes/routes.clj`                     | Mounts `/api/oidc-oss`                                              |
| `src/metabase/sso/settings.clj`                          | One line, so `sso-source-enabled?` knows about OIDC (see below)     |
| `.clj-kondo/config/modules/config.edn`                   | Allows the new API namespace (regenerate with `./bin/mage fix-modules-config`) |
| `frontend/src/metabase/plugins/builtin/auth/oidc.tsx`    | New. The login button and auto-redirect                             |
| `frontend/src/metabase/plugins/builtin.ts`               | Registers the plugin                                                |
| `frontend/src/metabase-types/api/settings.ts` (+ mocks)  | Types the `oidc-oss-enabled` setting                                |

### Why `sso/settings.clj` needs touching

`sso-source-enabled?` decides whether a user's SSO provider is still live, and password reset is
blocked for them if it is. Upstream reads the enterprise `oidc-enabled` setting there, which is not
registered at all in an OSS build — `setting/get` throws `Unknown setting` on it. Upstream never hits
that branch, because without enterprise code no OSS user can have `sso_source = "oidc"` in the first
place. This fork creates exactly those users, so the branch becomes reachable and has to check
`oidc-oss-enabled` (and check registration before reading either setting). Without it, "forgot
password" returns a 500 for every OIDC user.
