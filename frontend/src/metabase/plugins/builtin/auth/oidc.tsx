import { useEffect, useState } from "react";
import { t } from "ttag";

import {
  PLUGIN_AUTH_PROVIDERS,
  PLUGIN_IS_PASSWORD_USER,
} from "metabase/plugins";
import type { AuthProviderButtonProps } from "metabase/plugins/types";
import { Button } from "metabase/ui";
import MetabaseSettings from "metabase/utils/settings";

const LOGIN_URL = "/api/oidc-oss/login";

// Lets someone who needs to sign in with a password reach the login page without being bounced
// to the identity provider: /auth/login?disable_sso=true
const DISABLE_SSO_PARAM = "disable_sso";

const getLoginUrl = (redirectUrl?: string) =>
  redirectUrl
    ? `${LOGIN_URL}?redirect=${encodeURIComponent(redirectUrl)}`
    : LOGIN_URL;

function OidcButton({ redirectUrl }: AuthProviderButtonProps) {
  const [isRedirecting, setIsRedirecting] = useState(false);
  const url = getLoginUrl(redirectUrl);

  useEffect(() => {
    const isSsoDisabled = new URLSearchParams(window.location.search).has(
      DISABLE_SSO_PARAM,
    );

    // A redirect URL means the route guard sent them here from a page they weren't signed in
    // for, so sign them in straight away. Reaching the login page without one is deliberate —
    // usually they just logged out — and auto-redirecting would sign them right back in.
    if (redirectUrl && !isSsoDisabled) {
      setIsRedirecting(true);
      window.location.href = url;
    }
  }, [redirectUrl, url]);

  return (
    <Button component="a" href={url} variant="filled" loading={isRedirecting}>
      {isRedirecting ? t`Signing in…` : t`Sign in with SSO`}
    </Button>
  );
}

PLUGIN_AUTH_PROVIDERS.providers.push((providers) => {
  const oidcProvider = {
    name: "oidc",
    Button: OidcButton,
  };

  return MetabaseSettings.get("oidc-oss-enabled")
    ? [oidcProvider, ...providers]
    : providers;
});

PLUGIN_IS_PASSWORD_USER.push((user) => user.sso_source !== "oidc");
