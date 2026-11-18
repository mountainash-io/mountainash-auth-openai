"""OpenAI's sign-in rules ("Sign in with ChatGPT") on mountainash-auth-client's flow hooks.

From kleene-server's proof of concept (`kleene_server/auth/chatgpt.py`, 2026-10-19), with the application's name
in place of kleene's.
"""
from __future__ import annotations

import secrets
import webbrowser
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import httpx
import jwt
from mountainash_auth_client import OAuth2AuthProfile, OAuth2ProviderProfile, OAuthFlow
from mountainash_auth_client.errors import TokenRefreshError
from mountainash_auth_client.oauth.server.callback import LocalCallbackServer
from pydantic import Field

from .errors import OpenAIAuthError

if TYPE_CHECKING:
    from mountainash_auth_client import TokenCredential

__all__ = ["BOOTSTRAP", "ISSUER", "PLAN_SCOPE", "RESOURCE", "BrowserCallbackServer", "OpenAIFlow", "OpenAIProfile", "provider"]

ISSUER = "https://auth.openai.com"
RESOURCE = "https://api.openai.com/v1"
DISCOVERY = ISSUER + "/.well-known/openid-configuration"
BOOTSTRAP = "dynamic_agent_client"   # the client a first sign-in starts as; OpenAI issues the application its own
PLAN_SCOPE = "chatgpt.tokens.use.direct"   # the permission to bill use to the person's ChatGPT plan
SCOPES = "openid profile email offline_access resource.invoke " + PLAN_SCOPE


class OpenAIProfile(OAuth2AuthProfile):
    ACCOUNT_ID: str = Field(pattern=r"^[a-z0-9_]+$")
    SCOPE: str = SCOPES

    def persist_key(self) -> str:
        return f"openai.{self.ACCOUNT_ID}"


def provider() -> OAuth2ProviderProfile:
    return OAuth2ProviderProfile(
        NAME="openai", AUTHORIZE_URL=ISSUER + "/api/accounts/authorize",
        TOKEN_URL=ISSUER + "/api/accounts/oauth/token", BASE_URL=RESOURCE,
        DEFAULT_SCOPE=SCOPES, USE_PKCE=True, TOKEN_ENDPOINT_AUTH_METHOD="none",
    )


class BrowserCallbackServer(LocalCallbackServer):
    """Opens the system browser; never prints the authorize URL, which carries the saved identity hint."""

    def __init__(self):
        super().__init__(host="127.0.0.1", path="/auth/callback", timeout=120)

    def obtain_callback(self, authorize_url: str) -> dict[str, str]:
        try:
            try:
                opened = webbrowser.open(authorize_url)
            except Exception:
                opened = False
            if not opened:
                raise OpenAIAuthError("BROWSER_UNAVAILABLE", "Could not open the system browser for sign-in.")
            return self.wait_for_callback()
        finally:
            self.close()


class OpenAIFlow(OAuthFlow):
    def __init__(self, provider, *, application: str, host_id: str, registration: dict | None = None,
                 consent: bool = False, token_store=None, callback_server=None):
        super().__init__(provider, token_store=token_store, callback_server=callback_server)
        self.application = application
        self.host_id = host_id
        self.registration = dict(registration or {})
        self.consent = consent
        self.refused: str | None = None   # OpenAI's error code when it refused this flow's refresh

    def authorization_parameters(self, context) -> dict[str, str]:
        nonce = secrets.token_urlsafe(32)
        context.data["nonce"] = nonce
        params = {"nonce": nonce, "resource": RESOURCE, "ext_agent_host_id": self.host_id}
        if context.client_id == BOOTSTRAP:
            params["agent_name_hint"] = self.application
        else:
            hint = context.session_metadata.get("id_token")
            if isinstance(hint, str) and hint:
                params["id_token_hint"] = hint
            email = self.registration.get("email") or context.registration.get("email")
            if isinstance(email, str) and email:
                params["login_hint"] = email
        if self.consent:
            params["prompt"] = "consent"
        return params

    def token_parameters(self, context) -> dict[str, str]:
        return {"resource": RESOURCE}

    def process_callback(self, params, context):
        issued = params.get("client_id")
        if context.client_id == BOOTSTRAP:
            if not issued or issued == BOOTSTRAP:
                raise OpenAIAuthError("REGISTRATION_INCOMPLETE", "Registration did not return an issued client identity.")
        else:
            if issued is not None and issued != context.client_id:
                raise OpenAIAuthError("IDENTITY_MISMATCH", "Sign-in changed the selected client identity.")
            issued = context.client_id
        registration = dict(self.registration or context.registration)
        if registration.get("client_id") not in (None, issued):
            raise OpenAIAuthError("IDENTITY_MISMATCH", "Sign-in does not match the saved registration.")
        return issued, {**registration, "client_id": issued, "ext_agent_host_id": self.host_id}

    def refresh(self, refresh_token, client_id=None, client_secret=None, *, previous=None):
        try:
            return super().refresh(refresh_token, client_id, client_secret, previous=previous)
        except TokenRefreshError as error:
            self.refused = error.error_code
            raise

    @staticmethod
    def _discovery(client: httpx.Client) -> dict:
        response = client.get(DISCOVERY)
        response.raise_for_status()
        metadata = response.json()
        if not isinstance(metadata, dict) or metadata.get("issuer") != ISSUER:
            raise ValueError("Untrusted discovery issuer")
        for name in ("jwks_uri", "revocation_endpoint"):
            parsed = urlparse(metadata.get(name, ""))
            if parsed.scheme != "https" or parsed.netloc != "auth.openai.com" or parsed.fragment:
                raise ValueError("Untrusted discovery endpoint")
        return metadata

    def _claims(self, token: str, client_id: str) -> dict:
        with httpx.Client(timeout=30, follow_redirects=False) as client:
            discovery = self._discovery(client)
            response = client.get(discovery["jwks_uri"])
            response.raise_for_status()
            key_set = jwt.PyJWKSet.from_dict(response.json())
        header = jwt.get_unverified_header(token)
        matches = [key for key in key_set.keys
                   if key.key_id == header.get("kid") and key.algorithm_name == "RS256" and key.public_key_use in (None, "sig")]
        if len(matches) != 1:
            raise ValueError("No unique signing key")
        claims = jwt.decode(token, matches[0].key, algorithms=["RS256"], issuer=ISSUER,
                            audience=client_id, options={"require": ["iss", "aud", "exp", "iat", "sub"]})
        if not isinstance(claims["sub"], str) or not claims["sub"]:
            raise ValueError("Missing account identity")
        if isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and claims.get("azp") != client_id:
            raise ValueError("Incorrect authorized party")
        return claims

    def validate_token_response(self, response, context, previous, candidate):
        try:
            initial = context.grant_type == "authorization_code"
            if initial and not isinstance(response.get("scope"), str):
                raise ValueError("Missing explicit grant")
            if "scope" in response and not isinstance(response["scope"], str):
                raise ValueError("Invalid grant")
            if not isinstance(candidate.get("access_token"), str) or not candidate["access_token"]:
                raise ValueError("Missing access token")
            if response.get("token_type", "Bearer").lower() != "bearer":
                raise ValueError("Unsupported token type")
            registration = dict(self.registration or context.registration)
            if registration.get("client_id") not in (None, context.client_id):
                raise ValueError("Changed client identity")
            token = response.get("id_token")
            metadata = dict(previous.get("session_metadata", {})) if previous else {}
            if initial or token is not None:
                if not isinstance(token, str) or not token:
                    raise ValueError("Missing identity token")
                claims = self._claims(token, context.client_id)
                expected_nonce = context.data.get("nonce") if initial else metadata.get("nonce")
                if initial or "nonce" in claims:
                    if not expected_nonce or claims.get("nonce") != expected_nonce:
                        raise ValueError("Invalid nonce")
                if registration.get("subject") not in (None, claims["sub"]):
                    raise ValueError("Changed account identity")
                registration = {"issuer": ISSUER, "subject": claims["sub"], "client_id": context.client_id,
                                "ext_agent_host_id": self.host_id,
                                "email": claims.get("email") if isinstance(claims.get("email"), str) else None}
                metadata = {"id_token": token, "nonce": expected_nonce}
            elif not registration.get("subject") or registration.get("issuer") != ISSUER:
                raise ValueError("No previously validated identity")
            candidate["registration"] = registration
            candidate["session_metadata"] = metadata
            return candidate
        except OpenAIAuthError:
            raise
        except (jwt.PyJWTError, ValueError, TypeError, KeyError, AttributeError, httpx.HTTPError):
            raise OpenAIAuthError("IDENTITY_INVALID", "The sign-in identity or granted permission could not be verified.") from None

    def validate_credential(self, credential: TokenCredential) -> None:
        expected = self.registration
        registration = credential.registration
        if (registration.get("issuer") != ISSUER or not registration.get("subject")
                or registration.get("client_id") != credential.client_id
                or registration.get("ext_agent_host_id") != self.host_id
                or any(registration.get(key) != expected[key] for key in ("issuer", "subject", "client_id") if key in expected)):
            raise OpenAIAuthError("IDENTITY_MISMATCH", "Stored credentials do not match the selected account.")
        if PLAN_SCOPE not in (credential.scope or "").split():
            raise OpenAIAuthError("PLAN_PERMISSION_REQUIRED", "ChatGPT plan permission is not enabled for this account.")
