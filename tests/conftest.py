"""A stand-in for OpenAI's identity service, reached through httpx, and a callback that needs no browser."""
from __future__ import annotations

import json
import threading
import time
from urllib.parse import parse_qs, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "https://auth.openai.com"
FULL_SCOPE = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
NO_PLAN_SCOPE = "openid profile email offline_access resource.invoke"


class FakeOpenAI:
    """OpenAI's sign-in as kleene-server found it live on 2026-10-19: an issued client, rotating refresh tokens."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.signing_key = self.key
        self.issued_client = "oaiapp_issued"
        self.subject = "person-one"
        self.email = "owner@example.com"
        self.scope = FULL_SCOPE
        self.expires_in = 3600
        self.refresh_error: tuple[int, dict] | None = None
        self.claims_override: dict = {}
        self.nonce: str | None = None
        self.authorize_queries: list[dict] = []
        self.refreshes: list[dict] = []
        self.used_refresh_tokens: set[str] = set()
        self._issued = 0
        self._lock = threading.Lock()

    def _id_token(self, *, nonce: str | None) -> str:
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": self.issued_client, "sub": self.subject, "iat": now, "exp": now + 3600,
                  "email": self.email}
        if nonce is not None:
            claims["nonce"] = nonce
        claims.update(self.claims_override)
        return jwt.encode(claims, self.signing_key, algorithm="RS256", headers={"kid": "one"})

    def _tokens(self, *, nonce: str | None) -> dict:
        self._issued += 1
        return {"access_token": f"access-{self._issued}", "refresh_token": f"refresh-{self._issued}",
                "token_type": "Bearer", "expires_in": self.expires_in, "scope": self.scope,
                "id_token": self._id_token(nonce=nonce)}

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": ISSUER + "/jwks",
                                             "revocation_endpoint": ISSUER + "/revoke"})
        if path == "/jwks":
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
            return httpx.Response(200, json={"keys": [{**jwk, "kid": "one", "use": "sig", "alg": "RS256"}]})
        if path == "/revoke":
            return httpx.Response(200)
        assert path == "/api/accounts/oauth/token", path
        data = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        assert data["resource"] == "https://api.openai.com/v1"
        assert "client_secret" not in data
        with self._lock:
            if data["grant_type"] == "authorization_code":
                return httpx.Response(200, json=self._tokens(nonce=self.nonce))
            self.refreshes.append(data)
            time.sleep(0.05)   # long enough for a second caller to arrive while this refresh is in flight
            if self.refresh_error is not None:
                status, body = self.refresh_error
                return httpx.Response(status, json=body)
            if data["refresh_token"] in self.used_refresh_tokens:
                return httpx.Response(400, json={"error": "refresh_token_reused"})
            self.used_refresh_tokens.add(data["refresh_token"])
            return httpx.Response(200, json=self._tokens(nonce=None))

    def callback(self):
        """A callback server factory: answers the authorize URL as OpenAI would after consent."""
        owner = self

        class Callback:
            port = 1455
            redirect_uri = "http://127.0.0.1:1455/auth/callback"

            def obtain_callback(self, url: str) -> dict[str, str]:
                query = {k: v[0] for k, v in parse_qs(urlparse(url).query).items()}
                owner.authorize_queries.append(query)
                owner.nonce = query["nonce"]
                return {"state": query["state"], "code": "code-1", "client_id": owner.issued_client}

        return Callback()


@pytest.fixture
def openai(monkeypatch, tmp_path):
    fake = FakeOpenAI()
    original = httpx.Client.__init__

    def init(client, *args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(fake.handle)
        original(client, *args, **kwargs)

    monkeypatch.setattr(httpx.Client, "__init__", init)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    return fake


@pytest.fixture
def accounts(openai):
    from mountainash_auth_openai import OpenAIAccounts

    opened = OpenAIAccounts.open("hiivmind-agent-core", callback_server=openai.callback)
    yield opened
    opened.close()
