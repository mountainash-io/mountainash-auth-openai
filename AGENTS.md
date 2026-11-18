# AGENTS.md — mountainash-auth-openai

OpenAI's sign-in rules over `mountainash-auth-client`. Read `README.md` first.

## Boundaries

- This package holds what is OpenAI's: sign-in endpoints, scopes, PKCE, client registration, identity-token checks, refusal codes, the subscription route's facts. It builds no model client and has no knowledge of any consumer (agent-core, kleene-server).
- OAuth wire handling, refresh and the token files belong to `mountainash-auth-client` and `mountainash-settings`; use their hooks (`OAuthFlow`, `flow_factory`, `FilesystemBackend`) rather than reimplementing them.
- The token call never falls back to another account, and never prints or logs a token, a refresh token or the authorize URL.

## Layout

- `flow.py` — `OpenAIFlow` on auth-client's hooks; `BrowserCallbackServer`.
- `accounts.py` — `OpenAIAccounts`: the store per application, sign-in, the token call, status.
- `refusals.py`, `route.py` — OpenAI's refusal codes and the subscription route's facts, as data.
- `cli.py` — `mountainash-auth-openai sign-in | status`.

## Planning

The requirements are §4.1 (CRED-1 to CRED-12) of the approved design in hiivmind-central, `04.planning/hiivmind-agent-core/superpowers/specs/2026-11-18-agent-core-model-provider-credentials-design.md`. This package has no planning project in mountainash-central yet.

## Checks

```sh
uv run pytest
uv run ruff check src tests
```

Tests run against a stand-in for OpenAI's identity service (`tests/conftest.py`); none calls OpenAI.
