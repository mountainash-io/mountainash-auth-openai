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

Design principles and planning live in **mountainash-central** (beside this checkout): principles in `01.principles/mountainash-auth-openai/` (read them before changing a boundary), the backlog in `04.planning/mountainash-auth-openai/a.backlog/INDEX.md`, and the design (requirements CRED-1 to CRED-12) in `04.planning/mountainash-auth-openai/superpowers/specs/2026-11-18-mountainash-auth-openai-design.md`. Save new specs and plans there, not in this repository.

## Checks

```sh
uv run pytest
uv run ruff check src tests
```

Tests run against a stand-in for OpenAI's identity service (`tests/conftest.py`); none calls OpenAI.
