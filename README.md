# mountainash-auth-openai

OpenAI's sign-in rules over [`mountainash-auth-client`](../mountainash-auth-client): "Sign in with ChatGPT", so that an application bills its model use to a person's ChatGPT plan rather than an API key. One sign-in per application, kept on the machine, refreshed without a person.

It holds what is OpenAI's and nobody else's: the sign-in endpoints and scopes (including the plan permission `chatgpt.tokens.use.direct`), PKCE, client registration, the identity-token checks, the refresh refusals that will not pass, and the subscription route's facts. It builds no model client: each application builds its own from `ROUTE`.

Status: alpha. The sign-in rules come from kleene-server's proof of concept, qualified live on `gpt-6-luna` on 2026-10-19. This package was checked live on 2026-11-18: a browser sign-in with plan usage enabled, a forced refresh through its identity checks, and one streamed reply from `gpt-6-luna` on the subscription route. The tests run against a stand-in for OpenAI.

## Sign in once

```sh
mountainash-auth-openai sign-in --application hiivmind-agent-core
# Opening the browser to sign in with ChatGPT…
# Signed in as owner@example.com (account 3f9c1a2b…). Plan usage: enabled. Selected.

mountainash-auth-openai status --application hiivmind-agent-core
# * 3f9c1a2b…  owner@example.com  signed in  plan usage enabled
```

`sign-in` signs the selected account in again (asking for consent), for instance after a refusal or to allow plan usage. `sign-in --new` adds another account and selects it. The command opens the system browser and listens on `127.0.0.1` for the callback; it never prints the authorize URL, which carries the saved identity hint.

## Use the token

```python
from mountainash_auth_openai import OpenAIAccounts, ROUTE, PlanPermissionRequired, RefreshFailed, SignInRequired

accounts = OpenAIAccounts.open("hiivmind-agent-core")
token = await accounts.token()        # or accounts.token_sync()
```

The call returns the selected account's access token, refreshing it first when it is stale. It never uses another account. It raises:

| Error | When | Retry? |
|---|---|---|
| `SignInRequired` | nobody is signed in; or OpenAI refused the refresh for good (`invalid_grant`, `refresh_token_reused`, …). The message names the account and the command to run. | no |
| `PlanPermissionRequired` | the grant does not allow the ChatGPT plan to be used | no |
| `RefreshFailed` | the refresh failed for now (a `5xx`, a dropped connection); the sign-in is kept | yes |

A refused account stays refused, without asking OpenAI again, until someone signs it in again.

To build a client on the subscription route, read `ROUTE`: `base_url` (`https://api.openai.com/v1`, the Responses API), `stream=True` and `store=False` are required; `input` must be a list of items, not a string; a `system` message is refused, so the system text goes as `instructions`; `max_output_tokens` and `temperature` are refused; `response.completed` can carry an empty `output`, so read items from `response.output_item.done`. To read a refusal from that route, `classify(code, status)` gives `Refusal.USAGE_LIMIT`, `PERMISSION`, `SIGN_IN` or `OTHER`, and `reason(refusal)` the person-facing text.

## Where credentials are kept

```text
$XDG_CONFIG_HOME/mountainash/auth/openai/<application>/     (~/.config when XDG_CONFIG_HOME is unset; 0700)
├── catalogue.yaml                       the accounts, their registrations, the selected one (0600)
└── oauth/openai-<account-id>.yaml       each account's tokens (0600), with its lock file
```

The files are owner-only, **not encrypted at rest**. Any number of processes may open the same store. A refresh holds that account's lock (`flock`) from reading the refresh token to writing its replacement, so two jobs never send the same rotated refresh token. A store folder that others can read is refused.

## Development

Side-by-side checkouts of `mountainash-auth-client` and `mountainash-settings` are expected next to this one (`[tool.uv.sources]`).

```sh
uv sync
uv run pytest
uv run ruff check src tests
```

Design, principles and backlog: mountainash-central, `04.planning/mountainash-auth-openai/` and `01.principles/mountainash-auth-openai/`.
