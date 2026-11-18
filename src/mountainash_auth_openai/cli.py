"""`mountainash-auth-openai`: sign an application in once, through the browser, and list its accounts."""
from __future__ import annotations

import argparse
import sys

from .accounts import OpenAIAccounts
from .errors import OpenAIAuthError
from .flow import BrowserCallbackServer


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mountainash-auth-openai", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    sign_in = commands.add_parser("sign-in", help="sign in with ChatGPT and select the account")
    sign_in.add_argument("--application", required=True, help="the application's name, e.g. hiivmind-agent-core")
    sign_in.add_argument("--new", action="store_true", help="add another account instead of signing the selected one in again")
    status = commands.add_parser("status", help="list the application's accounts")
    status.add_argument("--application", required=True)
    return parser


def _sign_in(accounts: OpenAIAccounts, new: bool) -> int:
    print("Opening the browser to sign in with ChatGPT…", flush=True)
    try:
        result = accounts.sign_in(new=new)
    except (OpenAIAuthError, OSError) as error:
        print(f"sign-in failed: {error}", file=sys.stderr)
        return 1
    plan = "enabled" if result.plan_allowed else "NOT allowed"
    print(f"Signed in as {result.email or 'an unnamed account'} (account {result.account_id[:8]}…). Plan usage: {plan}. Selected.")
    if not result.plan_allowed:
        print("Jobs will fail until plan usage is allowed: run sign-in again and allow it.")
    return 0


def _status(accounts: OpenAIAccounts) -> int:
    rows = accounts.status()
    if not rows:
        print(f"No OpenAI account is signed in for {accounts.application}.\n"
              f"Sign in: mountainash-auth-openai sign-in --application {accounts.application}")
        return 0
    for row in rows:
        state = {"signed_in": "signed in", "signed_out": "signed out"}.get(row.state, f"needs signing in again ({row.refused})")
        plan = "plan usage enabled" if row.plan_allowed else "plan usage NOT allowed"
        print(f"{'*' if row.selected else ' '} {row.account_id[:8]}…  {row.email or '-'}  {state}  {plan}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        accounts = OpenAIAccounts.open(args.application, callback_server=BrowserCallbackServer)
    except (OpenAIAuthError, ValueError) as error:
        print(f"{args.command} failed: {error}", file=sys.stderr)
        return 1
    with accounts:
        return _sign_in(accounts, args.new) if args.command == "sign-in" else _status(accounts)


if __name__ == "__main__":
    sys.exit(main())
