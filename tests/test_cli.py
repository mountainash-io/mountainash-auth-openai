"""The command a person runs once to sign an application in, and to see its accounts (examples E1 and E1b)."""
from __future__ import annotations

import pytest

from conftest import NO_PLAN_SCOPE
from mountainash_auth_openai import cli

APP = "hiivmind-agent-core"


@pytest.fixture
def run(openai, monkeypatch, capsys):
    monkeypatch.setattr(cli, "BrowserCallbackServer", openai.callback)

    def run(*argv: str) -> tuple[int, str, str]:
        code = cli.main(list(argv))
        out, err = capsys.readouterr()
        return code, out, err

    return run


def test_sign_in_says_who_is_signed_in_and_that_plan_usage_is_enabled(run):   # E1
    code, out, _ = run("sign-in", "--application", APP)
    assert code == 0
    lines = out.splitlines()
    assert lines[0] == "Opening the browser to sign in with ChatGPT…"
    assert lines[1].startswith("Signed in as owner@example.com (account ")
    assert lines[1].endswith("…). Plan usage: enabled. Selected.")


def test_sign_in_without_plan_permission_says_jobs_will_fail_until_it_is_allowed(run, openai):   # E1b
    openai.scope = NO_PLAN_SCOPE
    code, out, _ = run("sign-in", "--application", APP)
    assert code == 0
    assert out.splitlines()[1].endswith("…). Plan usage: NOT allowed. Selected.")
    assert out.splitlines()[2] == "Jobs will fail until plan usage is allowed: run sign-in again and allow it."


def test_a_failed_sign_in_says_why_and_exits_non_zero(run, openai):
    openai.claims_override = {"iss": "https://evil.invalid"}
    code, _, err = run("sign-in", "--application", APP)
    assert code == 1
    assert err.strip() == "sign-in failed: The sign-in identity or granted permission could not be verified."


def test_status_marks_the_selected_account_and_its_state(run, openai):
    run("sign-in", "--application", APP)
    openai.subject, openai.email, openai.scope = "person-two", "two@example.com", NO_PLAN_SCOPE
    run("sign-in", "--application", APP, "--new")
    code, out, _ = run("status", "--application", APP)
    assert code == 0
    rows = out.splitlines()
    assert len(rows) == 2
    assert rows[0].startswith("  ") and rows[0].endswith("owner@example.com  signed in  plan usage enabled")
    assert rows[1].startswith("* ") and rows[1].endswith("two@example.com  signed in  plan usage NOT allowed")


def test_status_with_no_account_says_how_to_sign_in(run):
    code, out, _ = run("status", "--application", APP)
    assert code == 0
    assert out == f"No OpenAI account is signed in for {APP}.\nSign in: mountainash-auth-openai sign-in --application {APP}\n"
