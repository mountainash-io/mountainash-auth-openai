"""The account store: sign in once, then hand out the selected account's token without a person."""
from __future__ import annotations

import asyncio
import stat
import threading
from typing import TYPE_CHECKING

import pytest

from conftest import FULL_SCOPE, NO_PLAN_SCOPE
from mountainash_auth_openai import (
    OpenAIAccounts, OpenAIAuthError, PlanPermissionRequired, RefreshFailed, SignInRequired,
)

if TYPE_CHECKING:
    from pathlib import Path

APP = "hiivmind-agent-core"
SIGN_IN = f"mountainash-auth-openai sign-in --application {APP}"


def _store(tmp_path: Path) -> Path:
    return tmp_path / "config" / "mountainash" / "auth" / "openai" / APP


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


# --- where credentials are kept (CRED-2, CRED-3) ---

def test_the_store_is_an_owner_only_folder_per_application_under_the_config_home(accounts, tmp_path):
    root = _store(tmp_path)
    assert root.is_dir()
    for folder in (root, root.parent, root.parent.parent, root.parent.parent.parent):
        assert _mode(folder) == 0o700, folder


def test_each_signed_in_account_has_its_own_owner_only_credential_file(accounts, openai, tmp_path):
    first = accounts.sign_in()
    openai.subject, openai.email = "person-two", "other@example.com"
    second = accounts.sign_in(new=True)
    files = sorted(p for p in _store(tmp_path).rglob("*.yaml") if first.account_id in p.name or second.account_id in p.name)
    assert len(files) == 2
    assert all(_mode(f) == 0o600 for f in files)
    assert all(_mode(d) == 0o700 for d in _store(tmp_path).rglob("*") if d.is_dir())


@pytest.mark.parametrize("name", ["", "../escape", "Upper", "a/b", ".hidden"])
def test_an_application_name_that_is_not_one_plain_folder_name_is_refused(openai, name):
    with pytest.raises(ValueError):
        OpenAIAccounts.open(name, callback_server=openai.callback)


def test_a_store_folder_others_can_read_is_refused(openai, tmp_path):
    root = _store(tmp_path)
    root.mkdir(parents=True)
    root.chmod(0o755)
    with pytest.raises(OpenAIAuthError) as caught:
        OpenAIAccounts.open(APP, callback_server=openai.callback)
    assert caught.value.code == "AUTH_STORE_UNSAFE"


# --- signing in (CRED-1, CRED-9) ---

def test_signing_in_selects_the_account_and_its_token_is_then_handed_out(accounts):
    result = accounts.sign_in()
    assert (result.email, result.plan_allowed) == ("owner@example.com", True)
    assert accounts.token_sync() == "access-1"


def test_the_first_sign_in_registers_the_application_by_its_name(accounts, openai):
    accounts.sign_in()
    query = openai.authorize_queries[0]
    assert query["client_id"] == "dynamic_agent_client"
    assert query["agent_name_hint"] == APP
    assert "chatgpt.tokens.use.direct" in query["scope"].split()
    assert query["code_challenge_method"] == "S256"


def test_a_sign_in_whose_identity_token_is_not_signed_by_openai_is_refused(accounts, openai):
    from cryptography.hazmat.primitives.asymmetric import rsa

    openai.signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(OpenAIAuthError) as caught:
        accounts.sign_in()
    assert caught.value.code == "IDENTITY_INVALID"
    assert accounts.status() == []


@pytest.mark.parametrize("claim, value", [("iss", "https://evil.invalid"), ("aud", "another-client"), ("nonce", "replayed")])
def test_a_sign_in_whose_identity_token_names_the_wrong_party_is_refused(accounts, openai, claim, value):
    openai.claims_override = {claim: value}
    with pytest.raises(OpenAIAuthError) as caught:
        accounts.sign_in()
    assert caught.value.code == "IDENTITY_INVALID"


# --- the token call: refusals (CRED-7, CRED-7a, CRED-7b; examples E3, E3b, E4) ---

def test_with_nobody_signed_in_the_token_call_says_how_to_sign_in(accounts):   # E3
    with pytest.raises(SignInRequired) as caught:
        accounts.token_sync()
    assert str(caught.value) == f"no OpenAI account is signed in for {APP}.\nSign in: {SIGN_IN}"


def test_a_grant_without_plan_permission_is_kept_but_its_token_is_refused(accounts, openai):   # E1b, E3b
    openai.scope = NO_PLAN_SCOPE
    assert accounts.sign_in().plan_allowed is False
    with pytest.raises(PlanPermissionRequired) as caught:
        accounts.token_sync()
    assert str(caught.value) == (
        f"owner@example.com has not allowed {APP} to use the ChatGPT plan.\n"
        f"Sign in again and allow plan usage: {SIGN_IN}"
    )


def test_signing_in_again_asks_for_consent_and_keeps_the_same_account(accounts, openai):
    openai.scope = NO_PLAN_SCOPE
    first = accounts.sign_in()
    openai.scope = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
    again = accounts.sign_in()
    assert again.account_id == first.account_id and again.plan_allowed
    assert openai.authorize_queries[1]["prompt"] == "consent"
    assert openai.authorize_queries[1]["client_id"] == "oaiapp_issued"
    assert accounts.token_sync()


def test_signing_in_again_as_another_person_is_refused(accounts, openai):
    accounts.sign_in()
    openai.subject = "person-two"
    with pytest.raises(OpenAIAuthError) as caught:
        accounts.sign_in()
    assert caught.value.code == "IDENTITY_INVALID"


# --- refresh without a person (CRED-4, CRED-5, CRED-6, CRED-7, CRED-8) ---

def test_a_stale_token_is_refreshed_without_a_person(accounts, openai):
    openai.expires_in = 0   # stale at once
    accounts.sign_in()
    assert accounts.token_sync() == "access-2"
    assert openai.refreshes[0]["grant_type"] == "refresh_token"


def test_concurrent_callers_share_one_refresh_so_a_rotated_refresh_token_is_never_reused(accounts, openai):
    openai.expires_in = 0
    accounts.sign_in()
    openai.expires_in = 3600
    results, errors = [], []

    def call():
        try:
            results.append(accounts.token_sync())
        except Exception as e:   # noqa: BLE001 - the assertion below names it
            errors.append(e)

    threads = [threading.Thread(target=call) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(openai.refreshes) == 1
    assert set(results) == {"access-2"}


def test_two_store_handles_on_one_folder_share_one_refresh(openai):
    """Two jobs, each with its own handle on the store, as two processes would have."""
    one = OpenAIAccounts.open(APP, callback_server=openai.callback)
    two = OpenAIAccounts.open(APP, callback_server=openai.callback)
    try:
        openai.expires_in = 0
        one.sign_in()
        openai.expires_in = 3600
        threads = [threading.Thread(target=h.token_sync) for h in (one, two, one, two)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(openai.refreshes) == 1
    finally:
        one.close()
        two.close()


@pytest.mark.parametrize("code", ["invalid_grant", "refresh_token_reused", "refresh_token_expired"])
def test_a_refresh_refused_for_good_names_the_account_and_how_to_sign_in_again(accounts, openai, code):   # E4
    openai.expires_in = 0
    accounts.sign_in()
    openai.refresh_error = (400, {"error": code})
    expected = f"OpenAI refused the sign-in of owner@example.com for {APP} ({code}).\nSign in again: {SIGN_IN}"
    for _ in range(2):   # and the next job is told the same, without asking OpenAI again
        with pytest.raises(SignInRequired) as caught:
            accounts.token_sync()
        assert str(caught.value) == expected
    assert len(openai.refreshes) == 1


def test_signing_in_again_after_a_refusal_restores_the_same_account(accounts, openai):
    openai.expires_in = 0
    first = accounts.sign_in()
    openai.refresh_error = (400, {"error": "invalid_grant"})
    with pytest.raises(SignInRequired):
        accounts.token_sync()
    openai.refresh_error, openai.expires_in = None, 3600
    assert accounts.sign_in().account_id == first.account_id
    assert accounts.token_sync()


def test_a_refresh_that_failed_for_now_keeps_the_sign_in(accounts, openai):
    openai.expires_in = 0
    accounts.sign_in()
    openai.refresh_error = (503, {"error": "temporarily_unavailable"})
    with pytest.raises(RefreshFailed):
        accounts.token_sync()
    openai.refresh_error = None
    assert accounts.token_sync() == "access-2"


def test_a_refused_account_is_never_replaced_by_another_signed_in_account(accounts, openai):
    openai.expires_in = 0
    other = accounts.sign_in()
    openai.subject, openai.email = "person-two", "two@example.com"
    accounts.sign_in(new=True)   # selected: person two
    openai.refresh_error = (400, {"error": "invalid_grant"})
    with pytest.raises(SignInRequired) as caught:
        accounts.token_sync()
    assert "two@example.com" in str(caught.value)
    assert other.account_id not in str(caught.value)


def test_the_token_call_has_an_async_form(accounts):
    accounts.sign_in()
    assert asyncio.run(accounts.token()) == "access-1"


# --- status (CRED-10) ---

def test_status_lists_each_account_its_state_and_which_is_selected(accounts, openai):
    first = accounts.sign_in()
    openai.subject, openai.email, openai.scope = "person-two", "two@example.com", NO_PLAN_SCOPE
    second = accounts.sign_in(new=True)
    openai.subject, openai.email, openai.scope, openai.expires_in = "person-three", "three@example.com", FULL_SCOPE, 0
    third = accounts.sign_in(new=True)
    openai.refresh_error = (400, {"error": "invalid_grant"})
    with pytest.raises(SignInRequired):
        accounts.token_sync()
    rows = {row.account_id: (row.email, row.state, row.plan_allowed, row.selected) for row in accounts.status()}
    assert rows == {
        first.account_id: ("owner@example.com", "signed_in", True, False),
        second.account_id: ("two@example.com", "signed_in", False, False),
        third.account_id: ("three@example.com", "refused", False, True),
    }
