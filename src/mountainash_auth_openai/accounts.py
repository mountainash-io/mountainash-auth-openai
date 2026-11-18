"""One application's OpenAI accounts on this machine, and the selected account's token for unattended use.

Kept under `$XDG_CONFIG_HOME/mountainash/auth/openai/<application>/` (`~/.config` when unset). The folders are
owner-only and each file is `0600`; the credentials are not encrypted at rest. Any number of processes may open the
same store: a refresh holds the account's lock from reading the refresh token to writing its replacement, so a
rotated refresh token is never sent twice.
"""
from __future__ import annotations

import asyncio
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import httpx
from mountainash_auth_client import OAuth2TokenManager
from mountainash_auth_client.errors import AuthorizationRequired, TokenRefreshError
from mountainash_settings.secrets import FilesystemBackend, NamespacedSecretStore
from pydantic import BaseModel, ConfigDict, Field

from .errors import OpenAIAuthError, PlanPermissionRequired, RefreshFailed, SignInRequired
from .flow import BOOTSTRAP, ISSUER, PLAN_SCOPE, BrowserCallbackServer, OpenAIFlow, OpenAIProfile, provider

__all__ = ["AccountStatus", "OpenAIAccounts", "SignInResult", "store_root"]

_APPLICATION = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
# OpenAI's refresh refusals that no retry will pass. auth-client itself clears the record for the first two.
_TERMINAL = {"invalid_grant", "invalid_token", "invalid_refresh_token", "token_expired",
             "refresh_token_expired", "refresh_token_invalidated", "refresh_token_reused"}


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _Account(_Model):
    registration: dict[str, str | None] = Field(default_factory=dict)
    refused: str | None = None   # OpenAI's code when it refused a refresh for good; cleared by signing in again


class _Catalogue(_Model):
    version: Literal[1] = 1
    host_id: str
    accounts: dict[str, _Account] = Field(default_factory=dict)
    selected_account_id: str | None = None


@dataclass(frozen=True)
class SignInResult:
    account_id: str
    email: str | None
    plan_allowed: bool


@dataclass(frozen=True)
class AccountStatus:
    account_id: str
    email: str | None
    state: Literal["signed_in", "signed_out", "refused"]
    refused: str | None
    plan_allowed: bool
    selected: bool


def store_root(application: str) -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or Path.home() / ".config"
    return Path(base) / "mountainash" / "auth" / "openai" / application


def _private_folder(root: Path) -> None:
    """Make each missing folder from `mountainash/` down owner-only, then refuse a store others can reach."""
    root.parents[3].mkdir(parents=True, exist_ok=True)   # the config home itself keeps the user's own permissions
    # mountainash, auth, openai, <application>, and the token store's own `oauth` folder, which it would make 0777 & umask
    for folder in [*reversed([root, *root.parents][:4]), root / "oauth"]:
        try:
            folder.mkdir(mode=0o700)
            folder.chmod(0o700)   # whatever the umask
        except FileExistsError:
            pass
    info = root.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise OpenAIAuthError("AUTH_STORE_UNSAFE", f"The account store {root} must be a folder only its owner can use.")


class OpenAIAccounts:
    @classmethod
    def open(cls, application: str, *, callback_server=BrowserCallbackServer) -> OpenAIAccounts:
        if not isinstance(application, str) or not _APPLICATION.fullmatch(application):
            raise ValueError("The application name must be lowercase letters, digits and hyphens.")
        root = store_root(application)
        _private_folder(root)
        return cls(application, FilesystemBackend(root), callback_server)

    def __init__(self, application: str, store: FilesystemBackend, callback_server):
        self.application = application
        self._store = store
        self._records = NamespacedSecretStore(store, "oauth")
        self._callback_server = callback_server

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> OpenAIAccounts:
        return self

    def __exit__(self, *_) -> None:
        self.close()

    # --- the catalogue: read fresh each time, since other processes share it ---

    def _catalogue(self) -> _Catalogue:
        with self._store.transaction("catalogue"):
            saved = self._store.get("catalogue")
            if saved:
                return _Catalogue.model_validate(saved)
            catalogue = _Catalogue(host_id="urn:uuid:" + str(uuid.uuid4()))
            self._store.set("catalogue", catalogue.model_dump(mode="json"))
            return catalogue

    def _update(self, change) -> _Catalogue:
        self._catalogue()   # made, if new
        with self._store.transaction("catalogue"):
            catalogue = _Catalogue.model_validate(self._store.get("catalogue"))
            change(catalogue)
            self._store.set("catalogue", catalogue.model_dump(mode="json"))
            return catalogue

    def _record(self, account_id: str) -> dict:
        key = f"openai.{account_id}"
        with self._records.transaction(key):
            return {} if self._records.is_cleared(key) else (self._records.get(key) or {})

    def _manager(self, catalogue: _Catalogue, account_id: str, *, consent: bool = False, flows: list | None = None):
        registration = dict(catalogue.accounts[account_id].registration)
        profile = OpenAIProfile(ACCOUNT_ID=account_id, CLIENT_ID=registration.get("client_id") or BOOTSTRAP)

        def factory(p, **kwargs):
            flow = OpenAIFlow(p, application=self.application, host_id=catalogue.host_id,
                              registration=registration, consent=consent, **kwargs)
            if flows is not None:
                flows.append(flow)
            return flow

        return OAuth2TokenManager(provider(), profile, token_store=self._store,
                                  callback_server=self._callback_server, flow_factory=factory)

    # --- messages (approved as examples E3, E3b and E4 of agent-core's credentials design) ---

    def _command(self) -> str:
        return f"mountainash-auth-openai sign-in --application {self.application}"

    def _nobody(self) -> SignInRequired:
        return SignInRequired(f"no OpenAI account is signed in for {self.application}.\nSign in: {self._command()}")

    def _refused(self, who: str, code: str) -> SignInRequired:
        return SignInRequired(
            f"OpenAI refused the sign-in of {who} for {self.application} ({code}).\nSign in again: {self._command()}",
            refused=code,
        )

    def _no_plan(self, who: str) -> PlanPermissionRequired:
        return PlanPermissionRequired(
            f"{who} has not allowed {self.application} to use the ChatGPT plan.\n"
            f"Sign in again and allow plan usage: {self._command()}"
        )

    # --- signing in ---

    def sign_in(self, *, new: bool = False) -> SignInResult:
        """Sign in through the browser. Signs the selected account in again, asking for consent, unless `new`."""
        catalogue = self._catalogue()
        account_id = None if new else catalogue.selected_account_id
        created = account_id is None
        if created:
            account_id = uuid.uuid4().hex
            catalogue = self._update(lambda c: c.accounts.__setitem__(account_id, _Account()))
        manager = self._manager(catalogue, account_id, consent=not created)
        try:
            manager.authorize()
        except BaseException:
            if created:
                self._update(lambda c: c.accounts.pop(account_id, None))
            raise
        record = self._record(account_id)
        registration = record.get("registration") or {}
        if registration.get("issuer") != ISSUER or not registration.get("subject"):
            raise OpenAIAuthError("IDENTITY_INVALID", "The sign-in identity could not be verified.")

        def publish(c: _Catalogue) -> None:
            c.accounts[account_id] = _Account(registration=dict(registration))
            c.selected_account_id = account_id

        self._update(publish)
        return SignInResult(account_id, registration.get("email"), PLAN_SCOPE in (record.get("scope") or "").split())

    # --- the token, without a person ---

    def token_sync(self) -> str:
        """The selected account's access token, refreshed first when stale. Never another account's."""
        catalogue = self._catalogue()
        account_id = catalogue.selected_account_id
        if account_id is None or not catalogue.accounts[account_id].registration:
            raise self._nobody()
        entry = catalogue.accounts[account_id]
        who = entry.registration.get("email") or f"account {account_id[:8]}"
        if entry.refused:
            raise self._refused(who, entry.refused)
        flows: list[OpenAIFlow] = []
        manager = self._manager(catalogue, account_id, flows=flows)
        try:
            return manager.acquire().access_token
        except AuthorizationRequired:
            code = flows[-1].refused if flows else None
            if code is None:
                raise self._nobody() from None
            self._mark_refused(account_id, code)
            raise self._refused(who, code) from None
        except TokenRefreshError as error:
            if error.error_code in _TERMINAL:
                manager.revoke()
                self._mark_refused(account_id, error.error_code)
                raise self._refused(who, error.error_code) from None
            raise RefreshFailed(f"The sign-in of {who} could not be refreshed (HTTP {error.status_code}); try again later.") from None
        except httpx.HTTPError:
            raise RefreshFailed(f"The sign-in of {who} could not be refreshed: OpenAI could not be reached.") from None
        except OpenAIAuthError as error:
            if error.code == "PLAN_PERMISSION_REQUIRED":
                raise self._no_plan(who) from None
            raise

    async def token(self) -> str:
        """`token_sync` off the event loop: a refresh blocks on the account's lock and on OpenAI."""
        return await asyncio.to_thread(self.token_sync)

    def _mark_refused(self, account_id: str, code: str) -> None:
        def mark(c: _Catalogue) -> None:
            c.accounts[account_id].refused = code
        self._update(mark)

    # --- status ---

    def status(self) -> list[AccountStatus]:
        catalogue = self._catalogue()
        rows = []
        for account_id, entry in catalogue.accounts.items():
            if not entry.registration:
                continue   # a sign-in still in progress, or one that never finished
            record = self._record(account_id)
            state = "refused" if entry.refused else "signed_in" if record.get("access_token") else "signed_out"
            rows.append(AccountStatus(
                account_id=account_id, email=entry.registration.get("email"), state=state, refused=entry.refused,
                plan_allowed=bool(record.get("access_token")) and PLAN_SCOPE in (record.get("scope") or "").split(),
                selected=account_id == catalogue.selected_account_id,
            ))
        return rows
