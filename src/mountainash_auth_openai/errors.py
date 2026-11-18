"""Errors a person can act on. None carries a token or a raw response body."""
from __future__ import annotations

__all__ = ["OpenAIAuthError", "PlanPermissionRequired", "RefreshFailed", "SignInRequired"]


class OpenAIAuthError(RuntimeError):
    """A failure with a stable `code` and a message safe to show."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(message)


class SignInRequired(OpenAIAuthError):
    """No account is signed in, or OpenAI refused the selected account's sign-in for good. Will not pass by retrying."""

    def __init__(self, message: str, *, refused: str | None = None):
        self.refused = refused   # OpenAI's error code, when it refused a refresh
        super().__init__("SIGN_IN_REQUIRED", message)


class PlanPermissionRequired(OpenAIAuthError):
    """The selected account's grant does not allow the ChatGPT plan to be used. Will not pass by retrying."""

    def __init__(self, message: str):
        super().__init__("PLAN_PERMISSION_REQUIRED", message)


class RefreshFailed(OpenAIAuthError):
    """A refresh failed for now (a server error, a dropped connection). The sign-in is kept; a later call may pass."""

    def __init__(self, message: str):
        super().__init__("REFRESH_FAILED", message)
