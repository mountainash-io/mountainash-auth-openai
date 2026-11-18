"""What an OpenAI refusal on the subscription route means, so that each consumer maps it to its own errors."""
from __future__ import annotations

from enum import StrEnum

__all__ = ["Refusal", "classify", "reason"]


class Refusal(StrEnum):
    USAGE_LIMIT = "usage_limit"   # the plan's usage is spent: will not pass until the plan resets
    PERMISSION = "permission"     # the account or grant may not use the plan
    SIGN_IN = "sign_in"           # the token was not accepted: sign in again
    OTHER = "other"               # anything else, including a rate limit that passes


_USAGE_LIMIT = {"subscription_sharing_usage_limit_exceeded"}
_PERMISSION = {
    "subscription_sharing_user_not_eligible",
    "subscription_sharing_invalid_user",
    "chatpass_v2_scope_not_authorized",
    "chatpass_v2_invalid_authorization_context",
}

_REASONS = {
    Refusal.USAGE_LIMIT: "ChatGPT plan usage is limited. Review https://chatgpt.com/settings/usage before resuming.",
    Refusal.PERMISSION: "ChatGPT did not authorize this request. Check the selected account and its plan permission.",
    Refusal.SIGN_IN: "OpenAI did not accept the account's sign-in. Sign in again.",
}


def classify(code: str | None, status: int | None) -> Refusal:
    """A refusal's meaning from its error code, else its HTTP status. A stream event carries a code and no status."""
    if code in _USAGE_LIMIT:
        return Refusal.USAGE_LIMIT
    if code in _PERMISSION or status == 403:
        return Refusal.PERMISSION
    if status == 401:
        return Refusal.SIGN_IN
    return Refusal.OTHER


def reason(refusal: Refusal) -> str | None:
    """The person-facing reason for a refusal that will not pass; `None` for `OTHER`."""
    return _REASONS.get(refusal)
