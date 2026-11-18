"""OpenAI's sign-in rules over mountainash-auth-client: Sign in with ChatGPT, one account store per application,
the refusal codes and the subscription route's facts. It builds no model client."""
from .__version__ import __version__
from .accounts import AccountStatus, OpenAIAccounts, SignInResult, store_root
from .errors import OpenAIAuthError, PlanPermissionRequired, RefreshFailed, SignInRequired
from .flow import PLAN_SCOPE
from .refusals import Refusal, classify, reason
from .route import ROUTE, SubscriptionRoute

__all__ = [
    "PLAN_SCOPE", "ROUTE", "AccountStatus", "OpenAIAccounts", "OpenAIAuthError", "PlanPermissionRequired",
    "Refusal", "RefreshFailed", "SignInRequired", "SignInResult", "SubscriptionRoute", "__version__", "classify",
    "reason", "store_root",
]
