import pytest

from mountainash_auth_openai import Refusal, classify, reason


@pytest.mark.parametrize("code, status, expected", [
    ("subscription_sharing_usage_limit_exceeded", 429, Refusal.USAGE_LIMIT),
    ("subscription_sharing_usage_limit_exceeded", None, Refusal.USAGE_LIMIT),   # arrived as a stream event
    ("subscription_sharing_user_not_eligible", 403, Refusal.PERMISSION),
    ("chatpass_v2_scope_not_authorized", None, Refusal.PERMISSION),
    (None, 403, Refusal.PERMISSION),
    (None, 401, Refusal.SIGN_IN),
    ("rate_limit_exceeded", 429, Refusal.OTHER),   # a refusal that passes: the caller retries it
    (None, 500, Refusal.OTHER),
    (None, None, Refusal.OTHER),
])
def test_an_openai_refusal_is_classified_by_its_code_then_its_status(code, status, expected):
    assert classify(code, status) is expected


def test_the_usage_limit_reason_points_to_the_plan_settings():
    assert reason(Refusal.USAGE_LIMIT) == (
        "ChatGPT plan usage is limited. Review https://chatgpt.com/settings/usage before resuming."
    )


def test_a_refusal_that_passes_has_no_reason_of_its_own():
    assert reason(Refusal.OTHER) is None
