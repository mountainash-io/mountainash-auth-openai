"""The ChatGPT subscription route's facts, as kleene-server found them live on `gpt-6-luna` (2026-10-19).

Data only: each consumer builds its own model client from them.
"""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ROUTE", "SubscriptionRoute"]


@dataclass(frozen=True)
class SubscriptionRoute:
    base_url: str = "https://api.openai.com/v1"   # the Responses API, `POST /responses`, with the access token as bearer
    stream: bool = True                           # the route needs `stream=true`
    store: bool = False                           # the route needs `store=false`
    accepts_output_token_cap: bool = False        # `max_output_tokens` is refused
    accepts_temperature: bool = False             # `temperature` is refused
    # `response.completed` can carry an empty `output`: read the items from `response.output_item.done`.
    completed_output_may_be_empty: bool = True


ROUTE = SubscriptionRoute()
