"""Payment API boundary defined by api-schema.json."""

from __future__ import annotations


def payment_response(payment_id: str, amount_cents: int, currency: str = "USD") -> dict:
    if amount_cents < 0:
        raise ValueError("amount_cents must not be negative")
    return {
        "id": payment_id,
        "amount": amount_cents,
        "currency": currency,
    }
