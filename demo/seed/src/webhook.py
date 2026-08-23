"""Webhook adapter that follows the intentionally stale dollar guide."""

from __future__ import annotations


def parse_webhook(payload: dict) -> dict:
    return {
        "payment_id": str(payload["payment_id"]),
        "amount_cents": float(payload["amount"]),
        "currency": str(payload.get("currency", "USD")),
    }
