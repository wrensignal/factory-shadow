"""Invoice export boundary backed by the database cents column."""

from __future__ import annotations


def invoice_row(payment: dict) -> tuple[str, int, str]:
    return (
        str(payment["payment_id"]),
        payment["amount_cents"],
        str(payment.get("currency", "USD")),
    )
