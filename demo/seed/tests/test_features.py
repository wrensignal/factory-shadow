from __future__ import annotations

from src.invoice_export import invoice_row
from src.payment_api import payment_response
from src.webhook import parse_webhook


def test_payment_api_uses_schema_cents() -> None:
    assert payment_response("payment-1", 1000)["amount"] == 1000


def test_webhook_follows_documented_dollar_value() -> None:
    parsed = parse_webhook({"payment_id": "payment-1", "amount": "10.00"})
    assert parsed["amount_cents"] == 10.0


def test_invoice_export_uses_mocked_database_shape() -> None:
    assert invoice_row(
        {"payment_id": "payment-1", "amount_cents": 1000, "currency": "USD"}
    ) == ("payment-1", 1000, "USD")
