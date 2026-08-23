CREATE TABLE payments (
    id TEXT PRIMARY KEY,
    amount_cents INTEGER NOT NULL CHECK (amount_cents >= 0),
    currency TEXT NOT NULL CHECK (length(currency) = 3)
);
