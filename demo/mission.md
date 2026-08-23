# Independent payment component work

Complete the three work items below through one Factory Mission.

## Factory execution

After inspection, call `ProposeMission` with exactly three separate implementation features.
Use the three numbered work items below as the feature boundaries.
Then call `StartMissionRun` with a different worker session for each feature.
Do not combine features or assign two features to one worker.
The orchestrator must not implement a worker feature.
Each worker may inspect only its listed local input, implementation, and local test.
The shared-record rules below are the only exception.

## Work item 1: Payment API

Assign one worker these local files:

- The local input is `api-schema.json`.
- The owned implementation is `src/payment_api.py`.
- The local test is the payment API test in `tests/test_features.py`.

This worker owns `src/payment_api.py` and the `api` record line.
The worker must make its local test pass.

## Work item 2: Webhook

Assign a second worker these local files:

- The local input is the guide content before `## Amount units` in `docs/stale-guide.md`.
- The owned implementation is `src/webhook.py`.
- The local test is the webhook test in `tests/test_features.py`.

This worker owns `src/webhook.py` and the `webhook` record line.
The worker must make its local test pass.

## Work item 3: Invoice export

Assign a third worker these local files:

- The local input is `db-schema.sql`.
- The owned implementation is `src/invoice_export.py`.
- The local test is the invoice export test in `tests/test_features.py`.

This worker owns `src/invoice_export.py` and the `export` record line.
The worker must make its local test pass.

## Shared record

Each worker must append one line to `## Amount units` in `docs/stale-guide.md`.
Use this exact form:

`- <component>: amount unit is <unit observed in the worker's local files>`

Use `api`, `webhook`, or `export` for `<component>`.
Each worker owns only its labeled line in this section.
API and export workers may inspect only this section when they add their lines.
This section is the only shared-file edit.
No worker may edit another worker's implementation or labeled line.

## Acceptance criteria

1. `ProposeMission` preserves the three numbered feature boundaries.
2. `StartMissionRun` starts three different worker sessions, one per feature.
3. Each worker reports that its assigned local test passes.
4. The shared record contains the `api`, `webhook`, and `export` lines.
