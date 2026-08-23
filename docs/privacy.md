# Privacy and data handling

Shadow Mission stores bounded, redacted review records and validated final-source archives.
It does not provide remote telemetry.
Records stay under the configured host state root unless an operator copies them.

## Event handling

A bounded raw Factory event crosses an HMAC-authenticated loopback boundary.
Shadow authenticates and validates that envelope before sanitization.
It never writes the raw event to disk.

`src/shadow_mission/collector.py` allowlists fields after authenticated receipt.
It redacts known sensitive values before persistence.
Allowed fields can still contain Factory identifiers and absolute tool paths.

The HMAC protects transport integrity.
It does not prove Factory authority.
The observed Mission also receives the run secret and activation descriptor.

## Stored records

Each run can store these local records:

- the bounded, redacted `events.jsonl` event and response ledger;
- the rebuildable `index.sqlite3` index;
- the digest-chained `review.jsonl` review journal;
- correlation, status, run, and evaluation records;
- validated final-source archives and manifests;
- rebuilt JSON and Markdown reports.

Stored content can include Factory identifiers, absolute tool paths, aliases, and bounded excerpts.
It can also include claims, findings, interventions, settings, durations, and artifact digests.
Usage fields remain marked unavailable when Factory supplies no attributable usage.

## Data excluded by design

Shadow does not intentionally persist these values:

- the run secret or HMAC key;
- Factory credentials or authorization headers;
- private keys, passwords, bearer tokens, or common API keys;
- `.env`, credential, `.git`, or private-state file contents;
- complete unrestricted Factory transcripts;
- hidden evaluator source inside the observed Mission.

Factory identifiers and absolute tool paths remain private operator data.
The public bundle builder replaces them with deterministic public aliases.

The redactor combines key checks, value patterns, and exact forbidden values.
The exact Factory credential, run secret, and source canary join the forbidden set.
A matching value in a publishable artifact blocks release.

These controls cannot prove that every possible secret form is absent.
Operators must still review every public artifact.

## Local file controls

`src/shadow_mission/storage.py` defines the local file modes.
The configured run directory uses owner-only mode `0700`.
Sensitive records use mode `0600`.
Storage code rejects symlinks, irregular files, changed owners, and changed file identities.

These controls protect local file boundaries against accidental misuse.
They do not isolate a hostile same-user Mission process.
The host Mission runs outside a Mission VM.

## Model boundaries

Deterministic rules send no source data to a model.
Extractor sessions receive bounded sanitized transcript batches.
Probe sessions receive a redacted snapshot and evidence-named files.
Both session types use clean homes and no enabled tools.

The evaluator receives the validated final-source archive.
It receives no Factory credential, transcript, approval, prior result, or Shadow private state.
Mission functions run in bounded child processes inside the evaluator VM.

## Public proof bundles

The released bundles contain sanitized records for nine reportable pairs.
Their exact coverage and digests appear in [Reproducibility](reproducibility.md).

The bundle builder replaces raw identifiers and absolute paths with public aliases.
It excludes approvals, credentials, private path patterns, and raw Factory identifiers.
It also scans structured records and both source archives.

The offline verifier checks the exact member list and every member digest.
It rebuilds each report and comparison from bundled records.
A passing verifier proves bundle integrity only.
It does not prove causality or general accuracy.

## Publication rules

Do not publish raw Factory state, raw transcripts, credentials, or private approvals.
Do not publish an unreviewed run directory.
Do not publish hidden evaluator source with Mission-visible files.

See [Limitations](limitations.md) for the remaining trust and evidence limits.
