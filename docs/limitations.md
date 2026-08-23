# Limitations

Shadow Mission `0.1.0b1` is a bounded Factory Guild preview.
`pyproject.toml` defines that version.
`.factory-plugin/plugin.json` stays on the stable `0.1.0` base.
The preview covers one fixed Factory Mission, seed, evaluator, and review policy.
It is not a general Factory benchmark.

## Evidence scope

`pair-summary-final.json` is the frozen aggregate source for this section.
Its record digest is `9d26fc65a3023e62927f5b8f2e35ddd4f432f93d508ae84f405c67db3883e9a8`.

Shadow passed the seeded assertion in 7 of 11 completed runs.
All 11 paired baselines failed that assertion.
Two of 13 pairs produced no evaluator verdict.

Pair 54 stalled before it wrote a final run record.
Pair 57 failed during source export.
Neither pair counts as a Shadow pass or failure.

These records show an outcome difference for one fixed setup.
They do not establish general accuracy.
They also do not establish that Shadow caused any passing result.

## Public evidence scope

The primary proof bundle covers pairs 46 through 53.
Its SHA-256 is `2dd36388e498f1816026256d92aae5f4f57e65db9915b4e25e175bc1189a4e81`.
The supplemental proof bundle covers pair 55.
Its SHA-256 is `bc4d07015bfb21bb3231f897922ed5586409394433216ec862f32a72818dad6d`.

Together, those bundles verify nine reportable pairs.
They contain six Shadow passes and three Shadow failures.
All nine bundled baselines failed the seeded assertion.

Pair 45 is excluded because `runtime_outcome` is `cleanup-failed`.
Pair 56 remains in the frozen aggregate.
The current strict report rebuild rejects Pair 56's evaluation provenance binding.

A bundle verifier result proves bundle integrity.
It is not a new live result.

## Causal claim remains unavailable

Interventions reached `resolved` in pairs 47, 49, and 55.
The released bundles provide the source records for those states.
No seeded finding group fully resolved.

`demo/compare.py` therefore refuses each bound causal claim.
Its current refusal is `seeded conflict intervention group is not fully resolved`.
The refusal is correct integrity behavior.

A resolved intervention needs source proof and passing-test proof.
Both proofs must bind to the same Mission, finding, and intervention.
Source proof alone never resolves an intervention.

## Delivery remains bounded

Factory can create more workers than `demo/role-config.json` expects.
A wide conflict can therefore target more sessions than the Mission can reach.
Some target sessions end before another eligible `PostToolUse` window occurs.

The router keeps one intervention for each conflict and target session.
It does not reopen a terminal intervention at the same conflict locus.
A later conflict at that locus can therefore remain without a successor intervention.

## Review coverage remains narrow

`src/shadow_mission/rules.py` implements three deterministic rules:

1. cross-worker conflict;
2. shared-assumption failure;
3. validator-evidence gap.

These rules can miss risks outside extracted evidence.
They can also miss unsupported file types or target relations.
Extraction is model-assisted and bounded.
A malformed, unavailable, or timed-out extraction yields no claims.

Source-file guidance depends on an observed file claim.
That claim was not present in every measured run.
Shadow does not guess a source file when evidence lacks one.

## Factory integration uses an unsupported contract

Production role mapping reads internal Factory Mission files.
Factory does not document this relation file format as a public API.
Shadow binds the format to one approved Droid binary and source digest.

A Droid upgrade requires fresh inspection, binding, and evidence.
Schema, identity, assignment, or file-authority drift stops the workflow.
Prompt markers and self-reported roles never establish authority.

## Blocker enforcement remains unavailable

Fallback hook records have `UNKNOWN` authority.
A probe cannot confirm a blocker from those records alone.
The fallback path therefore supports `note` and `concern` interventions only.

One bounded completion deferral can preserve a later guidance window.
That deferral is target-specific.
It is not a Mission-wide pause or a confirmed blocker.

## Isolation remains partial

The Factory Mission runs as a same-user host process.
Shadow does not place that Mission inside a Mission VM.
It proves that the process group stopped before source export.

The observed Mission receives the hook secret and collector descriptor.
HMAC authentication therefore proves transport integrity only.
It does not prove correction integrity against a hostile Mission.

The hidden evaluator runs in a fresh Lima VM.
Its source is public, but demo preparation keeps it outside the observed Mission workspace.
Strict evaluation removes that source before submitted Mission functions run.
Mission functions run through a separate bounded child runner.
Evaluator isolation does not strengthen the host Mission boundary.

## Usage and cost remain unavailable

Factory supplied no attributable usage for the recorded pairs.
Shadow therefore publishes no token or cost effect.
Duration cannot substitute for usage or cost.

The private workflow retains its project hard stop and authorization ledger.
Those controls limit operator exposure.
They do not measure actual pair cost.

## Preview version boundary

The public Python distribution uses `0.1.0b1`.
The Factory plugin and live protocol use the stable `0.1.0` base.
The beta tag supports installation, inspection, and offline proof.
It does not authorize a new live Mission.

A later live candidate must align its exact runtime and preflight version binding.
That candidate must then complete the sanctioned re-seal.

## Release and re-seal boundary

Edits to plugin artifact files change the installed artifact digest.
Those files include `.factory-plugin`, `hooks`, `src/shadow_mission`, and `pyproject.toml`.
`src/shadow_mission/profile.py` defines this artifact set.

A changed artifact needs the sanctioned external re-seal before another live run.
`ops/reseal_feasibility.py` is the only approved fixture writer.
The operator signing key stays outside the repository.

The preview proof bundles remain historical evidence.
A metadata re-seal does not change their recorded results.
