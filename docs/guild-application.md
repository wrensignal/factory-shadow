# The Factory Guild application draft

Shadow Mission passed the seeded assertion in 7 of 11 completed runs for one fixed Mission and seed.
All 11 paired baselines failed the same assertion.
Two of 13 pairs produced no evaluator verdict.
These results show a bounded outcome difference, not causality or general accuracy.

## Project and public proof

I built Shadow Mission to review claims across Factory orchestrator, worker, and validator sessions.
It routes target-specific guidance through `PostToolUse.additionalContext`.
The project uses the MIT license.

The public proof bundles verify nine reportable pairs.
They contain six Shadow passes and three Shadow failures.
All nine bundled baselines failed the seeded assertion.
The bundles record `resolved` interventions in pairs 47, 49, and 55.
No seeded finding group fully resolved.
The comparison therefore refuses a bound causal claim.

The repository is [WrenSignal/factory-shadow](https://github.com/WrenSignal/factory-shadow).
The local release candidate is `0.1.0b5`.
Its planned [release page](https://github.com/WrenSignal/factory-shadow/releases/tag/v0.1.0b5) needs approved publication.
The [offline reviewer path](reproducibility.md) uses `shadow-mission[proof]` and the tagged source.
It rebuilds reports and comparisons without Factory credentials, model calls, Lima, or a paid Mission.

## Integration learning

The recorded integration used `PostToolUse.additionalContext` for model-visible guidance.
A top-level `decision: "block"` did not provide that `PostToolUse` guidance path.
This lesson applies to the recorded versions, not current Droid compatibility.

## Current limitations

Pair 45 lacks reportable cleanup evidence.
Strict report rebuilding rejects Pair 56's evaluation provenance binding.
Both pairs remain outside the nine-pair public proof.

Fallback provenance does not support blocker enforcement.
The relation source uses an undocumented, binary-bound Factory file contract.
The host Mission runs as a same-user process.
Live bindings remain Droid `0.197.0` and droid-sdk `0.2.0`.
This candidate does not establish current Droid compatibility.
Usage and cost remain unavailable.

## Requests for Factory

Please document a Mission relation source with stable Mission, session, role, and assignment identifiers.
Please provide a hook-signing mechanism that the observed Mission cannot use to forge evidence.
These contracts would improve relation authority and hook evidence provenance.
