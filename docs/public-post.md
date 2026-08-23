# Factory Guild public post

Publish this text with the release page as its link preview.
A short demonstration clip is optional.

## Post copy

I built Shadow Mission, a mission-wide reviewer for Factory Missions.

The frozen `pair-summary-final.json` records 7 seeded-assertion passes in 11 completed Shadow runs.
All 11 paired baselines failed the same assertion.
The separate `incomplete-pairs.json` records two additional pairs without evaluator verdicts.

Shadow compares claims across orchestrator, worker, and validator sessions.
It sends target-specific guidance through `PostToolUse.additionalContext`.

The public proof bundles verify nine reportable pairs.
They contain six Shadow passes and three Shadow failures.
All nine bundled baselines failed.

The proof bundles record `resolved` interventions in pairs 47, 49, and 55.
No seeded finding group fully resolved.
The strict comparison therefore refuses a causal claim.

This is one fixed Mission and seed.
It is not a general accuracy claim.
Usage and cost remain unavailable.

Repository: https://github.com/WrenSignal/factory-shadow

Release and offline proof: https://github.com/WrenSignal/factory-shadow/releases/tag/v0.1.0b2

@FactoryAI

## Optional attachment

Attach a clip only when it follows the [demonstration script](demo-video.md).
The clip must show the real bundle verifier and the comparison refusal.
Do not attach a staged screenshot without its source record.
