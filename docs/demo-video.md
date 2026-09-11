# Demonstration video script

Record a short artifact walkthrough for The Factory Guild's `v0.1.0b5` release candidate.
Use the candidate source and unchanged historical release assets.
Complete installation and asset downloads before recording.
Keep the recording offline.
Do not stage a new intervention or type a result manually.

Target length is about three minutes.

## Recording controls

Use a clean terminal profile with no private scrollback.
Hide notifications and unrelated windows.
Show only repository-relative paths and public aliases.
Do not show credentials, approvals, raw Factory identifiers, or private paths.

Generate every result from these released assets:

- `pair-summary-final.json`;
- `incomplete-pairs.json`;
- `factory-shadow-proof-pairs-46-53.tar`;
- `factory-shadow-proof-pair-55.tar`.

Show each asset digest before its contents.
Stop recording if any digest differs from [Reproducibility](reproducibility.md).

## Opening

Show the repository title and `demo/mission.md`.
Then show the API schema and the stale guide side by side.

Narration:

> Factory Missions divide work across several sessions. Shadow Mission reviews those sessions together. This fixed demonstration tests one dollars-to-cents conflict across API, webhook, and export boundaries.

Show the repository URL and planned release tag:

- The repository is `https://github.com/WrenSignal/factory-shadow`.
- The planned release tag is `v0.1.0b5`.

## Offline reviewer setup

Complete the [offline reviewer setup](reproducibility.md) before recording.
Install `shadow-mission[proof]` from the candidate source.
Do not install a Factory plugin for this walkthrough.
Show the installed package check and proof entry path:

```sh
.venv/bin/python ci/verify_release.py --tag v0.1.0b5
.venv/bin/python demo/proof_bundle.py verify --help
```

Narration:

> The proof extra supplies PyYAML for the offline verifier. The candidate source contains the proof script. These checks need no Factory account or model call.

## Real review path

Open Pair 55 from the supplemental proof bundle.
Show the sanitized cross-worker finding and its target session.
Show the recorded `PostToolUse.additionalContext` guidance.
Show the exact intervention transition history.

Narration:

> Shadow compared claims across Mission sessions. It sent target-specific guidance through `PostToolUse.additionalContext`. Pair 55 contains one resolved intervention with bound source and passing-test proof.

Do not say that every intervention resolved.
Do not say that the seeded finding group closed.

## Paired evaluator result

Show Pair 55's baseline and Shadow evaluator records together.
Show their matching frozen inputs and artifact bindings.
Show the baseline failure and Shadow pass for the seeded assertion.

Narration:

> This pair starts both sides from matching frozen inputs. Its baseline failed the seeded assertion. Its Shadow run passed that assertion.

Show the recorded final-source validation before the evaluator result.
Show the recorded evaluator VM deletion before the persisted success record.
Do not show hidden evaluator source.

## Integrity refusal

Run the offline verifier against the supplemental bundle.
Then show the rebuilt comparison record.
Keep its refusal reason visible.

Narration:

> One intervention resolved, but the seeded finding group did not fully resolve. The comparison refuses a causal claim with this exact reason.

Show `seeded conflict intervention group is not fully resolved`.

## Bounded measured result

Show `pair-summary-final.json` and its record digest.
Then show the public bundle manifest totals.

Narration:

> The frozen aggregate records seven seeded-assertion passes in eleven completed Shadow runs. All eleven paired baselines failed. Two of thirteen pairs produced no verdict.

Continue:

> The public bundles verify nine reportable pairs. Shadow passed six and failed three. All nine bundled baselines failed.

Display the source beside every number.
Do not convert this outcome difference into a causal claim.
Do not claim general accuracy.

## Limits and privacy

Show the limitations page beside the sanitized bundle manifest.

Narration:

> Blocker enforcement remains unavailable under fallback provenance. Usage and cost remain unavailable. Raw hook bodies and Factory identifiers are excluded from the public bundles.

Show Pair 45's cleanup exclusion in the limitations page.
Show Pair 56's strict provenance rejection there.
Do not show either private run directory.

## Closing

End on the repository URL, MIT license, and both bundle digests.
Tag `@FactoryAI` in the published post.
Link the release candidate page and attach this unedited clip only after publication approval.

Final narration:

> Shadow Mission is a public preview with checkable evidence and explicit limits. The result is bounded, and the causal claim remains withheld.
