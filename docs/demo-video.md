# Demonstration video script

Record a short artifact walkthrough for the `v0.1.0b1` Guild preview.
Use only the released source, aggregate record, and proof bundles.
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

Show the repository URL and tag:

- `https://github.com/WrenSignal/factory-shadow`;
- `v0.1.0b1`.

## Factory installation

Show these commands without running a paid Mission:

```sh
droid plugin marketplace add 'https://github.com/WrenSignal/factory-shadow#v0.1.0b1'
droid plugin install shadow-mission@factory-shadow --scope user
```

Narration:

> Factory installs the plugin from a tagged Marketplace. Its hook stays silent without a signed Shadow runtime activation.

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

Show final-source validation before the evaluator result.
Show evaluator VM deletion before persisted success.
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
Link the release page and attach this unedited clip.

Final narration:

> Shadow Mission is a public preview with checkable evidence and explicit limits. The result is bounded, and the causal claim remains withheld.
