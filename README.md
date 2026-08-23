# Shadow Mission

Shadow Mission is a preview reviewer for Factory Missions.
It observes orchestrator, worker, and validator sessions as one Mission.
It compares cross-session claims and routes target-specific guidance through `PostToolUse.additionalContext`.

The project is open source under the MIT license.
The public repository is [WrenSignal/factory-shadow](https://github.com/WrenSignal/factory-shadow).

## Measured preview result

`pair-summary-final.json` is the frozen aggregate source for this section.
Its record digest is `9d26fc65a3023e62927f5b8f2e35ddd4f432f93d508ae84f405c67db3883e9a8`.

- Shadow passed the seeded assertion in 7 of 11 completed runs.
- All 11 paired baselines failed the same assertion.
- Two of 13 pairs produced no evaluator verdict.

`incomplete-pairs.json` records the two additional pairs without evaluator verdicts.

These results show an outcome difference for one fixed Mission and seed.
They do not show general accuracy or causality.

The public proof bundles are the source for the reportable subset.
They verify nine pairs, with six Shadow passes and three Shadow failures.
All nine bundled baselines failed the seeded assertion.

| Asset | Covered records | Verified outcome | SHA-256 |
| --- | --- | --- | --- |
| `pair-summary-final.json` | 11 completed pairs | Seven Shadow passes and four failures | `63c9283c3a269f2bbf77cdf35e602d2c1f49067781acda2bafcc757e3b6e3250` |
| `incomplete-pairs.json` | Pairs 54 and 57 | Two incomplete pairs | `84a13287bd07bae58fbb036b60e87c603195325f6c97607589710504ffedb4c0` |
| `factory-shadow-proof-pairs-46-53.tar` | Pairs 46 through 53 | Five Shadow passes and three failures | `2dd36388e498f1816026256d92aae5f4f57e65db9915b4e25e175bc1189a4e81` |
| `factory-shadow-proof-pair-55.tar` | Pair 55 | One Shadow pass | `bc4d07015bfb21bb3231f897922ed5586409394433216ec862f32a72818dad6d` |

Both bundles passed the offline verifier.
Pair 45 is absent because its cleanup failed.
Pair 56 remains in the aggregate.
The strict report rebuild rejects Pair 56's evaluation provenance binding.

The released bundles record `resolved` interventions in pairs 47, 49, and 55.
No seeded finding group fully resolved.
`demo/compare.py` therefore refuses a bound causal claim.

## Install the preview

Add the tagged repository as a Factory Marketplace.
Then install the `shadow-mission` plugin at user scope.

```sh
droid plugin marketplace add 'https://github.com/WrenSignal/factory-shadow#v0.1.0b4'
droid plugin install shadow-mission@factory-shadow@v0.1.0b4 --scope user
```

Install the companion Python CLI from the same tag.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install \
  'git+https://github.com/WrenSignal/factory-shadow.git@v0.1.0b4'
.venv/bin/shadow --help
```

The plugin installs Factory lifecycle hooks.
The hooks emit nothing without a signed Shadow runtime activation.
The beta tag supports installation, inspection, and offline proof.
The embedded live workflow remains bound to `0.1.0`.
A later live release needs aligned bindings, a sanctioned re-seal, and direct authorization.

## Use Shadow with Factory

`shadow preflight` validates one release-bound run without starting a Mission.
`shadow mission` starts the approved collector before the Factory Mission.
`shadow status` reads the current router state.
`shadow report` rebuilds a report from durable records.

Run `.venv/bin/shadow --help` to list every command contract.
The preview does not enable blocker enforcement under fallback provenance.

## Verify without spending

Download the four release assets into `$HOME/Downloads`.
Then use the tagged source and these commands.

```sh
shasum -a 256 "$HOME/Downloads/factory-shadow-proof-pairs-46-53.tar"
shasum -a 256 "$HOME/Downloads/factory-shadow-proof-pair-55.tar"
shasum -a 256 "$HOME/Downloads/pair-summary-final.json"
shasum -a 256 "$HOME/Downloads/incomplete-pairs.json"

.venv/bin/python demo/proof_bundle.py verify \
  --bundle "$HOME/Downloads/factory-shadow-proof-pairs-46-53.tar"
.venv/bin/python demo/proof_bundle.py verify \
  --bundle "$HOME/Downloads/factory-shadow-proof-pair-55.tar"
```

Each verifier prints `proof bundle: pass` on success.
Verification rebuilds reports and comparisons from sanitized, digest-bound records.
It needs no Factory account, credential, model call, or network after download.

See [Reproducibility](docs/reproducibility.md) for package and source checks.

## Architecture

The plugin sends bounded hook events to an authenticated loopback collector.
The collector allowlists fields and redacts known secret values before persistence.
An append-only JSONL ledger is authoritative.
SQLite and the Mission graph are rebuildable projections.

Deterministic rules detect cross-worker conflicts, shared assumptions, and validator-evidence gaps.
A router sends one target-specific intervention per session update.
A separate evaluator checks the exported final source inside a fresh Lima VM.

See [Architecture](docs/architecture.md) for the complete trust boundaries.

## Privacy and exact limits

Shadow stores bounded private review records and validated final-source archives locally.
Private ledgers can contain Factory identifiers and absolute tool paths.
Public proof bundles replace those values with deterministic aliases.

Usage and cost remain unavailable for the recorded pairs.
The supported Factory relation source is an undocumented, binary-bound file contract.
The host Mission runs as a same-user process, not inside a Mission VM.

Read [Privacy](docs/privacy.md) and [Limitations](docs/limitations.md) before any live use.

## Development

`pyproject.toml` requires Python 3.10 or later.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -e '.[dev]'
.venv/bin/python -m pytest tests/unit tests/integration
.venv/bin/python ci/verify_release.py --tag v0.1.0b4
```

These checks make no Factory or model call.
Do not run a paid Mission without direct authorization.

## Documentation

- [Architecture](docs/architecture.md)
- [Privacy](docs/privacy.md)
- [Limitations](docs/limitations.md)
- [Reproducibility](docs/reproducibility.md)
- [Demonstration video script](docs/demo-video.md)
- [Public post](docs/public-post.md)

## License

Shadow Mission uses the [MIT license](LICENSE).
