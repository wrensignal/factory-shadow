# Reproducibility

This guide separates public no-spend checks from the private paid workflow.
The public checks need no Factory account, credential, approval, model call, or paid Mission.

## Evidence sources

The GitHub release for `v0.1.0b4` publishes these evidence sources:

- `pair-summary-final.json` contains the frozen aggregate record;
- `incomplete-pairs.json` records pairs 54 and 57;
- `factory-shadow-proof-pairs-46-53.tar` contains the primary public proof;
- `factory-shadow-proof-pair-55.tar` contains the supplemental public proof.

The aggregate record digest is `9d26fc65a3023e62927f5b8f2e35ddd4f432f93d508ae84f405c67db3883e9a8`.
It records 7 seeded-assertion passes in 11 completed Shadow runs.
It also records 11 paired baseline failures.
The separate incomplete record covers the two pairs without verdicts.

The primary bundle SHA-256 is `2dd36388e498f1816026256d92aae5f4f57e65db9915b4e25e175bc1189a4e81`.
The supplemental bundle SHA-256 is `bc4d07015bfb21bb3231f897922ed5586409394433216ec862f32a72818dad6d`.
Both bundles passed the offline verifier before publication.

The aggregate file SHA-256 is `63c9283c3a269f2bbf77cdf35e602d2c1f49067781acda2bafcc757e3b6e3250`.
The incomplete record SHA-256 is `84a13287bd07bae58fbb036b60e87c603195325f6c97607589710504ffedb4c0`.

## Get the tagged source

```sh
git clone https://github.com/WrenSignal/factory-shadow.git
cd factory-shadow
git checkout --detach v0.1.0b4
python3 -m venv .venv
.venv/bin/python -m pip install --disable-pip-version-check -e '.[dev]'
```

`pyproject.toml` requires Python 3.10 or later.

## Run source checks without Factory

```sh
.venv/bin/python -m pytest tests/unit tests/integration
.venv/bin/python ci/verify_release.py --tag v0.1.0b4
```

These commands make no Factory, model, Lima, or paid Mission call.
The release verifier checks package metadata, plugin metadata, Marketplace metadata, hook bindings, and Lima manifests.
It also scans tracked files for defined private path patterns.
The verifier writes no success message.

This release does not publish a volatile test count.
The command exit status is the check result.

## Build and inspect the Python package

```sh
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
.venv/bin/python ci/verify_release.py --tag v0.1.0b4 --dist dist

WHEEL_VENV="$(mktemp -d)/venv"
.venv/bin/python -m venv "$WHEEL_VENV"
"$WHEEL_VENV/bin/python" -m pip install --disable-pip-version-check dist/*.whl
"$WHEEL_VENV/bin/shadow" --help
```

The distribution verifier requires one wheel and one source archive.
It rejects unsafe archive paths, linked source members, private paths, and common secret forms.

## Download the release evidence

```sh
mkdir -p "$HOME/Downloads"

curl -fL \
  https://github.com/WrenSignal/factory-shadow/releases/download/v0.1.0b4/factory-shadow-proof-pairs-46-53.tar \
  -o "$HOME/Downloads/factory-shadow-proof-pairs-46-53.tar"

curl -fL \
  https://github.com/WrenSignal/factory-shadow/releases/download/v0.1.0b4/factory-shadow-proof-pair-55.tar \
  -o "$HOME/Downloads/factory-shadow-proof-pair-55.tar"

curl -fL \
  https://github.com/WrenSignal/factory-shadow/releases/download/v0.1.0b4/pair-summary-final.json \
  -o "$HOME/Downloads/pair-summary-final.json"

curl -fL \
  https://github.com/WrenSignal/factory-shadow/releases/download/v0.1.0b4/incomplete-pairs.json \
  -o "$HOME/Downloads/incomplete-pairs.json"
```

The download step uses the network.
Every later proof step is local.

## Check the published SHA-256 values

```sh
shasum -a 256 "$HOME/Downloads/factory-shadow-proof-pairs-46-53.tar"
shasum -a 256 "$HOME/Downloads/factory-shadow-proof-pair-55.tar"
shasum -a 256 "$HOME/Downloads/pair-summary-final.json"
shasum -a 256 "$HOME/Downloads/incomplete-pairs.json"
```

Compare all four outputs with the published digests above.
Stop if any value differs.

## Verify the proof bundles offline

```sh
.venv/bin/python demo/proof_bundle.py verify \
  --bundle "$HOME/Downloads/factory-shadow-proof-pairs-46-53.tar"

.venv/bin/python demo/proof_bundle.py verify \
  --bundle "$HOME/Downloads/factory-shadow-proof-pair-55.tar"
```

Each successful command prints `proof bundle: pass`.
The verifier uses bounded safe extraction.
It checks the exact member list and every member digest.
It scans structured records and both source archives for excluded data.
It validates cleanup, run, relation, source, and evaluation bindings.
It rebuilds each report and comparison from bundled records.

The primary bundle covers pairs 46 through 53.
It verifies five Shadow passes and three Shadow failures.
The supplemental bundle covers pair 55 and verifies one Shadow pass.
All nine bundled baselines failed the seeded assertion.

## What the public path proves

A reviewer can reproduce these results:

- source, package, plugin, Marketplace, hook, and archive checks;
- bundle membership and SHA-256 integrity;
- source archive validation for each bundled side;
- report and comparison rebuilding for nine reportable pairs;
- the published refusal of a bound causal claim.

A passing proof verifier does not replay a live Factory Mission.
It does not establish general accuracy.
It does not establish that Shadow caused a passing evaluator result.

Several interventions resolved in pairs 47, 49, and 55.
No seeded finding group fully resolved.
The rebuilt comparisons therefore refuse with `seeded conflict intervention group is not fully resolved`.

## Evidence exclusions

Pair 45 is absent because cleanup failed.
Its `runtime_outcome` is not release-reportable.

Pair 56 remains in `pair-summary-final.json`.
The current strict report rebuild rejects its evaluation provenance binding.
It therefore stays outside the public proof bundles.

Pairs 54 and 57 produced no evaluator verdict.
They are excluded from `pair-summary-final.json`.
The separate `incomplete-pairs.json` record preserves both outcomes.

## Install through the Factory Marketplace

These commands use the official Factory Marketplace interface.
They change the reviewer's Factory plugin state.

```sh
droid plugin marketplace add 'https://github.com/WrenSignal/factory-shadow#v0.1.0b4'
droid plugin install shadow-mission@factory-shadow@v0.1.0b4 --scope user
```

The catalog name is `factory-shadow`.
The tagged registration ID is `factory-shadow@v0.1.0b4`.
The plugin name is `shadow-mission`.
The catalog source is the repository root.

Plugin installation alone does not start Shadow.
The installed hook remains silent without a signed runtime activation.

## Private live workflow

The paid workflow is not part of the public reproduction path.
It needs private approvals, a private Factory credential, and a sanctioned signed re-seal.
It also needs the exact pinned Factory and Lima boundaries.

`src/shadow_mission/runtime.py` pins Droid `0.197.0` for the recorded live workflow.
`pyproject.toml` pins Droid SDK `0.2.0`.
The files under `ops/lima/` pin Lima `2.2.0` and image digests.
The Factory plugin and live protocol use the stable `0.1.0` base.
The `0.1.0b4` Python distribution does not authorize a new live Mission.
A later live candidate must align every runtime and preflight binding before re-sealing.

Do not copy a Factory credential into a repository or Mission checkout.
Do not print approval or credential contents.
Do not start a paid Mission without direct authorization.

## Re-seal rule

Any plugin artifact change updates the installed artifact digest.
Metadata changes in this preview require a final sanctioned re-seal before another live run.

`ops/reseal_feasibility.py` is the only approved fixture writer.
Its `prepare` command creates a canonical request.
An external Ed25519 signer authorizes that request outside the repository.
Its `apply` command requires a staged offline dry run before any canonical write.
Its `verify` command checks the public signature and receipt offline.

The preview re-seal completed with request digest
`cff3475fd3ca57bb5d73f9ca4f33edc90916a2bdd6d25ae57d6f8114fe8814a7`.
Its verified receipt digest is
`5769969d8694b010e32354af14ae4ec6b287e94fc4d82f041c1cc390a3b04121`.

Never hand-edit the sealed fixture or regenerate its pin.
Re-sealing consumes no live run.
It does not change historical proof bundle results.
