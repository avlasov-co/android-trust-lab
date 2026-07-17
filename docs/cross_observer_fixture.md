# Cross-observer fixture contract

Step 35 uses one project-authored synthetic target state to exercise the app,
ADB-shell, and root-collector observers together. The fixture validates
normalization and comparison behavior; it is not an AVD capture and does not
represent physical OEM behavior.

## Architecture and ownership

The fixture lives outside `datasets/`. Dataset source v1 and manifest v2 are
frozen around `text/plain` raw artifacts, while the app observer correctly emits
a typed `application/json` app-probe artifact. Keeping the cross-observer bundle
under `tests/fixtures/cross_observer_bundle/` preserves both contracts instead
of disguising the app JSON as raw text or mutating a frozen dataset schema.

The file layout is:

```text
tests/fixtures/cross_observer_bundle/
├── expectations.json                 manually authored bundle and expectations
├── app/
│   ├── app_probe.json                manually authored synthetic source evidence
│   └── collection_manifest.json      manually authored source binding
├── adb/
│   ├── adb_snapshot.txt              manually authored synthetic source evidence
│   └── collection_manifest.json      manually authored source binding
├── root/
│   ├── raw.txt                       manually authored synthetic source evidence
│   └── collection_manifest.json      manually authored source binding
└── generated/
    ├── reports/*.json                generated normalized reports
    └── diffs/*.json                  generated pairwise observer-axis diffs

results/figures/cross_observer_matrix.md  generated human-readable matrix
```

`expectations.json`, the three raw artifacts, and the three collection manifests
are author-owned inputs. `tools/generate_report.py` owns every file under
`generated/` and the result matrix. Reviewers must not hand-edit generated
outputs to make an expectation pass.

## Link and provenance contract

`expectations.json` declares one bundle ID, one synthetic origin, one
pseudonymous target, one state ID, one experiment ID, and one shared
experimental protocol ID. Each observer entry names exactly one raw artifact,
one collection manifest, and one generated report. Each pairwise entry names
exactly one generated diff.

The shared protocol is the experimental procedure that holds target state
constant while changing observers. It is intentionally distinct from the
`comparison.context.*.protocol` values `app`, `adb`, and `root`, which describe
observer-specific visibility transports in diff 2.x. All three collection
manifests carry the same experiment and target identity while retaining their
honest observer, privilege, collection method, and observer-specific transport.
The enclosing contract classifies the complete linked bundle as synthetic;
collection IDs and timestamps are deterministic fixture metadata, not claims of
real device collection events.

Every collection manifest independently binds the exact raw bytes with SHA-256
and byte size. Generation validates the manifests, rechecks their bindings,
normalizes all three reports, attaches the common state identity, validates all
three pairwise diffs, and evaluates the manually authored expectations before
publishing any output. Diff input identities resolve to normalized report
digests; each report then resolves to its raw-artifact digest and collection
manifest binding.

## Expected comparison behavior

All three pairs must classify as `same_state_observer_change`. The synthetic app
fixture deliberately records its SELinux self-context as inaccessible while the
ADB and root fixtures observe their contexts. Those transitions are visibility
context changes and must never be called target regressions or improvements.

Evidence that multiple observers can see, including AVD/emulator state and the
common ADB/root boot and mount observations, must remain unchanged. The ADB and
root fixtures deliberately disagree on SELinux policy mode. That contradiction
must remain a changed dimension with factorized confidence and a complete
provenance chain back to both independently hashed source artifacts.

## Reproduction

From the repository root:

```bash
python tools/generate_report.py --check
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer \
  python -m pytest -q tests/test_cross_observer_fixtures.py
```

Run `python tools/generate_report.py` only after intentionally changing a source
artifact, manifest, expectation, or generator. The complete repository gate
also checks freshness.
