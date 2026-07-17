# E35: Cross-observer synthetic target-state protocol

## Classification

- Protocol ID: `atl_cross_observer_v1`
- Evidence origin: project-authored `synthetic`
- Target model: one rooted Android Virtual Device state
- Target pseudonym: `target-3535353535353535`
- State ID: `state-e35-cross-observer-rooted-avd`
- Observers: unprivileged app, ADB shell, root collector

This protocol validates analyzer and collector contracts. No real device
collection event occurred; collection IDs and timestamps are deterministic
synthetic fixture metadata. The fixture is not an AVD capture and does not
represent physical OEM, boot-chain, TEE, attestation, or hardware behavior.

## Controlled invariants

All three source artifacts describe the same pseudonymous target, experiment,
target-state ID, Android release/API model, emulator state, and synthetic origin.
The target state is held fixed. Only observer identity, privilege, visibility
transport, collection method, and synthetic collection-event metadata change.

`comparison.context.protocol` is the observer visibility transport (`app`,
`adb`, or `root`), not this shared experimental protocol ID. The distinct values
are therefore expected and help classify the pairwise diffs as observer-axis
comparisons.

## Procedure

1. Validate each collection manifest and its independent raw-artifact SHA-256.
2. Normalize the app JSON, ADB text, and root text through their manifest-selected
   adapters.
3. Attach the shared pseudonymous target and state identity.
4. Validate all normalized reports.
5. Generate app-versus-ADB, app-versus-root, and ADB-versus-root diffs without a
   mixed-change acknowledgement.
6. Evaluate `tests/fixtures/cross_observer_bundle/expectations.json` against the
   in-memory reports and diffs.
7. Publish generated reports, diffs, and the cross-observer matrix through the
   canonical generator's safe per-file atomic replacement path.

## Manually authored expectations

- Every pair is `same_state_observer_change`.
- No observer-axis change is an improvement or regression.
- App-inaccessible SELinux context becomes an evidence-availability context
  change for ADB and root.
- Emulator state agrees across all three observers.
- Verified boot, mount integrity, and `su` visibility agree between ADB and root.
- The deliberately conflicting ADB/root SELinux modes retain both report
  identities, both independently hashed raw sources, evidence references, and
  factorized confidence.

## Reproduce

```bash
python tools/generate_report.py --check
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 PYTHONPATH=analyzer \
  python -m pytest -q tests/test_cross_observer_fixtures.py
```
