# Golden Fixture Provenance

The Step 10 golden expectations in this directory are manually curated review
oracles. They are not emitted by `trustlab`, `tools/generate_report.py`, or any
other implementation code during tests.

`cli_expectations.json` was authored from the public report/diff schemas and a
line-by-line review of `tests/fixtures/sample_raw_report.txt`. It records only
semantically important fields. The expected transition to the checked-in rooted
ADB report is independently described as one `root_presence` change.

`expected_diff_summary.md` was authored from that expected transition and the
documented Markdown CLI contract. Its stable IDs are fixed test vectors for the
explicit timestamp, experiment, provenance reference, and comparison report
used by `test_installed_cli.py`; they are not refreshed automatically.

The stable identifiers can be reproduced without importing project code. The
first 16 hexadecimal characters of each digest are prefixed with `atl-` or
`atldiff-`:

```bash
printf '%s' 'E10_golden:adb_shell:2026-01-02T03:04:05Z:tests/golden/raw_observation.txt' | shasum -a 256
printf '%s' '{"base_report":"atl-4f360e670e68448a","changed_dimensions":[{"after":true,"before":false,"dimension":"root_presence","evidence_paths":["root_state.su_present"],"interpretation":"Root-related evidence changed between reports. This is an observation, not an app verdict or bypass claim.","severity":"medium"}],"compare_report":"atl-40b3dd9d667c204d","confidence_changes":[],"unchanged_dimensions":["bootloader_lock_state","verified_boot_state","vbmeta_state","verity_mode","selinux_mode","mount_integrity","magisk_presence","property_consistency","emulator_state","observer_privilege"]}' | shasum -a 256
```

The adversarial suite constructs invalid UTF-8 and a one-megabyte line at test
time so the repository does not contain an opaque binary or oversized fixture.
The exact byte/character recipes are literal test data, not values returned by
the parser under test.
