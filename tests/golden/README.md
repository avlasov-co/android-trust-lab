# Golden Fixture Provenance

The golden expectations in this directory are manually curated review oracles.
They are not emitted by `trustlab`, `tools/generate_report.py`, or any other
implementation code during tests.

`cli_expectations.json` was authored from the public report/diff schemas and a
line-by-line review of `tests/fixtures/sample_raw_report.txt`. It records only
semantically important fields. The expected transition to the checked-in rooted
ADB report is independently described as one `root_presence` change.

`expected_diff_summary.md` was authored from that expected transition and the
documented Markdown CLI contract. Its stable IDs are fixed test vectors for the
explicit timestamp, experiment, provenance reference, and comparison report
used by `test_installed_cli.py`; they are not refreshed automatically.

Current identifiers use the report-v3 and diff-v2 ATL canonical frames:
`atlrep-`/`atldiff-` plus 32 hexadecimal characters, with a separate full
`content_digest`. The independently reproducible canonical bytes and full digest
vector are frozen in `tests/test_content_identity.py`; the exact projection and
framing rules are documented in `docs/content_identity.md`. This file does not
duplicate a second, easily stale serialization recipe.

The adversarial suite constructs invalid UTF-8 and a one-megabyte line at test
time so the repository does not contain an opaque binary or oversized fixture.
The exact byte/character recipes are literal test data, not values returned by
the parser under test.

`report_v1_to_v2_expectations.json` pins the historical v1 source bytes, exact
migration outcomes, and a canonical migrated-document digest. The digest was
independently reproduced with `jq -cS` piped to `shasum -a 256`; the migration
test uses an equivalent explicit Python serialization only to avoid a runtime
dependency on `jq`.
