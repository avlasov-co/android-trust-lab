from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "check_metadata", ROOT / "tools/check_metadata.py"
)
check_metadata = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(check_metadata)


def test_canonical_project_metadata_is_consistent():
    assert check_metadata.main() == 0


def test_retired_repository_slug_is_rejected(tmp_path):
    stale = tmp_path / "stale.txt"
    stale.write_text(
        "https://github.com/" + check_metadata.retired_repository_slug(),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="retired repository slug"):
        check_metadata.main([stale])


def test_tracked_text_scan_ignores_worktree_deletions(tmp_path, monkeypatch):
    present = tmp_path / "present.txt"
    present.write_text("present\n", encoding="utf-8")

    class GitResult:
        stdout = b"deleted.txt\0present.txt\0"

    monkeypatch.setattr(
        check_metadata.subprocess, "run", lambda *args, **kwargs: GitResult()
    )

    assert check_metadata.tracked_text_paths(tmp_path) == [present]


def test_malformed_citation_is_rejected_by_cff_schema():
    citation = check_metadata.load_mapping(ROOT / "CITATION.cff")
    citation.pop("message")
    with pytest.raises(ValueError, match="fails the CFF 1.2 schema"):
        check_metadata.validate_citation(citation)
