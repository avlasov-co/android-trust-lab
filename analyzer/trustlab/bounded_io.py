"""Bounded, no-follow snapshots for untrusted local input files."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .exceptions import CollectionError, MissingFileError, safe_path_label

_READ_CHUNK_BYTES = 1024 * 1024


def read_bounded_regular_file(
    path: str | Path,
    *,
    limit: int,
    subject: str,
) -> bytes:
    """Read one stable regular-file snapshot without following its final symlink."""

    source = Path(path)
    label = safe_path_label(source)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        descriptor = os.open(source, flags)
    except FileNotFoundError as exc:
        raise MissingFileError(f"input file not found: {label}") from exc
    except OSError as exc:
        raise CollectionError(f"could not open {subject}: {label}") from exc

    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise CollectionError(f"{subject} must be a regular file: {label}")
        if before.st_size > limit:
            raise CollectionError(f"{subject} exceeds the byte limit: {label}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(_READ_CHUNK_BYTES, (limit + 1) - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise CollectionError(f"{subject} exceeds the byte limit: {label}")
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ) or total != after.st_size:
            raise CollectionError(f"{subject} changed while being read: {label}")
        return b"".join(chunks)
    except OSError as exc:
        raise CollectionError(f"could not read {subject}: {label}") from exc
    finally:
        os.close(descriptor)
