"""Project-domain exceptions exposed by the analyzer library."""

from __future__ import annotations

from pathlib import Path


def safe_path_label(path: str | Path) -> str:
    """Return a non-host-identifying label suitable for user-facing errors."""

    portable = str(path).replace("\\", "/").rstrip("/")
    label = portable.rsplit("/", 1)[-1]
    label = "".join(
        "_" if ord(character) < 32 or ord(character) == 127 else character
        for character in label
    )
    return label[:255] or "<path>"


class TrustLabError(Exception):
    """Base class for expected Android Trust Lab failures."""


class NormalizationError(TrustLabError):
    """A raw artifact could not be normalized into a report."""


class UnsupportedObserverError(NormalizationError):
    """The requested observer is not registered by the analyzer."""


class InvalidJSONError(TrustLabError):
    """An input is not syntactically valid UTF-8 JSON."""


class SchemaValidationError(TrustLabError):
    """A JSON value does not conform to the selected project schema."""


class UnsupportedSchemaVersionError(TrustLabError):
    """An artifact declares a schema version the analyzer cannot read."""


class MissingFileError(TrustLabError):
    """A requested input file does not exist."""


class CollectionError(TrustLabError):
    """An input artifact could not be read or collected."""


class OutputWriteError(TrustLabError):
    """A validated artifact could not be written atomically."""
