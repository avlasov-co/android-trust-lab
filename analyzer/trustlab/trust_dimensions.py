"""Trust-dimension compatibility exports and state-class helpers."""

from .dimension_registry import (
    CONTEXTUAL_DIMENSION_DEFINITIONS,
    TRUST_DIMENSION_DEFINITIONS,
)

TRUST_DIMENSIONS = [definition.id for definition in TRUST_DIMENSION_DEFINITIONS]

VISIBILITY_CONTEXT_FIELDS = [
    "observer_type",
    "observer_privilege",
    "observer_effective_uid_is_root",
    "protocol",
]

# These dimensions are part of the trust model, but should only be diffed when
# reports include direct supporting payloads. They are not mapped to generic
# target or observer metadata by default because that creates misleading signal.
CONTEXTUAL_DIMENSIONS = [
    definition.id for definition in CONTEXTUAL_DIMENSION_DEFINITIONS
]

STATE_CLASSES = {
    "A": "stock virtual baseline",
    "B": "rooted virtual system",
    "C": "writable system modified",
    "D": "Magisk collector present",
    "E": "physical device baseline",
    "F": "physical rooted device",
}

_LEGACY_MATERIALITY_BY_DIMENSION = {
    "observer_uid_root": "moderate",
    "observer_privilege": "informational",
}
MATERIALITY_BY_DIMENSION = {
    definition.id: definition.materiality_rule.value
    for definition in TRUST_DIMENSION_DEFINITIONS
} | _LEGACY_MATERIALITY_BY_DIMENSION


def materiality_for_dimension(dimension: str) -> str:
    return MATERIALITY_BY_DIMENSION.get(dimension, "low")
