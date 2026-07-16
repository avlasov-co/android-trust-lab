"""Project-domain exceptions exposed by the analyzer library."""


class TrustLabError(Exception):
    """Base class for expected Android Trust Lab failures."""


class NormalizationError(TrustLabError):
    """A raw artifact could not be normalized into a report."""


class UnsupportedObserverError(NormalizationError):
    """The requested observer is not registered by the analyzer."""
