"""Explicit exception hierarchy for user-facing failures."""


class IronVeilError(Exception):
    """Base class for recoverable IronVeil errors."""


class ConfigurationError(IronVeilError):
    """Raised when configuration cannot be validated."""


class GitError(IronVeilError):
    """Raised when a required Git operation fails."""


class ReportError(IronVeilError):
    """Raised when a report cannot be generated or written."""
