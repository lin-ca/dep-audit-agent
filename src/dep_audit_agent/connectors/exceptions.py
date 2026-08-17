"""Custom exceptions for connecting to OSV api."""


class OSVClientError(Exception):
    """Base exception for the OSV connector."""


class OSVRequestError(OSVClientError):
    """Raised on HTTP errors or timeouts from the OSV API."""


class OSVResponseValidationError(OSVClientError):
    """Raised when the OSV response fails Pydantic validation."""
