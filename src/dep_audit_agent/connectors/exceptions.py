"""Custom exceptions for the OSV and Claude connectors."""


class OSVClientError(Exception):
    """Base exception for the OSV connector."""


class OSVRequestError(OSVClientError):
    """Raised on HTTP errors or timeouts from the OSV API."""


class OSVResponseValidationError(OSVClientError):
    """Raised when the OSV response fails Pydantic validation."""


class ClaudeClientError(Exception):
    """Base exception for the Claude connector."""


class ClaudeRequestError(ClaudeClientError):
    """Raised on HTTP errors, timeouts, or rate limits from the Anthropic API."""
