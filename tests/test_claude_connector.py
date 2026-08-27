"""Tests for connectors/claude.py"""

from collections.abc import Callable
from typing import Any

import anthropic
import httpx
import pytest

from dep_audit_agent.connectors.claude import ClaudeConnector
from dep_audit_agent.connectors.exceptions import ClaudeRequestError


class _FakeTextBlock:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeMessage:
    def __init__(self, content: list[Any]) -> None:
        self.content = content


class _FakeMessages:
    """Records the kwargs passed to create() and returns a canned response,
    or raises the configured error."""

    def __init__(
        self,
        content: list[Any] | None = None,
        error: Exception | None = None,
    ) -> None:
        self._content = content if content is not None else []
        self._error = error
        self.calls: list[dict[str, Any]] = []

    async def create(self, **kwargs: Any) -> _FakeMessage:
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return _FakeMessage(self._content)


class _FakeAnthropicClient:
    """Test double standing in for anthropic.AsyncAnthropic — ClaudeConnector
    only relies on client.messages.create, so a duck-typed fake is sufficient."""

    def __init__(
        self,
        content: list[Any] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.messages = _FakeMessages(content, error)


_DUMMY_REQUEST = httpx.Request("POST", "https://api.anthropic.com/v1/messages")


def _api_connection_error() -> anthropic.APIConnectionError:
    return anthropic.APIConnectionError(request=_DUMMY_REQUEST)


def _rate_limit_error() -> anthropic.RateLimitError:
    return anthropic.RateLimitError(
        "rate limited",
        response=httpx.Response(429, request=_DUMMY_REQUEST),
        body=None,
    )


async def test_send_message_returns_text_content() -> None:
    client = _FakeAnthropicClient(content=[_FakeTextBlock("# Report\n\nAll clear.")])
    connector = ClaudeConnector(client, "claude-sonnet-5")

    result = await connector.send_message("system prompt", "user message", 1000)

    assert result == "# Report\n\nAll clear."


async def test_send_message_returns_empty_string_when_no_text_block() -> None:
    client = _FakeAnthropicClient(content=[])
    connector = ClaudeConnector(client, "claude-sonnet-5")

    result = await connector.send_message("system prompt", "user message", 1000)

    assert result == ""


async def test_send_message_passes_model_max_tokens_and_messages() -> None:
    client = _FakeAnthropicClient(content=[_FakeTextBlock("ok")])
    connector = ClaudeConnector(client, "claude-sonnet-5")

    await connector.send_message("system prompt", "user message", 1234)

    call = client.messages.calls[0]
    assert call["model"] == "claude-sonnet-5"
    assert call["max_tokens"] == 1234
    assert call["system"] == "system prompt"
    assert call["messages"] == [{"role": "user", "content": "user message"}]


@pytest.mark.parametrize(
    "make_error",
    [_api_connection_error, _rate_limit_error],
    ids=["connection-error", "rate-limit-error"],
)
async def test_send_message_wraps_anthropic_errors(
    make_error: Callable[[], anthropic.APIError],
) -> None:
    client = _FakeAnthropicClient(error=make_error())
    connector = ClaudeConnector(client, "claude-sonnet-5")

    with pytest.raises(ClaudeRequestError):
        await connector.send_message("system prompt", "user message", 1000)
