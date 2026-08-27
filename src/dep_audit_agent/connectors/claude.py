"""Connector for the Anthropic Claude API."""

import anthropic

from dep_audit_agent.connectors.exceptions import ClaudeRequestError


class ClaudeConnector:
    """
    Thin wrapper around the Anthropic client: owns the Messages API call,
    extracting the text response, and translating SDK errors into
    ClaudeRequestError so callers never need to catch anthropic.* directly.
    """

    def __init__(self, client: anthropic.AsyncAnthropic, model: str):
        self._client = client
        self._model = model

    async def send_message(self, system: str, message: str, max_tokens: int) -> str:
        """Sends one Messages API request and returns its text content."""
        try:
            response = await self._client.messages.create(
                model=self._model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": message}],
            )
        except anthropic.APIError as exc:
            raise ClaudeRequestError(f"Claude request failed: {exc}") from exc

        return next(
            (block.text for block in response.content if block.type == "text"), ""
        )
