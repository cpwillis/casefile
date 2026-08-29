"""Test helpers importable from any test module (pytest puts tests/ on sys.path)."""

import httpx


def mock_client(handler) -> httpx.AsyncClient:
    """An AsyncClient whose requests are answered by `handler` instead of the network."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))
