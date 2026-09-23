"""Transports: newline-delimited stdio and Starlette HTTP/SSE. Both share the Dispatcher."""

from .stdio import StdioTransport

__all__ = ["StdioTransport"]
