from __future__ import annotations

from html import escape


def format_elapsed_seconds(elapsed_seconds: float) -> str:
    return f"{elapsed_seconds:.2f}"


def format_latency_ms(latency_ms: int | None) -> str:
    return f"{latency_ms}ms" if latency_ms is not None else "n/a"


def escape_html(text: str) -> str:
    return escape(text, quote=True)
