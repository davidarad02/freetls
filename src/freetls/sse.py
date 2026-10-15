"""Server-Sent Events (SSE) parsing helper.

``iter_sse`` consumes raw ``text/event-stream`` bytes (or text) from any
iterable of chunks and yields :class:`SSEEvent` objects as events complete,
following the WHATWG event-stream rules (``data``/``event``/``id``/``retry``
fields, ``:`` comments, blank-line dispatch).
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass


@dataclass
class SSEEvent:
    """One dispatched SSE event."""

    data: str = ""
    event: str = ""
    id: str | None = None
    retry: int | None = None

    @property
    def is_comment_only(self) -> bool:
        return self.data == "" and self.event == ""


def iter_sse(source: Iterable[bytes | str]) -> Iterator[SSEEvent]:
    """Yield :class:`SSEEvent` objects from an iterable of byte/str chunks."""
    data_lines: list[str] = []
    event = ""
    last_id: str | None = None
    retry: int | None = None
    started = False

    def _dispatch() -> SSEEvent | None:
        nonlocal data_lines, event, retry
        if not started:
            return None
        payload = "\n".join(data_lines)
        ev = SSEEvent(data=payload, event=event, id=last_id, retry=retry)
        data_lines = []
        event = ""
        retry = None
        return ev

    buffer = ""
    for chunk in source:
        text = chunk.decode("utf-8", "replace") if isinstance(chunk, (bytes, bytearray)) else chunk
        buffer += text
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            if line.endswith("\r"):
                line = line[:-1]
            if line == "":
                ev = _dispatch()
                if ev is not None:
                    yield ev
                started = False
                continue
            if line.startswith(":"):
                continue
            started = True
            if ":" in line:
                field_name, value = line.split(":", 1)
                if value.startswith(" "):
                    value = value[1:]
            else:
                field_name, value = line, ""
            if field_name == "data":
                data_lines.append(value)
            elif field_name == "event":
                event = value
            elif field_name == "id":
                last_id = value
            elif field_name == "retry":
                try:
                    retry = int(value)
                except ValueError:
                    pass
    ev = _dispatch()
    if ev is not None:
        yield ev
