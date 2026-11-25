"""Case-insensitive, multi-value header container and raw header file parser."""

from __future__ import annotations

from typing import Iterable


class HeaderSet:
    """Ordered list of (name, value) pairs with case-insensitive lookup.

    Duplicate headers (e.g. several ``Set-Cookie`` lines) are preserved.
    """

    def __init__(self, pairs: Iterable[tuple[str, str]] = ()):
        self._pairs = [(str(n).strip(), str(v).strip()) for n, v in pairs]

    def get(self, name: str, default: str | None = None) -> str | None:
        name = name.lower()
        for n, v in self._pairs:
            if n.lower() == name:
                return v
        return default

    def get_all(self, name: str) -> list[str]:
        name = name.lower()
        return [v for n, v in self._pairs if n.lower() == name]

    def items(self) -> list[tuple[str, str]]:
        return list(self._pairs)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self.get(name) is not None

    def __len__(self) -> int:
        return len(self._pairs)

    def __repr__(self) -> str:
        return f"HeaderSet({self._pairs!r})"


def _status_code(line: str) -> int | None:
    parts = line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


def parse_raw(text: str) -> tuple[int | None, HeaderSet]:
    """Parse raw HTTP response headers (as saved by ``curl -I`` / ``curl -D``).

    When the text contains several responses (a redirect chain), the last
    header block is used. A body following the blank line is ignored.
    Returns ``(status_code_or_None, HeaderSet)``.
    """
    blocks: list[dict] = []
    current: dict | None = None
    in_headers = True

    for raw in text.splitlines():
        line = raw.rstrip("\r")
        if line.startswith("HTTP/"):
            current = {"status": _status_code(line), "pairs": []}
            blocks.append(current)
            in_headers = True
            continue
        if not line.strip():
            if current is not None and current["pairs"]:
                in_headers = False
            continue
        if not in_headers:
            continue
        if line[0] in " \t" and current is not None and current["pairs"]:
            name, value = current["pairs"][-1]
            current["pairs"][-1] = (name, f"{value} {line.strip()}".strip())
            continue
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip()
        if not name or " " in name or "<" in name:
            continue
        if current is None:
            current = {"status": None, "pairs": []}
            blocks.append(current)
        current["pairs"].append((name, value.strip()))

    for block in reversed(blocks):
        if block["pairs"]:
            return block["status"], HeaderSet(block["pairs"])
    raise ValueError("no HTTP headers found in input")
