"""Minimal ANSI colouring, disabled automatically for pipes and NO_COLOR."""

from __future__ import annotations

import os
import sys

_CODES = {
    "bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
    "blue": "34", "magenta": "35", "cyan": "36", "grey": "90",
}


def _enable_windows_vt() -> None:
    if os.name != "nt":
        return
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)
    except Exception:
        pass


def should_color(stream=None, force: bool | None = None) -> bool:
    if force is not None:
        return force
    if os.environ.get("NO_COLOR"):
        return False
    stream = stream or sys.stdout
    return bool(getattr(stream, "isatty", lambda: False)())


class Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        if enabled:
            _enable_windows_vt()

    def __call__(self, text: str, *styles: str) -> str:
        if not self.enabled or not styles:
            return text
        seq = ";".join(_CODES[s] for s in styles)
        return f"\033[{seq}m{text}\033[0m"
