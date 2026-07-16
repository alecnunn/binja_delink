"""binja_delink: delinking plugin for Binary Ninja."""

from __future__ import annotations

__version__ = "0.1.0"


def _register_if_in_binja() -> None:
    try:
        import binaryninja  # noqa: F401
    except Exception:
        return
    from binja_delink import plugin
    plugin.register()


_register_if_in_binja()
