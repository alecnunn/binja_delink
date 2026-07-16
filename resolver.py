"""Address -> symbol resolution for relocation recovery (Binja-free)."""

from __future__ import annotations

import bisect
from dataclasses import dataclass

from binja_delink.model import Model, Reloc, SegClass

DATA_START = "__delink_data_start"
CONST_START = "__delink_const_start"
BSS_START = "__delink_bss_start"


@dataclass
class Variable:
    name: str
    public: bool


class SymbolResolver:
    def __init__(self, model: Model, relocs: list[Reloc]) -> None:
        self._names: dict[int, str] = {}
        # function start -> (end, name)
        self._func_starts: list[int] = []
        self._func_info: dict[int, tuple[int, str]] = {}
        for f in model.functions:
            self._func_info[f.start] = (f.end, f.name)
            self._names.setdefault(f.start, f.name)
        for s in model.symbols:
            self._names[s.addr] = s.name
        self._func_starts = sorted(self._func_info)

        def section_range(cls: SegClass) -> tuple[int, int] | None:
            # Returns only the FIRST segment of the given class: section-relative
            # fallback addends (see resolve_data below) assume one segment per
            # class. Images with multiple same-class segments (e.g. more than
            # one DATA segment) will resolve fallback addends against the first
            # one only -- a documented limitation, not handled here.
            for s in model.sections:
                if s.seg_class == cls:
                    return (s.start, s.end)
            return None

        self._data_range: tuple[int, int] | None = section_range(SegClass.DATA)
        self._const_range: tuple[int, int] | None = section_range(SegClass.CONST)
        self._bss_range: tuple[int, int] | None = section_range(SegClass.BSS)

        def in_data(va: int) -> bool:
            return any(rng is not None and rng[0] <= va < rng[1]
                       for rng in (self._data_range, self._const_range, self._bss_range))

        self.variables: dict[int, Variable] = {}
        for s in model.symbols:
            if s.is_func or s.addr in self._func_info:
                continue
            if in_data(s.addr):
                self.variables[s.addr] = Variable(s.name, s.public)

        self._relocs_sorted: list[Reloc] = sorted(relocs, key=lambda r: r.addr)
        self._reloc_addrs: list[int] = [r.addr for r in self._relocs_sorted]

    def relocs_in(self, start: int, end: int) -> list[Reloc]:
        lo = bisect.bisect_left(self._reloc_addrs, start)
        hi = bisect.bisect_left(self._reloc_addrs, end)
        return self._relocs_sorted[lo:hi]

    def _resolve_in_func(self, va: int) -> tuple[str, int] | None:
        idx = bisect.bisect_right(self._func_starts, va) - 1
        if idx < 0:
            return None
        start = self._func_starts[idx]
        end, name = self._func_info[start]
        if va < end:
            return (name, va - start)
        return None

    def resolve_code(self, va: int) -> tuple[str, int] | None:
        if va in self._names:
            return (self._names[va], 0)
        return self._resolve_in_func(va)

    def resolve_data(self, va: int) -> tuple[str, int] | None:
        if va in self._names:
            return (self._names[va], 0)
        in_func = self._resolve_in_func(va)
        if in_func is not None:
            return in_func
        for rng, sym in ((self._data_range, DATA_START),
                         (self._const_range, CONST_START),
                         (self._bss_range, BSS_START)):
            if rng is not None and rng[0] <= va < rng[1]:
                return (sym, va - rng[0])
        return None
