"""Address -> symbol resolution for relocation recovery (Binja-free)."""

from __future__ import annotations

import bisect
from dataclasses import dataclass

from binja_delink.model import Model, Reloc, SegClass

DATA_START = "__delink_data_start"
CONST_START = "__delink_const_start"
BSS_START = "__delink_bss_start"

_CLASS_START_SYMBOL = {
    SegClass.DATA: DATA_START,
    SegClass.CONST: CONST_START,
    SegClass.BSS: BSS_START,
}


def section_start_symbols(sections) -> "dict[int, str]":
    """Start-symbol name for every data-bearing section, keyed by section start.

    The first section of a class keeps the bare name, so output for the usual
    one-segment-per-class image is unchanged. Any further section of the same
    class gets its address appended: one symbol cannot describe two sections,
    and a reference into the second would otherwise be written as an offset
    from the first -- landing wherever that arithmetic happens to point. Images
    with many CONST segments (a PE with debug sections, say) hit this for real.
    """
    out: dict[int, str] = {}
    seen: set = set()
    for sec in sections:
        base = _CLASS_START_SYMBOL.get(sec.seg_class)
        if base is None:
            continue
        out[sec.start] = base if sec.seg_class not in seen else f"{base}_{sec.start:x}"
        seen.add(sec.seg_class)
    return out


@dataclass
class Variable:
    name: str
    public: bool


class SymbolResolver:
    def __init__(self, model: Model, relocs: list[Reloc]) -> None:
        self._names: dict[int, str] = {}
        # Every function address RANGE, sorted by start. A function may cover
        # several disjoint ranges (see model.Function); resolving against the
        # outer span would claim addresses in the gaps, which belong to other
        # functions. Each entry carries the offset of the range within the
        # function's emitted bytes so an in-symbol addend stays correct.
        self._range_starts: list[int] = []
        self._range_info: dict[int, tuple[int, str, int]] = {}  # start -> (end, name, base_off)
        self._func_starts: set[int] = set()
        for f in model.functions:
            self._func_starts.add(f.start)
            self._names.setdefault(f.start, f.name)
            # Offsets are relative to the ENTRY point, which is where the
            # function's symbol is defined, so an address inside the function
            # resolves to "name + addend" with addend 0 at the entry.
            entry_off = f.entry_offset()
            off = 0
            for start, end in f.ranges:
                self._range_info[start] = (end, f.name, off - entry_off)
                off += end - start
        for s in model.symbols:
            self._names[s.addr] = s.name
        self._range_starts = sorted(self._range_info)

        # Every data-bearing section, each with its own start symbol. Keyed on
        # the first section of a class alone, a symbol in a second CONST
        # segment -- a jump table, typically -- is never collected and never
        # defined, so every reference to it links as undefined; and a
        # section-relative fallback addend is measured from the wrong base.
        self._data_sections = [s for s in model.sections
                               if s.seg_class in (SegClass.DATA, SegClass.CONST, SegClass.BSS)]
        self._section_symbols = section_start_symbols(model.sections)

        def in_data(va: int) -> bool:
            return any(s.contains(va) for s in self._data_sections)

        self.variables: dict[int, Variable] = {}
        for s in model.symbols:
            if s.is_func or s.addr in self._func_starts:
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
        idx = bisect.bisect_right(self._range_starts, va) - 1
        if idx < 0:
            return None
        start = self._range_starts[idx]
        end, name, base_off = self._range_info[start]
        if va < end:
            return (name, base_off + (va - start))
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
        # Section-relative fallback, against the section actually holding the
        # address rather than the first one of its class.
        for sec in self._data_sections:
            if sec.contains(va):
                return (self._section_symbols[sec.start], va - sec.start)
        return None
