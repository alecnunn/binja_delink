"""Binja-free data model mirroring delink's IdaModel."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SegClass(Enum):
    CODE = "CODE"
    DATA = "DATA"
    CONST = "CONST"
    BSS = "BSS"
    XTRN = "XTRN"
    OTHER = "OTHER"


class Arch(Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    AARCH64 = "aarch64"
    OTHER = "other"


@dataclass(frozen=True)
class Section:
    name: str
    start: int
    end: int
    read: bool
    write: bool
    execute: bool
    seg_class: SegClass

    def size(self) -> int:
        return max(0, self.end - self.start)

    def contains(self, va: int) -> bool:
        return self.start <= va < self.end


def _normalize_ranges(ranges: "tuple[tuple[int, int], ...]") -> "tuple[tuple[int, int], ...]":
    """Sort, drop empties and merge touching/overlapping ranges."""
    ordered = sorted((s, e) for s, e in ranges if e > s)
    merged: list[list[int]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return tuple((s, e) for s, e in merged)


@dataclass(frozen=True)
class Function:
    """A function, possibly covering several disjoint address ranges.

    Binary Ninja reports a function as a list of address ranges (see
    ``Function.address_ranges``); block-reordered code (MSVC POGO/BBT, hot/cold
    splitting) routinely produces more than one. ``start``/``end`` remain the
    outer span for convenience, but the bytes that belong to the function are
    exactly the concatenation of ``ranges`` -- the gaps belong to *other*
    functions and must never be emitted.
    """

    start: int
    end: int
    name: str
    thunk: bool = False
    lib: bool = False
    static: bool = False
    public: bool = False
    ranges: "tuple[tuple[int, int], ...]" = field(default=())

    def __post_init__(self) -> None:
        # ``start`` is the entry point and stays put -- it identifies the
        # function everywhere else (grouping keys, symbol addresses) and is not
        # necessarily the lowest address the function covers.
        ranges = _normalize_ranges(tuple(self.ranges) or ((self.start, self.end),))
        object.__setattr__(self, "ranges", ranges)
        if ranges:
            object.__setattr__(self, "end", ranges[-1][1])

    def size(self) -> int:
        """Number of bytes emitted for this function (sum of its ranges)."""
        return sum(e - s for s, e in self.ranges)

    def span(self) -> int:
        """Distance from the lowest start to the highest end, gaps included."""
        return max(0, self.end - self.start)

    def contiguous(self) -> bool:
        return len(self.ranges) <= 1

    def contains(self, va: int) -> bool:
        return any(s <= va < e for s, e in self.ranges)

    def entry_offset(self) -> int:
        """Offset of the entry point within the emitted bytes."""
        off = self.offset_of(self.start)
        return off if off is not None else 0

    def offset_of(self, va: int) -> "int | None":
        """Offset of ``va`` within the concatenated function bytes, if covered."""
        off = 0
        for s, e in self.ranges:
            if s <= va < e:
                return off + (va - s)
            off += e - s
        return None


@dataclass(frozen=True)
class Symbol:
    addr: int
    name: str
    public: bool = False
    weak: bool = False
    is_func: bool = False


@dataclass(frozen=True)
class Reloc:
    addr: int
    kind: str          # "ABS" or "PCREL"
    size: int
    target: int
    addend: int = 0
    pc_relative: bool = False
    data: bool = True  # RelocationInfo.data_relocation


@dataclass
class Model:
    arch: Arch
    bits: int
    little_endian: bool
    image_base: int
    filetype: str
    input_file: str
    sections: list[Section]
    functions: list[Function]
    symbols: list[Symbol]
    relocations: list[Reloc]

    def section_for(self, va: int) -> "Section | None":
        for s in self.sections:
            if s.contains(va):
                return s
        return None
