"""Neutral object-image types accepted by the COFF and ELF writers."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto

from binja_delink.model import Arch
from binja_delink.objwrite.relocs import RelocKind


class ObjSectionKind(Enum):
    TEXT = auto()
    DATA = auto()
    RDATA = auto()
    BSS = auto()


@dataclass
class ObjSection:
    name: str
    kind: ObjSectionKind
    data: bytes
    bss_size: int = 0


@dataclass
class ObjSymbol:
    name: str
    section_index: int  # 0 = undefined extern; else 1-based section number
    value: int          # offset within its section
    is_global: bool
    is_func: bool


@dataclass
class ObjReloc:
    section_index: int  # 1-based section number the fixup lives in
    offset: int         # offset within that section
    symbol_index: int   # index into ObjectImage.symbols
    kind: RelocKind
    addend: int
    trailing: int = 0   # trailing bytes after a PCREL32 field (AMD64 REL32_N)


@dataclass
class ObjectImage:
    arch: Arch
    sections: list[ObjSection] = field(default_factory=list)
    symbols: list[ObjSymbol] = field(default_factory=list)
    relocs: list[ObjReloc] = field(default_factory=list)
