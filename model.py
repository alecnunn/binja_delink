"""Binja-free data model mirroring delink's IdaModel."""

from __future__ import annotations

from dataclasses import dataclass
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


@dataclass(frozen=True)
class Function:
    start: int
    end: int
    name: str
    thunk: bool = False
    lib: bool = False
    static: bool = False
    public: bool = False

    def size(self) -> int:
        return max(0, self.end - self.start)


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
    kind: str
    size: int
    target: int


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

    def section_for(self, va: int) -> Section | None:
        for s in self.sections:
            if s.contains(va):
                return s
        return None
