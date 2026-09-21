"""A stand-in for the ``binaryninja`` module, so the adapter can be tested.

Only the handful of attributes ``binja_delink.binja_adapter`` touches are
modelled, with the same shapes the real API documents (see
``python/binaryview.py`` and ``python/function.py`` in Vector35/binaryninja-api).
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass, field
from enum import Enum


class BranchType(Enum):
    UnconditionalBranch = 0
    FalseBranch = 1
    TrueBranch = 2
    CallDestination = 3
    FunctionReturn = 4
    IndirectBranch = 6


class SectionSemantics(Enum):
    DefaultSectionSemantics = 0
    ReadOnlyCodeSectionSemantics = 1
    ReadOnlyDataSectionSemantics = 2
    ReadWriteDataSectionSemantics = 3


class SymbolBinding(Enum):
    NoBinding = 0
    LocalBinding = 1
    GlobalBinding = 2
    WeakBinding = 3


@dataclass
class AddressRange:
    start: int
    end: int


@dataclass
class Segment:
    start: int
    end: int
    readable: bool = True
    writable: bool = False
    executable: bool = False
    data_length: int = 0


@dataclass
class Section:
    name: str
    semantics: SectionSemantics = SectionSemantics.DefaultSectionSemantics


@dataclass
class Symbol:
    address: int
    name: str
    binding: SymbolBinding = SymbolBinding.LocalBinding


@dataclass
class Branch:
    type: BranchType
    target: int


@dataclass
class InstructionInfo:
    length: int
    branches: list = field(default_factory=list)


@dataclass
class RelocationInfo:
    size: int
    target: int
    addend: int = 0
    pc_relative: bool = False
    data_relocation: bool = True


class Relocation:
    def __init__(self, info: RelocationInfo) -> None:
        self._info = info

    @property
    def info(self) -> RelocationInfo:
        return self._info


class Architecture:
    def __init__(self, name: str, address_size: int, instructions: dict) -> None:
        self.name = name
        self.address_size = address_size
        self._instructions = instructions

    def get_instruction_info(self, data: bytes, addr: int) -> "InstructionInfo | None":
        return self._instructions.get(addr)


class BasicBlock:
    def __init__(self, start: int, end: int) -> None:
        self.start = start
        self.end = end


class Function:
    def __init__(self, start: int, ranges, name: str, arch: Architecture,
                 binding: SymbolBinding = SymbolBinding.LocalBinding, blocks=None) -> None:
        self.start = start
        self.name = name
        self.arch = arch
        self.address_ranges = [AddressRange(s, e) for s, e in ranges]
        self.symbol = Symbol(start, name, binding)
        self.basic_blocks = [BasicBlock(s, e) for s, e in (blocks or ranges)]


class BinaryViewFile:
    def __init__(self, filename: str) -> None:
        self.filename = filename


class BinaryView:
    """Enough of a BinaryView to drive build_model and make_recover_fn."""

    def __init__(self, arch: Architecture, memory: dict, functions=(), symbols=(),
                 segments=(), relocation_ranges=(), relocations=None, data_refs=None,
                 view_type: str = "PE", start: int = 0x1000) -> None:
        self.arch = arch
        self._memory = memory          # {address: bytes}
        self.functions = list(functions)
        self._symbols = list(symbols)
        self.segments = list(segments)
        self.relocation_ranges = list(relocation_ranges)
        self._relocations = relocations or {}
        self._data_refs = data_refs or {}
        self.view_type = view_type
        self.start = start
        self.file = BinaryViewFile("sample.bin")

    def get_symbols(self):
        return list(self._symbols)

    def get_sections_at(self, _addr: int):
        return []

    def get_function_at(self, addr: int):
        for f in self.functions:
            if f.start == addr:
                return f
        return None

    def get_data_refs_from(self, addr: int):
        return list(self._data_refs.get(addr, ()))

    def relocations_at(self, addr: int):
        return [Relocation(info) for info in self._relocations.get(addr, ())]

    def read(self, addr: int, length: int) -> bytes:
        out = bytearray()
        for i in range(length):
            for base, blob in self._memory.items():
                if base <= addr + i < base + len(blob):
                    out.append(blob[addr + i - base])
                    break
            else:
                break
        return bytes(out)


def install() -> types.ModuleType:
    """Register this stub as ``binaryninja`` and return the module."""
    module = types.ModuleType("binaryninja")
    module.BranchType = BranchType
    module.SectionSemantics = SectionSemantics
    module.SymbolBinding = SymbolBinding
    # Names plugin.py imports, so importing it never reaches the real core.
    module.BackgroundTaskThread = object
    module.BinaryView = BinaryView
    module.PluginCommand = object
    module.Settings = object
    module.interaction = types.ModuleType("binaryninja.interaction")

    binaryview = types.ModuleType("binaryninja.binaryview")
    binaryview.BinaryView = BinaryView
    binaryview.Segment = Segment
    function = types.ModuleType("binaryninja.function")
    function.Function = Function
    module.binaryview = binaryview
    module.function = function

    sys.modules["binaryninja"] = module
    sys.modules["binaryninja.binaryview"] = binaryview
    sys.modules["binaryninja.function"] = function
    return module
