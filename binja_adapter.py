"""
Binary Ninja adapter: BinaryView -> Model, bytes, and recovery.
"""

from __future__ import annotations

from typing import Callable

from binaryninja import BranchType, SectionSemantics, SymbolBinding
from binaryninja.binaryview import BinaryView, Segment
from binaryninja.function import Function as BnFunction

from binja_delink.model import Arch, Function, Model, Reloc, SegClass, Section, Symbol
from binja_delink.objwrite.relocs import RelocKind
from binja_delink.recover.arm64 import aarch64_branch_reloc
from binja_delink.recover.interface import RecoveredReloc, find_abs_field, find_pcrel_field

_ARCH_MAP = {
    "x86_64": Arch.X86_64,
    "x86": Arch.X86,
    "aarch64": Arch.AARCH64,
}

_PUBLIC_BINDINGS = (SymbolBinding.GlobalBinding, SymbolBinding.WeakBinding)
_READONLY_SEMANTICS = (
    SectionSemantics.ReadOnlyCodeSectionSemantics,
    SectionSemantics.ReadOnlyDataSectionSemantics,
)
_DIRECT_BRANCH_TYPES = (
    BranchType.UnconditionalBranch,
    BranchType.TrueBranch,
    BranchType.FalseBranch,
    BranchType.CallDestination,
)

BytesFn = Callable[[int, int], "bytes | None"]
RecoverFn = Callable[[Function, bytes], "list[RecoveredReloc]"]


def arch_of(bv: BinaryView) -> Arch:
    name = bv.arch.name if bv.arch is not None else ""
    return _ARCH_MAP.get(name, Arch.OTHER)


def _seg_class(bv: BinaryView, seg: Segment) -> SegClass:
    if seg.executable:
        return SegClass.CODE
    if seg.data_length < (seg.end - seg.start):
        # Zero-filled tail (or wholly zero-filled): a BSS-like segment.
        return SegClass.BSS
    sections = bv.get_sections_at(seg.start)
    if sections:
        sec = sections[0]
        if sec.semantics in _READONLY_SEMANTICS:
            return SegClass.CONST
        if "bss" in sec.name.lower():
            return SegClass.BSS
    return SegClass.DATA if seg.writable else SegClass.CONST


def build_model(bv: BinaryView) -> Model:
    arch = arch_of(bv)
    sections: list[Section] = []
    for seg in bv.segments:
        cls = _seg_class(bv, seg)
        sections.append(Section(
            name=f"seg_{seg.start:x}", start=seg.start, end=seg.end,
            read=seg.readable, write=seg.writable, execute=seg.executable, seg_class=cls))

    functions: list[Function] = []
    for f in bv.functions:
        start = f.start
        end = max((r.end for r in f.address_ranges), default=start)
        sym = f.symbol
        public = bool(sym is not None and sym.binding in _PUBLIC_BINDINGS)
        functions.append(Function(start=start, end=end, name=f.name,
                                   static=not public, public=public))

    symbols: list[Symbol] = []
    for s in bv.get_symbols():
        symbols.append(Symbol(addr=s.address, name=s.name,
                              public=s.binding in _PUBLIC_BINDINGS,
                              weak=s.binding == SymbolBinding.WeakBinding,
                              is_func=bv.get_function_at(s.address) is not None))

    relocations: list[Reloc] = []
    ptr_size = 8 if bv.arch is not None and bv.arch.address_size == 8 else 4
    for start, end in bv.relocation_ranges:
        addr = start
        while addr < end:
            raw = bv.read(addr, ptr_size)
            if len(raw) == ptr_size:
                target = int.from_bytes(raw, "little")
                relocations.append(Reloc(addr=addr, kind="ABS", size=ptr_size, target=target))
            addr += ptr_size

    return Model(arch=arch, bits=(64 if ptr_size == 8 else 32),
                 little_endian=True, image_base=bv.start,
                 filetype=bv.view_type, input_file=bv.file.filename,
                 sections=sections, functions=functions,
                 symbols=symbols, relocations=relocations)


def make_bytes_fn(bv: BinaryView) -> BytesFn:
    def fn(va: int, length: int) -> "bytes | None":
        data = bv.read(va, length)
        return data if len(data) == length else None
    return fn


def make_recover_fn(bv: BinaryView, model: Model) -> RecoverFn:
    arch = model.arch

    def fn(func: Function, data: bytes) -> "list[RecoveredReloc]":
        out: list[RecoveredReloc] = []
        base = func.start
        ptr_size = 8 if model.bits == 64 else 4
        bn_func: BnFunction | None = bv.get_function_at(base)
        if bn_func is None:
            return out
        for block in bn_func.basic_blocks:
            addr = block.start
            while addr < block.end:
                info = bn_func.arch.get_instruction_info(bv.read(addr, 16), addr)
                if info is None or info.length == 0:
                    break
                ilen = info.length
                instr_bytes = data[addr - base: addr - base + ilen]

                # PC-relative branch targets.
                for branch in info.branches:
                    if branch.type not in _DIRECT_BRANCH_TYPES:
                        continue  # indirect/unresolved/return/syscall: no fixed target
                    tgt = branch.target
                    if base <= tgt < func.end:
                        continue  # intra-function branch
                    if arch == Arch.AARCH64:
                        word = int.from_bytes(instr_bytes[:4], "little")
                        rec = aarch64_branch_reloc(word, is_call=(branch.type == BranchType.CallDestination))
                        if rec is not None:
                            out.append(RecoveredReloc(addr - base, tgt, rec.kind, 4))
                    else:
                        found = find_pcrel_field(instr_bytes, addr, ilen, tgt)
                        if found is not None:
                            off, trailing = found
                            out.append(RecoveredReloc(addr - base + off, tgt,
                                                     RelocKind.PCREL32, 4, trailing))

                # Absolute / RIP-relative data references.
                for tgt in bv.get_data_refs_from(addr):
                    if model.section_for(tgt) is None:
                        continue
                    pc = find_pcrel_field(instr_bytes, addr, ilen, tgt)
                    if pc is not None and arch != Arch.AARCH64:
                        off, trailing = pc
                        out.append(RecoveredReloc(addr - base + off, tgt,
                                                 RelocKind.PCREL32, 4, trailing))
                        continue
                    width = ptr_size
                    kind = RelocKind.ABS64 if width == 8 else RelocKind.ABS32
                    aoff = find_abs_field(instr_bytes, tgt, width)
                    if aoff is not None:
                        out.append(RecoveredReloc(addr - base + aoff, tgt, kind, width))
                addr += ilen
        return out
    return fn
