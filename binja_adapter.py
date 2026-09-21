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
from binja_delink.recover.arm64 import aarch64_branch_reloc, aarch64_data_reloc
from binja_delink.recover.interface import (
    FieldClaims, RecoveredReloc, find_abs_fields, find_pcrel_field, find_pcrel_fields,
)

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

_MAX_INSTR_LEN = 16


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


def _read_relocations(bv: BinaryView, ptr_size: int) -> "list[Reloc]":
    """Relocations as Binary Ninja records them.

    ``relocations_at`` hands back the real ``RelocationInfo`` -- size, target
    and addend -- so none of it has to be inferred from the stored word, which
    is wrong for any relocation narrower than a pointer. Addresses that the
    core covers with a relocation range but reports no ``Relocation`` for fall
    back to reading a pointer-sized word, which is all the previous code did.
    """
    relocations: list[Reloc] = []
    for start, end in bv.relocation_ranges:
        addr = start
        while addr < end:
            found = bv.relocations_at(addr)
            if not found:
                raw = bv.read(addr, ptr_size)
                if raw is not None and len(raw) == ptr_size:
                    relocations.append(Reloc(addr=addr, kind="ABS", size=ptr_size,
                                             target=int.from_bytes(raw, "little")))
                addr += ptr_size
                continue
            step = 0
            for rel in found:
                info = rel.info
                size = info.size or ptr_size
                target = info.target
                if not target:
                    raw = bv.read(addr, size)
                    target = int.from_bytes(raw, "little") if raw and len(raw) == size else 0
                relocations.append(Reloc(
                    addr=addr, kind="PCREL" if info.pc_relative else "ABS", size=size,
                    target=target, addend=info.addend, pc_relative=bool(info.pc_relative),
                    data=bool(info.data_relocation)))
                step = max(step, size)
            addr += max(step, 1)
    return relocations


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
        # A function may cover several disjoint ranges; carry them all, so the
        # bytes in the gaps (which belong to other functions) are never emitted.
        ranges = tuple((r.start, r.end) for r in f.address_ranges)
        sym = f.symbol
        public = bool(sym is not None and sym.binding in _PUBLIC_BINDINGS)
        functions.append(Function(start=f.start, end=f.start, name=f.name,
                                  static=not public, public=public, ranges=ranges))

    symbols: list[Symbol] = []
    for s in bv.get_symbols():
        symbols.append(Symbol(addr=s.address, name=s.name,
                              public=s.binding in _PUBLIC_BINDINGS,
                              weak=s.binding == SymbolBinding.WeakBinding,
                              is_func=bv.get_function_at(s.address) is not None))

    ptr_size = 8 if bv.arch is not None and bv.arch.address_size == 8 else 4
    relocations = _read_relocations(bv, ptr_size)

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


def _instr_slice(func: Function, data: bytes, addr: int, ilen: int) -> "tuple[int, bytes] | None":
    """(offset, bytes) of one instruction inside the emitted function bytes."""
    off = func.offset_of(addr)
    if off is None or off + ilen > len(data):
        return None
    last = func.offset_of(addr + ilen - 1)
    if last != off + ilen - 1:
        return None  # instruction straddles a gap between two function ranges
    return (off, data[off:off + ilen])


def make_recover_fn(bv: BinaryView, model: Model) -> RecoverFn:
    arch = model.arch

    def fn(func: Function, data: bytes) -> "list[RecoveredReloc]":
        out: list[RecoveredReloc] = []
        ptr_size = 8 if model.bits == 64 else 4
        bn_func: "BnFunction | None" = bv.get_function_at(func.start)
        if bn_func is None:
            return out
        for block in bn_func.basic_blocks:
            addr = block.start
            while addr < block.end:
                raw = bv.read(addr, _MAX_INSTR_LEN)
                info = bn_func.arch.get_instruction_info(raw, addr) if raw else None
                if info is None or info.length == 0:
                    break
                ilen = info.length
                located = _instr_slice(func, data, addr, ilen)
                if located is None:
                    addr += ilen
                    continue
                off, instr_bytes = located
                # One instruction may hold several relocatable fields, but no
                # two fixups may overlap: whoever claims a byte window owns it.
                claims = FieldClaims()

                # PC-relative branch targets.
                for branch in info.branches:
                    if branch.type not in _DIRECT_BRANCH_TYPES:
                        continue  # indirect/unresolved/return/syscall: no fixed target
                    tgt = branch.target
                    if func.contains(tgt):
                        continue  # intra-function branch
                    if arch == Arch.AARCH64:
                        word = int.from_bytes(instr_bytes[:4], "little")
                        rec = aarch64_branch_reloc(
                            word, is_call=(branch.type == BranchType.CallDestination))
                        if rec is not None and claims.claim(0, 4):
                            out.append(RecoveredReloc(off, tgt, rec.kind, 4))
                    else:
                        found = find_pcrel_field(instr_bytes, addr, ilen, tgt)
                        if found is not None:
                            field_off, trailing = found
                            if claims.claim(field_off, 4):
                                out.append(RecoveredReloc(off + field_off, tgt,
                                                          RelocKind.PCREL32, 4, trailing))

                # Absolute / PC-relative data references.
                for tgt in bv.get_data_refs_from(addr):
                    if model.section_for(tgt) is None:
                        continue
                    if arch == Arch.AARCH64:
                        word = int.from_bytes(instr_bytes[:4], "little")
                        rec = aarch64_data_reloc(word, addr, tgt)
                        if rec is not None and claims.claim(0, 4):
                            out.append(RecoveredReloc(off, tgt, rec.kind, 4))
                        continue
                    # Every matching field gets its own relocation: an
                    # instruction can reference one address twice (a ModRM
                    # displacement and an immediate, say) and both need fixing.
                    candidates: list[tuple[int, int, RelocKind, int]] = [
                        (field_off, 4, RelocKind.PCREL32, trailing)
                        for field_off, trailing in find_pcrel_fields(instr_bytes, addr, ilen, tgt)
                    ]
                    abs_kind = RelocKind.ABS64 if ptr_size == 8 else RelocKind.ABS32
                    candidates += [
                        (field_off, ptr_size, abs_kind, 0)
                        for field_off in find_abs_fields(instr_bytes, tgt, ptr_size)
                    ]
                    # Lowest offset first (displacement before a trailing
                    # immediate), PC-relative first where both interpretations
                    # fit the same bytes.
                    candidates.sort(key=lambda c: (c[0], 0 if c[2] == RelocKind.PCREL32 else 1))
                    for field_off, width, kind, trailing in candidates:
                        if claims.claim(field_off, width):
                            out.append(RecoveredReloc(off + field_off, tgt, kind, width, trailing))
                addr += ilen
        return out
    return fn
