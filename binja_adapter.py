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
from binja_delink.recover.arm64 import (
    aarch64_branch_reloc, aarch64_data_reloc, adrp_page, base_reg, dest_reg, is_adrp,
)
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
    # The core can report one fixup through more than one record at the same
    # address. Emitting it twice is merely wasteful under RELA, where the
    # addend is explicit and the write is idempotent, but REL (ELF32/i386) and
    # COFF accumulate into the section data, where a duplicate doubles the
    # stored value.
    seen: set[Reloc] = set()
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
                entry = Reloc(
                    addr=addr, kind="PCREL" if info.pc_relative else "ABS", size=size,
                    target=target, addend=info.addend, pc_relative=bool(info.pc_relative),
                    data=bool(info.data_relocation))
                if entry not in seen:
                    seen.add(entry)
                    relocations.append(entry)
                step = max(step, size)
            addr += max(step, 1)
    return relocations


def refs_from(bv: BinaryView, addr: int,
              func: "BnFunction | None" = None) -> "list[int]":
    """Every address the instruction at ``addr`` references.

    References that originate at an *instruction* live in the code
    cross-reference database, even when the target is data:
    ``get_data_refs_from`` covers the data-to-data direction and returns
    nothing for a code address. Both are unioned so recovery does not depend
    on which side of that split a given core build files a reference under.
    """
    out: list[int] = []
    seen: set[int] = set()
    for target in list(bv.get_code_refs_from(addr, func)) + list(bv.get_data_refs_from(addr)):
        if target not in seen:
            seen.add(target)
            out.append(target)
    return out


def _array_shape(bv: BinaryView, base: int) -> "tuple[int, int] | None":
    """``(element width, count)`` if Binary Ninja typed ``base`` as an array."""
    var = bv.get_data_var_at(base)
    if var is None or var.address != base:
        return None
    elem = getattr(var.type, "element_type", None)
    count = getattr(var.type, "count", None)
    if elem is None or not count:
        return None
    width = getattr(elem, "width", 0)
    return (int(width), int(count)) if width in (4, 8) else None


def _read_words(bv: BinaryView, base: int, width: int, count: int) -> "list[int] | None":
    raw = bv.read(base, width * count)
    if raw is None or len(raw) != width * count:
        return None
    return [int.from_bytes(raw[i * width:(i + 1) * width], "little") for i in range(count)]


def jump_table_relocs(bv: BinaryView, model: Model) -> "list[Reloc]":
    """Relocations for the entries of absolute jump tables.

    A switch compiles to a table the image's own relocation table says nothing
    about: in a fully linked non-PIE executable the linker has already baked
    the absolute addresses in and dropped the relocations. Nothing else
    recovers them -- the instruction scan only walks code, and the data
    sections are written from ``model.relocations`` -- so they are synthesized
    here and read back out when the shared object is written.

    Addresses the image already relocates itself are left alone. A PE keeps
    base relocations for absolute addresses, so its tables need no recovery,
    and emitting a second fixup over one the image supplied would double the
    stored value in any format that accumulates in place (COFF, ELF REL).

    Only *absolute* tables get relocations. The self-relative forms (PE's
    32-bit offsets from the table base, AArch64's byte offsets from a label
    inside the function) are already position-independent and must be left
    alone. The two are told apart by checking that the stored words actually
    are the branch destinations Binary Ninja recorded: an offset table stores
    small biases, which never match a destination address.
    """
    ptr_size = 8 if model.bits == 64 else 4
    out: list[Reloc] = []
    claimed: set[int] = {r.addr for r in model.relocations}
    for fn in bv.functions:
        by_source: dict[int, set[int]] = {}
        for branch in fn.indirect_branches:
            by_source.setdefault(branch.source_addr, set()).add(branch.dest_addr)
        for source, dests in by_source.items():
            if not dests:
                continue
            for base in refs_from(bv, source, fn):
                section = model.section_for(base)
                if section is None or section.execute:
                    continue  # the table lives in data, not in the code stream
                width, count = _array_shape(bv, base) or (ptr_size, len(dests))
                if width not in (4, 8) or count <= 0:
                    continue
                words = _read_words(bv, base, width, count)
                # Every entry must be a recorded destination; otherwise this is
                # an offset table (or not a table at all) and relocating it
                # would corrupt data that is already position-independent.
                if not words or not all(w in dests for w in words):
                    continue
                for i, target in enumerate(words):
                    addr = base + i * width
                    if addr in claimed:
                        continue
                    claimed.add(addr)
                    out.append(Reloc(addr=addr, kind="ABS", size=width, target=target))
                break
    return out


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

    model = Model(arch=arch, bits=(64 if ptr_size == 8 else 32),
                  little_endian=True, image_base=bv.start,
                  filetype=bv.view_type, input_file=bv.file.filename,
                  sections=sections, functions=functions,
                  symbols=symbols, relocations=relocations)
    # Needs the finished model to classify a table base by section, so it runs
    # after construction rather than inside it.
    model.relocations.extend(jump_table_relocs(bv, model))
    return model


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


def _adrp_full_targets(bv: BinaryView, bn_func: "BnFunction") -> "dict[int, int]":
    """ADRP address -> the full address whose page it materializes.

    Binary Ninja reports the *page* at an ADRP (``0x220000``) and the full
    address at the ADD/LDR that supplies the low 12 bits (``0x220384``). A page
    base is usually not inside any section, and in any case
    ``R_AARCH64_ADR_PREL_PG_HI21`` is written against the full symbol+addend --
    the linker takes the page of it -- so the two halves are matched up here by
    the register the ADRP writes and its consumer reads.
    """
    out: dict[int, int] = {}
    # Carried across the whole function, not reset per basic block: the ADRP
    # and the instruction consuming it are routinely separated by a branch
    # ("adrp x9, P / b.lt / ... / ldr w11, [x9, #off]"). A stale register entry
    # can only ever yield a target in the ADRP's own page, because of the page
    # check below, and that page is the entirety of what PG_HI21 encodes -- so
    # carrying it is safe even without tracking intervening register writes.
    pending: dict[int, tuple[int, int]] = {}   # register -> (adrp addr, page)
    for rng in bn_func.address_ranges:
        addr = rng.start
        while addr < rng.end:
            raw = bv.read(addr, 4)
            if raw is None or len(raw) < 4:
                break
            word = int.from_bytes(raw, "little")
            if is_adrp(word):
                pending[dest_reg(word)] = (addr, adrp_page(word, addr))
            else:
                found = pending.get(base_reg(word))
                if found is not None:
                    adrp_addr, page = found
                    for target in refs_from(bv, addr, bn_func):
                        if (target & ~0xFFF) == page:
                            out[adrp_addr] = target
                            break
            addr += 4
    return out


def make_recover_fn(bv: BinaryView, model: Model) -> RecoverFn:
    arch = model.arch

    def fn(func: Function, data: bytes) -> "list[RecoveredReloc]":
        out: list[RecoveredReloc] = []
        ptr_size = 8 if model.bits == 64 else 4
        bn_func: "BnFunction | None" = bv.get_function_at(func.start)
        if bn_func is None:
            return out
        adrp_targets = _adrp_full_targets(bv, bn_func) if arch == Arch.AARCH64 else {}
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
                # An ADRP is relocated against the address its paired ADD or
                # LDR reaches, never the page it names: that page is usually
                # inside no section at all, and Binary Ninja frequently reports
                # no reference for the ADRP whatsoever, filing the pair's
                # reference on the consumer instead. So the pairing wins where
                # it exists, and is the only source when the ref list is empty.
                targets = refs_from(bv, addr, bn_func)
                if arch == Arch.AARCH64 and is_adrp(int.from_bytes(instr_bytes[:4], "little")):
                    paired = adrp_targets.get(addr)
                    if paired is not None:
                        targets = [paired]
                for tgt in targets:
                    if model.section_for(tgt) is None:
                        continue
                    if func.contains(tgt):
                        continue  # intra-function: a branch target or local label
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
                    # Both widths are tried on a 64-bit image. An absolute
                    # address reaches a ModRM displacement or an immediate as a
                    # 32-bit field; only a movabs-style operand is a full 8
                    # bytes. Searching at pointer width alone can never match
                    # inside a 7-byte instruction, which is how absolute data
                    # references used to go missing on x86_64.
                    for abs_width in ((ptr_size, 4) if ptr_size == 8 else (4,)):
                        abs_kind = RelocKind.ABS64 if abs_width == 8 else RelocKind.ABS32
                        candidates += [
                            (field_off, abs_width, abs_kind, 0)
                            for field_off in find_abs_fields(instr_bytes, tgt, abs_width)
                        ]
                    # Lowest offset first (displacement before a trailing
                    # immediate), PC-relative first where both interpretations
                    # fit the same bytes, and the wider absolute field ahead of
                    # the narrower one nested inside it.
                    candidates.sort(
                        key=lambda c: (c[0], 0 if c[2] == RelocKind.PCREL32 else 1, -c[1]))
                    for field_off, width, kind, trailing in candidates:
                        if claims.claim(field_off, width):
                            out.append(RecoveredReloc(off + field_off, tgt, kind, width, trailing))
                addr += ilen
        return out
    return fn
