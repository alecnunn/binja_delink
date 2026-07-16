"""Split orchestration: build ObjectImages from a Model (Binja-free)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from binja_delink.grouping import SymbolDef
from binja_delink.model import Arch, Function, Model, SegClass
from binja_delink.objwrite.objfile import (
    ObjectImage, ObjReloc, ObjSection, ObjSectionKind, ObjSymbol,
)
from binja_delink.objwrite.relocs import RelocKind
from binja_delink.recover.interface import RecoveredReloc
from binja_delink.resolver import BSS_START, CONST_START, DATA_START, SymbolResolver

BytesFn = Callable[[int, int], "bytes | None"]
RecoverFn = Callable[[Function, bytes], "list[RecoveredReloc]"]

_SHARED_STEM = "__shared_data"

# The imm26 bits of an AArch64 BL/B are baked into the instruction word itself;
# the linker (or our writers) patch only those bits at link time. Zeroing the
# reloc "field" for these kinds would zero the entire 4-byte instruction
# (opcode + imm26), destroying the branch. Every other reloc kind stores its
# value in a plain little-endian field that is safe (and expected) to zero
# before the addend/relocation entry supplies the real value.
_AARCH64_BRANCH_KINDS = (RelocKind.AARCH64_CALL26, RelocKind.AARCH64_JUMP26)


@dataclass
class EmitStats:
    text_bytes: int = 0
    relocations: int = 0
    unresolved: int = 0
    local_symbols: int = 0
    undef_symbols: int = 0


def _resolve(resolver: SymbolResolver, kind: RelocKind, va: int) -> "tuple[str, int] | None":
    if kind == RelocKind.PCREL32:
        return resolver.resolve_code(va) or resolver.resolve_data(va)
    return resolver.resolve_data(va)


class _Builder:
    """Accumulates one section's symbols/relocs with two-pass name binding."""

    def __init__(self, arch: Arch) -> None:
        self.image = ObjectImage(arch=arch)
        self._sym_index: dict[str, int] = {}   # name -> symbol list index (defined)
        self._pending: list[tuple[int, int, str, int, RelocKind, int]] = []
        # (section_index, offset, name, addend, kind, trailing)

    def add_section(self, sec: ObjSection) -> int:
        self.image.sections.append(sec)
        return len(self.image.sections)  # 1-based index

    def define_symbol(self, name: str, section_index: int, value: int,
                      is_global: bool, is_func: bool) -> int:
        idx = len(self.image.symbols)
        self.image.symbols.append(ObjSymbol(name, section_index, value, is_global, is_func))
        self._sym_index[name] = idx
        return idx

    def stage_reloc(self, section_index: int, offset: int, name: str,
                    addend: int, kind: RelocKind, trailing: int) -> None:
        self._pending.append((section_index, offset, name, addend, kind, trailing))

    def finish(self) -> "tuple[int, int]":
        undef: dict[str, int] = {}
        for section_index, offset, name, addend, kind, trailing in self._pending:
            if name in self._sym_index:
                sym_idx = self._sym_index[name]
            elif name in undef:
                sym_idx = undef[name]
            else:
                sym_idx = len(self.image.symbols)
                self.image.symbols.append(ObjSymbol(name, 0, 0, True, False))
                undef[name] = sym_idx
            self.image.relocs.append(
                ObjReloc(section_index, offset, sym_idx, kind, addend, trailing))
        return (len(self._sym_index), len(undef))


def build_group_image(model: Model, resolver: SymbolResolver,
                      group_syms: "dict[str, SymbolDef]", bytes_fn: BytesFn,
                      recover_fn: RecoverFn) -> "tuple[ObjectImage, EmitStats]":
    stats = EmitStats()
    builder = _Builder(model.arch)
    text_idx = builder.add_section(ObjSection(".text", ObjSectionKind.TEXT, b""))
    text_bytes = bytearray()

    funcs = sorted(
        ((name, d) for name, d in group_syms.items() if d.size > 0),
        key=lambda kv: kv[1].address,
    )
    func_by_start = {f.start: f for f in model.functions}

    for name, d in funcs:
        raw = bytes_fn(d.address, d.size)
        if raw is None or len(raw) < d.size:
            continue
        buf = bytearray(raw)
        func = func_by_start.get(d.address, Function(d.address, d.address + d.size, name))
        fn_off = len(text_bytes)

        for rec in recover_fn(func, bytes(buf)):
            resolved = _resolve(resolver, rec.kind, rec.target_va)
            if resolved is None:
                stats.unresolved += 1
                continue
            sym_name, in_sym_addend = resolved
            w = rec.width
            # AArch64 BL/B branch words carry the imm26 bits in the
            # instruction itself; the linker patches only those bits, so we
            # must not zero the (whole) instruction word here.
            if rec.kind not in _AARCH64_BRANCH_KINDS:
                if rec.offset + w <= len(buf):
                    buf[rec.offset:rec.offset + w] = b"\x00" * w
            builder.stage_reloc(text_idx, fn_off + rec.offset, sym_name,
                                in_sym_addend, rec.kind, rec.trailing)
            stats.relocations += 1

        text_bytes += buf
        builder.define_symbol(name, text_idx, fn_off, d.scope == "global", True)
        stats.text_bytes += d.size

    builder.image.sections[text_idx - 1] = ObjSection(".text", ObjSectionKind.TEXT, bytes(text_bytes))
    stats.local_symbols, stats.undef_symbols = builder.finish()
    return (builder.image, stats)


def emit_shared(model: Model, resolver: SymbolResolver,
                bytes_fn: BytesFn) -> "tuple[ObjectImage, EmitStats]":
    stats = EmitStats()
    builder = _Builder(model.arch)
    class_meta = {
        SegClass.DATA: (ObjSectionKind.DATA, ".data", DATA_START),
        SegClass.CONST: (ObjSectionKind.RDATA, ".rdata", CONST_START),
        SegClass.BSS: (ObjSectionKind.BSS, ".bss", BSS_START),
    }
    start_done: set = set()

    for sec in model.sections:
        if sec.seg_class not in class_meta:
            continue
        kind, sec_name, start_sym = class_meta[sec.seg_class]
        if kind == ObjSectionKind.BSS:
            sidx = builder.add_section(ObjSection(sec_name, kind, b"", bss_size=sec.size()))
        else:
            raw = bytes_fn(sec.start, sec.size()) or bytes(sec.size())
            buf = bytearray(raw)
            data_relocs: list[tuple[int, str, int, RelocKind]] = []
            for r in resolver.relocs_in(sec.start, sec.end):
                w = r.size
                off = r.addr - sec.start
                if off + w > len(buf):
                    continue
                resolved = resolver.resolve_data(r.target)
                if resolved is None:
                    continue
                sym_name, addend = resolved
                buf[off:off + w] = b"\x00" * w
                kind_r = RelocKind.ABS64 if w == 8 else RelocKind.ABS32
                data_relocs.append((off, sym_name, addend, kind_r))
            sidx = builder.add_section(ObjSection(sec_name, kind, bytes(buf)))
            for off, sym_name, addend, kind_r in data_relocs:
                builder.stage_reloc(sidx, off, sym_name, addend, kind_r, 0)
                stats.relocations += 1

        if start_sym not in start_done:
            builder.define_symbol(start_sym, sidx, 0, True, False)
            start_done.add(start_sym)

        for va, var in list(resolver.variables.items()):
            if sec.contains(va):
                builder.define_symbol(var.name, sidx, va - sec.start, var.public, False)

    stats.local_symbols, stats.undef_symbols = builder.finish()
    return (builder.image, stats)


def split(model: Model, resolver: SymbolResolver, groups: "dict[str, dict[str, SymbolDef]]",
          bytes_fn: BytesFn, recover_fn: RecoverFn, fmt: str) -> "list[tuple[str, ObjectImage]]":
    ext = "obj" if fmt == "coff" else "o"
    out: list[tuple[str, ObjectImage]] = []
    for filename, syms in groups.items():
        image, _stats = build_group_image(model, resolver, syms, bytes_fn, recover_fn)
        out.append((filename, image))
    shared_image, _s = emit_shared(model, resolver, bytes_fn)
    out.append((f"{_SHARED_STEM}.{ext}", shared_image))
    return out
