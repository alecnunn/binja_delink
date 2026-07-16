"""Binary Ninja Components <-> grouping JSON sync.

The pure ``groups_from_component_map`` function is Binja-free: it maps a
plain ``{component display name: [function start addr, ...]}`` dict onto the
grouping schema and is unit-tested without a BinaryView. The remaining
helpers (``read_component_map``, ``groups_from_components``,
``components_from_groups``) talk to the Binary Ninja Component API.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from binja_delink.grouping import Groups, SymbolDef, sanitize_filename
from binja_delink.model import Function, Model

if TYPE_CHECKING:
    from binaryninja.binaryview import BinaryView
    from binaryninja.component import Component


def _def(f: Function) -> SymbolDef:
    return SymbolDef(f.start, f.size(), "global" if f.public else "static")


def groups_from_component_map(
    comp_map: dict[str, list[int]], model: Model, ext: str
) -> Groups:
    """Map component-name -> [function start addrs] onto the grouping schema.

    Functions listed under a component name are grouped into one output
    object per component. Any function not mentioned in ``comp_map`` (a
    "loose" function) falls back to its own object, named after itself, as
    ``generate_default`` does.

    Binary Ninja allows a function to belong to more than one Component, but
    a defined global symbol may only live in one output object (else the
    linker sees a duplicate definition). So membership is first-component-wins,
    in ``comp_map`` iteration order: once a function start has been placed in
    a bucket it is skipped for every subsequent component that also lists it.
    A component whose functions are all claimed by an earlier component thus
    produces no bucket at all (buckets are created lazily, only when a
    function is actually added to them).
    """
    by_start = {f.start: f for f in model.functions if f.size() > 0}
    grouped_starts: set[int] = set()
    groups: Groups = {}

    for comp_name, starts in comp_map.items():
        fname = f"{sanitize_filename(comp_name)}.{ext}"
        for start in starts:
            if start in grouped_starts:
                continue
            f = by_start.get(start)
            if f is None:
                continue
            groups.setdefault(fname, {})[f.name] = _def(f)
            grouped_starts.add(start)

    for start, f in by_start.items():
        if start in grouped_starts:
            continue
        fname = f"{sanitize_filename(f.name)}.{ext}"
        groups.setdefault(fname, {})[f.name] = _def(f)
    return groups


def read_component_map(bv: "BinaryView") -> dict[str, list[int]]:
    """Read Binary Ninja components into {component-name: [function start, ...]}."""
    out: dict[str, list[int]] = {}

    def walk(component: "Component") -> None:
        name = component.display_name
        starts = [f.start for f in component.functions]
        if starts:
            out[name] = starts
        for child in component.components:
            walk(child)

    for child in bv.root_component.components:
        walk(child)
    return out


def groups_from_components(bv: "BinaryView", model: Model, ext: str) -> Groups:
    return groups_from_component_map(read_component_map(bv), model, ext)


def components_from_groups(bv: "BinaryView", groups: Groups) -> None:
    """Create one component per output object and add its functions."""
    for obj_name, syms in groups.items():
        comp = bv.create_component(obj_name)
        for d in syms.values():
            func = bv.get_function_at(d.address)
            if func is not None:
                comp.add_function(func)
