"""User-editable grouping: output filename -> {symbol: definition}."""

from __future__ import annotations

import json
from dataclasses import dataclass

from binja_delink.model import Model

Groups = dict[str, dict[str, "SymbolDef"]]

# Default on-disk name for the grouping config. The CONTENT is byte-compatible
# with delink's ``idapro.json`` (see ``save``); only the filename differs, so the
# name reads naturally for a Binary Ninja tool while staying a drop-in for
# delink-based projects.
CONFIG_FILENAME = "binja.json"


@dataclass
class SymbolDef:
    address: int
    size: int
    scope: str  # "global" or "static"


def sanitize_filename(name: str) -> str:
    out = "".join(c if (c.isalnum() or c in "_-.") else "_" for c in name)
    out = out.lstrip("._")[:200]
    return out if out else "unknown"


def generate_default(model: Model, ext: str) -> Groups:
    groups: Groups = {}
    for f in model.functions:
        if f.size() == 0:
            continue
        fname = f"{sanitize_filename(f.name)}.{ext}"
        groups.setdefault(fname, {})[f.name] = SymbolDef(
            address=f.start,
            size=f.size(),
            scope="global" if f.public else "static",
        )
    return groups


def retarget_extensions(groups: Groups, ext: str) -> "tuple[Groups, list[str]]":
    """Rewrite each output filename's extension to ``ext``.

    A grouping file bakes in the extension that was current when it was
    generated (``.obj`` for COFF, ``.o`` for ELF). Reusing it after the output
    format changed would otherwise write, say, ELF objects into ``.obj`` files.
    Returns the retargeted grouping plus one warning per renamed file.
    """
    out: Groups = {}
    warnings: list[str] = []
    for filename, syms in groups.items():
        stem, dot, old_ext = filename.rpartition(".")
        if not dot or "/" in old_ext or "\\" in old_ext:
            stem, old_ext = filename, ""
        new_name = f"{stem}.{ext}"
        if new_name != filename:
            warnings.append(
                f"grouping entry {filename!r} renamed to {new_name!r} to match the "
                f"requested output format")
        if new_name in out:
            # Two grouping keys collapsed onto one filename; keep them apart.
            warnings.append(f"grouping entries collide on {new_name!r}; keeping {filename!r}")
            out[filename] = syms
            continue
        out[new_name] = syms
    return out, warnings


def save(groups: Groups, path: str) -> None:
    # Byte-identical to delink's idapro.json (serde_json to_string_pretty):
    # object keys and symbol keys sorted, but each SymbolDef's fields kept in
    # struct-declaration order (address, size, scope) rather than alphabetized.
    # dict insertion order is preserved by json.dump (no sort_keys), so we sort
    # the outer/inner keys ourselves and lay out the three fields explicitly.
    serializable = {
        obj: {name: {"address": d.address, "size": d.size, "scope": d.scope}
              for name, d in sorted(syms.items())}
        for obj, syms in sorted(groups.items())
    }
    # ensure_ascii=False: serde_json writes raw UTF-8, so escaping non-ASCII
    # symbol names as \uXXXX here would break that byte compatibility. The file
    # is already opened as UTF-8.
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(serializable, fh, indent=2, ensure_ascii=False)


def load(path: str) -> Groups:
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    return {
        obj: {name: SymbolDef(d["address"], d["size"], d["scope"])
              for name, d in syms.items()}
        for obj, syms in raw.items()
    }
