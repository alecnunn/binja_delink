# Binja Delink

This is a Binary Ninja plugin that is based on [delink](https://github.com/HaydnTrigg/delink),
which splits up PEs and ELFs into individual object files per-function. It is
primarily designed for those who work on decomp projects, to be used in
conjunction with [objdiff](https://github.com/encounter/objdiff).

The grouping file it writes (`binja.json`) is byte-compatible with delink's
`idapro.json`, so a project set up for delink can be driven from Binary Ninja
and back again.

# Requirements

Binary Ninja 5.0.7290 or newer: relocations are read through
`BinaryView.relocations_at()`, which the Python API gained in the 5.0 series.
Development tracks the `dev` branch of
[binaryninja-api](https://github.com/Vector35/binaryninja-api) (6.1.10706 at the
time of writing).

# Installation

Clone this repository into your Binary Ninja user plugins directory or install
from the plugin manager in Binary Ninja.

# Output

| Input | Output format | Notes |
| --- | --- | --- |
| x86_64 | COFF, ELF64 (RELA) | PC-relative and absolute references |
| x86 (i386) | COFF, ELF32 (REL) | ELF32 stores addends in the section data |
| AArch64 | COFF, ELF64 (RELA) | `B`/`BL`, `ADRP`+`ADD`, `ADR`, `LDR` literal, and `LDR`/`STR` page offsets |

The output format follows the input view (PE goes to COFF, ELF and Mach-O go to
ELF) unless `delink.outputFormat` overrides it. Grouping filenames are
retargeted to the format's extension (`.obj` or `.o`) when the two disagree.

Every split logs a summary — objects, functions, text bytes, relocations,
unresolved and unsupported relocations, skipped functions, undefined symbols —
plus a warning for each individual thing that was dropped or renamed. The
`unresolved` and `skipped functions` counts are the ones to watch: both change
how the output links.

# Limitations

- AArch64 conditional branches (`B.cond`, `CBZ`, `TBZ`) that leave the function
  get no relocation. Ordinary `B`/`BL` do.
- COFF has nowhere but the instruction to store an AArch64 addend, so a
  relocation whose addend does not fit that field is dropped with a warning.
  ELF is unaffected.
- A symbol defined by two different objects (same-named statics in different
  translation units) is reported, not renamed: the grouping schema is keyed by
  name and cannot express the distinction.
- Section-relative fallback symbols (`__delink_data_start` and friends) assume
  one segment per class; images with several DATA segments resolve against the
  first.

# Development

The modules that do not talk to Binary Ninja are covered by a test suite that
runs without it:

```sh
pip install pytest
python -m pytest
```

# Credits

- [HaydnTrigg](https://github.com/HaydnTrigg) for the original implementation
  and idea for this plugin

# Contributing

Please feel free to contribute to this project, PRs are greatly appreciated.
The use of AI is okay, but your code is expected to be reasonably clean and
tested.

# License

This project is released into the public domain under [The Unlicense](./LICENSE)
