# Binja Delink

This is a Binary Ninja plugin that is based on [delink](https://github.com/HaydnTrigg/delink),
which splits up PEs and ELFs into individual object files per-function. It is
primarily designed for those who work on decomp projects, to be used in
conjunction with [objdiff](https://github.com/encounter/objdiff).

Right now support is fairly limited, but has been tested to be byte compatible
with the original delink project. Support for other architectures and file types
that Binary Ninja supports will come in over time, as well as documented
workflows for how to use the output of this project.

# Installation

Clone this repository into your Binary Ninja user plugins directory or install
from the plugin manager in Binary Ninja.

# Credits

- [HaydnTrigg](https://github.com/HaydnTrigg) for the original implementation
  and idea for this plugin

# Contributing

Please feel free to contribute to this project, PRs are greatly appreciated.
The use of AI is okay, but your code is expected to be reasonably clean and
tested.

# License

This project is released into the public domain under [The Unlicense](./LICENSE)
