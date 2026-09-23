"""Make the checkout importable as the ``binja_delink`` package.

The plugin lives at the repository root (Binary Ninja imports a plugin
directory by its own name), so the tests bind that directory to the package
name explicitly rather than relying on the checkout being called
``binja_delink``.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

if "binja_delink" not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        "binja_delink", ROOT / "__init__.py", submodule_search_locations=[str(ROOT)])
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["binja_delink"] = module
    spec.loader.exec_module(module)
