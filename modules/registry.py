#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Module registry for scanner.py."""

import re
from typing import Dict

from modules.base import ScannerModule
from modules.elasticsearch import ElasticsearchModule
from modules.laravel_debug import LaravelDebugModule


AVAILABLE_MODULES: Dict[str, ScannerModule] = {
    ElasticsearchModule.name: ElasticsearchModule(),
    LaravelDebugModule.name: LaravelDebugModule(),
}


def validate_registry():
    name_re = re.compile(r"^[a-z][a-z0-9_]*$")
    for name, module in AVAILABLE_MODULES.items():
        if not isinstance(module, ScannerModule):
            raise TypeError(f"Module '{name}' must inherit ScannerModule")
        if module.name != name:
            raise ValueError(f"Module registry key '{name}' does not match module.name '{module.name}'")
        if not name_re.match(name):
            raise ValueError(f"Module name '{name}' must match ^[a-z][a-z0-9_]*$")
        if not module.description:
            raise ValueError(f"Module '{name}' must define a description")


def get_modules(names):
    validate_registry()
    selected = []
    for name in names:
        if name not in AVAILABLE_MODULES:
            available = ", ".join(sorted(AVAILABLE_MODULES))
            raise ValueError(f"Unknown module '{name}'. Available modules: {available}")
        selected.append(AVAILABLE_MODULES[name])
    return selected
