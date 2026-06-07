#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Shared module interfaces for research scanners.

Modules should keep network-specific logic inside the module and return plain
dict-compatible ModuleResult objects so reporting and filtering can stay common.
"""

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional


@dataclass
class ScanTarget:
    """Normalized target passed to scanner modules."""
    raw: str
    host: str
    port: Optional[int] = None
    scheme: Optional[str] = None
    url: str = ""
    metadata: Dict = field(default_factory=dict)


@dataclass
class ModuleResult:
    """Common result shape used by all scanner modules."""
    module: str
    url: str
    host: str
    accessible: bool
    port: Optional[int] = None
    scheme: str = ""
    severity_score: int = 0
    detected_rules: List[str] = field(default_factory=list)
    sample_data: Dict = field(default_factory=dict)
    environment: str = "unknown"
    environment_confidence: int = 0
    environment_signals: List[str] = field(default_factory=list)
    response_time: float = 0.0
    error: str = ""
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        data = {
            "module": self.module,
            "url": self.url,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "accessible": self.accessible,
            "severity_score": self.severity_score,
            "detected_rules": self.detected_rules,
            "sample_data": self.sample_data,
            "environment": self.environment,
            "environment_confidence": self.environment_confidence,
            "environment_signals": self.environment_signals,
            "response_time": self.response_time,
            "error": self.error,
        }
        data.update(self.details)
        return data


class ScannerModule:
    """Base class for all scanner modules."""
    name = "base"
    description = ""

    def supports_target(self, target: ScanTarget) -> bool:
        return True

    def scan(self, target: ScanTarget, timeout: int, sample_size: int) -> Iterable[ModuleResult]:
        raise NotImplementedError
