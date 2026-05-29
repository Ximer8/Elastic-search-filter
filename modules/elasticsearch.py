#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Elasticsearch scanner module adapter."""

from typing import Iterable

import es_advanced_scanner
from modules.base import ModuleResult, ScannerModule, ScanTarget


class ElasticsearchModule(ScannerModule):
    name = "elasticsearch"
    description = "Detects exposed Elasticsearch instances and sensitive content"

    def scan(self, target: ScanTarget, timeout: int, sample_size: int) -> Iterable[ModuleResult]:
        results = es_advanced_scanner.scan_elasticsearch(
            target.host,
            target.port,
            timeout,
            sample_size
        )

        for result in results:
            yield ModuleResult(
                module=self.name,
                url=f"{result.scheme}://{result.host}:{result.port}",
                host=result.host,
                port=result.port,
                scheme=result.scheme,
                accessible=result.accessible,
                severity_score=result.severity_score,
                detected_rules=result.detected_rules,
                sample_data=result.sample_data,
                environment=result.environment,
                environment_confidence=result.environment_confidence,
                environment_signals=result.environment_signals,
                response_time=result.response_time,
                error=result.error,
                details={
                    "cluster_name": result.cluster_name,
                    "version": result.version,
                    "indices_count": result.indices_count,
                }
            )
