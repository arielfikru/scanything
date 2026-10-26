"""Scan helpers for tests; fixture builders live in tests/fixtures.py."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from scanything.report import build_report
from scanything.scanner import Scan, analyze_blob


def scan_bytes(name: str, data: bytes, password: str | None = None) -> dict:
    scan = Scan(SimpleNamespace(password=password, yara=None))
    analyze_blob(scan, name, data, 0, None)
    report = build_report(Path(name), scan, {})
    report["_scan"] = scan
    return report


def signal_ids(report: dict, index: int | None = None) -> set[str]:
    files = report["files"] if index is None else [report["files"][index]]
    return {s["id"] for f in files for s in f["signals"]}


@pytest.fixture
def scan():
    return scan_bytes
