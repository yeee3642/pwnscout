"""Deep web red-team module: crawl the app, brute content, and run safe active
probes (XSS / SSTI / SQLi / traversal / open-redirect / CORS / headers).

Reuses the same Finding / Host / ScanResult model as the network scanner so
web findings land in the exact same ranked report.
"""

from __future__ import annotations

from .runner import web_scan

__all__ = ["web_scan"]
