"""Active verification stage. Only *safe*, read-only PoCs live here — the goal
is to prove a hole exists without changing state on the target."""

from __future__ import annotations

from .poc import verify_host

__all__ = ["verify_host"]
