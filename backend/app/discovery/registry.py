"""The fixed set of adapters RedDock is allowed to run.

Adapters are registered here explicitly rather than discovered at runtime: a
tool that can reach a target should never arrive by accident.
"""

from app.discovery.base import DiscoveryAdapter
from app.discovery.http_probe import HttpProbeAdapter
from app.discovery.nmap import NmapAdapter

_ADAPTERS: tuple[DiscoveryAdapter, ...] = (NmapAdapter(), HttpProbeAdapter())


def available_adapters() -> tuple[DiscoveryAdapter, ...]:
    return _ADAPTERS


def get_adapter(name: str) -> DiscoveryAdapter | None:
    return next((adapter for adapter in _ADAPTERS if adapter.name == name), None)
