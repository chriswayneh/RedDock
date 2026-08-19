"""Helpers that record Phase 1 state for Phase 2 tests to reason over.

Detection reads what discovery already stored, so a detection test needs a
Dockyard that looks like one discovery has run against it. These helpers write
that state directly instead of running an adapter, which keeps detection tests
about detection and keeps them off the network.
"""

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models import Asset, DiscoveryRun, EvidenceRecord, Observation, Service

BASE_TIME = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)

#: The header set the Phase 1 HTTP probe records, as an observation states it.
EXAMINED_HEADERS = [
    "server",
    "content-type",
    "content-length",
    "location",
    "x-powered-by",
    "strict-transport-security",
    "x-content-type-options",
    "content-security-policy",
    "x-frame-options",
]


class Recorder:
    """Writes the discovery-shaped rows a detection run reads."""

    def __init__(self, session: Session, dockyard_id: int) -> None:
        self.session = session
        self.dockyard_id = dockyard_id
        self._clock = 0

    def _next_time(self) -> datetime:
        self._clock += 1
        return BASE_TIME + timedelta(minutes=self._clock)

    def discovery_run(self, adapter: str = "http", profile: str = "http_probe") -> DiscoveryRun:
        run = DiscoveryRun(
            dockyard_id=self.dockyard_id,
            adapter=adapter,
            adapter_version="1.0.0",
            profile=profile,
            requested_target="http://127.0.0.1:8080",
            normalized_target="http://127.0.0.1:8080",
            status="completed",
            decision="allowed",
            decision_reason="Target is covered by authorized scope entry 127.0.0.1",
        )
        self.session.add(run)
        self.session.flush()
        self.session.add(
            EvidenceRecord(
                dockyard_id=self.dockyard_id,
                discovery_run_id=run.id,
                kind="normalized",
                relative_path="normalized/result.json",
                media_type="application/json",
                size_bytes=128,
                sha256="a" * 64,
                truncated=False,
            )
        )
        self.session.flush()
        return run

    def asset(self, identity: str, asset_type: str = "web", **fields) -> Asset:
        seen = self._next_time()
        asset = Asset(
            dockyard_id=self.dockyard_id,
            asset_type=asset_type,
            identity=identity,
            display_name=fields.pop("display_name", identity),
            ip_address=fields.pop("ip_address", "127.0.0.1"),
            hostname=fields.pop("hostname", None),
            first_seen=seen,
            last_seen=seen,
        )
        self.session.add(asset)
        self.session.flush()
        return asset

    def service(self, asset: Asset, port: int, transport: str = "tcp", **fields) -> Service:
        seen = self._next_time()
        service = Service(
            asset_id=asset.id,
            transport=transport,
            port=port,
            state=fields.pop("state", "open"),
            service_name=fields.pop("service_name", None),
            product=fields.pop("product", None),
            version=fields.pop("version", None),
            first_seen=seen,
            last_seen=seen,
        )
        self.session.add(service)
        self.session.flush()
        return service

    def observation(
        self,
        run: DiscoveryRun,
        observation_type: str,
        summary: str,
        *,
        asset: Asset | None = None,
        service: Service | None = None,
        detail: dict | None = None,
        confidence: str = "observed",
        adapter: str = "http",
        observed_at: datetime | None = None,
    ) -> Observation:
        observation = Observation(
            dockyard_id=self.dockyard_id,
            discovery_run_id=run.id,
            asset_id=asset.id if asset else None,
            service_id=service.id if service else None,
            adapter=adapter,
            observation_type=observation_type,
            summary=summary,
            detail=detail,
            confidence=confidence,
            raw_reference=f"{self.dockyard_id}/{run.id}",
            observed_at=observed_at or self._next_time(),
        )
        self.session.add(observation)
        self.session.flush()
        return observation

    def http_endpoint(
        self,
        origin: str,
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
        examined: list[str] | None = None,
        port: int | None = None,
        run: DiscoveryRun | None = None,
    ) -> tuple[Asset, Service, DiscoveryRun]:
        """One probed HTTP origin: asset, service, response and header records."""
        scheme = origin.split("://", 1)[0]
        run = run or self.discovery_run()
        asset = self.asset(origin)
        service = self.service(
            asset, port if port is not None else (443 if scheme == "https" else 80),
            service_name=scheme,
        )
        sent = headers or {}
        self.observation(
            run,
            "http_response",
            f"{origin} returned HTTP {status}",
            asset=asset,
            service=service,
            detail={
                "status": status,
                "address": "127.0.0.1",
                "scheme": scheme,
                "headers_examined": EXAMINED_HEADERS if examined is None else examined,
                "headers_present": sorted(sent),
            },
        )
        for name, value in sent.items():
            self.observation(
                run,
                "http_header",
                f"{origin} reported {name}: {value}",
                asset=asset,
                service=service,
                detail={"header": name, "value": value},
                confidence="reported",
            )
        self.session.commit()
        return asset, service, run

    def tls_endpoint(
        self, origin: str, *, tls: dict, run: DiscoveryRun | None = None
    ) -> tuple[Asset, Service, DiscoveryRun]:
        run = run or self.discovery_run()
        asset = self.asset(origin)
        service = self.service(asset, 443, service_name="https")
        self.observation(
            run,
            "tls_session",
            f"{origin} presented a TLS session",
            asset=asset,
            service=service,
            detail=tls,
        )
        self.session.commit()
        return asset, service, run

    def identified_service(
        self,
        address: str,
        port: int,
        *,
        service_name: str,
        product: str | None = None,
        version: str | None = None,
        run: DiscoveryRun | None = None,
    ) -> tuple[Asset, Service, DiscoveryRun]:
        run = run or self.discovery_run(adapter="nmap", profile="service_discovery")
        asset = self.asset(address, asset_type="host", ip_address=address)
        service = self.service(
            asset, port, service_name=service_name, product=product, version=version
        )
        self.observation(
            run,
            "service_identified",
            f"TCP/{port} identified as {product or service_name} {version or ''}".strip(),
            asset=asset,
            service=service,
            detail={"name": service_name, "product": product, "version": version},
            confidence="reported",
            adapter="nmap",
        )
        self.session.commit()
        return asset, service, run
