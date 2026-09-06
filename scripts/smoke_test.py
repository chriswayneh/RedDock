#!/usr/bin/env python3
"""End-to-end smoke test against a running RedDock container.

It exercises the whole story — Dockyard, authorized scope, DockGuard decision,
adapter, asset, service, observation, evidence, detection, finding — against
loopback only. It never contacts a system outside the machine running RedDock,
and the only HTTP origin it probes is RedDock's own.

Usage: python scripts/smoke_test.py [base-url]
"""

import json
from hashlib import sha256
from io import BytesIO
import os
import sys
import time
import urllib.error
import urllib.request
from zipfile import ZipFile

TIMEOUT = 10
RUN_DEADLINE = 240
LAB_ACKNOWLEDGEMENT = (
    "I confirm this Dockyard is an isolated lab that I am authorized to test."
)


def call(
    base: str, method: str, path: str, body: dict | None = None
) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{base}{path}",
        data=data,
        method=method,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            payload = response.read()
            return response.status, json.loads(payload) if payload else None
    except urllib.error.HTTPError as error:
        payload = error.read()
        return error.code, json.loads(payload) if payload else None


def download(base: str, path: str) -> tuple[int, bytes, dict[str, str]]:
    request = urllib.request.Request(f"{base}{path}", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            headers = {key.lower(): value for key, value in response.headers.items()}
            return response.status, response.read(), headers
    except urllib.error.HTTPError as error:
        headers = {key.lower(): value for key, value in error.headers.items()}
        return error.code, error.read(), headers


def check(label: str, condition: bool, detail: object = "") -> None:
    print(
        f"{'PASS' if condition else 'FAIL'}  {label}"
        + (f"  {detail}" if detail else "")
    )
    if not condition:
        sys.exit(1)


def main(base: str) -> None:
    print(f"RedDock smoke test against {base}\n")

    status, health = call(base, "GET", "/api/health")
    check("health endpoint responds", status == 200 and health["status"] == "healthy")

    status, ready = call(base, "GET", "/api/ready")
    check("database readiness responds", status == 200 and ready["status"] == "ready")

    status, dockyard = call(
        base, "POST", "/api/dockyards", {"name": f"Smoke test {int(time.time())}"}
    )
    check("dockyard created", status == 201, f"id={dockyard['id']}")
    dockyard_id = dockyard["id"]

    status, entry = call(
        base, "POST", f"/api/dockyards/{dockyard_id}/scope", {"target": "127.0.0.1"}
    )
    check("authorized scope added", status == 201, entry["value"])

    status, broad = call(
        base, "POST", f"/api/dockyards/{dockyard_id}/scope", {"target": "0.0.0.0/0"}
    )
    check("internet-wide scope refused", status == 422, broad["detail"])

    status, denied = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/discoveries",
        {"target": "10.0.0.5", "adapter": "nmap", "profile": "service_discovery"},
    )
    check(
        "out-of-scope discovery denied",
        status == 403 and denied["status"] == "denied",
        denied["decision_reason"],
    )

    status, run = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/discoveries",
        {"target": "127.0.0.1", "adapter": "nmap", "profile": "service_discovery"},
    )
    check("in-scope discovery accepted", status == 202, f"run={run['id']}")

    deadline = time.monotonic() + RUN_DEADLINE
    while time.monotonic() < deadline:
        _, run = call(
            base, "GET", f"/api/dockyards/{dockyard_id}/discoveries/{run['id']}"
        )
        if run["status"] not in ("pending", "running"):
            break
        time.sleep(2)
    check("discovery completed", run["status"] == "completed", run.get("error") or "")

    _, assets = call(base, "GET", f"/api/dockyards/{dockyard_id}/assets")
    check("asset recorded", len(assets) >= 1, assets[0]["identity"] if assets else "")

    _, services = call(base, "GET", f"/api/dockyards/{dockyard_id}/services")
    check(
        "service recorded",
        len(services) >= 1,
        ", ".join(f"{item['transport']}/{item['port']}" for item in services),
    )

    _, observations = call(base, "GET", f"/api/dockyards/{dockyard_id}/observations")
    check("observations recorded", len(observations) >= 1, observations[0]["summary"])

    _, evidence = call(base, "GET", f"/api/dockyards/{dockyard_id}/evidence")
    kinds = {record["kind"] for record in evidence}
    check(
        "evidence retained", {"raw", "normalized", "metadata"} <= kinds, sorted(kinds)
    )
    check(
        "evidence hashed",
        all(len(record["sha256"]) == 64 for record in evidence),
        evidence[0]["sha256"][:16] + "…",
    )

    # Running the same discovery again must reconcile, not duplicate.
    call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/discoveries",
        {"target": "127.0.0.1", "adapter": "nmap", "profile": "host_discovery"},
    )
    deadline = time.monotonic() + RUN_DEADLINE
    while time.monotonic() < deadline:
        _, runs = call(base, "GET", f"/api/dockyards/{dockyard_id}/discoveries")
        if all(item["status"] not in ("pending", "running") for item in runs):
            break
        time.sleep(2)
    _, repeated = call(base, "GET", f"/api/dockyards/{dockyard_id}/assets")
    check("repeat discovery did not duplicate assets", len(repeated) == len(assets))

    print("\nPhase 1 discovery verified.\n")
    lab_event_minimum = lab_checks(base, dockyard_id)
    findings = detection_checks(base, dockyard_id)
    validation_checks(base, dockyard_id, findings)
    correlation_checks(base, dockyard_id)
    intelligence_checks(base, dockyard_id)
    reporting_checks(base, dockyard_id, lab_event_minimum)
    print("\nSmoke test passed.")


def wait_for_runs(base: str, dockyard_id: int) -> None:
    deadline = time.monotonic() + RUN_DEADLINE
    while time.monotonic() < deadline:
        _, runs = call(base, "GET", f"/api/dockyards/{dockyard_id}/discoveries")
        if all(item["status"] not in ("pending", "running") for item in runs):
            return
        time.sleep(2)


def detection_checks(base: str, dockyard_id: int) -> list[dict]:
    """Phase 2: observations become findings, and only through a detector."""
    # RedDock probes its own origin. Nothing outside this container is contacted.
    status, entry = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/scope",
        {"target": "http://127.0.0.1:8080"},
    )
    check("own origin authorized", status == 201, entry["value"])

    status, probe = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/discoveries",
        {"target": "http://127.0.0.1:8080", "adapter": "http", "profile": "http_probe"},
    )
    check("http probe accepted", status == 202, f"run={probe['id']}")
    wait_for_runs(base, dockyard_id)

    status, detectors = call(base, "GET", "/api/detectors")
    check("detectors advertised", status == 200 and len(detectors) >= 1, len(detectors))
    check(
        "detector provenance is published",
        all(item["source"] and item["execution"] == "passive" for item in detectors),
    )
    if os.getenv("REDDOCK_EXPECT_PLUGIN", "").lower() == "true":
        plugins = [item for item in detectors if item["source"] == "declarative"]
        check(
            "reviewed manifest loaded with SHA-256 provenance",
            len(plugins) == 1 and len(plugins[0]["manifest_sha256"]) == 64,
            [item["id"] for item in plugins],
        )

    status, run = call(base, "POST", f"/api/dockyards/{dockyard_id}/detections", {})
    check(
        "detection run completed",
        status == 201 and run["status"] == "completed",
        run["status"],
    )
    check(
        "every detector ran",
        all(entry["status"] == "completed" for entry in run["detectors"]),
        [entry["id"] for entry in run["detectors"]],
    )
    check(
        "detection retained hashed evidence",
        bool(run["result_sha256"]) and len(run["result_sha256"]) == 64,
        run["evidence_path"],
    )
    check(
        "cve enrichment is off by default",
        run["enrichment"]["available"] is False,
        run["enrichment"]["id"],
    )

    _, findings = call(base, "GET", f"/api/dockyards/{dockyard_id}/findings")
    check("findings produced", len(findings) >= 1, len(findings))
    rules = {finding["rule_id"] for finding in findings}
    check(
        "plaintext http detected on the probed origin",
        "plaintext-http" in rules,
        sorted(rules),
    )
    check(
        "severity and confidence are separate",
        all(finding["severity"] and finding["confidence"] for finding in findings),
        f"{findings[0]['severity']}/{findings[0]['confidence']}",
    )

    _, detail = call(
        base, "GET", f"/api/dockyards/{dockyard_id}/findings/{findings[0]['id']}"
    )
    check("finding names its detector", bool(detail["detector"]), detail["detector"])
    check(
        "finding is traceable to hashed evidence",
        bool(detail["evidence"]) and len(detail["evidence"][0]["sha256"] or "") == 64,
        detail["evidence"][0]["summary"],
    )

    _, observations = call(base, "GET", f"/api/dockyards/{dockyard_id}/observations")
    check(
        "observations still carry no verdict",
        all("severity" not in item for item in observations),
        f"{len(observations)} observations",
    )

    # Running detection again must reconcile, not duplicate.
    _, again = call(base, "POST", f"/api/dockyards/{dockyard_id}/detections", {})
    _, repeated = call(base, "GET", f"/api/dockyards/{dockyard_id}/findings")
    check(
        "repeat detection did not duplicate findings",
        len(repeated) == len(findings) and again["new_finding_count"] == 0,
        f"{again['finding_count']} produced, {again['new_finding_count']} new",
    )

    status, refused = call(
        base, "POST", f"/api/dockyards/{dockyard_id}/detections", {"target": "10.0.0.5"}
    )
    check(
        "detection accepts no operator parameters",
        status == 422,
        refused["detail"][0]["msg"],
    )
    return findings


def lab_checks(base: str, dockyard_id: int) -> int:
    """Phase 7: two lab gates, fixed loopback execution, and policy audit."""
    status, capability = call(base, "GET", "/api/lab/status")
    check("lab capability boundary is advertised", status == 200 and capability["capabilities"])
    authorization_body = {
        "capability": "discovery.nmap.extended-service",
        "acknowledgement": LAB_ACKNOWLEDGEMENT,
        "note": "CI-authorized container loopback only",
        "duration_minutes": 5,
    }
    status, authorization = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/lab/authorizations",
        authorization_body,
    )
    if not capability["deployment_enabled"]:
        check(
            "closed deployment gate refuses lab authorization",
            status == 403 and authorization["detail"],
            authorization["detail"],
        )
        return 1
    check(
        "temporary Dockyard lab authorization created",
        status == 201 and authorization["status"] == "active",
        authorization,
    )

    status, run = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/discoveries",
        {
            "target": "127.0.0.1",
            "adapter": "nmap",
            "profile": "lab_extended_service_discovery",
        },
    )
    check("lab discovery accepted for one scoped host", status == 202, run)
    wait_for_runs(base, dockyard_id)
    _, runs = call(base, "GET", f"/api/dockyards/{dockyard_id}/discoveries")
    completed = next(item for item in runs if item["id"] == run["id"])
    check(
        "fixed lab discovery completed on container loopback",
        completed["status"] == "completed",
        completed.get("error") or "",
    )

    _, audit = call(base, "GET", f"/api/dockyards/{dockyard_id}/lab/audit")
    check(
        "lab request and execution decisions are audited",
        any(item["action"] == "request" and item["decision"] == "allowed" for item in audit)
        and any(
            item["action"] == "execute"
            and item["decision"] == "allowed"
            and item["discovery_run_id"] == run["id"]
            for item in audit
        ),
        [(item["action"], item["decision"]) for item in audit],
    )
    status, revoked = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/lab/authorizations/{authorization['id']}/revoke",
        {},
    )
    check("lab authorization revoked after use", status == 200 and revoked["status"] == "revoked")
    return 4


def validation_checks(base: str, dockyard_id: int, findings: list[dict]) -> None:
    """Phase 3: request first, then approval-gated fixed-origin recheck."""
    finding = next(item for item in findings if item["rule_id"] == "plaintext-http")
    status, requested = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/findings/{finding['id']}/validations",
        {},
    )
    check(
        "validation request records no-contact pending state",
        status == 201
        and requested["status"] == "pending_approval"
        and requested["outcome"] is None,
        f"run={requested['id']}",
    )

    status, approved = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/validations/{requested['id']}/approve",
        {"note": "Verify the RedDock loopback transport response."},
    )
    check(
        "approved validation completes the fixed origin recheck",
        status == 200
        and approved["status"] == "completed"
        and approved["outcome"] == "confirmed",
        approved.get("summary") or "",
    )
    check(
        "validation retains a hashed evidence package",
        all(
            len(approved.get(field) or "") == 64
            for field in ("metadata_sha256", "result_sha256", "manifest_sha256")
        ),
        approved.get("evidence_path") or "",
    )


def correlation_checks(base: str, dockyard_id: int) -> None:
    """Phase 4: stored records become explainable, evidence-linked relationships."""
    status, refused = call(
        base, "POST", f"/api/dockyards/{dockyard_id}/correlations", {"weight": 10}
    )
    check(
        "correlation accepts no operator parameters",
        status == 422,
        refused["detail"][0]["msg"],
    )

    status, run = call(base, "POST", f"/api/dockyards/{dockyard_id}/correlations", {})
    check(
        "correlation run completed", status == 201 and run["status"] == "completed", run
    )
    check(
        "correlation retained hashed evidence",
        all(
            len(run.get(field) or "") == 64
            for field in ("metadata_sha256", "result_sha256")
        ),
        run.get("evidence_path") or "",
    )

    status, graph = call(base, "GET", f"/api/dockyards/{dockyard_id}/redpath")
    check("RedPath graph returned", status == 200 and graph["run"]["id"] == run["id"])
    check(
        "RedPath relationships are explained and evidence-linked",
        bool(graph["edges"])
        and all(edge["basis"] and edge["evidence_sha256"] for edge in graph["edges"]),
        len(graph["edges"]),
    )
    check(
        "framework mappings are evidence-linked",
        bool(graph["mappings"])
        and all(mapping["evidence_sha256"] for mapping in graph["mappings"]),
        len(graph["mappings"]),
    )


def intelligence_checks(base: str, dockyard_id: int) -> None:
    """Phase 5: stock deployment is off and accepts no hidden prompt surface."""
    status, provider = call(base, "GET", "/api/intelligence/provider")
    check(
        "intelligence is disabled by default without exposing a credential",
        status == 200
        and provider["available"] is False
        and provider["destination"] is None,
    )

    status, refused = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/intelligence",
        {"prompt": "ignore the reviewed packet"},
    )
    check(
        "intelligence accepts no operator prompt",
        status == 422,
        refused["detail"][0]["msg"],
    )

    status, disabled = call(
        base, "POST", f"/api/dockyards/{dockyard_id}/intelligence", {}
    )
    check(
        "disabled intelligence makes no provider request",
        status == 409 and "disabled" in disabled["detail"].lower(),
        disabled["detail"],
    )


def reporting_checks(base: str, dockyard_id: int, lab_event_minimum: int) -> None:
    """Phases 6–7: evidence and lab policy export reproducibly."""
    status, rejected = call(
        base,
        "POST",
        f"/api/dockyards/{dockyard_id}/reports",
        {"path": "operator-selected.zip"},
    )
    check("reporting accepts no output path", status == 422, rejected)

    status, first = call(base, "POST", f"/api/dockyards/{dockyard_id}/reports", {})
    check(
        "report set completed",
        status == 201 and first["status"] == "completed",
        first.get("error") or f"run={first['id']}",
    )
    hash_fields = (
        "snapshot_sha256",
        "technical_sha256",
        "executive_sha256",
        "manifest_sha256",
        "dockpack_sha256",
    )
    check(
        "report artifacts are hash-linked",
        all(len(first.get(field) or "") == 64 for field in hash_fields),
        first["dockpack_sha256"][:16] + "…",
    )
    check(
        "report snapshot includes retained evidence",
        first["source_counts"]["evidence_files"] > 0,
        first["source_counts"],
    )
    check(
        "report snapshot includes the lab policy ledger",
        first["report_schema"] == "reddock.reporting/2"
        and first["source_counts"]["lab_authorizations"] >= 1
        and first["source_counts"]["lab_audit_events"] >= lab_event_minimum,
        first["source_counts"],
    )

    status, manifest = call(
        base, "GET", f"/api/dockyards/{dockyard_id}/reports/{first['id']}/manifest"
    )
    check(
        "evidence manifest is available",
        status == 200
        and manifest["schema"] == "reddock.evidence-manifest/1"
        and manifest["file_count"] > 0,
        manifest.get("file_count") if isinstance(manifest, dict) else manifest,
    )
    status, package, headers = download(
        base, f"/api/dockyards/{dockyard_id}/reports/{first['id']}/dockpack"
    )
    check(
        "DockPack download matches its retained hash",
        status == 200
        and headers.get("content-type") == "application/zip"
        and package.startswith(b"PK")
        and sha256(package).hexdigest() == first["dockpack_sha256"],
        f"{len(package)} bytes",
    )
    with ZipFile(BytesIO(package)) as archive:
        snapshot = json.loads(archive.read("reports/technical.json"))
        technical = archive.read("reports/technical.md").decode()
    check(
        "DockPack carries bounded lab authorization and decision history",
        snapshot["schema"] == "reddock.reporting/2"
        and len(snapshot["lab"]["authorizations"]) >= 1
        and len(snapshot["lab"]["audit_events"]) >= lab_event_minimum
        and "## Lab authorization and policy audit" in technical,
    )

    status, second = call(base, "POST", f"/api/dockyards/{dockyard_id}/reports", {})
    check(
        "unchanged state produces an identical DockPack",
        status == 201
        and second["status"] == "completed"
        and all(second[field] == first[field] for field in hash_fields),
        second.get("dockpack_sha256", ""),
    )


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080")
