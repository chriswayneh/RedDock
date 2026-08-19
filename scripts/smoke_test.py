#!/usr/bin/env python3
"""End-to-end smoke test against a running RedDock container.

It exercises the whole story — Dockyard, authorized scope, DockGuard decision,
adapter, asset, service, observation, evidence, detection, finding — against
loopback only. It never contacts a system outside the machine running RedDock,
and the only HTTP origin it probes is RedDock's own.

Usage: python scripts/smoke_test.py [base-url]
"""

import json
import sys
import time
import urllib.error
import urllib.request

TIMEOUT = 10
RUN_DEADLINE = 240


def call(base: str, method: str, path: str, body: dict | None = None) -> tuple[int, object]:
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(
        f"{base}{path}", data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            payload = response.read()
            return response.status, json.loads(payload) if payload else None
    except urllib.error.HTTPError as error:
        payload = error.read()
        return error.code, json.loads(payload) if payload else None


def check(label: str, condition: bool, detail: object = "") -> None:
    print(f"{'PASS' if condition else 'FAIL'}  {label}" + (f"  {detail}" if detail else ""))
    if not condition:
        sys.exit(1)


def main(base: str) -> None:
    print(f"RedDock smoke test against {base}\n")

    status, health = call(base, "GET", "/api/health")
    check("health endpoint responds", status == 200 and health["status"] == "healthy")

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
        _, run = call(base, "GET", f"/api/dockyards/{dockyard_id}/discoveries/{run['id']}")
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
    check("evidence retained", {"raw", "normalized", "metadata"} <= kinds, sorted(kinds))
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
    detection_checks(base, dockyard_id)
    print("\nSmoke test passed.")


def wait_for_runs(base: str, dockyard_id: int) -> None:
    deadline = time.monotonic() + RUN_DEADLINE
    while time.monotonic() < deadline:
        _, runs = call(base, "GET", f"/api/dockyards/{dockyard_id}/discoveries")
        if all(item["status"] not in ("pending", "running") for item in runs):
            return
        time.sleep(2)


def detection_checks(base: str, dockyard_id: int) -> None:
    """Phase 2: observations become findings, and only through a detector."""
    # RedDock probes its own origin. Nothing outside this container is contacted.
    status, entry = call(
        base, "POST", f"/api/dockyards/{dockyard_id}/scope", {"target": "http://127.0.0.1:8080"}
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

    status, run = call(base, "POST", f"/api/dockyards/{dockyard_id}/detections", {})
    check("detection run completed", status == 201 and run["status"] == "completed", run["status"])
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
    check("plaintext http detected on the probed origin", "plaintext-http" in rules, sorted(rules))
    check(
        "severity and confidence are separate",
        all(finding["severity"] and finding["confidence"] for finding in findings),
        f"{findings[0]['severity']}/{findings[0]['confidence']}",
    )

    _, detail = call(base, "GET", f"/api/dockyards/{dockyard_id}/findings/{findings[0]['id']}")
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
    check("detection accepts no operator parameters", status == 422, refused["detail"][0]["msg"])


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080")
