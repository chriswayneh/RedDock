import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const dockyard = {
  id: 1,
  name: "Lab review",
  description: "Approved lab",
  status: "draft",
  created_at: "2026-08-18T12:00:00Z",
  updated_at: "2026-08-18T12:00:00Z",
};

const adapters = [
  {
    name: "nmap",
    version: "1.0.0",
    title: "Nmap",
    description: "Non-invasive host and TCP service discovery.",
    profiles: [
      { name: "host_discovery", title: "Host discovery", description: "Which hosts respond." },
      { name: "service_discovery", title: "Service discovery", description: "Top 100 TCP ports." },
    ],
    target_kinds: ["ipv4", "hostname"],
  },
];

const detectors = [
  {
    id: "http.security_headers",
    version: "1.0.0",
    title: "HTTP security headers",
    description: "Reports response-level protections the recorded response did not carry.",
    consumes: ["http_response", "http_header"],
  },
];

const scopeEntry = {
  id: 7,
  rule: "include",
  kind: "ipv4",
  value: "127.0.0.1",
  note: null,
  created_at: "2026-08-18T12:00:00Z",
};

const asset = {
  id: 3,
  asset_type: "host",
  identity: "127.0.0.1",
  display_name: "127.0.0.1",
  ip_address: "127.0.0.1",
  hostname: null,
  first_seen: "2026-08-18T12:00:00Z",
  last_seen: "2026-08-18T12:30:00Z",
  service_count: 1,
};

const observation = {
  id: 11,
  discovery_run_id: 2,
  asset_id: 3,
  service_id: 4,
  adapter: "http",
  observation_type: "http_response",
  summary: "https://127.0.0.1:8443 returned HTTP 200",
  detail: { status: 200 },
  confidence: "observed",
  raw_reference: "1/2",
  observed_at: "2026-08-18T12:30:00Z",
};

const finding = {
  id: 9,
  fingerprint: "b8b1e0a2f4c6d8e0b8b1e0a2f4c6d8e0b8b1e0a2f4c6d8e0b8b1e0a2f4c6d8e0",
  detector: "http.security_headers",
  detector_version: "1.0.0",
  rule_id: "hsts-not-set",
  title: "https://127.0.0.1:8443 does not set Strict-Transport-Security",
  category: "hardening",
  severity: "low",
  confidence: "high",
  status: "open",
  status_note: null,
  asset_id: 3,
  service_id: 4,
  first_seen: "2026-08-18T12:30:00Z",
  last_seen: "2026-08-18T12:30:00Z",
  resolved_at: null,
  first_detection_run_id: 5,
  last_detection_run_id: 5,
  cve_references: [],
  asset_label: "https://127.0.0.1:8443",
  service_endpoint: "TCP/8443",
  evidence_count: 1,
};

const findingDetail = {
  ...finding,
  description: "The HTTPS response carried no Strict-Transport-Security header.",
  remediation: "Send Strict-Transport-Security with a max-age the operator can commit to.",
  detail: { status: 200 },
  evidence: [
    {
      id: 21,
      observation_id: 11,
      discovery_run_id: 2,
      detection_run_id: 5,
      evidence_record_id: 31,
      summary: "https://127.0.0.1:8443 returned HTTP 200",
      created_at: "2026-08-18T12:30:00Z",
      evidence_path: "normalized/result.json",
      sha256: "a".repeat(64),
    },
  ],
};

const detectionRun = {
  id: 5,
  dockyard_id: 1,
  status: "completed",
  detectors: [
    {
      id: "http.security_headers",
      version: "1.0.0",
      status: "completed",
      findings: 1,
      error: null,
    },
  ],
  enrichment: { id: "none", version: null, available: false, warning: null },
  asset_count: 1,
  service_count: 1,
  observation_count: 3,
  finding_count: 1,
  new_finding_count: 1,
  resolved_finding_count: 0,
  error: null,
  evidence_path: "1/detection/5",
  metadata_sha256: "b".repeat(64),
  result_sha256: "c".repeat(64),
  created_at: "2026-08-18T12:31:00Z",
  started_at: "2026-08-18T12:31:00Z",
  completed_at: "2026-08-18T12:31:01Z",
};

const allowed = {
  decision: "allowed",
  target: "127.0.0.1",
  reason: "Target is covered by authorized scope entry 127.0.0.1",
  normalized_target: "127.0.0.1",
  target_kind: "ipv4",
  matched_rule: "127.0.0.1",
  resolved_addresses: [],
  excluded_addresses: [],
  allowed: true,
};

const denied = {
  ...allowed,
  decision: "denied_out_of_scope",
  target: "10.0.0.5",
  normalized_target: "10.0.0.5",
  reason: "Target is not covered by any authorized scope entry",
  matched_rule: null,
  allowed: false,
};

type Options = {
  scope?: unknown[];
  assets?: unknown[];
  evaluation?: unknown;
  findings?: unknown[];
  observations?: unknown[];
};

type Calls = {
  discovery: ReturnType<typeof vi.fn>;
  detection: ReturnType<typeof vi.fn>;
  decision: ReturnType<typeof vi.fn>;
};

function stubApi({
  scope = [scopeEntry],
  assets = [],
  evaluation = allowed,
  findings = [],
  observations = [],
}: Options = {}): Calls {
  const calls: Calls = { discovery: vi.fn(), detection: vi.fn(), decision: vi.fn() };
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      const path = url.pathname;
      const json = (body: unknown, status = 200) =>
        Promise.resolve(new Response(JSON.stringify(body), { status }));

      if (path.endsWith("/health")) return json({ status: "healthy", service: "reddock-core" });
      if (path.endsWith("/version"))
        return json({ name: "RedDock", version: "0.3.0", phase: "Phase 2 — Detection" });
      if (path.endsWith("/adapters")) return json(adapters);
      if (path.endsWith("/detectors")) return json(detectors);
      if (path.endsWith("/scope/evaluate")) return json(evaluation);
      if (path.endsWith("/scope")) return json(scope);
      if (path.endsWith("/assets")) return json(assets);
      if (path.endsWith("/services")) return json([]);
      if (path.endsWith("/observations")) return json(observations);
      if (path.endsWith("/evidence")) return json([]);
      if (/\/findings\/\d+$/.test(path)) {
        if (init?.method === "PATCH") {
          const body = JSON.parse(String(init.body));
          calls.decision(body);
          return json({ ...findingDetail, status: body.status, status_note: body.note });
        }
        return json(findingDetail);
      }
      if (path.endsWith("/findings")) {
        const severity = url.searchParams.get("severity");
        const status = url.searchParams.get("status");
        return json(
          findings.filter((row) => {
            const item = row as { severity: string; status: string };
            return (
              (!severity || item.severity === severity) && (!status || item.status === status)
            );
          }),
        );
      }
      if (path.endsWith("/detections")) {
        if (init?.method === "POST") {
          calls.detection(JSON.parse(String(init.body)));
          return json(detectionRun, 201);
        }
        return json(findings.length ? [detectionRun] : []);
      }
      if (path.endsWith("/discoveries")) {
        if (init?.method === "POST") {
          calls.discovery(JSON.parse(String(init.body)));
          return json({ id: 5, dockyard_id: 1, status: "pending" }, 202);
        }
        return json([]);
      }
      if (path.endsWith("/dockyards") && init?.method === "POST")
        return json({ ...dockyard, id: 2, name: JSON.parse(String(init.body)).name }, 201);
      return json([dockyard, { ...dockyard, id: 2, name: "Second workspace" }]);
    }),
  );
  return calls;
}

async function openWorkspace(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getAllByRole("button", { name: "Dockyards" })[0]);
  await user.click(await screen.findByRole("button", { name: /Lab review/ }));
}

describe("RedDock application", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  beforeEach(() => {
    stubApi();
  });

  it("shows healthy status and the current phase", async () => {
    render(<App />);
    expect(await screen.findByText("Healthy")).toBeInTheDocument();
    expect(screen.getByText("PHASE 2 — DETECTION")).toBeInTheDocument();
    expect(screen.getByText("Lab review")).toBeInTheDocument();
  });

  it("creates a Dockyard", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: "Dockyards" })[0]);
    await user.type(screen.getByLabelText("Name"), "New engagement");
    await user.click(screen.getByRole("button", { name: "Create Dockyard" }));
    await waitFor(() => expect(screen.getAllByText("New engagement").length).toBeGreaterThan(0));
  });

  it("shows the Dockyard scope and its DockGuard decision", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await openWorkspace(user);

    expect(await screen.findByText("Scope entries")).toBeInTheDocument();
    expect(screen.getAllByText("127.0.0.1").length).toBeGreaterThan(0);

    await user.type(screen.getByLabelText("Candidate target"), "127.0.0.1");
    await user.click(screen.getByRole("button", { name: "Evaluate" }));
    expect(await screen.findByText("ALLOWED")).toBeInTheDocument();
  });

  it("keeps discovery unavailable until DockGuard allows the target", async () => {
    const calls = stubApi({ evaluation: denied });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await openWorkspace(user);
    await user.click(await screen.findByRole("button", { name: "Discovery" }));

    const run = screen.getByRole("button", { name: "Run discovery" });
    expect(run).toBeDisabled();

    await user.type(screen.getByLabelText("Target"), "10.0.0.5");
    await user.click(screen.getByRole("button", { name: "Check with DockGuard" }));

    expect(await screen.findByText("DENIED")).toBeInTheDocument();
    expect(run).toBeDisabled();
    expect(calls.discovery).not.toHaveBeenCalled();
  });

  it("launches discovery once the target is allowed", async () => {
    const calls = stubApi();
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await openWorkspace(user);
    await user.click(await screen.findByRole("button", { name: "Discovery" }));

    await user.type(screen.getByLabelText("Target"), "127.0.0.1");
    await user.click(screen.getByRole("button", { name: "Check with DockGuard" }));
    await screen.findByText("ALLOWED");

    const run = screen.getByRole("button", { name: "Run discovery" });
    await waitFor(() => expect(run).toBeEnabled());
    await user.click(run);

    await waitFor(() =>
      expect(calls.discovery).toHaveBeenCalledWith({
        target: "127.0.0.1",
        adapter: "nmap",
        profile: "host_discovery",
      }),
    );
  });

  it("lists discovered assets without inventing risk", async () => {
    stubApi({ assets: [asset] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: "Assets" })[0]);

    const table = await screen.findByRole("table");
    expect(within(table).getByText("Host")).toBeInTheDocument();
    expect(within(table).getAllByText("127.0.0.1").length).toBeGreaterThan(0);
    expect(within(table).queryByText(/critical|high|severity/i)).toBeNull();
  });

  it("keeps unbuilt capabilities visibly planned", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: /RedPath/ })[0]);
    expect(await screen.findByText("RedPath is not available yet.")).toBeInTheDocument();
  });
});

describe("Phase 2 detection", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("counts open findings on the dashboard", async () => {
    stubApi({ findings: [finding] });
    render(<App />);

    expect(await screen.findByText("Open findings")).toBeInTheDocument();
    expect(
      screen.getByText("Produced by a detector, from recorded observations"),
    ).toBeInTheDocument();
  });

  it("lists findings with severity, confidence and status stated separately", async () => {
    stubApi({ findings: [finding] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: /^Findings/ })[0]);

    const table = await screen.findByRole("table");
    const headers = within(table)
      .getAllByRole("columnheader")
      .map((cell) => cell.textContent);
    expect(headers).toEqual([
      "Finding",
      "Severity",
      "Confidence",
      "Status",
      "Affected",
      "Detector",
      "Seen",
    ]);
    expect(within(table).getByText("low")).toBeInTheDocument();
    expect(within(table).getByText("High")).toBeInTheDocument();
    expect(within(table).getByText("Open")).toBeInTheDocument();
    expect(within(table).getByText(/last seen/)).toBeInTheDocument();
    expect(within(table).getByText("https://127.0.0.1:8443")).toBeInTheDocument();
  });

  it("presents no risk score or aggregate rating", async () => {
    stubApi({ findings: [finding] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: /^Findings/ })[0]);
    await screen.findByRole("table");

    expect(screen.queryByText(/risk score|cvss|overall rating|\d+\s*\/\s*10/i)).toBeNull();
  });

  it("shows the detector, the observation and the hash behind a finding", async () => {
    stubApi({ findings: [finding] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: /^Findings/ })[0]);
    await user.click(await screen.findByRole("button", { name: finding.title }));

    expect(await screen.findByText(findingDetail.description)).toBeInTheDocument();
    expect(screen.getByText("hsts-not-set")).toBeInTheDocument();
    expect(screen.getAllByText("http.security_headers").length).toBeGreaterThan(0);
    expect(screen.getByText(/Observation #11/)).toBeInTheDocument();
    expect(screen.getByText(/discovery run #2/)).toBeInTheDocument();
    expect(screen.getByText(/normalized\/result\.json · aaaaaaaaaaaaaaaa…/)).toBeInTheDocument();
  });

  it("records an operator decision without deleting the finding", async () => {
    const calls = stubApi({ findings: [finding] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: /^Findings/ })[0]);
    await user.click(await screen.findByRole("button", { name: finding.title }));
    await user.click(await screen.findByRole("button", { name: "Suppressed" }));

    await waitFor(() =>
      expect(calls.decision).toHaveBeenCalledWith({ status: "suppressed", note: null }),
    );
    expect(screen.queryByRole("button", { name: "Resolved" })).toBeNull();
  });

  it("closes a finding when the Dockyard changes", async () => {
    stubApi({ findings: [finding] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: /^Findings/ })[0]);
    await user.click(await screen.findByRole("button", { name: finding.title }));
    expect(await screen.findByText(findingDetail.description)).toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText("Dockyard"), "2");
    await waitFor(() => expect(screen.queryByText(findingDetail.description)).toBeNull());
  });

  it("filters findings by severity through the API", async () => {
    stubApi({ findings: [finding] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: /^Findings/ })[0]);
    await screen.findByRole("table");

    await user.selectOptions(screen.getByLabelText("Severity"), "critical");
    await waitFor(() =>
      expect(
        screen.getByText(/No findings match this view/),
      ).toBeInTheDocument(),
    );
  });

  it("runs detection from the Dockyard workspace without sending a target", async () => {
    const calls = stubApi({ findings: [finding], observations: [observation] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await openWorkspace(user);
    await user.click(await screen.findByRole("button", { name: "Detection" }));

    expect(await screen.findByText("HTTP security headers")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Run detection" }));

    await waitFor(() => expect(calls.detection).toHaveBeenCalledWith({}));
  });

  it("shows detection runs with what they read and what they produced", async () => {
    stubApi({ findings: [finding], observations: [observation] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await openWorkspace(user);
    await user.click(await screen.findByRole("button", { name: "Detection" }));

    expect(await screen.findByText("Detection runs")).toBeInTheDocument();
    expect(screen.getByText(/1 assets · 3 observations/)).toBeInTheDocument();
    expect(screen.getByText(/1 produced · 1 new · 0 resolved/)).toBeInTheDocument();
    expect(screen.getByText(/cccccccccccccccc…/)).toBeInTheDocument();
  });

  it("keeps observations described as records rather than findings", async () => {
    stubApi({ observations: [observation] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await openWorkspace(user);
    await user.click(await screen.findByRole("button", { name: "Observations" }));

    expect(
      await screen.findByText(/It carries no severity and no verdict/),
    ).toBeInTheDocument();
  });
});
