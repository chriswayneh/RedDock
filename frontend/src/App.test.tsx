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
  validations: [],
};

const validationRun = {
  id: 12,
  dockyard_id: 1,
  finding_id: finding.id,
  validator: "http.origin_recheck",
  validator_version: "1.0.0",
  target: "https://127.0.0.1:8443",
  status: "pending_approval",
  decision: "allowed",
  decision_reason: "Target is covered by authorized scope entry 127.0.0.1",
  approval_note: null,
  outcome: null,
  confidence: null,
  summary: null,
  detail: null,
  error: null,
  evidence_path: null,
  metadata_sha256: null,
  result_sha256: null,
  manifest_sha256: null,
  created_at: "2026-08-18T12:32:00Z",
  approved_at: null,
  started_at: null,
  completed_at: null,
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

const correlationRun = {
  id: 8,
  dockyard_id: 1,
  status: "completed",
  asset_count: 1,
  finding_count: 1,
  asset_relationship_count: 0,
  finding_correlation_count: 0,
  framework_mapping_count: 1,
  error: null,
  evidence_path: "1/correlation/8",
  metadata_sha256: "d".repeat(64),
  result_sha256: "e".repeat(64),
  created_at: "2026-08-18T12:33:00Z",
  started_at: "2026-08-18T12:33:00Z",
  completed_at: "2026-08-18T12:33:01Z",
};

const redpath = {
  run: correlationRun,
  nodes: [
    {
      id: "asset:3",
      kind: "asset",
      label: "127.0.0.1",
      subtitle: "host",
      status: null,
      severity: null,
    },
    {
      id: "finding:9",
      kind: "finding",
      label: finding.title,
      subtitle: finding.rule_id,
      status: "open",
      severity: "low",
    },
  ],
  edges: [
    {
      id: "finding-subject:9",
      source: "asset:3",
      target: "finding:9",
      kind: "finding_subject",
      label: "supported finding",
      confidence: "high",
      basis: "Finding #9 cites observations attached to asset #3.",
      evidence_sha256: ["a".repeat(64)],
    },
  ],
  mappings: [
    {
      id: 1,
      finding_id: 9,
      framework: "CWE",
      external_id: "CWE-319",
      title: "Cleartext Transmission of Sensitive Information",
      basis: "Fixed RedDock mapping.",
      mapping_version: "1.0.0",
      evidence_sha256: "a".repeat(64),
    },
  ],
};

const intelligenceProvider = {
  available: true,
  provider: "openai-compatible",
  model: "local-model",
  destination: "http://127.0.0.1:11434/v1",
  sends_data_external: false,
  reason: null,
};

const intelligenceRun = {
  id: 14,
  dockyard_id: 1,
  correlation_run_id: 8,
  status: "pending_approval",
  provider: "openai-compatible",
  model: "local-model",
  destination: "http://127.0.0.1:11434/v1",
  sends_data_external: false,
  prompt_version: "1",
  approval_note: null,
  input: {
    schema: "reddock.intelligence-input/1",
    purpose: "advice-only remediation and prioritization",
    constraints: ["Stored evidence only."],
    dockyard_id: 1,
    correlation_run_id: 8,
    findings: [
      {
        id: finding.id,
        rule_id: finding.rule_id,
        title: finding.title,
        description: findingDetail.description,
        remediation: findingDetail.remediation,
        severity: finding.severity,
        confidence: finding.confidence,
        status: finding.status,
        asset_id: finding.asset_id,
        service_id: finding.service_id,
        evidence_sha256: ["a".repeat(64)],
      },
    ],
  },
  output: null,
  input_sha256: "f".repeat(64),
  result_sha256: null,
  metadata_sha256: null,
  evidence_path: "1/intelligence/14",
  error: null,
  created_at: "2026-08-18T12:34:00Z",
  approved_at: null,
  started_at: null,
  completed_at: null,
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
  validations?: unknown[];
  redpath?: unknown;
  intelligenceProvider?: unknown;
  intelligenceRuns?: unknown[];
};

type Calls = {
  discovery: ReturnType<typeof vi.fn>;
  detection: ReturnType<typeof vi.fn>;
  decision: ReturnType<typeof vi.fn>;
  validationRequest: ReturnType<typeof vi.fn>;
  validationApproval: ReturnType<typeof vi.fn>;
  correlation: ReturnType<typeof vi.fn>;
  intelligenceCreate: ReturnType<typeof vi.fn>;
  intelligenceApproval: ReturnType<typeof vi.fn>;
};

function stubApi({
  scope = [scopeEntry],
  assets = [],
  evaluation = allowed,
  findings = [],
  observations = [],
  validations = [],
  redpath: redpathResponse = { run: null, nodes: [], edges: [], mappings: [] },
  intelligenceProvider: providerResponse = {
    available: false,
    provider: null,
    model: null,
    destination: null,
    sends_data_external: false,
    reason: "Configure a model provider.",
  },
  intelligenceRuns = [],
}: Options = {}): Calls {
  const calls: Calls = {
    discovery: vi.fn(),
    detection: vi.fn(),
    decision: vi.fn(),
    validationRequest: vi.fn(),
    validationApproval: vi.fn(),
    correlation: vi.fn(),
    intelligenceCreate: vi.fn(),
    intelligenceApproval: vi.fn(),
  };
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = new URL(String(input), "http://localhost");
      const path = url.pathname;
      const json = (body: unknown, status = 200) =>
        Promise.resolve(new Response(JSON.stringify(body), { status }));

      if (path.endsWith("/health")) return json({ status: "healthy", service: "reddock-core" });
      if (path.endsWith("/version"))
        return json({ name: "RedDock", version: "0.6.0", phase: "Phase 5 — Intelligence" });
      if (path.endsWith("/adapters")) return json(adapters);
      if (path.endsWith("/detectors")) return json(detectors);
      if (path.endsWith("/scope/evaluate")) return json(evaluation);
      if (path.endsWith("/scope")) return json(scope);
      if (path.endsWith("/assets")) return json(assets);
      if (path.endsWith("/services")) return json([]);
      if (path.endsWith("/observations")) return json(observations);
      if (path.endsWith("/evidence")) return json([]);
      if (path.endsWith("/redpath")) return json(redpathResponse);
      if (path.endsWith("/intelligence/provider")) return json(providerResponse);
      if (/\/intelligence\/\d+\/approve$/.test(path) && init?.method === "POST") {
        calls.intelligenceApproval(JSON.parse(String(init.body)));
        return json({
          ...intelligenceRun,
          status: "completed",
          approval_note: JSON.parse(String(init.body)).note,
          output: {
            summary: "Review this finding first.",
            priorities: [
              {
                finding_id: finding.id,
                priority: "high",
                rationale: "The evidence supports review.",
                remediation_steps: ["Apply the documented remediation."],
                evidence_sha256: ["a".repeat(64)],
              },
            ],
            limitations: ["Stored evidence only."],
          },
          result_sha256: "1".repeat(64),
          metadata_sha256: "2".repeat(64),
          completed_at: "2026-08-18T12:35:00Z",
        });
      }
      if (path.endsWith("/intelligence")) {
        if (init?.method === "POST") {
          calls.intelligenceCreate(JSON.parse(String(init.body)));
          return json(intelligenceRun, 201);
        }
        return json(intelligenceRuns);
      }
      if (path.endsWith("/correlations")) {
        if (init?.method === "POST") {
          calls.correlation(JSON.parse(String(init.body)));
          return json(correlationRun, 201);
        }
        return json([]);
      }
      if (/\/findings\/\d+\/validations$/.test(path) && init?.method === "POST") {
        calls.validationRequest(JSON.parse(String(init.body)));
        return json(validationRun, 201);
      }
      if (/\/validations\/\d+\/approve$/.test(path) && init?.method === "POST") {
        calls.validationApproval(JSON.parse(String(init.body)));
        return json({ ...validationRun, status: "completed", outcome: "confirmed" });
      }
      if (path.endsWith("/validations")) return json(validations);
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
    expect(screen.getByText("PHASE 5 — INTELLIGENCE")).toBeInTheDocument();
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

  it("keeps reports visibly planned", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: /Reports/ })[0]);
    expect(await screen.findByText("Reports is not available yet.")).toBeInTheDocument();
  });

  it("shows evidence-linked RedPath data and runs correlation with an empty body", async () => {
    const calls = stubApi({ redpath });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: "RedPath" })[0]);

    expect(
      await screen.findByText("Explainable relationships, not inferred attack paths"),
    ).toBeInTheDocument();
    expect(screen.getByText("CWE-319")).toBeInTheDocument();
    expect(
      screen.getByText("Finding #9 cites observations attached to asset #3."),
    ).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Run correlation" }));
    await waitFor(() => expect(calls.correlation).toHaveBeenCalledWith({}));
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

describe("Phase 3 validation", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("requests an eligible finding without approving it", async () => {
    const calls = stubApi({ findings: [finding] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await openWorkspace(user);
    await user.click(await screen.findByRole("button", { name: "Validation" }));

    expect(await screen.findByText("Request a bounded recheck")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Request validation" }));
    await waitFor(() => expect(calls.validationRequest).toHaveBeenCalledWith({}));
    expect(calls.validationApproval).not.toHaveBeenCalled();
  });

  it("requires an approval note before it invokes the recheck endpoint", async () => {
    const calls = stubApi({ findings: [finding], validations: [validationRun] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await openWorkspace(user);
    await user.click(await screen.findByRole("button", { name: "Validation" }));

    await user.click(await screen.findByRole("button", { name: "Approve and recheck" }));
    expect(calls.validationApproval).not.toHaveBeenCalled();
    await user.type(
      screen.getByLabelText("Approval note for validation 12"),
      "Confirm this authorized recheck.",
    );
    await user.click(screen.getByRole("button", { name: "Approve and recheck" }));
    await waitFor(() =>
      expect(calls.validationApproval).toHaveBeenCalledWith({
        note: "Confirm this authorized recheck.",
      }),
    );
  });
});

describe("Phase 5 intelligence", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("creates a review packet without sending it to the provider", async () => {
    const calls = stubApi({ intelligenceProvider });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: "Intelligence" })[0]);

    expect(await screen.findByText("local-model")).toBeInTheDocument();
    expect(screen.getByText("Local")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Create intelligence packet" }));

    await waitFor(() => expect(calls.intelligenceCreate).toHaveBeenCalledWith({}));
    expect(calls.intelligenceApproval).not.toHaveBeenCalled();
  });

  it("requires an approval note before sending the reviewed packet", async () => {
    const calls = stubApi({ intelligenceProvider, intelligenceRuns: [intelligenceRun] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: "Intelligence" })[0]);

    const reviewPacket = await screen.findByText("Review exact provider packet");
    const approve = screen.getByRole("button", { name: "Approve and send to local-model" });
    expect(approve).toBeDisabled();
    expect(calls.intelligenceApproval).not.toHaveBeenCalled();

    await user.type(
      screen.getByLabelText("Approval note for intelligence 14"),
      "Send this reviewed packet to the configured local model.",
    );
    expect(approve).toBeDisabled();
    await user.click(reviewPacket);
    expect(approve).toBeEnabled();
    await user.click(approve);

    await waitFor(() =>
      expect(calls.intelligenceApproval).toHaveBeenCalledWith({
        note: "Send this reviewed packet to the configured local model.",
      }),
    );
  });

  it("refuses a stale packet that does not match the selected Dockyard", async () => {
    const calls = stubApi({ intelligenceProvider, intelligenceRuns: [intelligenceRun] });
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: "Intelligence" })[0]);
    await screen.findByText("Review exact provider packet");

    await user.selectOptions(screen.getByLabelText("Dockyard"), "2");
    await user.click(await screen.findByText("Review exact provider packet"));
    await user.type(
      screen.getByLabelText("Approval note for intelligence 14"),
      "This packet should not be sent.",
    );
    await user.click(screen.getByRole("button", { name: "Approve and send to local-model" }));

    expect(calls.intelligenceApproval).not.toHaveBeenCalled();
    expect(
      await screen.findByText(/does not belong to the selected Dockyard/),
    ).toBeInTheDocument();
  });
});
