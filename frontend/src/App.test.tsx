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

type Options = { scope?: unknown[]; assets?: unknown[]; evaluation?: unknown };

function stubApi({ scope = [scopeEntry], assets = [], evaluation = allowed }: Options = {}) {
  const started = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const json = (body: unknown, status = 200) =>
        Promise.resolve(new Response(JSON.stringify(body), { status }));

      if (url.endsWith("/health")) return json({ status: "healthy", service: "reddock-core" });
      if (url.endsWith("/version"))
        return json({ name: "RedDock", version: "0.1.0", phase: "Phase 1 — Discovery" });
      if (url.endsWith("/adapters")) return json(adapters);
      if (url.endsWith("/scope/evaluate")) return json(evaluation);
      if (url.endsWith("/scope")) return json(scope);
      if (url.endsWith("/assets")) return json(assets);
      if (url.endsWith("/services")) return json([]);
      if (url.endsWith("/observations")) return json([]);
      if (url.endsWith("/evidence")) return json([]);
      if (url.endsWith("/discoveries")) {
        if (init?.method === "POST") {
          started(JSON.parse(String(init.body)));
          return json({ id: 5, dockyard_id: 1, status: "pending" }, 202);
        }
        return json([]);
      }
      if (url.endsWith("/dockyards") && init?.method === "POST")
        return json({ ...dockyard, id: 2, name: JSON.parse(String(init.body)).name }, 201);
      return json([dockyard]);
    }),
  );
  return started;
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
    expect(screen.getByText("PHASE 1 — DISCOVERY")).toBeInTheDocument();
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
    const started = stubApi({ evaluation: denied });
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
    expect(started).not.toHaveBeenCalled();
  });

  it("launches discovery once the target is allowed", async () => {
    const started = stubApi();
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
      expect(started).toHaveBeenCalledWith({
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

  it("keeps Phase 2 capabilities visibly planned", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: /Findings/ })[0]);
    expect(await screen.findByText("Findings is not available yet.")).toBeInTheDocument();
  });
});
