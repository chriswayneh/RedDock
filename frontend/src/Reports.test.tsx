import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Reports } from "./Reports";

const dockyard = {
  id: 1,
  name: "Reporting lab",
  description: "Authorized evidence review",
  status: "draft",
  created_at: "2026-09-05T04:00:00Z",
  updated_at: "2026-09-05T04:00:00Z",
};

const report = {
  id: 21,
  dockyard_id: 1,
  status: "completed",
  report_schema: "reddock.reporting/1",
  snapshot_sha256: "a".repeat(64),
  technical_sha256: "b".repeat(64),
  executive_sha256: "c".repeat(64),
  manifest_sha256: "d".repeat(64),
  dockpack_sha256: "e".repeat(64),
  dockpack_bytes: 24_576,
  evidence_path: "1/reporting/21",
  source_counts: {
    assets: 3,
    services: 4,
    observations: 8,
    findings: 2,
    findings_by_severity: { critical: 0, high: 0, medium: 1, low: 1, informational: 0 },
    findings_by_status: { open: 1, accepted: 1, resolved: 0, suppressed: 0 },
    validations: 1,
    evidence_files: 9,
    evidence_bytes: 8192,
  },
  error: null,
  created_at: "2026-09-05T04:10:00Z",
  completed_at: "2026-09-05T04:10:01Z",
};

const manifest = {
  schema: "reddock.evidence-manifest/1",
  algorithm: "sha256",
  file_count: 1,
  total_bytes: 128,
  files: [
    {
      source: "discovery",
      run_id: 3,
      source_path: "1/3/normalized/result.json",
      archive_path: "evidence/discovery/3/normalized/result.json",
      media_type: "application/json",
      bytes: 128,
      sha256: "f".repeat(64),
      truncated: false,
    },
  ],
};

function stubReports(initial: typeof report[] = [report]) {
  let reports = initial;
  const create = vi.fn();
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input), "http://localhost").pathname;
      const dockyardId = Number(path.match(/\/dockyards\/(\d+)\//)?.[1] ?? 0);
      if (path.endsWith("/reports") && init?.method === "POST") {
        create(JSON.parse(String(init.body)));
        reports = [report];
        return Promise.resolve(new Response(JSON.stringify(report), { status: 201 }));
      }
      if (path.endsWith("/reports")) {
        return Promise.resolve(
          new Response(JSON.stringify(dockyardId === 1 ? reports : []), { status: 200 }),
        );
      }
      if (path.endsWith("/technical")) {
        return Promise.resolve(new Response("# RedDock technical report\n\nEvidence-linked detail."));
      }
      if (path.endsWith("/executive")) {
        return Promise.resolve(new Response("# RedDock executive report\n\nNo aggregate risk score."));
      }
      if (path.endsWith("/manifest")) {
        return Promise.resolve(new Response(JSON.stringify(manifest), { status: 200 }));
      }
      return Promise.resolve(new Response(JSON.stringify({ detail: "Not found" }), { status: 404 }));
    }),
  );
  return create;
}

describe("Phase 6 reporting", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  it("previews both reports, exposes the manifest, and offers the exact DockPack", async () => {
    stubReports();
    const user = userEvent.setup();
    render(<Reports dockyards={[dockyard]} onError={vi.fn()} />);

    expect(await screen.findByText("# RedDock technical report", { exact: false })).toBeInTheDocument();
    expect(screen.getByText("9")).toBeInTheDocument();
    const download = screen.getByRole("link", { name: "Download DockPack" });
    expect(download).toHaveAttribute("href", "/api/dockyards/1/reports/21/dockpack");

    await user.click(screen.getByRole("tab", { name: "Executive" }));
    expect(await screen.findByText("# RedDock executive report", { exact: false })).toBeInTheDocument();
    await user.click(screen.getByRole("tab", { name: "Manifest" }));
    const table = await screen.findByRole("table");
    expect(within(table).getByText("Discovery #3")).toBeInTheDocument();
    expect(within(table).getByText("evidence/discovery/3/normalized/result.json")).toBeInTheDocument();
  });

  it("creates a complete report set with an empty request", async () => {
    const create = stubReports([]);
    const user = userEvent.setup();
    render(<Reports dockyards={[dockyard]} onError={vi.fn()} />);
    await screen.findByText("No report snapshot has been generated for this Dockyard.");
    await user.click(screen.getByRole("button", { name: "Generate report set" }));
    await waitFor(() => expect(create).toHaveBeenCalledWith({}));
    expect(await screen.findByText("Report #21")).toBeInTheDocument();
  });

  it("clears stale report state when the Dockyard changes", async () => {
    stubReports();
    const user = userEvent.setup();
    render(<Reports dockyards={[dockyard, { ...dockyard, id: 2, name: "Other" }]} onError={vi.fn()} />);
    await screen.findByText("Report #21");
    await user.selectOptions(screen.getByLabelText("Dockyard"), "2");
    await waitFor(() => expect(screen.queryByText("Report #21")).not.toBeInTheDocument());
  });
});
