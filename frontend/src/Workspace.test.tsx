import { act, cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "./api";
import { Workspace } from "./Workspace";
import type { WorkspaceTab } from "./routes";
import type { DiscoveryRun, ValidationRun } from "./types";

const dockyard = { id: 1, name: "Test", description: "", status: "draft", created_at: "2026-09-01T00:00:00Z", updated_at: "2026-09-01T00:00:00Z" };
const onError = vi.fn();
const onBack = vi.fn();
const lists = ["scope", "assets", "services", "observations", "discoveries", "detections", "findings", "validations"] as const;
const validation: ValidationRun = {
  id: 1, dockyard_id: 1, finding_id: 1, validator: "http", validator_version: "1",
  target: "http://127.0.0.1:8080", status: "running", decision: "allowed", decision_reason: "Test",
  approval_note: "Test", outcome: null, confidence: null, summary: null, detail: null,
  error: null, evidence_path: null, metadata_sha256: null, result_sha256: null, manifest_sha256: null,
  created_at: "2026-09-01T00:00:00Z", approved_at: null, started_at: null, completed_at: null,
};

async function show(tab: WorkspaceTab) {
  await act(async () => { render(<Workspace dockyard={dockyard} adapters={[]} detectors={[]} initialTab={tab} onBack={onBack} onError={onError} />); });
}

describe("workspace request ownership", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    for (const name of lists) vi.spyOn(api, name).mockResolvedValue([]);
    vi.spyOn(api, "findingPage").mockResolvedValue({ items: [], total: 0 });
  });
  afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.useRealTimers(); });

  it.each<[WorkspaceTab, string[]]>([
    ["Scope", ["scope"]], ["Discovery", ["scope", "discoveries"]],
    ["Assets", ["assets"]], ["Services", ["services"]],
    ["Observations", ["observations"]], ["Detection", ["observations", "detections"]],
    ["Validation", ["findings", "validations"]], ["Runs", ["discoveries"]], ["Findings", []],
  ])("loads only the %s tab's dependencies", async (tab, expected) => {
    await show(tab);
    for (const name of lists) expect(api[name]).toHaveBeenCalledTimes(expected.includes(name) ? 1 : 0);
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    for (const name of lists) expect(api[name]).toHaveBeenCalledTimes(expected.includes(name) ? 1 : 0);
  });

  it("polls running validation every two seconds, then stops at completion", async () => {
    vi.mocked(api.validations).mockResolvedValueOnce([validation]).mockResolvedValue([{ ...validation, status: "completed" }]);
    await show("Validation");
    await act(async () => { await vi.advanceTimersByTimeAsync(1999); });
    expect(api.validations).toHaveBeenCalledTimes(1);
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(api.validations).toHaveBeenCalledTimes(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    expect(api.validations).toHaveBeenCalledTimes(2);
  });

  it("polls active discovery and stops after completion", async () => {
    const run: DiscoveryRun = {
      id: 1, dockyard_id: 1, adapter: "http", adapter_version: "1", profile: "http_probe",
      requested_target: "http://127.0.0.1:8080", normalized_target: "http://127.0.0.1:8080",
      status: "running", decision: "allowed", decision_reason: "Test", error: null,
      asset_count: 0, service_count: 0, observation_count: 0, evidence_path: null,
      created_at: "2026-09-01T00:00:00Z", started_at: null, completed_at: null,
    };
    vi.mocked(api.discoveries).mockResolvedValueOnce([run]).mockResolvedValue([{ ...run, status: "completed" }]);
    await show("Runs");
    await act(async () => { await vi.advanceTimersByTimeAsync(2000); });
    expect(api.discoveries).toHaveBeenCalledTimes(2);
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    expect(api.discoveries).toHaveBeenCalledTimes(2);
  });

  it("does not poll a pending human approval or after unmount", async () => {
    vi.mocked(api.validations).mockResolvedValue([{ ...validation, status: "pending" }]);
    await show("Validation");
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    expect(api.validations).toHaveBeenCalledTimes(1);
    cleanup();
    vi.mocked(api.validations).mockResolvedValue([validation]);
    await show("Validation");
    cleanup();
    await act(async () => { await vi.advanceTimersByTimeAsync(6000); });
    expect(api.validations).toHaveBeenCalledTimes(2);
  });
});
