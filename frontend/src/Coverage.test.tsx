import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { api } from "./api";
import { Coverage } from "./Coverage";
import type { AssessmentCoverage } from "./types";

const coverage: AssessmentCoverage = {
  checks: [{ id: "http_headers", title: "HTTP security headers", status: "collected", observation_count: 1, reviewed_observation_count: 0 }],
  latest_detection_run_id: null, latest_detection_status: null,
  unsupported: ["UDP discovery"], limitation: "Checked does not mean secure.",
};
afterEach(() => { cleanup(); jest.restoreAllMocks(); });

describe("assessment coverage", () => {
  it("distinguishes recorded observations from reviewed checks", async () => {
    jest.spyOn(api, "coverage").mockResolvedValue(coverage);
    render(<Coverage dockyardId={1} />);
    expect(await screen.findByText("Detection needed")).toBeInTheDocument();
    expect(screen.getByText("0 reviewed / 1 collected observations")).toBeInTheDocument();
    expect(screen.getByText("Checked does not mean secure.")).toBeInTheDocument();
  });
  it("ignores a response from a previously selected workspace", async () => {
    let resolveOld: (value: AssessmentCoverage) => void = () => {};
    jest.spyOn(api, "coverage").mockReturnValueOnce(new Promise((resolve) => { resolveOld = resolve; }))
      .mockResolvedValueOnce({ ...coverage, checks: [] });
    const view = render(<Coverage dockyardId={1} />);
    view.rerender(<Coverage dockyardId={2} />);
    await screen.findByText("Checked does not mean secure.");
    resolveOld(coverage);
    await waitFor(() => expect(screen.queryByText("HTTP security headers")).not.toBeInTheDocument());
  });
  it("shows an error instead of inventing empty coverage", async () => {
    jest.spyOn(api, "coverage").mockRejectedValue(new Error("Unavailable"));
    render(<Coverage dockyardId={1} />);
    expect(await screen.findByText("Coverage could not be loaded. Refresh to try again.")).toBeInTheDocument();
    expect(screen.queryByText("Not checked")).not.toBeInTheDocument();
  });
});
