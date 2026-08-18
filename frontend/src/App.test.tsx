import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { App } from "./App";

const dockyard = { id: 1, name: "Lab review", description: "Approved lab", status: "draft", created_at: "2026-08-18T12:00:00Z", updated_at: "2026-08-18T12:00:00Z" };

describe("RedDock application", () => {
  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
  });

  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/health")) return Promise.resolve(new Response(JSON.stringify({ status: "healthy", service: "reddock-core" })));
      if (url.endsWith("/version")) return Promise.resolve(new Response(JSON.stringify({ name: "RedDock", version: "0.1.0" })));
      if (url.endsWith("/dockyards") && init?.method === "POST") return Promise.resolve(new Response(JSON.stringify({ ...dockyard, id: 2, name: JSON.parse(String(init.body)).name }), { status: 201 }));
      return Promise.resolve(new Response(JSON.stringify([dockyard])));
    }));
  });

  it("shows healthy status and recent Dockyards", async () => {
    render(<App />);
    expect(await screen.findByText("Healthy")).toBeInTheDocument();
    expect(screen.getByText("Lab review")).toBeInTheDocument();
  });

  it("creates a Dockyard from the Phase 0 form", async () => {
    const user = userEvent.setup();
    render(<App />);
    await screen.findByText("Lab review");
    await user.click(screen.getAllByRole("button", { name: "Dockyards" })[0]);
    await user.type(screen.getByLabelText("Name"), "New engagement");
    await user.click(screen.getByRole("button", { name: "Create Dockyard" }));
    await waitFor(() => expect(screen.getAllByText("New engagement").length).toBeGreaterThan(0));
  });
});
