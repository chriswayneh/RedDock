import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";
import { Lab } from "./Lab";

const acknowledgement =
  "I confirm this Dockyard is an isolated lab that I am authorized to test.";
const dockyard = {
  id: 7,
  name: "Isolated range",
  description: "Loopback only",
  status: "draft",
  created_at: "2026-09-05T06:00:00Z",
  updated_at: "2026-09-05T06:00:00Z",
};
const capability = {
  id: "discovery.nmap.extended-service",
  title: "Extended TCP service discovery",
  description: "Fixed, bounded lab discovery.",
  risk: "lab" as const,
  single_host_only: true,
};

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function stubLabApi(enabled = true) {
  let authorizations: object[] = [];
  let audit: object[] = [];
  const calls: { authorize: unknown[]; revoke: unknown[] } = { authorize: [], revoke: [] };
  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
      const path = new URL(String(input), "http://localhost").pathname;
      const json = (body: unknown, status = 200) =>
        Promise.resolve(new Response(JSON.stringify(body), { status }));
      if (path.endsWith("/lab/status")) {
        return json({
          deployment_enabled: enabled,
          acknowledgement,
          max_authorization_minutes: 120,
          capabilities: [capability],
        });
      }
      if (path.endsWith("/lab/audit")) return json(audit);
      if (path.endsWith("/lab/authorizations") && init?.method === "POST") {
        const body = JSON.parse(String(init.body));
        calls.authorize.push(body);
        const created = {
          id: 3,
          dockyard_id: 7,
          capability: capability.id,
          status: "active",
          acknowledgement,
          note: body.note,
          created_at: "2026-09-05T06:00:00Z",
          expires_at: "2026-09-05T07:00:00Z",
          revoked_at: null,
        };
        authorizations = [created];
        audit = [
          {
            id: 4,
            dockyard_id: 7,
            capability: capability.id,
            action: "authorize",
            decision: "allowed",
            reason: "Explicit authorization",
            authorization_id: 3,
            discovery_run_id: null,
            created_at: "2026-09-05T06:00:00Z",
          },
        ];
        return json(created, 201);
      }
      if (path.endsWith("/revoke") && init?.method === "POST") {
        calls.revoke.push(JSON.parse(String(init.body)));
        const revoked = { ...authorizations[0], status: "revoked" };
        authorizations = [revoked];
        return json(revoked);
      }
      if (path.endsWith("/lab/authorizations")) return json(authorizations);
      return json({ detail: "Unexpected request" }, 500);
    }),
  );
  return calls;
}

it("keeps authorization disabled when the deployment gate is closed", async () => {
  stubLabApi(false);
  render(<Lab dockyards={[dockyard]} onError={vi.fn()} />);
  expect(await screen.findByText("DEPLOYMENT DISABLED")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Create temporary authorization" })).toBeDisabled();
  expect(screen.getByText(/The API cannot change this setting/)).toBeInTheDocument();
});

it("sends the exact acknowledgement and can revoke the resulting grant", async () => {
  const calls = stubLabApi();
  const user = userEvent.setup();
  render(<Lab dockyards={[dockyard]} onError={vi.fn()} />);

  await screen.findByText("DEPLOYMENT ENABLED");
  await user.type(screen.getByLabelText("Approval note"), "Authorized loopback range");
  await user.click(screen.getByLabelText(acknowledgement));
  await user.click(screen.getByRole("button", { name: "Create temporary authorization" }));

  await screen.findByText("Authorization active");
  expect(calls.authorize).toEqual([
    {
      capability: capability.id,
      acknowledgement,
      note: "Authorized loopback range",
      duration_minutes: 60,
    },
  ]);
  expect(screen.getByText("Explicit authorization")).toBeInTheDocument();

  await user.click(screen.getByRole("button", { name: "Revoke now" }));
  await waitFor(() => expect(calls.revoke).toEqual([{}]));
  expect(await screen.findByText("Authorize temporarily")).toBeInTheDocument();
});
