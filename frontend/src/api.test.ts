import { afterEach, expect, it, jest as vi } from "@jest/globals";
import { api } from "./api";

const CSRF = "C".repeat(43);
const CSRF_REPLACEMENT = "D".repeat(43);
const SESSION_ID = "S".repeat(43);
const SESSION_ID_REPLACEMENT = "T".repeat(43);
const STORAGE_KEY = "reddock.operator.browser-session.v1";

afterEach(() => {
  window.localStorage.clear();
  vi.restoreAllMocks();
});

it("stores only the derived CSRF proof and sends it on mutations", async () => {
  const fetchMock = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ session_id: SESSION_ID, csrf_token: CSRF })),
    )
    .mockResolvedValueOnce(new Response(JSON.stringify({ id: 1 })));

  await api.unlockOperator("M".repeat(43));
  await api.createDockyard("Review");

  expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "null")).toEqual({
    sessionId: SESSION_ID,
    csrfToken: CSRF,
  });
  const unlockHeaders = new Headers(fetchMock.mock.calls[0][1]?.headers);
  const mutationHeaders = new Headers(fetchMock.mock.calls[1][1]?.headers);
  expect(unlockHeaders.get("X-RedDock-Operator-CSRF")).toBeNull();
  expect(mutationHeaders.get("X-RedDock-Operator-CSRF")).toBe(CSRF);
  expect(window.localStorage.getItem(STORAGE_KEY)).not.toContain("M".repeat(43));
});

it("sends the derived proof on the custom discovery request path", async () => {
  window.localStorage.setItem(
    STORAGE_KEY,
    JSON.stringify({ sessionId: SESSION_ID, csrfToken: CSRF }),
  );
  const fetchMock = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(new Response(JSON.stringify({ id: 1 }), { status: 202 }));

  await api.startDiscovery(1, "127.0.0.1", "nmap", "host_discovery");

  const headers = new Headers(fetchMock.mock.calls[0][1]?.headers);
  expect(headers.get("X-RedDock-Operator-CSRF")).toBe(CSRF);
});

it("requires a matching origin-scoped proof before treating a cookie session as unlocked", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
    new Response(
      JSON.stringify({ available: true, unlocked: true, session_id: SESSION_ID }),
    ),
  );

  await expect(api.operatorStatus()).resolves.toEqual({
    available: true,
    unlocked: false,
    session_id: SESSION_ID,
  });
});

it("shares the newest browser session safely across tabs", async () => {
  const fetchMock = vi
    .spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(
      new Response(JSON.stringify({ session_id: SESSION_ID, csrf_token: CSRF })),
    )
    .mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          session_id: SESSION_ID_REPLACEMENT,
          csrf_token: CSRF_REPLACEMENT,
        }),
      ),
    )
    .mockResolvedValueOnce(new Response(JSON.stringify({ id: 1 })));

  await api.unlockOperator("M".repeat(43));
  await api.unlockOperator("M".repeat(43));
  await api.createDockyard("Shared tab state");

  const mutationHeaders = new Headers(fetchMock.mock.calls[2][1]?.headers);
  expect(mutationHeaders.get("X-RedDock-Operator-CSRF")).toBe(CSRF_REPLACEMENT);
  expect(JSON.parse(window.localStorage.getItem(STORAGE_KEY) ?? "null")).toEqual({
    sessionId: SESSION_ID_REPLACEMENT,
    csrfToken: CSRF_REPLACEMENT,
  });
});
