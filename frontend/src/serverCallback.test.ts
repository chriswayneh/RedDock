import { afterEach, expect, it, jest as vi } from "@jest/globals";
import { completeServerCallback } from "./serverCallback";
import { ServerSessionClient, ServerSessionError } from "./serverSession";

const STATE = "S".repeat(43);
const CODE = "private-code";
const CSRF = "C".repeat(43);
const OTHER = "D".repeat(43);
const EXPIRES = new Date(Date.now() + 60 * 60 * 1000).toISOString();
const SESSION = {
  role: "operator", permissions: ["dockyard:read"], expires_at: EXPIRES, csrf_token: CSRF,
};
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });

const pages: ServerSessionClient[] = [];
function page(): ServerSessionClient {
  const client = new ServerSessionClient();
  pages.push(client);
  return client;
}
afterEach(() => {
  vi.restoreAllMocks();
  pages.splice(0).forEach((client) => client.release());
  window.localStorage.clear();
  window.sessionStorage.clear();
});

it("recovers only after a same-origin callback with state and code and keeps the proof private", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json({ csrf_token: CSRF, expires_at: EXPIRES }))
    .mockResolvedValueOnce(json(SESSION))
    .mockResolvedValueOnce(json({ id: 1 }));
  const client = page();
  const session = await completeServerCallback(client, { state: STATE, code: CODE });
  expect(session).toEqual({ role: "operator", permissions: ["dockyard:read"], expiresAt: EXPIRES });
  expect(client.status).toBe("authenticated");
  expect(JSON.stringify(session)).not.toContain(CSRF);
  expect(window.localStorage.length).toBe(0);
  const callback = new URL(String(fetchMock.mock.calls[0][0]));
  expect(callback.origin).toBe(window.location.origin);
  expect(callback.pathname).toBe("/api/auth/callback");
  expect(callback.searchParams.get("state")).toBe(STATE);
  expect(callback.searchParams.get("code")).toBe(CODE);
  expect([...callback.searchParams.keys()]).toEqual(["state", "code"]);
  expect(fetchMock.mock.calls[0][1]).toMatchObject({
    method: "GET", credentials: "same-origin", mode: "same-origin",
    cache: "no-store", redirect: "error",
  });
  expect(String(fetchMock.mock.calls[1][0])).toBe("/api/auth/session");
  await client.request("/api/dockyards", { method: "POST", body: {} });
  expect(new Headers(fetchMock.mock.calls[2][1]?.headers).get("X-RedDock-CSRF")).toBe(CSRF);
});

it("does not send a callback unless state and code are the only fields", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch");
  const client = page();
  await expect(completeServerCallback(client, { state: STATE, code: CODE, next: "https://evil.example" }))
    .rejects.toBeInstanceOf(ServerSessionError);
  await expect(completeServerCallback(client, { state: "short", code: CODE }))
    .rejects.toBeInstanceOf(ServerSessionError);
  await expect(completeServerCallback(client, { state: STATE, code: "line\nbreak" }))
    .rejects.toBeInstanceOf(ServerSessionError);
  expect(fetchMock).not.toHaveBeenCalled();
  expect(client.status).toBe("unknown");
});

it("preserves an existing page session when the callback is denied", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json(SESSION))
    .mockResolvedValueOnce(new Response("private denial", { status: 401 }));
  const client = page();
  await client.recover();
  await expect(completeServerCallback(client, { state: STATE, code: CODE }))
    .rejects.toMatchObject({ status: 401, message: "Sign in to continue." });
  expect(client.status).toBe("authenticated");
  expect(client.session?.role).toBe("operator");
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it("forgets the page when a successful callback body is not the exact proof", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json(SESSION))
    .mockResolvedValueOnce(json({ csrf_token: CSRF, expires_at: EXPIRES, role: "owner" }));
  const client = page();
  await client.recover();
  await expect(completeServerCallback(client, { state: STATE, code: CODE }))
    .rejects.toBeInstanceOf(ServerSessionError);
  expect(client.status).toBe("unknown");
  expect(client.session).toBeNull();
});

it("drops a recovered session whose proof does not match the callback", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json({ csrf_token: OTHER, expires_at: EXPIRES }))
    .mockResolvedValueOnce(json(SESSION));
  const client = page();
  await expect(completeServerCallback(client, { state: STATE, code: CODE }))
    .rejects.toBeInstanceOf(ServerSessionError);
  expect(client.status).toBe("unknown");
  expect(client.session).toBeNull();
  await expect(client.request("/api/dockyards", { method: "POST", body: {} }))
    .rejects.toMatchObject({ status: 401 });
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it("does not retry the authorization code when recovery fails", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json({ csrf_token: CSRF, expires_at: EXPIRES }))
    .mockRejectedValueOnce(new Error("private transport"));
  const client = page();
  await expect(completeServerCallback(client, { state: STATE, code: CODE }))
    .rejects.toThrow("Server request unavailable.");
  expect(fetchMock).toHaveBeenCalledTimes(2);
  expect(String(fetchMock.mock.calls[1][0])).not.toContain(CODE);
});

it("is not started by importing the local application", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch");
  await import("./App");
  expect(fetchMock).not.toHaveBeenCalled();
  expect(window.localStorage.length).toBe(0);
});
