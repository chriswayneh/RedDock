import { afterEach, expect, it, jest as vi } from "@jest/globals";
import { ServerSessionClient, ServerSessionError, SESSION_TAB_CHANNEL } from "./serverSession";

const CSRF = "C".repeat(43);
const NEXT_CSRF = "D".repeat(43);
const EXPIRES = new Date(Date.now() + 60 * 60 * 1000).toISOString();
const BODY = { role: "operator", permissions: ["dockyard:read", "workflow:run"],
  expires_at: EXPIRES, csrf_token: CSRF };
const json = (value: unknown, status = 200) => new Response(JSON.stringify(value), { status });

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

const pages: ServerSessionClient[] = [];
function page(): ServerSessionClient {
  const client = new ServerSessionClient();
  pages.push(client);
  return client;
}
async function tabsSettled(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
}
afterEach(() => {
  vi.restoreAllMocks();
  pages.splice(0).forEach((client) => client.release());
  window.localStorage.clear();
  window.sessionStorage.clear();
});

it("recovers only through a same-origin no-store request and keeps proofs out of public state", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY));
  const client = page();
  expect(client.status).toBe("unknown");
  const session = await client.recover();
  expect(client.status).toBe("authenticated");
  expect(session).toEqual({ role: "operator", permissions: BODY.permissions, expiresAt: EXPIRES });
  expect(Object.isFrozen(session)).toBe(true);
  expect(Object.isFrozen(session?.permissions)).toBe(true);
  expect(JSON.stringify(client)).not.toContain(CSRF);
  expect(JSON.stringify(session)).not.toContain(CSRF);
  expect(window.localStorage.length).toBe(0);
  expect(window.sessionStorage.length).toBe(0);
  expect(fetchMock).toHaveBeenCalledWith("/api/auth/session", {
    headers: { "X-RedDock-Session": "recover" }, credentials: "same-origin",
    mode: "same-origin", redirect: "error", cache: "no-store",
  });
});

it("shares overlapping recovery and renewal calls", async () => {
  const recovered = deferred<Response>();
  const renewed = deferred<Response>();
  const fetchMock = vi.spyOn(globalThis, "fetch").mockReturnValueOnce(recovered.promise)
    .mockReturnValueOnce(renewed.promise);
  const client = page();
  const first = client.recover();
  expect(client.recover()).toBe(first);
  recovered.resolve(json(BODY));
  await first;
  const renewing = client.renew();
  expect(client.renew()).toBe(renewing);
  renewed.resolve(json({ rotated: true, csrf_token: NEXT_CSRF, expires_at: EXPIRES }));
  await renewing;
  expect(fetchMock).toHaveBeenCalledTimes(2);
});

it("sends the replacement proof on a write queued behind renewal, and none on reads", async () => {
  const renewed = deferred<Response>();
  const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY))
    .mockReturnValueOnce(renewed.promise).mockResolvedValueOnce(json({ id: 1 }))
    .mockResolvedValueOnce(json([]));
  const client = page();
  await client.recover();
  const renewing = client.renew();
  const writing = client.request("/api/dockyards", { method: "POST", body: { name: "Team" } });
  await Promise.resolve();
  expect(fetchMock).toHaveBeenCalledTimes(2);
  renewed.resolve(json({ rotated: true, csrf_token: NEXT_CSRF, expires_at: EXPIRES }));
  await renewing;
  await writing;
  expect(new Headers(fetchMock.mock.calls[2][1]?.headers).get("X-RedDock-CSRF")).toBe(NEXT_CSRF);
  expect(new Headers(fetchMock.mock.calls[2][1]?.headers).has("X-RedDock-Operator-CSRF")).toBe(false);
  await client.request("/api/dockyards");
  expect(new Headers(fetchMock.mock.calls[3][1]?.headers).has("X-RedDock-CSRF")).toBe(false);
});

it("keeps the existing proof when renewal reports no rotation", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY))
    .mockResolvedValueOnce(json({ rotated: false, csrf_token: null, expires_at: EXPIRES }))
    .mockResolvedValueOnce(json({}));
  const client = page();
  await client.recover();
  await client.renew();
  await client.request("/api/dockyards", { method: "POST", body: {} });
  expect(new Headers(fetchMock.mock.calls[2][1]?.headers).get("X-RedDock-CSRF")).toBe(CSRF);
});

it("never retries a rejected or uncertain write", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY))
    .mockRejectedValueOnce(new Error("private transport details"))
    .mockResolvedValueOnce(json({ detail: "private rejection" }, 401));
  const client = page();
  await client.recover();
  await expect(client.request("/api/dockyards", { method: "POST" }))
    .rejects.toThrow("Server request unavailable.");
  expect(fetchMock).toHaveBeenCalledTimes(2);
  await expect(client.request("/api/dockyards", { method: "POST" }))
    .rejects.toMatchObject({ status: 401 });
  expect(fetchMock).toHaveBeenCalledTimes(3);
  expect(client.status).toBe("signed_out");
  expect(client.session).toBeNull();
});

it("does not let a stale read denial clear a newly renewed session", async () => {
  const read = deferred<Response>();
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY)).mockReturnValueOnce(read.promise)
    .mockResolvedValueOnce(json({ rotated: true, csrf_token: NEXT_CSRF, expires_at: EXPIRES }));
  const client = page();
  await client.recover();
  const reading = client.request("/api/dockyards");
  const rejected = expect(reading).rejects.toMatchObject({ status: 401 });
  await client.renew();
  read.resolve(json({}, 401));
  await rejected;
  expect(client.status).toBe("authenticated");
});

it("orders logout after renewal and refuses new requests during logout", async () => {
  const renewed = deferred<Response>();
  const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY))
    .mockReturnValueOnce(renewed.promise).mockResolvedValueOnce(new Response(null, { status: 204 }));
  const client = page();
  await client.recover();
  const renewing = client.renew();
  const logout = client.logout();
  expect(client.logout()).toBe(logout);
  await expect(client.request("/api/dockyards")).rejects.toMatchObject({ status: 401 });
  renewed.resolve(json({ rotated: true, csrf_token: NEXT_CSRF, expires_at: EXPIRES }));
  await renewing;
  await logout;
  expect(new Headers(fetchMock.mock.calls[2][1]?.headers).get("X-RedDock-CSRF")).toBe(NEXT_CSRF);
  expect(client.status).toBe("signed_out");
  expect(client.session).toBeNull();
  await expect(client.request("/api/dockyards", { method: "POST" })).rejects.toMatchObject({ status: 401 });
  expect(fetchMock).toHaveBeenCalledTimes(3);
});

it("discards a read result that completes after confirmed logout", async () => {
  const read = deferred<Response>();
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY)).mockReturnValueOnce(read.promise)
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  const client = page();
  await client.recover();
  const reading = client.request("/api/dockyards");
  const rejected = expect(reading).rejects.toMatchObject({ status: 401 });
  await client.logout();
  read.resolve(json([{ name: "Retained data" }]));
  await rejected;
});

it("does not claim logout succeeded after a transport failure", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY))
    .mockRejectedValueOnce(new Error("private transport"));
  const client = page();
  await client.recover();
  await expect(client.logout()).rejects.toBeInstanceOf(ServerSessionError);
  expect(client.status).toBe("unavailable");
  expect(client.session).toBeNull();
});

it("cannot resurrect a forgotten page from a late recovery response", async () => {
  const response = deferred<Response>();
  vi.spyOn(globalThis, "fetch").mockReturnValueOnce(response.promise).mockResolvedValueOnce(json(BODY));
  const client = page();
  const restoring = client.recover();
  const rejected = expect(restoring).rejects.toBeInstanceOf(ServerSessionError);
  await Promise.resolve();
  client.forget();
  response.resolve(json(BODY));
  await rejected;
  expect(client.status).toBe("unknown");
  expect(client.session).toBeNull();
  expect(await client.recover()).not.toBeNull();
});

it("treats an absent server session as signed out", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json({}, 401));
  const client = page();
  expect(await client.recover()).toBeNull();
  expect(client.status).toBe("signed_out");
});

it.each([
  { ...BODY, role: "superuser" }, { ...BODY, csrf_token: "short" },
  { ...BODY, permissions: ["script<script>"] }, { ...BODY, permissions: ["dockyard:read", "dockyard:read"] },
  { ...BODY, expires_at: "not a date" }, { ...BODY, expires_at: "2000-01-01T00:00:00Z" },
  { ...BODY, permissions: Array(65).fill("dockyard:read") }, null,
])("fails closed for a malformed recovery payload %j", async (body) => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(body));
  const client = page();
  await expect(client.recover()).rejects.toBeInstanceOf(ServerSessionError);
  expect(client.session).toBeNull();
  expect(client.status).toBe("unavailable");
});

it.each([
  { rotated: true, csrf_token: "bad", expires_at: EXPIRES },
  { rotated: false, csrf_token: NEXT_CSRF, expires_at: EXPIRES },
  { rotated: true, csrf_token: NEXT_CSRF, expires_at: "2099-01-01T00:00:00Z" },
  { rotated: "yes", csrf_token: NEXT_CSRF, expires_at: EXPIRES },
])("discards authority when renewal has an invalid contract %j", async (body) => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY)).mockResolvedValueOnce(json(body));
  const client = page();
  await client.recover();
  await expect(client.renew()).rejects.toBeInstanceOf(ServerSessionError);
  expect(client.session).toBeNull();
});

it.each(["https://other.example/api/dockyards", "//other.example/api/dockyards",
  "/api/../private", "/api/\\other.example", "/api/dockyards#secret", "/api/auth/renew",
])("refuses to send proofs outside the business API: %s", async (path) => {
  const fetchMock = vi.spyOn(globalThis, "fetch");
  const client = page();
  await expect(client.request(path, { method: "POST" })).rejects.toBeInstanceOf(ServerSessionError);
  expect(fetchMock).not.toHaveBeenCalled();
});

it("preserves the bounded retry hint without echoing server error content", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(new Response("private database details", {
    status: 429, headers: { "Retry-After": "25" },
  }));
  const client = page();
  await expect(client.recover()).rejects.toMatchObject({ status: 429, retryAfter: 25,
    message: "Too many requests. Try again shortly." });
  expect(client.status).toBe("unavailable");
});

it("retains a valid session after a permission denial", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY)).mockResolvedValueOnce(json({}, 403));
  const client = page();
  await client.recover();
  await expect(client.request("/api/team/members")).rejects.toMatchObject({ status: 403 });
  expect(client.status).toBe("authenticated");
});

function recordNotices(): unknown[] {
  const posted: unknown[] = [];
  const realPost = BroadcastChannel.prototype.postMessage;
  vi.spyOn(BroadcastChannel.prototype, "postMessage").mockImplementation(function (
    this: BroadcastChannel, data: unknown,
  ) {
    posted.push(JSON.parse(JSON.stringify(data)) as unknown);
    return realPost.call(this, data);
  });
  return posted;
}

it("tells other pages that the proof rotated without sharing it or replaying their write", async () => {
  const write = deferred<Response>();
  let sessions = 0;
  let writes = 0;
  const fetchMock = vi.spyOn(globalThis, "fetch").mockImplementation((input: unknown) => {
    const url = String(input);
    if (url === "/api/auth/session") {
      sessions += 1;
      return Promise.resolve(json({ ...BODY, csrf_token: sessions > 2 ? NEXT_CSRF : CSRF }));
    }
    if (url === "/api/auth/renew") {
      return Promise.resolve(json({ rotated: true, csrf_token: NEXT_CSRF, expires_at: EXPIRES }));
    }
    if (url === "/api/dockyards") {
      writes += 1;
      return writes === 1 ? write.promise : Promise.resolve(json({ id: 1 }));
    }
    return Promise.reject(new Error("unexpected " + url));
  });
  const posted = recordNotices();
  const leader = page();
  const peer = page();
  await leader.recover();
  await peer.recover();
  const writing = peer.request("/api/dockyards", { method: "POST", body: { name: "Team" } });
  await Promise.resolve();
  await leader.renew();
  await tabsSettled();
  expect(peer.status).toBe("unknown");
  expect(peer.session).toBeNull();
  expect(leader.status).toBe("authenticated");
  write.resolve(json({ detail: "stale proof" }, 401));
  await expect(writing).rejects.toBeInstanceOf(ServerSessionError);
  expect(fetchMock.mock.calls.filter((call) => call[0] === "/api/dockyards")).toHaveLength(1);
  expect(await peer.recover()).toMatchObject({ role: "operator" });
  expect(peer.status).toBe("authenticated");
  await leader.request("/api/dockyards", { method: "POST", body: {} });
  const dockyardCalls = fetchMock.mock.calls.filter((call) => call[0] === "/api/dockyards");
  expect(dockyardCalls).toHaveLength(2);
  expect(new Headers(dockyardCalls[1][1]?.headers).get("X-RedDock-CSRF")).toBe(NEXT_CSRF);
  expect(posted).toEqual([{ v: 1, kind: "proof_stale" }]);
  expect(JSON.stringify(posted)).not.toContain(CSRF);
  expect(JSON.stringify(posted)).not.toContain(NEXT_CSRF);
  expect(window.localStorage.length).toBe(0);
  expect(window.sessionStorage.length).toBe(0);
});

it("signs other pages out only after logout is confirmed", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json(BODY))
    .mockResolvedValueOnce(json(BODY))
    .mockResolvedValueOnce(new Response(null, { status: 204 }));
  const leader = page();
  const peer = page();
  await leader.recover();
  await peer.recover();
  await leader.logout();
  await tabsSettled();
  expect(peer.status).toBe("signed_out");
  expect(peer.session).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(3);
  await expect(peer.request("/api/dockyards", { method: "POST", body: {} }))
    .rejects.toMatchObject({ status: 401 });
  expect(fetchMock).toHaveBeenCalledTimes(3);
});

it("does not announce a transport failure, a local forget, or a renewal that kept the proof", async () => {
  const posted = recordNotices();
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json(BODY))
    .mockResolvedValueOnce(json(BODY))
    .mockResolvedValueOnce(json({ rotated: false, csrf_token: null, expires_at: EXPIRES }))
    .mockRejectedValueOnce(new Error("private transport"));
  const leader = page();
  const peer = page();
  await leader.recover();
  await peer.recover();
  await leader.renew();
  leader.forget();
  await expect(leader.logout()).rejects.toBeInstanceOf(ServerSessionError);
  await tabsSettled();
  expect(posted).toEqual([]);
  expect(peer.status).toBe("authenticated");
  expect(peer.session).not.toBeNull();
});

it("ignores tab notices that are not the fixed two-field contract", async () => {
  vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(json(BODY));
  const peer = page();
  await peer.recover();
  const channel = new BroadcastChannel(SESSION_TAB_CHANNEL);
  for (const body of [
    { v: 1, kind: "proof_stale", csrf_token: NEXT_CSRF },
    { v: 2, kind: "proof_stale" },
    { v: 1, kind: "logout" },
    { v: 1 },
    "proof_stale",
    null,
  ]) channel.postMessage(body);
  await tabsSettled();
  expect(peer.status).toBe("authenticated");
  expect(peer.session).toMatchObject({ role: "operator" });
  channel.close();
});

it("recovers explicitly after a denied write and does not replay that write", async () => {
  const fetchMock = vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json(BODY))
    .mockResolvedValueOnce(json({ detail: "stale" }, 401))
    .mockResolvedValueOnce(json({ ...BODY, csrf_token: NEXT_CSRF }));
  const client = page();
  await client.recover();
  await expect(client.request("/api/dockyards", { method: "POST", body: { name: "Team" } }))
    .rejects.toMatchObject({ status: 401 });
  expect(client.status).toBe("signed_out");
  expect(await client.recover()).toMatchObject({ role: "operator" });
  expect(fetchMock.mock.calls.map((call) => [call[0], call[1]?.method ?? "GET"])).toEqual([
    ["/api/auth/session", "GET"],
    ["/api/dockyards", "POST"],
    ["/api/auth/session", "GET"],
  ]);
});

it("stops hearing tab notices after release without signing the peer out", async () => {
  vi.spyOn(globalThis, "fetch")
    .mockResolvedValueOnce(json(BODY))
    .mockResolvedValueOnce(json(BODY))
    .mockResolvedValueOnce(json({ rotated: true, csrf_token: NEXT_CSRF, expires_at: EXPIRES }));
  const leader = page();
  const peer = page();
  await leader.recover();
  await peer.recover();
  peer.release();
  await leader.renew();
  await tabsSettled();
  expect(peer.status).toBe("authenticated");
  expect(leader.status).toBe("authenticated");
});

it("is not opened by importing the local application", async () => {
  const names: string[] = [];
  const Real = globalThis.BroadcastChannel;
  const Counting = class extends Real {
    constructor(name: string) {
      super(name);
      names.push(name);
    }
  };
  globalThis.BroadcastChannel = Counting as typeof BroadcastChannel;
  try {
    await import("./App");
  } finally {
    globalThis.BroadcastChannel = Real;
  }
  expect(names).not.toContain(SESSION_TAB_CHANNEL);
});
