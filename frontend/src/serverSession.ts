/** Dormant server transport. The local application does not instantiate this client.
 *  Other same-origin pages hear only a fixed rotation or confirmed-logout notice.
 *  Notices carry no CSRF proof, role, or identifier. A peer rotation drops this
 *  page's in-memory proof; the caller must recover explicitly, and a denied
 *  write is never replayed. */
export const SESSION_TAB_CHANNEL = "reddock-auth-tab-v1";
export type ServerRole = "owner" | "admin" | "operator" | "auditor" | "viewer";
export type ServerSession = Readonly<{
  role: ServerRole;
  permissions: readonly string[];
  expiresAt: string;
}>;
export type SessionStatus = "unknown" | "authenticated" | "signed_out" | "unavailable";
type Operation = { method?: "GET" | "HEAD" | "POST" | "PATCH" | "PUT" | "DELETE"; body?: unknown };

const ROLES = new Set<ServerRole>(["owner", "admin", "operator", "auditor", "viewer"]);
const PROOF = /^[A-Za-z0-9_-]{43}$/;
const SAFE = new Set(["GET", "HEAD"]);

export class ServerSessionError extends Error {
  constructor(public readonly status: number | null, public readonly retryAfter: number | null = null) {
    super(status === 401 ? "Sign in to continue." : status === 403 ? "Permission denied."
      : status === 429 ? "Too many requests. Try again shortly." : "Server request unavailable.");
    this.name = "ServerSessionError";
  }
}

function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ServerSessionError(null);
  return value as Record<string, unknown>;
}

function expiry(value: unknown): string {
  if (typeof value !== "string" || value.length > 40 || !Number.isFinite(Date.parse(value))) {
    throw new ServerSessionError(null);
  }
  return value;
}

function proof(value: unknown): string {
  if (typeof value !== "string" || !PROOF.test(value)) throw new ServerSessionError(null);
  return value;
}

function recovered(value: unknown): { session: ServerSession; csrf: string } {
  const body = object(value);
  if (!ROLES.has(body.role as ServerRole) || !Array.isArray(body.permissions)
    || body.permissions.length > 64 || body.permissions.some((item) => (
      typeof item !== "string" || !/^[a-z][a-z_:]{0,63}$/.test(item)
    )) || new Set(body.permissions).size !== body.permissions.length) {
    throw new ServerSessionError(null);
  }
  return {
    session: Object.freeze({ role: body.role as ServerRole,
      permissions: Object.freeze([...body.permissions] as string[]), expiresAt: expiry(body.expires_at) }),
    csrf: proof(body.csrf_token),
  };
}

function failure(response: Response): ServerSessionError {
  const retry = response.headers.get("Retry-After");
  return new ServerSessionError(response.status,
    retry && /^\d{1,5}$/.test(retry) ? Math.min(Number(retry), 86400) : null);
}

function tabNotice(value: unknown): "proof_stale" | "signed_out" | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const body = value as Record<string, unknown>;
  if (Object.keys(body).length !== 2 || body.v !== 1) return null;
  return body.kind === "proof_stale" || body.kind === "signed_out" ? body.kind : null;
}

export class ServerSessionClient {
  #session: ServerSession | null = null;
  #csrf: string | null = null;
  #status: SessionStatus = "unknown";
  #epoch = 0;
  #revision = 0;
  #queue: Promise<void> = Promise.resolve();
  #recovering: Promise<ServerSession | null> | null = null;
  #renewing: Promise<ServerSession> | null = null;
  #loggingOut: Promise<void> | null = null;
  #channel: BroadcastChannel | null = null;

  constructor() {
    try {
      const channel = new BroadcastChannel(SESSION_TAB_CHANNEL);
      channel.onmessage = (event: MessageEvent) => this.#onNotice(event.data);
      this.#channel = channel;
    } catch {
      // Without this browser API, a page can still recover explicitly after denial.
      this.#channel = null;
    }
  }

  get session(): ServerSession | null { return this.#session; }
  get status(): SessionStatus { return this.#status; }

  /** Discard this page's state; this does not claim to revoke the server cookie. */
  forget(): void {
    this.#epoch += 1;
    this.#recovering = null;
    this.#renewing = null;
    this.#loggingOut = null;
    this.#clear("unknown");
  }

  /** Stop listening. This does not revoke the server session or notify other pages. */
  release(): void {
    const channel = this.#channel;
    this.#channel = null;
    if (!channel) return;
    channel.onmessage = null;
    try { channel.close(); } catch { /* already closed */ }
  }

  #onNotice(value: unknown): void {
    const kind = tabNotice(value);
    if (!kind) return;
    this.#epoch += 1;
    this.#recovering = null;
    this.#renewing = null;
    this.#loggingOut = null;
    this.#clear(kind === "signed_out" ? "signed_out" : "unknown");
  }

  #publish(kind: "proof_stale" | "signed_out"): void {
    try { this.#channel?.postMessage({ v: 1, kind }); }
    catch { /* a closed channel must not undo a completed server action */ }
  }

  #clear(status: SessionStatus): void {
    this.#session = null;
    this.#csrf = null;
    this.#status = status;
    this.#revision += 1;
  }

  #require(): { session: ServerSession; csrf: string } {
    if (!this.#session || !this.#csrf) throw new ServerSessionError(401);
    if (Date.parse(this.#session.expiresAt) <= Date.now()) {
      this.#clear("signed_out");
      throw new ServerSessionError(401);
    }
    return { session: this.#session, csrf: this.#csrf };
  }

  #checkEpoch(epoch: number): void {
    if (epoch !== this.#epoch) throw new ServerSessionError(null);
  }

  #enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const pending = this.#queue.then(operation);
    this.#queue = pending.then(() => undefined, () => undefined);
    return pending;
  }

  async #fetch(path: string, init: RequestInit): Promise<Response> {
    try {
      return await fetch(path, { ...init, credentials: "same-origin", mode: "same-origin",
        cache: "no-store", redirect: "error" });
    } catch {
      throw new ServerSessionError(null);
    }
  }

  recover(): Promise<ServerSession | null> {
    if (this.#recovering) return this.#recovering;
    const epoch = this.#epoch;
    const pending = this.#enqueue(async () => {
      this.#checkEpoch(epoch);
      try {
        const response = await this.#fetch("/api/auth/session", {
          headers: { "X-RedDock-Session": "recover" },
        }); // The browser supplies Sec-Fetch-Site; scripts never forge it.
        this.#checkEpoch(epoch);
        if (response.status === 401) { this.#clear("signed_out"); return null; }
        if (!response.ok) throw failure(response);
        const next = recovered(await response.json());
        this.#checkEpoch(epoch);
        this.#session = next.session;
        this.#csrf = next.csrf;
        this.#status = "authenticated";
        this.#revision += 1;
        this.#require();
        return this.#session;
      } catch (error) {
        if (epoch === this.#epoch) this.#clear("unavailable");
        throw error instanceof ServerSessionError ? error : new ServerSessionError(null);
      }
    });
    this.#recovering = pending;
    const clear = () => { if (this.#recovering === pending) this.#recovering = null; };
    void pending.then(clear, clear);
    return pending;
  }

  renew(): Promise<ServerSession> {
    if (this.#renewing) return this.#renewing;
    const epoch = this.#epoch;
    const pending = this.#enqueue(async () => {
      this.#checkEpoch(epoch);
      const { session, csrf } = this.#require();
      try {
        const response = await this.#fetch("/api/auth/renew", {
          method: "POST", headers: { "X-RedDock-CSRF": csrf },
        });
        this.#checkEpoch(epoch);
        if (!response.ok) throw failure(response);
        const body = object(await response.json());
        this.#checkEpoch(epoch);
        if (typeof body.rotated !== "boolean" || expiry(body.expires_at) !== session.expiresAt
          || (!body.rotated && body.csrf_token !== null)) throw new ServerSessionError(null);
        this.#csrf = body.rotated ? proof(body.csrf_token) : csrf;
        this.#revision += 1;
        if (body.rotated) this.#publish("proof_stale");
        return session;
      } catch (error) {
        if (epoch === this.#epoch) this.#clear(error instanceof ServerSessionError && error.status === 401
          ? "signed_out" : "unavailable");
        throw error instanceof ServerSessionError ? error : new ServerSessionError(null);
      }
    });
    this.#renewing = pending;
    const clear = () => { if (this.#renewing === pending) this.#renewing = null; };
    void pending.then(clear, clear);
    return pending;
  }

  logout(): Promise<void> {
    if (this.#loggingOut) return this.#loggingOut;
    const epoch = this.#epoch;
    const pending = this.#enqueue(async () => {
      this.#checkEpoch(epoch);
      const { csrf } = this.#require();
      try {
        const response = await this.#fetch("/api/auth/logout", {
          method: "POST", headers: { "X-RedDock-CSRF": csrf },
        });
        this.#checkEpoch(epoch);
        if (response.status !== 204) throw failure(response);
        this.#clear("signed_out");
        this.#publish("signed_out");
      } catch (error) {
        // A network failure cannot confirm that the cookie was revoked.
        if (epoch === this.#epoch) this.#clear("unavailable");
        throw error instanceof ServerSessionError ? error : new ServerSessionError(null);
      }
    });
    this.#loggingOut = pending;
    const clear = () => { if (this.#loggingOut === pending) this.#loggingOut = null; };
    void pending.then(clear, clear);
    return pending;
  }

  /** Send exactly once. A failed write is never replayed after recovery or renewal. */
  request(path: string, operation: Operation = {}): Promise<Response> {
    let target: URL;
    try { target = new URL(path, window.location.origin); }
    catch { return Promise.reject(new ServerSessionError(null)); }
    if (!path.startsWith("/api/") || target.origin !== window.location.origin
      || !target.pathname.startsWith("/api/") || target.pathname.startsWith("/api/auth/")
      || target.hash || path.includes("\\")) {
      return Promise.reject(new ServerSessionError(null));
    }
    if (this.#loggingOut) return Promise.reject(new ServerSessionError(401));
    const epoch = this.#epoch;
    const method = operation.method ?? "GET";
    const send = async () => {
      this.#checkEpoch(epoch);
      const { csrf } = this.#require();
      const revision = this.#revision;
      const headers = new Headers();
      if (!SAFE.has(method)) headers.set("X-RedDock-CSRF", csrf);
      if (operation.body !== undefined) headers.set("Content-Type", "application/json");
      const response = await this.#fetch(path, { method, headers,
        body: operation.body === undefined ? undefined : JSON.stringify(operation.body) });
      this.#checkEpoch(epoch);
      if (!this.#session) throw new ServerSessionError(401);
      if (!response.ok) {
        if (response.status === 401 && revision === this.#revision) this.#clear("signed_out");
        throw failure(response);
      }
      return response;
    };
    return SAFE.has(method) ? send() : this.#enqueue(send);
  }
}
