/** Dormant callback completion. The local application does not call this. */
import { ServerSession, ServerSessionClient, ServerSessionError } from "./serverSession";

const STATE = /^[A-Za-z0-9_-]{43}$/;
const CODE_LIMIT = 4096;

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ServerSessionError(null);
  return value as Record<string, unknown>;
}

function callbackInput(value: unknown): { state: string; code: string } {
  const body = record(value);
  if (Object.keys(body).length !== 2) throw new ServerSessionError(null);
  const { state, code } = body;
  if (typeof state !== "string" || !STATE.test(state) || typeof code !== "string"
    || code.length < 1 || code.length > CODE_LIMIT
    || [...code].some((character) => {
      const point = character.codePointAt(0) ?? 0;
      return point < 0x20 || point === 0x7f;
    })) {
    throw new ServerSessionError(null);
  }
  return { state, code };
}

function expiry(value: unknown): string {
  if (typeof value !== "string" || value.length > 40 || !Number.isFinite(Date.parse(value))) {
    throw new ServerSessionError(null);
  }
  return value;
}

function issuedProof(value: unknown): { csrf: string; expiresAt: string } {
  const body = record(value);
  if (Object.keys(body).length !== 2 || typeof body.csrf_token !== "string"
    || !/^[A-Za-z0-9_-]{43}$/.test(body.csrf_token)) {
    throw new ServerSessionError(null);
  }
  return { csrf: body.csrf_token, expiresAt: expiry(body.expires_at) };
}

function failed(response: Response): ServerSessionError {
  const retry = response.headers.get("Retry-After");
  return new ServerSessionError(response.status,
    retry && /^\d{1,5}$/.test(retry) ? Math.min(Number(retry), 86400) : null);
}

/**
 * Exchange one same-origin callback for a recovered session.
 * Sends only state and code. A denial leaves any existing page session untouched.
 * The authorization code is never retried.
 */
export async function completeServerCallback(
  client: ServerSessionClient, input: unknown,
): Promise<ServerSession> {
  const { state, code } = callbackInput(input);
  let target: URL;
  try { target = new URL("/api/auth/callback", window.location.origin); }
  catch { throw new ServerSessionError(null); }
  target.searchParams.set("state", state);
  target.searchParams.set("code", code);
  if (target.origin !== window.location.origin || target.pathname !== "/api/auth/callback"
    || target.hash || target.username || target.password) {
    throw new ServerSessionError(null);
  }
  let response: Response;
  try {
    response = await fetch(target, {
      method: "GET", credentials: "same-origin", mode: "same-origin",
      cache: "no-store", redirect: "error",
    });
  } catch {
    throw new ServerSessionError(null);
  }
  if (response.redirected || response.type === "opaqueredirect") throw new ServerSessionError(null);
  if (!response.ok) throw failed(response);
  let proof: { csrf: string; expiresAt: string };
  try { proof = issuedProof(await response.json()); }
  catch (error) {
    client.forget();
    throw error instanceof ServerSessionError ? error : new ServerSessionError(null);
  }
  const session = await client.recover();
  if (!session) throw new ServerSessionError(401);
  client.confirmIssuedProof(proof.csrf, proof.expiresAt);
  return session;
}
