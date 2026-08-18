import type {
  Adapter,
  Asset,
  Dockyard,
  DiscoveryRun,
  EvidenceRecord,
  Health,
  Observation,
  ScopeEntry,
  ScopeEvaluation,
  ServiceRow,
  Version,
} from "./types";

async function detailOf(response: Response): Promise<string> {
  try {
    const body = await response.json();
    if (typeof body?.detail === "string") return body.detail;
  } catch {
    /* the API did not return a JSON problem detail */
  }
  return `Request failed with ${response.status}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`/api${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  if (!response.ok) {
    throw new Error(await detailOf(response));
  }
  if (response.status === 204) {
    return undefined as T;
  }
  return response.json() as Promise<T>;
}

function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body: JSON.stringify(body) });
}

/** A discovery request that DockGuard denied is a result, not a transport error. */
export type DiscoveryOutcome =
  | { accepted: boolean; run: DiscoveryRun }
  | { accepted: false; error: string };

export const api = {
  health: () => request<Health>("/health"),
  version: () => request<Version>("/version"),
  adapters: () => request<Adapter[]>("/adapters"),

  dockyards: () => request<Dockyard[]>("/dockyards"),
  dockyard: (id: number) => request<Dockyard>(`/dockyards/${id}`),
  createDockyard: (name: string, description?: string) =>
    post<Dockyard>("/dockyards", { name, description: description || null }),

  scope: (id: number) => request<ScopeEntry[]>(`/dockyards/${id}/scope`),
  addScope: (id: number, rule: "include" | "exclude", target: string) =>
    post<ScopeEntry>(`/dockyards/${id}/scope`, { rule, target }),
  removeScope: (id: number, entryId: number) =>
    request<void>(`/dockyards/${id}/scope/${entryId}`, { method: "DELETE" }),
  evaluate: (id: number, target: string, resolve = false) =>
    post<ScopeEvaluation>(`/dockyards/${id}/scope/evaluate`, { target, resolve }),

  assets: (id: number) => request<Asset[]>(`/dockyards/${id}/assets`),
  services: (id: number) => request<ServiceRow[]>(`/dockyards/${id}/services`),
  observations: (id: number) => request<Observation[]>(`/dockyards/${id}/observations`),
  evidence: (id: number) => request<EvidenceRecord[]>(`/dockyards/${id}/evidence`),

  discoveries: (id: number) => request<DiscoveryRun[]>(`/dockyards/${id}/discoveries`),
  discovery: (id: number, runId: number) =>
    request<DiscoveryRun>(`/dockyards/${id}/discoveries/${runId}`),

  async startDiscovery(
    id: number,
    target: string,
    adapter: string,
    profile: string,
  ): Promise<DiscoveryOutcome> {
    const response = await fetch(`/api/dockyards/${id}/discoveries`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, adapter, profile }),
    });
    if (response.status === 202 || response.status === 403) {
      return { accepted: response.status === 202, run: (await response.json()) as DiscoveryRun };
    }
    return { accepted: false, error: await detailOf(response) };
  },
};
