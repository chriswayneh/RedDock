import type {
  Adapter,
  DashboardSummary,
  ListPage,
  Settings,
  Asset,
  CorrelationRun,
  DetectionRun,
  Detector,
  Dockyard,
  DiscoveryRun,
  EvidenceRecord,
  Finding,
  FindingDetail,
  Health,
  IntelligenceProvider,
  IntelligenceRun,
  LabAuditEvent,
  LabAuthorization,
  LabStatus,
  Observation,
  RedPathGraph,
  ReportRun,
  EvidenceManifest,
  ScopeEntry,
  ScopeEvaluation,
  ServiceRow,
  ValidationRun,
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

async function requestText(path: string): Promise<string> {
  const response = await fetch(`/api${path}`);
  if (!response.ok) throw new Error(await detailOf(response));
  return response.text();
}

async function requestPage<T>(path: string): Promise<ListPage<T>> {
  const response = await fetch(`/api${path}`);
  if (!response.ok) throw new Error(await detailOf(response));
  const count = response.headers.get("X-Total-Count");
  const total = count !== null && /^\d+$/.test(count) && Number.isSafeInteger(Number(count)) ? Number(count) : null;
  return { items: await response.json() as T[], total };
}

function post<T>(path: string, body: unknown): Promise<T> {
  return request<T>(path, { method: "POST", body: JSON.stringify(body) });
}

/** Only the filters the API accepts, and only when they are set. */
function query(filters: Record<string, string | undefined>): string {
  const parameters = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value) parameters.set(key, value);
  }
  const rendered = parameters.toString();
  return rendered ? `?${rendered}` : "";
}

function dockyardPage<T>(id: number, resource: string, offset = 0): Promise<ListPage<T>> {
  return requestPage<T>(`/dockyards/${id}/${resource}${query({ offset: String(offset) })}`);
}

/** A discovery request that DockGuard denied is a result, not a transport error. */
export type DiscoveryOutcome =
  | { accepted: boolean; run: DiscoveryRun }
  | { accepted: false; error: string };

export const api = {
  dashboard: () => request<DashboardSummary>("/dashboard"),
  settings: () => request<Settings>("/settings"),
  assetPage: (id: number, offset = 0) => dockyardPage<Asset>(id, "assets", offset),
  servicePage: (id: number, offset = 0) => dockyardPage<ServiceRow>(id, "services", offset),
  observationPage: (id: number, offset = 0) => dockyardPage<Observation>(id, "observations", offset),
  discoveryPage: (id: number, offset = 0) => dockyardPage<DiscoveryRun>(id, "discoveries", offset),
  evidencePage: (id: number, offset = 0) => dockyardPage<EvidenceRecord>(id, "evidence", offset),
  detectionPage: (id: number, offset = 0) => dockyardPage<DetectionRun>(id, "detections", offset),
  correlationPage: (id: number, offset = 0) => dockyardPage<CorrelationRun>(id, "correlations", offset),
  intelligencePage: (id: number, offset = 0) => dockyardPage<IntelligenceRun>(id, "intelligence", offset),
  reportPage: (id: number, offset = 0) => dockyardPage<ReportRun>(id, "reports", offset),
  validationPage: (id: number, offset = 0) => dockyardPage<ValidationRun>(id, "validations", offset),
  labAuthorizationPage: (id: number, offset = 0) =>
    dockyardPage<LabAuthorization>(id, "lab/authorizations", offset),
  labAuditPage: (id: number, offset = 0) => dockyardPage<LabAuditEvent>(id, "lab/audit", offset),
  findingPage: (id: number, filters: { severity?: string; status?: string } = {}, offset = 0) =>
    requestPage<Finding>(`/dockyards/${id}/findings${query({ ...filters, offset: String(offset) })}`),
  health: () => request<Health>("/health"),
  version: () => request<Version>("/version"),
  adapters: () => request<Adapter[]>("/adapters"),
  labStatus: () => request<LabStatus>("/lab/status"),
  authorizeLab: (
    id: number,
    capability: string,
    acknowledgement: string,
    note: string,
    durationMinutes: number,
  ) =>
    post<LabAuthorization>(`/dockyards/${id}/lab/authorizations`, {
      capability,
      acknowledgement,
      note,
      duration_minutes: durationMinutes,
    }),
  revokeLab: (id: number, authorizationId: number) =>
    post<LabAuthorization>(`/dockyards/${id}/lab/authorizations/${authorizationId}/revoke`, {}),

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

  detectors: () => request<Detector[]>("/detectors"),
  /** Detection takes no target and no options, so the request carries nothing. */
  startDetection: (id: number) => post<DetectionRun>(`/dockyards/${id}/detections`, {}),

  /** Correlation reads stored state only and accepts no selectors or weights. */
  startCorrelation: (id: number) => post<CorrelationRun>(`/dockyards/${id}/correlations`, {}),
  redpath: (id: number) => request<RedPathGraph>(`/dockyards/${id}/redpath`),

  intelligenceProvider: () => request<IntelligenceProvider>("/intelligence/provider"),
  /** Packet creation contacts nothing and accepts no prompt, target, or provider option. */
  createIntelligence: (id: number) =>
    post<IntelligenceRun>(`/dockyards/${id}/intelligence`, {}),
  approveIntelligence: (id: number, runId: number, note: string) =>
    post<IntelligenceRun>(`/dockyards/${id}/intelligence/${runId}/approve`, { note }),

  /** Reporting snapshots complete retained state and accepts no path or selector. */
  createReport: (id: number) => post<ReportRun>(`/dockyards/${id}/reports`, {}),
  technicalReport: (id: number, runId: number) =>
    requestText(`/dockyards/${id}/reports/${runId}/technical`),
  executiveReport: (id: number, runId: number) =>
    requestText(`/dockyards/${id}/reports/${runId}/executive`),
  reportManifest: (id: number, runId: number) =>
    request<EvidenceManifest>(`/dockyards/${id}/reports/${runId}/manifest`),
  dockpackUrl: (id: number, runId: number) =>
    `/api/dockyards/${id}/reports/${runId}/dockpack`,

  finding: (id: number, findingId: number) =>
    request<FindingDetail>(`/dockyards/${id}/findings/${findingId}`),
  updateFinding: (id: number, findingId: number, status: string, note?: string) =>
    request<FindingDetail>(`/dockyards/${id}/findings/${findingId}`, {
      method: "PATCH",
      body: JSON.stringify({ status, note: note ?? null }),
    }),

  /** This records a request only; a separate approval makes the bounded recheck. */
  requestValidation: (id: number, findingId: number) =>
    post<ValidationRun>(`/dockyards/${id}/findings/${findingId}/validations`, {}),
  approveValidation: (id: number, runId: number, note: string) =>
    post<ValidationRun>(`/dockyards/${id}/validations/${runId}/approve`, { note }),

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
