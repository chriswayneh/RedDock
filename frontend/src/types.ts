export type Dockyard = {
  id: number;
  name: string;
  description: string | null;
  status: string;
  created_at: string;
  updated_at: string;
};

export type Health = { status: string; service: string };
export type Version = { name: string; version: string; phase: string };

export type ScopeEntry = {
  id: number;
  rule: "include" | "exclude";
  kind: string;
  value: string;
  note: string | null;
  created_at: string;
};

export type ScopeEvaluation = {
  decision: string;
  target: string;
  reason: string;
  normalized_target: string | null;
  target_kind: string | null;
  matched_rule: string | null;
  resolved_addresses: string[];
  excluded_addresses: string[];
  allowed: boolean;
};

export type Service = {
  id: number;
  asset_id: number;
  transport: string;
  port: number;
  state: string;
  service_name: string | null;
  product: string | null;
  version: string | null;
  first_seen: string;
  last_seen: string;
};

export type ServiceRow = Service & { asset_label: string };

export type Asset = {
  id: number;
  asset_type: string;
  identity: string;
  display_name: string;
  ip_address: string | null;
  hostname: string | null;
  first_seen: string;
  last_seen: string;
  service_count: number;
};

export type Observation = {
  id: number;
  discovery_run_id: number | null;
  asset_id: number | null;
  service_id: number | null;
  adapter: string;
  observation_type: string;
  summary: string;
  detail: Record<string, unknown> | null;
  confidence: string;
  raw_reference: string | null;
  observed_at: string;
};

export type DiscoveryRun = {
  id: number;
  dockyard_id: number;
  adapter: string;
  adapter_version: string;
  profile: string;
  requested_target: string;
  normalized_target: string | null;
  status: string;
  decision: string;
  decision_reason: string;
  error: string | null;
  asset_count: number;
  service_count: number;
  observation_count: number;
  evidence_path: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};

export type EvidenceRecord = {
  id: number;
  discovery_run_id: number;
  kind: string;
  relative_path: string;
  media_type: string;
  size_bytes: number;
  sha256: string;
  truncated: boolean;
  created_at: string;
};

export type AdapterProfile = { name: string; title: string; description: string };

export type Adapter = {
  name: string;
  version: string;
  title: string;
  description: string;
  profiles: AdapterProfile[];
  target_kinds: string[];
};
