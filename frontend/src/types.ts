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

export type AdapterProfile = {
  name: string;
  title: string;
  description: string;
  risk: "standard" | "lab";
  capability: string | null;
  requires_lab_authorization: boolean;
  single_host_only: boolean;
};

export type Adapter = {
  name: string;
  version: string;
  title: string;
  description: string;
  profiles: AdapterProfile[];
  target_kinds: string[];
};

export type Detector = {
  id: string;
  version: string;
  title: string;
  description: string;
  consumes: string[];
};

export type LabCapability = {
  id: string;
  title: string;
  description: string;
  risk: "lab";
  single_host_only: boolean;
};

export type LabStatus = {
  deployment_enabled: boolean;
  acknowledgement: string;
  max_authorization_minutes: number;
  capabilities: LabCapability[];
};

export type LabAuthorization = {
  id: number;
  dockyard_id: number;
  capability: string;
  status: "active" | "expired" | "revoked" | "superseded" | "denied";
  acknowledgement: string;
  note: string;
  created_at: string;
  expires_at: string;
  revoked_at: string | null;
};

export type LabAuditEvent = {
  id: number;
  dockyard_id: number;
  capability: string;
  action: "authorize" | "request" | "execute" | "revoke";
  decision: "allowed" | "denied";
  reason: string;
  authorization_id: number | null;
  discovery_run_id: number | null;
  created_at: string;
};

export type DetectorOutcome = {
  id: string;
  version: string;
  status: string;
  findings: number;
  error: string | null;
};

export type DetectionRun = {
  id: number;
  dockyard_id: number;
  status: string;
  detectors: DetectorOutcome[] | null;
  enrichment: {
    id: string;
    version: string | null;
    available: boolean;
    warning: string | null;
  } | null;
  asset_count: number;
  service_count: number;
  observation_count: number;
  finding_count: number;
  new_finding_count: number;
  resolved_finding_count: number;
  error: string | null;
  evidence_path: string | null;
  metadata_sha256: string | null;
  result_sha256: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};

export type CorrelationRun = {
  id: number;
  dockyard_id: number;
  status: string;
  asset_count: number;
  finding_count: number;
  asset_relationship_count: number;
  finding_correlation_count: number;
  framework_mapping_count: number;
  error: string | null;
  evidence_path: string | null;
  metadata_sha256: string | null;
  result_sha256: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
};

export type RedPathNode = {
  id: string;
  kind: "asset" | "finding";
  label: string;
  subtitle: string;
  status: string | null;
  severity: string | null;
};

export type RedPathEdge = {
  id: string;
  source: string;
  target: string;
  kind: "asset_relationship" | "finding_subject" | "finding_correlation";
  label: string;
  confidence: string;
  basis: string;
  evidence_sha256: string[];
};

export type FrameworkMapping = {
  id: number;
  finding_id: number;
  framework: string;
  external_id: string;
  title: string;
  basis: string;
  mapping_version: string;
  evidence_sha256: string;
};

export type RedPathGraph = {
  run: CorrelationRun | null;
  nodes: RedPathNode[];
  edges: RedPathEdge[];
  mappings: FrameworkMapping[];
};

/** Enrichment, not proof: a catalogue matched a reported product and version. */
export type CveReference = {
  cve_id: string;
  source: string;
  source_version: string | null;
  match_type: string;
  matched_product: string;
  matched_version: string;
  url: string | null;
};

export type Finding = {
  id: number;
  fingerprint: string;
  detector: string;
  detector_version: string;
  rule_id: string;
  title: string;
  category: string;
  severity: string;
  confidence: string;
  status: string;
  status_note: string | null;
  asset_id: number | null;
  service_id: number | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  first_detection_run_id: number | null;
  last_detection_run_id: number | null;
  cve_references: CveReference[];
  asset_label: string | null;
  service_endpoint: string | null;
  evidence_count: number;
};

/** One observation that supported a finding, with the hash that proves it. */
export type FindingEvidence = {
  id: number;
  observation_id: number;
  discovery_run_id: number | null;
  detection_run_id: number | null;
  evidence_record_id: number | null;
  summary: string;
  created_at: string;
  evidence_path: string | null;
  sha256: string | null;
};

/** A separately approved, bounded recheck of one finding's recorded HTTP origin. */
export type ValidationRun = {
  id: number;
  dockyard_id: number;
  finding_id: number;
  validator: string;
  validator_version: string;
  target: string;
  status: string;
  decision: string;
  decision_reason: string;
  approval_note: string | null;
  outcome: string | null;
  confidence: string | null;
  summary: string | null;
  detail: Record<string, unknown> | null;
  error: string | null;
  evidence_path: string | null;
  metadata_sha256: string | null;
  result_sha256: string | null;
  manifest_sha256: string | null;
  created_at: string;
  approved_at: string | null;
  started_at: string | null;
  completed_at: string | null;
};

export type FindingDetail = Finding & {
  description: string;
  remediation: string | null;
  detail: Record<string, unknown> | null;
  evidence: FindingEvidence[];
  validations: ValidationRun[];
};

export type IntelligenceProvider = {
  available: boolean;
  provider: string | null;
  model: string | null;
  destination: string | null;
  sends_data_external: boolean;
  reason: string | null;
};

export type IntelligencePacket = {
  schema: string;
  purpose: string;
  constraints: string[];
  dockyard_id: number;
  correlation_run_id: number;
  findings: Array<{
    id: number;
    rule_id: string;
    title: string;
    description: string;
    remediation: string | null;
    severity: string;
    confidence: string;
    status: string;
    asset_id: number | null;
    service_id: number | null;
    evidence_sha256: string[];
  }>;
};

export type IntelligenceAdvice = {
  summary: string;
  priorities: Array<{
    finding_id: number;
    priority: string;
    rationale: string;
    remediation_steps: string[];
    evidence_sha256: string[];
  }>;
  limitations: string[];
};

export type IntelligenceRun = {
  id: number;
  dockyard_id: number;
  correlation_run_id: number;
  status: string;
  provider: string;
  model: string;
  destination: string;
  sends_data_external: boolean;
  prompt_version: string;
  approval_note: string | null;
  input: IntelligencePacket;
  output: IntelligenceAdvice | null;
  input_sha256: string;
  result_sha256: string | null;
  metadata_sha256: string | null;
  evidence_path: string | null;
  error: string | null;
  created_at: string;
  approved_at: string | null;
  started_at: string | null;
  completed_at: string | null;
};

export type ReportCounts = {
  assets: number;
  services: number;
  observations: number;
  findings: number;
  findings_by_severity: Record<string, number>;
  findings_by_status: Record<string, number>;
  validations: number;
  evidence_files: number;
  evidence_bytes: number;
};

export type ReportRun = {
  id: number;
  dockyard_id: number;
  status: string;
  report_schema: string;
  snapshot_sha256: string | null;
  technical_sha256: string | null;
  executive_sha256: string | null;
  manifest_sha256: string | null;
  dockpack_sha256: string | null;
  dockpack_bytes: number;
  evidence_path: string | null;
  source_counts: ReportCounts | null;
  error: string | null;
  created_at: string;
  completed_at: string | null;
};

export type EvidenceManifestFile = {
  source: string;
  run_id: number;
  source_path: string;
  archive_path: string;
  media_type: string;
  bytes: number;
  sha256: string;
  truncated: boolean;
};

export type EvidenceManifest = {
  schema: string;
  algorithm: "sha256";
  files: EvidenceManifestFile[];
  file_count: number;
  total_bytes: number;
};
