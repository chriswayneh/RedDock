import { useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { DataTable, EmptyState, StatusPill } from "./components";
import { formatCompact, formatDate, humanize } from "./format";
import type { DetectionRun, Detector, Finding, FindingDetail, ValidationRun } from "./types";

const SEVERITIES = ["critical", "high", "medium", "low", "informational"] as const;
const STATUSES = ["open", "resolved", "suppressed", "accepted"] as const;
/** An operator states a decision; whether an issue is still there is not one. */
const DECISIONS = ["open", "suppressed", "accepted"] as const;
const VALIDATION_RULES = new Set([
  "plaintext-http",
  "hsts-not-set",
  "content-type-options-not-nosniff",
  "content-security-policy-not-set",
  "frame-protection-not-set",
]);

export function SeverityTag({ severity }: { severity: string }) {
  return <span className={`severity ${severity}`}>{severity}</span>;
}

export function FindingsPanel({
  dockyardId,
  refreshKey,
  onError,
}: {
  dockyardId: number;
  refreshKey: number;
  onError: (message: string | null) => void;
}) {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState<FindingDetail | null>(null);

  const load = useCallback(async () => {
    try {
      setFindings(await api.findings(dockyardId, { severity, status }));
      onError(null);
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not load findings.");
    }
  }, [dockyardId, severity, status, onError]);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  // A finding belongs to one Dockyard. Changing workspace must not leave the
  // previous one's finding open beside another workspace's list.
  useEffect(() => {
    setSelected(null);
  }, [dockyardId]);

  async function open(finding: Finding) {
    try {
      setSelected(await api.finding(dockyardId, finding.id));
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not load this finding.");
    }
  }

  async function decide(finding: FindingDetail, next: string) {
    try {
      setSelected(await api.updateFinding(dockyardId, finding.id, next));
      await load();
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not update this finding.");
    }
  }

  return (
    <div className="split-layout findings-layout">
      <section className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">DETECTION RESULTS</p>
            <h2>Findings</h2>
          </div>
          <span className="count-chip">{findings.length}</span>
        </div>
        <p className="hint">
          A finding is a normalized conclusion a named detector drew from recorded observations,
          and it carries the observations that support it. An observation on its own is still only
          a record of what was seen.
        </p>
        <div className="filter-row">
          <label>
            Severity
            <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
              <option value="">All</option>
              {SEVERITIES.map((item) => (
                <option key={item} value={item}>
                  {humanize(item)}
                </option>
              ))}
            </select>
          </label>
          <label>
            Status
            <select value={status} onChange={(event) => setStatus(event.target.value)}>
              <option value="">All</option>
              {STATUSES.map((item) => (
                <option key={item} value={item}>
                  {humanize(item)}
                </option>
              ))}
            </select>
          </label>
        </div>
        {findings.length ? (
          <DataTable
            headers={[
              "Finding",
              "Severity",
              "Confidence",
              "Status",
              "Affected",
              "Detector",
              "Seen",
            ]}
          >
            {findings.map((finding) => (
              <tr
                key={finding.id}
                className={selected?.id === finding.id ? "finding-row selected" : "finding-row"}
                onClick={() => void open(finding)}
              >
                <td>
                  <button className="link-button" type="button">
                    {finding.title}
                  </button>
                </td>
                <td>
                  <SeverityTag severity={finding.severity} />
                </td>
                <td>{humanize(finding.confidence)}</td>
                <td>
                  <StatusPill status={finding.status} />
                </td>
                <td>
                  {finding.asset_label ?? "—"}
                  {finding.service_endpoint && (
                    <div>
                      <code>{finding.service_endpoint}</code>
                    </div>
                  )}
                </td>
                <td>
                  <code>{finding.detector}</code>
                </td>
                <td className="seen-cell">
                  {formatCompact(finding.first_seen)}
                  <small>last seen {formatCompact(finding.last_seen)}</small>
                </td>
              </tr>
            ))}
          </DataTable>
        ) : (
          <EmptyState message="No findings match this view. Run detection after discovery to produce them." />
        )}
      </section>

      <section className="panel detail-panel">
        <p className="eyebrow">FINDING</p>
        {selected ? (
          <FindingDetailView finding={selected} onDecide={decide} />
        ) : (
          <>
            <h2>Select a finding</h2>
            <EmptyState message="Open a finding to read what was concluded and the evidence behind it." />
          </>
        )}
      </section>
    </div>
  );
}

function FindingDetailView({
  finding,
  onDecide,
}: {
  finding: FindingDetail;
  onDecide: (finding: FindingDetail, status: string) => Promise<void>;
}) {
  return (
    <>
      <h2>{finding.title}</h2>
      <div className="tag-row">
        <SeverityTag severity={finding.severity} />
        <span className="status-pill">{humanize(finding.confidence)} confidence</span>
        <StatusPill status={finding.status} />
      </div>
      <p className="detail-copy">{finding.description}</p>
      {finding.remediation && (
        <>
          <p className="eyebrow">REMEDIATION</p>
          <p className="detail-copy">{finding.remediation}</p>
        </>
      )}
      <dl>
        <div>
          <dt>Detector</dt>
          <dd>
            <code>
              {finding.detector} {finding.detector_version}
            </code>{" "}
            · rule <code>{finding.rule_id}</code>
          </dd>
        </div>
        <div>
          <dt>Affected</dt>
          <dd>
            {finding.asset_label ?? "—"}
            {finding.service_endpoint ? ` · ${finding.service_endpoint}` : ""}
          </dd>
        </div>
        <div>
          <dt>First seen</dt>
          <dd>{formatDate(finding.first_seen)}</dd>
        </div>
        <div>
          <dt>Last seen</dt>
          <dd>{formatDate(finding.last_seen)}</dd>
        </div>
        {finding.resolved_at && (
          <div>
            <dt>Resolved</dt>
            <dd>{formatDate(finding.resolved_at)}</dd>
          </div>
        )}
        <div>
          <dt>Fingerprint</dt>
          <dd>
            <code className="hash">{finding.fingerprint.slice(0, 24)}…</code>
          </dd>
        </div>
        {finding.status_note && (
          <div>
            <dt>Operator note</dt>
            <dd>{finding.status_note}</dd>
          </div>
        )}
      </dl>

      {finding.cve_references.length > 0 && (
        <div className="scope-group">
          <h3>CVE references</h3>
          <p className="hint">
            A catalogue associated these identifiers with the exact product and version this
            service reported. That is an association, not a test result.
          </p>
          <ul className="scope-list">
            {finding.cve_references.map((reference) => (
              <li key={reference.cve_id}>
                <code>{reference.cve_id}</code>
                <small>
                  {reference.source} · {humanize(reference.match_type)}
                </small>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="scope-group">
        <h3>Evidence</h3>
        {finding.evidence.length ? (
          <ul className="scope-list evidence-list">
            {finding.evidence.map((item) => (
              <li key={item.id}>
                <span className="row-main">
                  <strong>{item.summary}</strong>
                  <small>
                    Observation #{item.observation_id}
                    {item.discovery_run_id ? ` · discovery run #${item.discovery_run_id}` : ""}
                    {item.detection_run_id ? ` · detection run #${item.detection_run_id}` : ""}
                  </small>
                  {item.sha256 && (
                    <small>
                      <code className="hash">
                        {item.evidence_path} · {item.sha256.slice(0, 16)}…
                      </code>
                    </small>
                  )}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="hint">None recorded.</p>
        )}
      </div>

      <div className="scope-group">
        <h3>Decision</h3>
        <div className="button-row">
          {DECISIONS.map((decision) => (
            <button
              key={decision}
              className="secondary-button"
              type="button"
              disabled={finding.status === decision}
              onClick={() => void onDecide(finding, decision)}
            >
              {humanize(decision)}
            </button>
          ))}
        </div>
        <p className="hint">
          A finding is never deleted. RedDock resolves one that a later run no longer reproduces;
          suppressing or accepting one records your decision and keeps its history.
        </p>
      </div>
    </>
  );
}

/**
 * Phase 3 intentionally offers one small validation profile instead of a
 * general-purpose testing surface. Requesting a run stores intent; approving
 * it immediately rechecks DockGuard and makes the fixed HTTP-origin probe.
 */
export function ValidationPanel({
  dockyardId,
  findings,
  runs,
  onChanged,
  onError,
}: {
  dockyardId: number;
  findings: Finding[];
  runs: ValidationRun[];
  onChanged: () => Promise<void>;
  onError: (message: string | null) => void;
}) {
  const [busy, setBusy] = useState<number | null>(null);
  const [notes, setNotes] = useState<Record<number, string>>({});
  const eligible = findings.filter(
    (finding) => finding.detector === "http.security_headers" && VALIDATION_RULES.has(finding.rule_id),
  );
  const pending = runs.filter((run) => run.status === "pending_approval");

  async function requestRun(finding: Finding) {
    setBusy(finding.id);
    try {
      await api.requestValidation(dockyardId, finding.id);
      onError(null);
      await onChanged();
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not request validation.");
    } finally {
      setBusy(null);
    }
  }

  async function approve(runId: number) {
    const note = (notes[runId] ?? "").trim();
    if (note.length < 3) {
      onError("An approval note of at least three characters is required.");
      return;
    }
    setBusy(runId);
    try {
      await api.approveValidation(dockyardId, runId, note);
      onError(null);
      await onChanged();
    } catch (error) {
      // A 403 can mean DockGuard revoked scope between request and approval;
      // reload so that retained denial becomes visible in the audit trail.
      onError(error instanceof Error ? error.message : "Could not approve validation.");
      await onChanged();
    } finally {
      setBusy(null);
    }
  }

  return (
    <>
      <div className="split-layout">
        <section className="panel">
          <p className="eyebrow">VALIDATION CANDIDATES</p>
          <h2>Request a bounded recheck</h2>
          <p className="hint">
            Phase 3 can only recheck an open HTTP security-header finding at its recorded origin.
            Requesting a run makes no network contact. A separate, documented approval is required
            before RedDock re-evaluates DockGuard and sends its fixed safe HTTP probe.
          </p>
          {eligible.length ? (
            <DataTable headers={["Finding", "Affected origin", "Rule", "Action"]}>
              {eligible.map((finding) => (
                <tr key={finding.id}>
                  <td>{finding.title}</td>
                  <td>
                    <code>{finding.asset_label ?? "—"}</code>
                  </td>
                  <td>
                    <code>{finding.rule_id}</code>
                  </td>
                  <td>
                    <button
                      className="secondary-button"
                      type="button"
                      disabled={finding.status !== "open" || busy === finding.id}
                      onClick={() => void requestRun(finding)}
                    >
                      {busy === finding.id ? "Requesting…" : "Request validation"}
                    </button>
                  </td>
                </tr>
              ))}
            </DataTable>
          ) : (
            <EmptyState message="No open HTTP security-header findings are eligible for this Phase 3 profile." />
          )}
        </section>
        <section className="panel detail-panel">
          <p className="eyebrow">BOUNDARIES</p>
          <h2>What this does not do</h2>
          <ul className="scope-list">
            <li>No arbitrary URLs, commands, payloads, credentials, or browser automation.</li>
            <li>No redirects, request bodies, cookies, or authentication.</li>
            <li>Scope is checked again at approval time, immediately before contact.</li>
            <li>Raw, normalized, metadata, and hash manifest artifacts form one evidence package.</li>
          </ul>
        </section>
      </div>

      <section className="panel detection-runs">
        <p className="eyebrow">APPROVAL GATE</p>
        <h2>Pending validation requests</h2>
        {pending.length ? (
          <DataTable headers={["Run", "Finding", "Target", "Approval note", "Action"]}>
            {pending.map((run) => (
              <tr key={run.id}>
                <td>#{run.id}</td>
                <td>Finding #{run.finding_id}</td>
                <td>
                  <code>{run.target}</code>
                </td>
                <td>
                  <input
                    aria-label={`Approval note for validation ${run.id}`}
                    value={notes[run.id] ?? ""}
                    maxLength={500}
                    placeholder="Why this recheck is authorized"
                    onChange={(event) =>
                      setNotes((current) => ({ ...current, [run.id]: event.target.value }))
                    }
                  />
                </td>
                <td>
                  <button
                    className="primary-button"
                    type="button"
                    disabled={busy === run.id}
                    onClick={() => void approve(run.id)}
                  >
                    {busy === run.id ? "Approving…" : "Approve and recheck"}
                  </button>
                </td>
              </tr>
            ))}
          </DataTable>
        ) : (
          <EmptyState message="No validation requests await approval." />
        )}
      </section>

      <section className="panel detection-runs">
        <p className="eyebrow">VALIDATION AUDIT TRAIL</p>
        <h2>Validation runs</h2>
        {runs.length ? (
          <DataTable headers={["Run", "Finding", "Status", "Outcome", "DockGuard", "Evidence", "Completed"]}>
            {runs.map((run) => (
              <tr key={run.id}>
                <td>#{run.id}</td>
                <td>#{run.finding_id}</td>
                <td>
                  <StatusPill status={run.status} />
                  {run.error && <div className="row-error">{run.error}</div>}
                </td>
                <td>
                  {run.outcome ? `${humanize(run.outcome)} · ${humanize(run.confidence ?? "")}` : "—"}
                  {run.summary && <div>{run.summary}</div>}
                </td>
                <td title={run.decision_reason}>{humanize(run.decision)}</td>
                <td>
                  {run.manifest_sha256 ? (
                    <code className="hash">{run.manifest_sha256.slice(0, 16)}…</code>
                  ) : (
                    "—"
                  )}
                </td>
                <td>{formatDate(run.completed_at ?? run.created_at)}</td>
              </tr>
            ))}
          </DataTable>
        ) : (
          <EmptyState message="No validation history yet." />
        )}
      </section>
    </>
  );
}

export function DetectionPanel({
  dockyardId,
  detectors,
  runs,
  observationCount,
  onRan,
  onError,
}: {
  dockyardId: number;
  detectors: Detector[];
  runs: DetectionRun[];
  observationCount: number;
  onRan: () => Promise<void>;
  onError: (message: string | null) => void;
}) {
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    try {
      await api.startDetection(dockyardId);
      onError(null);
      await onRan();
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not run detection.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="split-layout">
        <section className="panel">
          <p className="eyebrow">DETECTION</p>
          <h2>Run detection</h2>
          <p className="hint">
            Detection reads what this Dockyard already recorded and contacts nothing. It takes no
            target and no options, so every registered detector runs over the same stored state
            and each finding it produces names the observations behind it.
          </p>
          <div className="button-row detection-actions">
            <button
              className="primary-button"
              type="button"
              onClick={() => void run()}
              disabled={busy || observationCount === 0}
            >
              {busy ? "Running…" : "Run detection"}
            </button>
          </div>
          {observationCount === 0 && (
            <p className="hint">
              There is nothing to detect against yet. Run a scoped discovery first.
            </p>
          )}
        </section>
        <section className="panel detail-panel">
          <p className="eyebrow">REGISTERED DETECTORS</p>
          <h2>{detectors.length}</h2>
          <ul className="scope-list">
            {detectors.map((detector) => (
              <li key={detector.id}>
                <span className="row-main">
                  <strong>{detector.title}</strong>
                  <small>
                    <code>{detector.id}</code> {detector.version}
                  </small>
                  <small>{detector.description}</small>
                  <small>
                    {detector.source === "declarative" ? "Reviewed manifest" : "RedDock built-in"}
                    {" · "}{detector.execution}
                    {detector.manifest_sha256 && (
                      <> · SHA-256 <code className="hash">{detector.manifest_sha256.slice(0, 16)}…</code></>
                    )}
                  </small>
                </span>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <section className="panel detection-runs">
        <div className="section-heading">
          <div>
            <p className="eyebrow">AUDIT TRAIL</p>
            <h2>Detection runs</h2>
          </div>
        </div>
        {runs.length ? (
          <DataTable
            headers={["Run", "Status", "Detectors", "Read", "Findings", "Evidence", "Completed"]}
          >
            {runs.map((detection) => (
              <tr key={detection.id}>
                <td>#{detection.id}</td>
                <td>
                  <StatusPill status={detection.status} />
                </td>
                <td>
                  {(detection.detectors ?? []).map((entry) => (
                    <div key={entry.id}>
                      <code>{entry.id}</code> {entry.status === "failed" ? "failed" : ""}
                      {entry.error && <div className="row-error">{entry.error}</div>}
                    </div>
                  ))}
                </td>
                <td>
                  {detection.asset_count} assets · {detection.observation_count} observations
                </td>
                <td>
                  {detection.finding_count} produced · {detection.new_finding_count} new ·{" "}
                  {detection.resolved_finding_count} resolved
                </td>
                <td>
                  {detection.result_sha256 ? (
                    <code className="hash">{detection.result_sha256.slice(0, 16)}…</code>
                  ) : (
                    "—"
                  )}
                </td>
                <td>{formatDate(detection.completed_at ?? detection.created_at)}</td>
              </tr>
            ))}
          </DataTable>
        ) : (
          <EmptyState message="No detection runs yet." />
        )}
      </section>
    </>
  );
}
