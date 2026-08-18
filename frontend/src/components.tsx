import type { ReactNode } from "react";
import { humanize } from "./format";
import type { ScopeEvaluation } from "./types";

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="empty-state">
      <span>◇</span>
      <p>{message}</p>
    </div>
  );
}

export function Planned({ page }: { page: string }) {
  return (
    <section className="planned-state">
      <span>◇</span>
      <p className="eyebrow">PLANNED CAPABILITY</p>
      <h2>{page} is not available yet.</h2>
      <p>
        RedDock does not simulate security results. This module will arrive in a later roadmap phase
        with evidence and policy controls.
      </p>
    </section>
  );
}

export function Metric({
  label,
  value,
  tone,
  note,
}: {
  label: string;
  value: string;
  tone?: "success" | "warning";
  note?: string;
}) {
  return (
    <article className="metric">
      <p>{label}</p>
      <strong className={tone ? `tone-${tone}` : ""}>{value}</strong>
      {note && <small>{note}</small>}
    </article>
  );
}

export function StatusPill({ status }: { status: string }) {
  const tone =
    status === "completed" ? "ok" : status === "denied" || status === "failed" ? "stop" : "busy";
  return <span className={`status-pill ${tone}`}>{humanize(status)}</span>;
}

/** DockGuard's answer, stated plainly with the reason it gave. */
export function DecisionPanel({ evaluation }: { evaluation: ScopeEvaluation }) {
  return (
    <div className={evaluation.allowed ? "decision allowed" : "decision denied"} role="status">
      <strong>{evaluation.allowed ? "ALLOWED" : "DENIED"}</strong>
      <p>{evaluation.reason}</p>
      <dl>
        <div>
          <dt>Normalized target</dt>
          <dd>{evaluation.normalized_target ?? evaluation.target}</dd>
        </div>
        <div>
          <dt>Decision</dt>
          <dd>{humanize(evaluation.decision)}</dd>
        </div>
        {evaluation.matched_rule && (
          <div>
            <dt>Matched scope entry</dt>
            <dd>{evaluation.matched_rule}</dd>
          </div>
        )}
        {evaluation.resolved_addresses.length > 0 && (
          <div>
            <dt>Resolved addresses</dt>
            <dd>{evaluation.resolved_addresses.join(", ")}</dd>
          </div>
        )}
        {evaluation.excluded_addresses.length > 0 && (
          <div>
            <dt>Excluded from the scan</dt>
            <dd>{evaluation.excluded_addresses.join(", ")}</dd>
          </div>
        )}
      </dl>
    </div>
  );
}

export function DataTable({ headers, children }: { headers: string[]; children: ReactNode }) {
  return (
    <div className="table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            {headers.map((header) => (
              <th key={header}>{header}</th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

export function DockyardPicker({
  dockyards,
  selected,
  onSelect,
}: {
  dockyards: { id: number; name: string }[];
  selected: number | null;
  onSelect: (id: number) => void;
}) {
  return (
    <label className="picker">
      Dockyard
      <select value={selected ?? ""} onChange={(event) => onSelect(Number(event.target.value))}>
        {dockyards.map((dockyard) => (
          <option key={dockyard.id} value={dockyard.id}>
            {dockyard.name}
          </option>
        ))}
      </select>
    </label>
  );
}
