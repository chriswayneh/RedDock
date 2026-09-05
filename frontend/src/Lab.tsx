import { FormEvent, useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { DataTable, DockyardPicker, EmptyState, StatusPill } from "./components";
import { formatDate, humanize } from "./format";
import type { Dockyard, LabAuditEvent, LabAuthorization, LabStatus } from "./types";

export function Lab({
  dockyards,
  onError,
}: {
  dockyards: Dockyard[];
  onError: (message: string | null) => void;
}) {
  const [selectedId, setSelectedId] = useState<number | null>(dockyards[0]?.id ?? null);
  const [status, setStatus] = useState<LabStatus | null>(null);
  const [authorizations, setAuthorizations] = useState<LabAuthorization[]>([]);
  const [audit, setAudit] = useState<LabAuditEvent[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (selectedId === null && dockyards[0]) setSelectedId(dockyards[0].id);
    if (selectedId !== null && !dockyards.some((item) => item.id === selectedId)) {
      setSelectedId(dockyards[0]?.id ?? null);
    }
  }, [dockyards, selectedId]);

  const refresh = useCallback(async () => {
    try {
      const nextStatus = await api.labStatus();
      if (selectedId === null) {
        setStatus(nextStatus);
        setAuthorizations([]);
        setAudit([]);
      } else {
        const [nextAuthorizations, nextAudit] = await Promise.all([
          api.labAuthorizations(selectedId),
          api.labAudit(selectedId),
        ]);
        setStatus(nextStatus);
        setAuthorizations(nextAuthorizations);
        setAudit(nextAudit);
      }
      onError(null);
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not load lab policy state.");
    }
  }, [onError, selectedId]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function authorize(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (selectedId === null || !status || !confirmed) return;
    const form = event.currentTarget;
    const data = new FormData(form);
    const note = String(data.get("note") || "").trim();
    const duration = Number(data.get("duration") || 60);
    const capability = status.capabilities[0];
    if (!note || !capability) return;
    setBusy(true);
    try {
      await api.authorizeLab(
        selectedId,
        capability.id,
        status.acknowledgement,
        note,
        duration,
      );
      form.reset();
      setConfirmed(false);
      onError(null);
      await refresh();
    } catch (error) {
      onError(error instanceof Error ? error.message : "Lab authorization was refused.");
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  async function revoke(authorizationId: number) {
    if (selectedId === null) return;
    setBusy(true);
    try {
      await api.revokeLab(selectedId, authorizationId);
      onError(null);
      await refresh();
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not revoke the authorization.");
    } finally {
      setBusy(false);
    }
  }

  const capability = status?.capabilities[0];
  const active = authorizations.find((item) => item.status === "active");

  return (
    <>
      <section className="hero lab-hero">
        <div>
          <p className="eyebrow">SEPARATELY GUARDED CAPABILITY</p>
          <h2>Lab access is explicit, temporary, and auditable.</h2>
          <p>
            DockGuard scope is necessary but never sufficient. The deployment owner must enable lab
            mode, and this Dockyard needs a short-lived authorization that RedDock rechecks when the
            tool is about to run.
          </p>
        </div>
        <span className={status?.deployment_enabled ? "lab-state enabled" : "lab-state disabled"}>
          {status?.deployment_enabled ? "DEPLOYMENT ENABLED" : "DEPLOYMENT DISABLED"}
        </span>
      </section>

      {dockyards.length === 0 ? (
        <section className="panel">
          <EmptyState message="Create a Dockyard and define narrow authorized scope before considering a lab capability." />
        </section>
      ) : (
        <>
          <div className="toolbar">
            <DockyardPicker
              dockyards={dockyards}
              selected={selectedId}
              onSelect={setSelectedId}
            />
          </div>
          <div className="split-layout lab-layout">
            <section className="panel">
              <p className="eyebrow">AVAILABLE LAB PLUGIN</p>
              <h2>{capability?.title ?? "Loading capability…"}</h2>
              <p className="detail-copy">{capability?.description}</p>
              <dl className="lab-facts">
                <div>
                  <dt>Capability ID</dt>
                  <dd><code>{capability?.id}</code></dd>
                </div>
                <div>
                  <dt>Target bound</dt>
                  <dd>{capability?.single_host_only ? "One scoped host" : "Declared by plugin"}</dd>
                </div>
                <div>
                  <dt>Maximum grant</dt>
                  <dd>{status?.max_authorization_minutes ?? "—"} minutes</dd>
                </div>
              </dl>
              {!status?.deployment_enabled && (
                <div className="decision denied">
                  <strong>DEPLOYMENT GATE CLOSED</strong>
                  <p>
                    Start RedDock with <code>REDDOCK_LAB_MODE_ENABLED=true</code> to let an operator
                    request a Dockyard grant. The API cannot change this setting.
                  </p>
                </div>
              )}
            </section>

            <section className="panel">
              <p className="eyebrow">DOCKYARD AUTHORIZATION</p>
              <h2>{active ? "Authorization active" : "Authorize temporarily"}</h2>
              {active ? (
                <div className="lab-active">
                  <StatusPill status={active.status} />
                  <p>{active.note}</p>
                  <small>Expires {formatDate(active.expires_at)}</small>
                  <button
                    className="secondary-button"
                    disabled={busy}
                    onClick={() => void revoke(active.id)}
                  >
                    Revoke now
                  </button>
                </div>
              ) : (
                <form className="dockyard-form" onSubmit={(event) => void authorize(event)}>
                  <label>
                    Approval note
                    <textarea
                      name="note"
                      required
                      minLength={3}
                      maxLength={500}
                      placeholder="Why this isolated lab run is authorized"
                      rows={3}
                    />
                  </label>
                  <label>
                    Authorization window
                    <select name="duration" defaultValue="60">
                      <option value="15">15 minutes</option>
                      <option value="30">30 minutes</option>
                      <option value="60">60 minutes</option>
                      <option value="120">120 minutes</option>
                    </select>
                  </label>
                  <label className="lab-acknowledgement">
                    <input
                      type="checkbox"
                      checked={confirmed}
                      onChange={(event) => setConfirmed(event.target.checked)}
                    />
                    <span>{status?.acknowledgement}</span>
                  </label>
                  <button
                    className="primary-button"
                    disabled={!status?.deployment_enabled || !confirmed || busy}
                  >
                    {busy ? "Authorizing…" : "Create temporary authorization"}
                  </button>
                </form>
              )}
            </section>
          </div>

          <section className="panel lab-history">
            <div className="section-heading">
              <div>
                <p className="eyebrow">LAB POLICY LEDGER</p>
                <h2>Authorization and execution decisions</h2>
              </div>
              <span className="count-chip">{audit.length} EVENTS</span>
            </div>
            {audit.length === 0 ? (
              <EmptyState message="No lab policy decision has been recorded for this Dockyard." />
            ) : (
              <DataTable headers={["Time", "Action", "Decision", "Capability", "Run", "Reason"]}>
                {audit.map((event) => (
                  <tr key={event.id}>
                    <td>{formatDate(event.created_at)}</td>
                    <td>{humanize(event.action)}</td>
                    <td><StatusPill status={event.decision} /></td>
                    <td><code>{event.capability}</code></td>
                    <td>{event.discovery_run_id ? `#${event.discovery_run_id}` : "—"}</td>
                    <td>{event.reason}</td>
                  </tr>
                ))}
              </DataTable>
            )}
          </section>
        </>
      )}
    </>
  );
}
