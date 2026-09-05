import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { DataTable, DockyardPicker, EmptyState, StatusPill } from "./components";
import { formatDate, humanize } from "./format";
import type { Dockyard, IntelligenceProvider, IntelligenceRun } from "./types";

export function Intelligence({
  dockyards,
  onError,
}: {
  dockyards: Dockyard[];
  onError: (message: string | null) => void;
}) {
  const [selected, setSelected] = useState<number | null>(null);
  const [provider, setProvider] = useState<IntelligenceProvider | null>(null);
  const [runs, setRuns] = useState<IntelligenceRun[]>([]);
  const [notes, setNotes] = useState<Record<number, string>>({});
  const [reviewedPackets, setReviewedPackets] = useState<Record<number, string>>({});
  const [busy, setBusy] = useState<number | "create" | null>(null);
  const refreshSequence = useRef(0);

  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current;
    const selectedDockyard = selected;
    const [capability, currentRuns] = await Promise.all([
      api.intelligenceProvider(),
      selectedDockyard === null ? Promise.resolve([]) : api.intelligenceRuns(selectedDockyard),
    ]);
    if (sequence !== refreshSequence.current) return;
    setProvider(capability);
    setRuns(currentRuns);
  }, [selected]);

  function selectDockyard(dockyardId: number) {
    refreshSequence.current += 1;
    setRuns([]);
    setNotes({});
    setReviewedPackets({});
    setSelected(dockyardId);
  }

  useEffect(() => {
    if (selected === null && dockyards.length) setSelected(dockyards[0].id);
  }, [dockyards, selected]);

  useEffect(() => {
    refresh().catch((problem) =>
      onError(problem instanceof Error ? problem.message : "Could not load intelligence."),
    );
  }, [refresh, onError]);

  async function create() {
    if (selected === null) return;
    setBusy("create");
    try {
      await api.createIntelligence(selected);
      onError(null);
      await refresh();
    } catch (problem) {
      onError(problem instanceof Error ? problem.message : "Could not create intelligence packet.");
    } finally {
      setBusy(null);
    }
  }

  async function approve(run: IntelligenceRun) {
    if (selected !== run.dockyard_id) {
      onError("This packet does not belong to the selected Dockyard. Reload and review it again.");
      return;
    }
    if (reviewedPackets[run.id] !== run.input_sha256) {
      onError("Open and review this exact packet before approving provider disclosure.");
      return;
    }
    const note = (notes[run.id] ?? "").trim();
    if (note.length < 3) {
      onError("An approval note of at least three characters is required.");
      return;
    }
    setBusy(run.id);
    try {
      await api.approveIntelligence(run.dockyard_id, run.id, note);
      onError(null);
      await refresh();
    } catch (problem) {
      onError(problem instanceof Error ? problem.message : "Could not approve intelligence run.");
      await refresh();
    } finally {
      setBusy(null);
    }
  }

  if (!dockyards.length) {
    return (
      <section className="panel">
        <EmptyState message="Create a Dockyard and evidence-linked findings before using intelligence." />
      </section>
    );
  }

  const pending = runs.filter((run) => run.status === "pending_approval");
  const completed = runs.filter((run) => run.status !== "pending_approval");

  return (
    <>
      <div className="toolbar">
        <DockyardPicker dockyards={dockyards} selected={selected} onSelect={selectDockyard} />
      </div>
      <div className="split-layout">
        <section className="panel">
          <p className="eyebrow">ADVICE-ONLY INTELLIGENCE</p>
          <h2>Create a reviewable packet</h2>
          <p className="hint">
            RedDock copies active, evidence-linked findings from the latest correlation snapshot
            into an immutable packet. Creating it contacts nothing. Review the exact packet before
            separately approving a provider call.
          </p>
          <button
            className="primary-button"
            type="button"
            disabled={!provider?.available || busy !== null}
            onClick={() => void create()}
          >
            {busy === "create" ? "Creating…" : "Create intelligence packet"}
          </button>
          {!provider?.available && <p className="row-error">{provider?.reason}</p>}
        </section>
        <section className="panel detail-panel">
          <p className="eyebrow">PROVIDER BOUNDARY</p>
          <h2>{provider?.available ? provider.model : "Disabled"}</h2>
          {provider?.available ? (
            <dl>
              <div><dt>Provider</dt><dd>{provider.provider}</dd></div>
              <div><dt>Destination</dt><dd><code>{provider.destination}</code></dd></div>
              <div><dt>Data boundary</dt><dd>{provider.sends_data_external ? "External" : "Local"}</dd></div>
            </dl>
          ) : (
            <p className="hint">No credential or destination is accepted through the API.</p>
          )}
        </section>
      </div>

      <section className="panel detection-runs">
        <p className="eyebrow">APPROVAL GATE</p>
        <h2>Packets awaiting review</h2>
        {pending.length ? pending.map((run) => (
          <article className="intelligence-packet" key={run.id}>
            <div className="section-heading">
              <div>
                <strong>Packet #{run.id}</strong>
                <small>Correlation #{run.correlation_run_id} · {run.input.findings.length} findings</small>
              </div>
              <code className="hash">{run.input_sha256.slice(0, 16)}…</code>
            </div>
            <details
              key={`${run.id}:${run.input_sha256}`}
              onToggle={(event) => {
                if (event.currentTarget.open) {
                  setReviewedPackets((current) => ({
                    ...current,
                    [run.id]: run.input_sha256,
                  }));
                }
              }}
            >
              <summary>Review exact provider packet</summary>
              <pre className="packet-preview">{JSON.stringify(run.input, null, 2)}</pre>
            </details>
            <label>
              Approval note
              <input
                aria-label={`Approval note for intelligence ${run.id}`}
                maxLength={500}
                value={notes[run.id] ?? ""}
                placeholder="Why sending this packet is approved"
                onChange={(event) => setNotes((current) => ({ ...current, [run.id]: event.target.value }))}
              />
            </label>
            <button
              className="primary-button"
              type="button"
              disabled={busy !== null || reviewedPackets[run.id] !== run.input_sha256}
              onClick={() => void approve(run)}
            >
              {busy === run.id ? "Analyzing…" : `Approve and send to ${run.model}`}
            </button>
            {reviewedPackets[run.id] !== run.input_sha256 && (
              <p className="hint">Open the exact packet above to enable approval.</p>
            )}
          </article>
        )) : <EmptyState message="No intelligence packets await approval." />}
      </section>

      <section className="panel detection-runs">
        <p className="eyebrow">REVIEWABLE ADVICE</p>
        <h2>Intelligence runs</h2>
        {completed.length ? completed.map((run) => (
          <article className="intelligence-result" key={run.id}>
            <div className="section-heading">
              <div><strong>Run #{run.id}</strong><small>{formatDate(run.completed_at ?? run.created_at)}</small></div>
              <StatusPill status={run.status} />
            </div>
            {run.error && <p className="row-error">{run.error}</p>}
            {run.output && (
              <>
                <p>{run.output.summary}</p>
                <DataTable headers={["Finding", "Priority", "Rationale", "Evidence"]}>
                  {run.output.priorities.map((item) => (
                    <tr key={item.finding_id}>
                      <td>#{item.finding_id}</td>
                      <td>{humanize(item.priority)}</td>
                      <td>{item.rationale}<ul>{item.remediation_steps.map((step) => <li key={step}>{step}</li>)}</ul></td>
                      <td><code className="hash">{item.evidence_sha256[0].slice(0, 16)}…</code></td>
                    </tr>
                  ))}
                </DataTable>
                {run.output.limitations.length > 0 && <p className="hint">Limitations: {run.output.limitations.join(" ")}</p>}
              </>
            )}
          </article>
        )) : <EmptyState message="No intelligence advice has been produced." />}
      </section>
    </>
  );
}
