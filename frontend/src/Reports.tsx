import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "./api";
import { DataTable, DockyardPicker, EmptyState, Metric, StatusPill } from "./components";
import { formatBytes, formatDate, humanize } from "./format";
import type { Dockyard, EvidenceManifest, ReportRun } from "./types";

type Preview = "technical" | "executive" | "manifest";
type ManifestView = "readable" | "json";

function artifactParts(path: string): { directory: string; name: string } {
  const separator = path.lastIndexOf("/");
  return separator === -1
    ? { directory: "", name: path }
    : { directory: path.slice(0, separator + 1), name: path.slice(separator + 1) };
}

export function Reports({
  dockyards,
  onError,
}: {
  dockyards: Dockyard[];
  onError: (message: string | null) => void;
}) {
  const [selected, setSelected] = useState<number | null>(null);
  const [runs, setRuns] = useState<ReportRun[]>([]);
  const [activeRun, setActiveRun] = useState<number | null>(null);
  const [preview, setPreview] = useState<Preview>("technical");
  const [reportText, setReportText] = useState("");
  const [manifest, setManifest] = useState<EvidenceManifest | null>(null);
  const [manifestView, setManifestView] = useState<ManifestView>("readable");
  const [busy, setBusy] = useState(false);
  const refreshSequence = useRef(0);
  const previewSequence = useRef(0);

  const refresh = useCallback(async () => {
    const sequence = ++refreshSequence.current;
    const dockyardId = selected;
    const current = dockyardId === null ? [] : await api.reports(dockyardId);
    if (sequence !== refreshSequence.current) return;
    setRuns(current);
    setActiveRun((value) =>
      value !== null && current.some((run) => run.id === value)
        ? value
        : (current.find((run) => run.status === "completed")?.id ?? null),
    );
  }, [selected]);

  function selectDockyard(dockyardId: number) {
    refreshSequence.current += 1;
    previewSequence.current += 1;
    setSelected(dockyardId);
    setRuns([]);
    setActiveRun(null);
    setReportText("");
    setManifest(null);
    setManifestView("readable");
    setPreview("technical");
  }

  useEffect(() => {
    if (selected === null && dockyards.length) setSelected(dockyards[0].id);
  }, [dockyards, selected]);

  useEffect(() => {
    refresh().catch((problem) =>
      onError(problem instanceof Error ? problem.message : "Could not load reports."),
    );
  }, [refresh, onError]);

  const loadPreview = useCallback(async () => {
    const sequence = ++previewSequence.current;
    const run = runs.find((item) => item.id === activeRun);
    if (!run || run.status !== "completed" || selected !== run.dockyard_id) {
      setReportText("");
      setManifest(null);
      return;
    }
    if (preview === "manifest") {
      const document = await api.reportManifest(run.dockyard_id, run.id);
      if (sequence !== previewSequence.current) return;
      setManifest(document);
      setManifestView("readable");
      setReportText("");
      return;
    }
    const body =
      preview === "technical"
        ? await api.technicalReport(run.dockyard_id, run.id)
        : await api.executiveReport(run.dockyard_id, run.id);
    if (sequence !== previewSequence.current) return;
    setReportText(body);
    setManifest(null);
  }, [activeRun, preview, runs, selected]);

  useEffect(() => {
    loadPreview().catch((problem) =>
      onError(problem instanceof Error ? problem.message : "Could not load report preview."),
    );
  }, [loadPreview, onError]);

  async function create() {
    if (selected === null) return;
    setBusy(true);
    try {
      const run = await api.createReport(selected);
      if (run.status === "failed") {
        onError(run.error ?? "Reporting failed closed.");
      } else {
        onError(null);
      }
      await refresh();
      if (run.status === "completed" && run.dockyard_id === selected) {
        setActiveRun(run.id);
        setPreview("technical");
      }
    } catch (problem) {
      onError(problem instanceof Error ? problem.message : "Could not create report set.");
    } finally {
      setBusy(false);
    }
  }

  if (!dockyards.length) {
    return (
      <section className="panel">
        <EmptyState message="Create a Dockyard and retain evidence before producing reports." />
      </section>
    );
  }

  const latest = runs.find((run) => run.status === "completed") ?? null;
  const counts = latest?.source_counts;
  const active = runs.find((run) => run.id === activeRun) ?? null;

  return (
    <>
      <div className="toolbar">
        <DockyardPicker dockyards={dockyards} selected={selected} onSelect={selectDockyard} />
      </div>
      <section className="hero reporting-hero">
        <div>
          <p className="eyebrow">REPRODUCIBLE FROM RETAINED EVIDENCE</p>
          <h2>Technical detail, executive context, one portable DockPack.</h2>
          <p>
            Reporting contacts nothing. RedDock re-verifies every referenced artifact, freezes a
            deterministic snapshot, and packages reports with a SHA-256 evidence manifest.
          </p>
        </div>
        <button className="primary-button" disabled={busy} onClick={() => void create()}>
          {busy ? "Building report set…" : "Generate report set"}
        </button>
      </section>

      {counts && (
        <div className="metrics compact-metrics">
          <Metric label="Assets" value={String(counts.assets)} note={`${counts.services} retained services`} />
          <Metric label="Findings" value={String(counts.findings)} note={`${counts.findings_by_status.open ?? 0} currently open`} />
          <Metric label="Evidence" value={String(counts.evidence_files)} note={`${formatBytes(counts.evidence_bytes)} · ${counts.lab_audit_events ?? 0} lab events`} />
          <Metric label="DockPack" value={formatBytes(latest?.dockpack_bytes ?? 0)} note="Portable, hash-verifiable ZIP" />
        </div>
      )}

      <div className="reporting-layout">
        <section className="panel">
          <div className="section-heading">
            <div><p className="eyebrow">IMMUTABLE SNAPSHOTS</p><h2>Report history</h2></div>
            <span className="count-chip">{runs.length}</span>
          </div>
          {runs.length ? (
            <div className="report-run-list">
              {runs.map((run) => (
                <button
                  className={run.id === activeRun ? "report-run selected" : "report-run"}
                  key={run.id}
                  onClick={() => run.status === "completed" && setActiveRun(run.id)}
                >
                  <span><strong>Report #{run.id}</strong><small>{formatDate(run.completed_at ?? run.created_at)}</small></span>
                  <span><StatusPill status={run.status} /><code className="hash">{run.snapshot_sha256?.slice(0, 12) ?? "—"}</code></span>
                  {run.error && <small className="row-error">{run.error}</small>}
                </button>
              ))}
            </div>
          ) : (
            <EmptyState message="No report snapshot has been generated for this Dockyard." />
          )}
        </section>

        <section className="panel report-preview-panel">
          {active ? (
            <>
              <div className="section-heading report-preview-heading">
                <div><p className="eyebrow">REPORT #{active.id}</p><h2>{humanize(preview)} view</h2></div>
                <a className="primary-button download-link" href={api.dockpackUrl(active.dockyard_id, active.id)} download>
                  Download DockPack
                </a>
              </div>
              <div className="button-row report-tabs" role="tablist" aria-label="Report preview">
                {(["technical", "executive", "manifest"] as Preview[]).map((item) => (
                  <button
                    className={preview === item ? "secondary-button active" : "secondary-button"}
                    key={item}
                    role="tab"
                    aria-selected={preview === item}
                    onClick={() => setPreview(item)}
                  >
                    {humanize(item)}
                  </button>
                ))}
              </div>
              {manifest ? (
                <>
                  <div className="button-row manifest-tabs" role="tablist" aria-label="Manifest format">
                    <button className={manifestView === "readable" ? "text-button active" : "text-button"} role="tab" aria-selected={manifestView === "readable"} onClick={() => setManifestView("readable")}>Readable HTML</button>
                    <button className={manifestView === "json" ? "text-button active" : "text-button"} role="tab" aria-selected={manifestView === "json"} onClick={() => setManifestView("json")}>Raw JSON</button>
                  </div>
                  {manifestView === "readable" ? (
                    <>
                      <div className="metrics compact-metrics manifest-summary">
                        <Metric label="Files" value={String(manifest.file_count)} note="Verified artifacts" />
                        <Metric label="Total size" value={formatBytes(manifest.total_bytes)} note="Portable evidence" />
                        <Metric label="Digest" value={manifest.algorithm.toUpperCase()} note="Integrity algorithm" />
                      </div>
                      <DataTable headers={["Source", "Artifact", "Type", "Size", "SHA-256"]}>
                        {manifest.files.map((file) => (
                          <tr key={file.archive_path}>
                            <td><strong>{humanize(file.source)}</strong><small className="cell-note">Run #{file.run_id}</small></td>
                            <td title={file.archive_path}><code className="manifest-path">{artifactParts(file.archive_path).name}</code><small className="cell-note manifest-directory">{artifactParts(file.archive_path).directory}</small></td>
                            <td>{file.media_type}</td>
                            <td>{formatBytes(file.bytes)}</td>
                            <td><button className="hash-copy" type="button" title="Copy full SHA-256" aria-label={`Copy SHA-256 for ${file.archive_path}`} onClick={() => void navigator.clipboard.writeText(file.sha256)}><code className="hash">{file.sha256.slice(0, 16)}…</code></button></td>
                          </tr>
                        ))}
                      </DataTable>
                    </>
                  ) : (
                    <pre className="report-preview">{JSON.stringify(manifest, null, 2)}</pre>
                  )}
                </>
              ) : (
                <pre className="report-preview">{reportText || "Loading verified report…"}</pre>
              )}
            </>
          ) : (
            <EmptyState message="Generate or select a completed snapshot to inspect its reports." />
          )}
        </section>
      </div>
    </>
  );
}
