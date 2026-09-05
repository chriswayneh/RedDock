import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import { DataTable, DockyardPicker, EmptyState, Metric, StatusPill } from "./components";
import type { Dockyard, RedPathEdge, RedPathGraph, RedPathNode } from "./types";

const EMPTY_GRAPH: RedPathGraph = { run: null, nodes: [], edges: [], mappings: [] };

type Position = { x: number; y: number };

function positions(nodes: RedPathNode[]): Map<string, Position> {
  const assets = nodes.filter((node) => node.kind === "asset");
  const findings = nodes.filter((node) => node.kind === "finding");
  const result = new Map<string, Position>();
  assets.forEach((node, index) => result.set(node.id, { x: 150, y: 70 + index * 90 }));
  findings.forEach((node, index) => result.set(node.id, { x: 650, y: 70 + index * 90 }));
  return result;
}

function short(value: string, limit = 35): string {
  return value.length > limit ? `${value.slice(0, limit - 1)}…` : value;
}

function RedPathCanvas({
  graph,
  onOpenNode,
}: {
  graph: RedPathGraph;
  onOpenNode: (node: RedPathNode) => void;
}) {
  const layout = useMemo(() => positions(graph.nodes), [graph.nodes]);
  const height = Math.max(
    260,
    120 + Math.max(
      graph.nodes.filter((node) => node.kind === "asset").length,
      graph.nodes.filter((node) => node.kind === "finding").length,
    ) * 90,
  );
  return (
    <div className="redpath-canvas-wrap" aria-label="RedPath relationship graph">
      <svg
        className="redpath-canvas"
        viewBox={`0 0 800 ${height}`}
        role="group"
        aria-label="Evidence-linked assets and findings"
      >
        <title>Evidence-linked assets and findings</title>
        {graph.edges.map((edge) => {
          const source = layout.get(edge.source);
          const target = layout.get(edge.target);
          if (!source || !target) return null;
          return (
            <line
              key={edge.id}
              x1={source.x}
              y1={source.y}
              x2={target.x}
              y2={target.y}
              className={`redpath-line ${edge.kind}`}
            />
          );
        })}
        {graph.nodes.map((node) => {
          const point = layout.get(node.id);
          if (!point) return null;
          return (
            <g
              key={node.id}
              className="redpath-node-link"
              transform={`translate(${point.x - 120} ${point.y - 29})`}
              role="button"
              tabIndex={0}
              aria-label={`Open ${node.kind} ${node.label}`}
              onClick={() => onOpenNode(node)}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  onOpenNode(node);
                }
              }}
            >
              <rect width="240" height="58" rx="8" className={`redpath-node ${node.kind}`} />
              <text x="12" y="23" className="redpath-node-title">
                {short(node.label)}
              </text>
              <text x="12" y="43" className="redpath-node-detail">
                {node.kind.toUpperCase()} · {short(node.subtitle, 27)}
              </text>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

function EdgeDetail({ edge }: { edge: RedPathEdge }) {
  return (
    <article className="relationship-detail">
      <div className="section-heading">
        <div>
          <p className="eyebrow">SELECTED RELATIONSHIP</p>
          <h2>{edge.label.replaceAll("_", " ")}</h2>
        </div>
        <StatusPill status={edge.confidence} />
      </div>
      <p>{edge.basis}</p>
      <dl>
        <div>
          <dt>From → to</dt>
          <dd><code>{edge.source}</code> → <code>{edge.target}</code></dd>
        </div>
        <div>
          <dt>Evidence SHA-256</dt>
          <dd>{edge.evidence_sha256.map((digest) => <code key={digest} className="hash block-hash">{digest}</code>)}</dd>
        </div>
      </dl>
    </article>
  );
}

export function RedPath({
  dockyards,
  onOpenAsset,
  onOpenFinding,
  onError,
}: {
  dockyards: Dockyard[];
  onOpenAsset: (dockyardId: number) => void;
  onOpenFinding: (dockyardId: number, findingId: number) => void;
  onError: (message: string | null) => void;
}) {
  const [selectedDockyard, setSelectedDockyard] = useState<number | null>(dockyards[0]?.id ?? null);
  const [graph, setGraph] = useState<RedPathGraph>(EMPTY_GRAPH);
  const [selectedEdge, setSelectedEdge] = useState<string | null>(null);
  const [running, setRunning] = useState(false);
  const activeDockyard = selectedDockyard ?? dockyards[0]?.id ?? null;

  const load = useCallback(async (dockyardId: number) => {
    try {
      const next = await api.redpath(dockyardId);
      setGraph(next);
      setSelectedEdge(next.edges[0]?.id ?? null);
      onError(null);
    } catch {
      onError("Could not load the RedPath correlation graph.");
    }
  }, [onError]);

  useEffect(() => {
    if (activeDockyard !== null) void load(activeDockyard);
  }, [activeDockyard, load]);

  async function runCorrelation() {
    if (activeDockyard === null) return;
    setRunning(true);
    try {
      const run = await api.startCorrelation(activeDockyard);
      if (run.status !== "completed") throw new Error(run.error ?? "Correlation failed");
      await load(activeDockyard);
    } catch {
      onError("Correlation could not be completed.");
    } finally {
      setRunning(false);
    }
  }

  const detail = graph.edges.find((edge) => edge.id === selectedEdge) ?? null;

  function openNode(node: RedPathNode) {
    if (activeDockyard === null) return;
    const id = Number(node.id.split(":", 2)[1]);
    if (!Number.isSafeInteger(id) || id < 1) return;
    if (node.kind === "asset") onOpenAsset(activeDockyard);
    else onOpenFinding(activeDockyard, id);
  }

  if (!dockyards.length) {
    return <section className="panel"><EmptyState message="Create a Dockyard before building a RedPath." /></section>;
  }

  return (
    <>
      <div className="toolbar">
        <DockyardPicker dockyards={dockyards} selected={activeDockyard} onSelect={setSelectedDockyard} />
        <button className="primary-button" onClick={runCorrelation} disabled={running}>
          {running ? "Correlating…" : "Run correlation"}
        </button>
      </div>
      <section className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">REDPATH · STORED STATE ONLY</p>
            <h2>Explainable relationships, not inferred attack paths</h2>
          </div>
          {graph.run ? <StatusPill status={graph.run.status} /> : null}
        </div>
        <p className="hint">Every edge states its basis and carries the retained SHA-256 evidence behind it. Correlation makes no network contact and does not calculate exploitability or risk.</p>
        {graph.run ? (
          <>
            <div className="metrics compact-metrics">
              <Metric label="Assets" value={String(graph.run.asset_count)} note="Recorded nodes" />
              <Metric label="Findings" value={String(graph.run.finding_count)} note="Evidence-backed nodes" />
              <Metric label="Relationships" value={String(graph.edges.length)} note="Explainable graph edges" />
              <Metric label="Mappings" value={String(graph.mappings.length)} note="Fixed CWE classifications" />
            </div>
            <RedPathCanvas graph={graph} onOpenNode={openNode} />
          </>
        ) : (
          <EmptyState message="No correlation snapshot yet. Run correlation over this Dockyard's stored assets and findings." />
        )}
      </section>
      {graph.edges.length ? (
        <div className="redpath-details-grid">
          <section className="panel">
            <div className="section-heading"><h2>Relationships</h2><span className="count-chip">{graph.edges.length}</span></div>
            <div className="relationship-list">
              {graph.edges.map((edge) => (
                <button key={edge.id} className={edge.id === selectedEdge ? "relationship-row selected" : "relationship-row"} onClick={() => setSelectedEdge(edge.id)}>
                  <strong>{edge.label.replaceAll("_", " ")}</strong>
                  <small>{edge.source} → {edge.target}</small>
                </button>
              ))}
            </div>
          </section>
          <section className="panel">{detail ? <EdgeDetail edge={detail} /> : null}</section>
        </div>
      ) : null}
      {graph.mappings.length ? (
        <section className="panel redpath-mappings">
          <div className="section-heading"><div><p className="eyebrow">CLASSIFICATION, NOT PROOF</p><h2>Framework mappings</h2></div></div>
          <DataTable headers={["Finding", "Framework", "Control", "Title", "Evidence"]}>
            {graph.mappings.map((mapping) => (
              <tr key={mapping.id}><td><button className="link-button" type="button" onClick={() => activeDockyard !== null && onOpenFinding(activeDockyard, mapping.finding_id)}>#{mapping.finding_id}</button></td><td>{mapping.framework}</td><td><a className="inline-link" href={`https://cwe.mitre.org/data/definitions/${mapping.external_id.replace("CWE-", "")}.html`} target="_blank" rel="noreferrer"><code>{mapping.external_id}</code></a></td><td>{mapping.title}</td><td><code className="hash">{mapping.evidence_sha256.slice(0, 16)}…</code></td></tr>
            ))}
          </DataTable>
        </section>
      ) : null}
    </>
  );
}
