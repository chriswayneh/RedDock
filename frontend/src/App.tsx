import { FormEvent, useCallback, useEffect, useState } from "react";
import { api } from "./api";
import {
  DataTable,
  DockyardPicker,
  EmptyState,
  Metric,
  StatusPill,
} from "./components";
import { FindingsPanel } from "./Findings";
import { Intelligence } from "./Intelligence";
import { Lab } from "./Lab";
import { RedPath } from "./RedPath";
import { Reports } from "./Reports";
import { SettingsPage } from "./Settings";
import { ListNotice } from "./ListNotice";
import { formatBytes, formatDate } from "./format";
import { AssetTable, Workspace } from "./Workspace";
import { pagePaths, pageUrl, useRoute, workspaceUrl } from "./routes";
import type { Page, WorkspaceTab } from "./routes";
import type {
  Adapter,
  Asset,
  Detector,
  DashboardSummary,
  ListPage,
  Dockyard,
  EvidenceRecord,
  Health,
  Version,
} from "./types";

const pages = Object.keys(pagePaths) as Page[];

export function App() {
  const { route, navigate } = useRoute();
  const { page, dockyardId: contextDockyardId, findingId: contextFindingId } = route;
  const [dockyards, setDockyards] = useState<Dockyard[]>([]);
  const [adapters, setAdapters] = useState<Adapter[]>([]);
  const [detectors, setDetectors] = useState<Detector[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [version, setVersion] = useState<Version | null>(null);
  const [error, setError] = useState<string | null>(null);
  const selected = route.workspace ? dockyards.find((item) => item.id === contextDockyardId) : null;

  const refresh = useCallback(async () => {
    try {
      const [nextHealth, nextVersion, nextDockyards, nextAdapters, nextDetectors] =
        await Promise.all([
          api.health(),
          api.version(),
          api.dockyards(),
          api.adapters(),
          api.detectors(),
        ]);
      setHealth(nextHealth);
      setVersion(nextVersion);
      setDockyards(nextDockyards);
      setAdapters(nextAdapters);
      setDetectors(nextDetectors);
      setError(null);
    } catch {
      setError("RedDock Core is unavailable. Check the container status and try again.");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  async function createDockyard(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const name = String(data.get("name") || "");
    const description = String(data.get("description") || "");
    if (!name.trim()) return;
    try {
      const created = await api.createDockyard(name, description);
      setDockyards((current) => [created, ...current]);
      openDockyard(created);
      form.reset();
      setError(null);
    } catch {
      setError("Could not create the Dockyard. Please try again.");
    }
  }

  function open(item: Page) {
    navigate(pageUrl(item, contextDockyardId));
  }

  function openDockyard(dockyard: Dockyard, tab: WorkspaceTab = "Scope") {
    navigate(workspaceUrl(dockyard.id, tab));
  }

  function openScoped(item: "Assets" | "Findings", dockyardId: number, findingId?: number) {
    navigate(findingId === undefined ? pageUrl(item, dockyardId) : workspaceUrl(dockyardId, "Findings", findingId));
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <button
          className="brand brand-button"
          type="button"
          aria-label="Go to the RedDock dashboard"
          onClick={() => open("Dashboard")}
        >
          <span className="brand-mark">R</span>
          <span>RedDock</span>
        </button>
        <p className="tagline">Discover. Validate. Prove.</p>
        <nav aria-label="Primary navigation">
          {pages.map((item) => (
            <button
              key={item}
              className={page === item ? "nav-item active" : "nav-item"}
              onClick={() => open(item)}
            >
              {item}
            </button>
          ))}
        </nav>
        <div className="sidebar-footer">
          <span className={health?.status === "healthy" ? "status-dot online" : "status-dot"} />{" "}
          Core {health?.status === "healthy" ? "online" : "checking"}
        </div>
      </aside>
      <main>
        <header>
          <div>
            <p className="eyebrow">REDDOCK CORE {version ? `· v${version.version}` : ""}</p>
            <h1>{page}</h1>
          </div>
          <span className="phase-pill">
            {(version?.phase ?? "Phase 7 — Advanced / Lab").toUpperCase()}
          </span>
        </header>
        {error && (
          <div className="alert" role="alert">
            {error}
          </div>
        )}
        {route.unknown && <p role="status">That page was not found. The dashboard is shown below.</p>}
        {page === "Dashboard" && (
          <Dashboard
            dockyards={dockyards}
            health={health}
            openPage={open}
            openDockyard={openDockyard}
            onError={setError}
          />
        )}
        {page === "Dockyards" &&
          (selected ? (
            <Workspace
              key={`${selected.id}/${route.tab}`}
              dockyard={selected}
              adapters={adapters}
              detectors={detectors}
              initialTab={route.tab}
              initialFindingId={contextFindingId}
              onTabChange={(tab) => navigate(workspaceUrl(selected.id, tab))}
              onFindingChange={(id) => navigate(workspaceUrl(selected.id, "Findings", id))}
              onBack={() => open("Dockyards")}
              onError={setError}
            />
          ) : (
            route.workspace ? <EmptyState message="This Dockyard is loading or is no longer available." /> : <Dockyards
              dockyards={dockyards}
              setSelected={(dockyard) => {
                if (dockyard) openDockyard(dockyard);
                else open("Dockyards");
              }}
              onCreate={createDockyard}
            />
          ))}
        {page === "Assets" && <AssetsPage key={contextDockyardId} dockyards={dockyards} initialDockyardId={contextDockyardId} onSelect={(id) => navigate(pageUrl("Assets", id), contextDockyardId === null)} onError={setError} />}
        {page === "Findings" && <FindingsPage key={contextDockyardId} dockyards={dockyards} initialDockyardId={contextDockyardId} initialFindingId={contextFindingId} onSelect={(id) => navigate(pageUrl("Findings", id), contextDockyardId === null)} onFindingChange={(id) => contextDockyardId !== null && navigate(workspaceUrl(contextDockyardId, "Findings", id))} onError={setError} />}
        {page === "RedPath" && <RedPath dockyards={dockyards} onOpenAsset={(dockyardId) => openScoped("Assets", dockyardId)} onOpenFinding={(dockyardId, findingId) => openScoped("Findings", dockyardId, findingId)} onError={setError} />}
        {page === "Intelligence" && <Intelligence dockyards={dockyards} onError={setError} />}
        {page === "Lab" && <Lab dockyards={dockyards} onError={setError} />}
        {page === "RedLedger" && <LedgerPage key={contextDockyardId} dockyards={dockyards} initialDockyardId={contextDockyardId} onSelect={(id) => navigate(pageUrl("RedLedger", id), contextDockyardId === null)} onError={setError} />}
        {page === "Reports" && <Reports dockyards={dockyards} onError={setError} />}
        {page === "Settings" && <SettingsPage onError={setError} />}
      </main>
    </div>
  );
}

function Dashboard({
  dockyards,
  health,
  openPage,
  openDockyard,
  onError,
}: {
  dockyards: Dockyard[];
  health: Health | null;
  openPage: (page: Page) => void;
  openDockyard: (dockyard: Dockyard, tab?: WorkspaceTab) => void;
  onError: (message: string | null) => void;
}) {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const runs = summary?.recent_runs ?? [];

  useEffect(() => {
    let active = true;
    api.dashboard().then((result) => { if (active) setSummary(result); })
      .catch(() => { if (active) onError("Could not load dashboard totals."); });
    return () => { active = false; };
  }, [onError]);

  return (
    <>
      <section className="hero">
        <div>
          <p className="eyebrow">AUTHORIZED ASSESSMENT WORKSPACE</p>
          <h2>Scoped discovery, evidence-backed findings, and controlled validation.</h2>
          <p>
            Check authorized targets, review findings, and keep the evidence together.
          </p>
        </div>
        <button className="primary-button" onClick={() => openPage("Dockyards")}>
          Manage Dockyards
        </button>
      </section>
      <section className="metrics">
        <Metric
          label="System status"
          value={health?.status === "healthy" ? "Healthy" : "Checking"}
          tone="success"
        />
        <Metric label="Dockyards" value={summary ? String(summary.dockyard_count) : "Loading"} onClick={() => openPage("Dockyards")} />
        <Metric label="Assets discovered" value={summary ? String(summary.asset_count) : "Loading"} onClick={() => openPage("Assets")} />
        <Metric label="Discovery runs" value={summary ? String(summary.discovery_run_count) : "Loading"} onClick={() => openPage("RedLedger")} />
        <Metric
          label="Open findings"
          value={summary ? String(summary.open_finding_count) : "Loading"}
          note="Produced by a detector, from recorded observations"
          onClick={() => openPage("Findings")}
        />
      </section>
      <section className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">ENGAGEMENT WORKSPACES</p>
            <h2>Recent Dockyards</h2>
          </div>
          <button className="text-button" onClick={() => openPage("Dockyards")}>
            View all
          </button>
        </div>
        {summary && <ListNotice shown={summary.recent_dockyards.length} total={summary.dockyard_count} />}
        {summary?.recent_dockyards.length ? (
          <DockyardList dockyards={summary.recent_dockyards} onSelect={openDockyard} />
        ) : (
          <EmptyState message="No Dockyards yet. Create an authorized engagement workspace to begin." />
        )}
      </section>
      {runs.length > 0 && (
        <section className="panel">
          <div className="section-heading">
            <div>
              <p className="eyebrow">AUDIT TRAIL</p>
              <h2>Recent discovery runs</h2>
            </div>
          </div>
          <ListNotice shown={runs.length} total={summary?.discovery_run_count ?? null} />
          <DataTable headers={["Run", "Target", "Adapter", "Status", "Requested"]}>
            {runs.slice(0, 8).map((run) => (
              <tr
                key={`${run.dockyard_id}-${run.id}`}
                className="clickable-row"
                tabIndex={0}
                onClick={() => {
                  const dockyard = dockyards.find((item) => item.id === run.dockyard_id);
                  if (dockyard) openDockyard(dockyard, "Runs");
                }}
                onKeyDown={(event) => {
                  if (event.key !== "Enter" && event.key !== " ") return;
                  event.preventDefault();
                  const dockyard = dockyards.find((item) => item.id === run.dockyard_id);
                  if (dockyard) openDockyard(dockyard, "Runs");
                }}
              >
                <td>#{run.id}</td>
                <td>
                  <code>{run.normalized_target ?? run.requested_target}</code>
                </td>
                <td>{run.adapter}</td>
                <td>
                  <StatusPill status={run.status} />
                </td>
                <td>{formatDate(run.created_at)}</td>
              </tr>
            ))}
          </DataTable>
        </section>
      )}
    </>
  );
}

function Dockyards({
  dockyards,
  setSelected,
  onCreate,
}: {
  dockyards: Dockyard[];
  setSelected: (dockyard: Dockyard | null) => void;
  onCreate: (event: FormEvent<HTMLFormElement>) => Promise<void>;
}) {
  return (
    <section className="panel">
      <div className="section-heading">
        <div>
          <p className="eyebrow">AUTHORIZED WORKSPACES</p>
          <h2>Dockyards</h2>
        </div>
        <span className="count-chip">{dockyards.length}</span>
      </div>
      <form className="dockyard-form" onSubmit={(event) => void onCreate(event)}>
        <label>
          Name
          <input name="name" required maxLength={120} placeholder="e.g. Q3 application review" />
        </label>
        <label>
          Description <span>(optional)</span>
          <textarea
            name="description"
            maxLength={2000}
            placeholder="A short, authorized engagement description."
            rows={3}
          />
        </label>
        <button className="primary-button" type="submit">
          Create Dockyard
        </button>
      </form>
      <div className="list-wrap">
        {dockyards.length ? (
          <DockyardList dockyards={dockyards} onSelect={setSelected} />
        ) : (
          <EmptyState message="This is where your authorized engagement workspaces will appear." />
        )}
      </div>
    </section>
  );
}

function DockyardList({
  dockyards,
  onSelect,
}: {
  dockyards: Dockyard[];
  onSelect: (dockyard: Dockyard) => void;
}) {
  return (
    <div className="dockyard-list">
      {dockyards.map((dockyard) => (
        <button className="dockyard-row" key={dockyard.id} onClick={() => onSelect(dockyard)}>
          <span className="row-icon">D</span>
          <span className="row-main">
            <strong>{dockyard.name}</strong>
            <small>{dockyard.description || "No description"}</small>
          </span>
          <span className="row-meta">
            <span className="draft-pill">{dockyard.status}</span>
            <small>{formatDate(dockyard.updated_at)}</small>
          </span>
        </button>
      ))}
    </div>
  );
}

/** A Dockyard-scoped view reached from the top-level navigation. */
function useDockyardScoped<T>(
  dockyards: Dockyard[],
  load: (id: number) => Promise<ListPage<T>>,
  onError: (message: string | null) => void,
  initialDockyardId: number | null = null,
  onSelect: (id: number) => void,
) {
  const selected = initialDockyardId;
  const [rows, setRows] = useState<T[]>([]);
  const [total, setTotal] = useState<number | null>(null);

  useEffect(() => {
    if (selected === null && dockyards.length) onSelect(dockyards[0].id);
  }, [dockyards, selected, onSelect]);

  useEffect(() => {
    if (selected === null) return;
    let active = true;
    load(selected)
      .then((result) => { if (active) { setRows(result.items); setTotal(result.total); } })
      .catch((problem) => {
        if (active) onError(problem instanceof Error ? problem.message : "Could not load this Dockyard.");
      });
    return () => { active = false; };
  }, [selected, load, onError]);

  return { selected, setSelected: onSelect, rows, total };
}

function AssetsPage({
  dockyards,
  initialDockyardId,
  onSelect,
  onError,
}: {
  dockyards: Dockyard[];
  initialDockyardId: number | null;
  onSelect: (id: number) => void;
  onError: (message: string | null) => void;
}) {
  const load = useCallback((id: number) => api.assetPage(id), []);
  const { selected, setSelected, rows, total } = useDockyardScoped<Asset>(dockyards, load, onError, initialDockyardId, onSelect);

  if (!dockyards.length) {
    return (
      <section className="panel">
        <EmptyState message="Create a Dockyard and run discovery to populate the asset inventory." />
      </section>
    );
  }
  return (
    <>
      <div className="toolbar">
        <DockyardPicker dockyards={dockyards} selected={selected} onSelect={setSelected} />
      </div>
      <ListNotice shown={rows.length} total={total} />
      <AssetTable assets={rows} />
    </>
  );
}

function FindingsPage({
  dockyards,
  initialDockyardId,
  initialFindingId,
  onSelect,
  onFindingChange,
  onError,
}: {
  dockyards: Dockyard[];
  initialDockyardId: number | null;
  initialFindingId: number | null;
  onSelect: (id: number) => void;
  onFindingChange: (id: number) => void;
  onError: (message: string | null) => void;
}) {
  const selected = initialDockyardId;

  useEffect(() => {
    if (selected === null && dockyards.length) onSelect(dockyards[0].id);
  }, [dockyards, selected, onSelect]);

  if (!dockyards.length) {
    return (
      <section className="panel">
        <EmptyState message="Create a Dockyard, run discovery, then run detection to produce findings." />
      </section>
    );
  }
  return (
    <>
      <div className="toolbar">
        <DockyardPicker dockyards={dockyards} selected={selected} onSelect={onSelect} />
      </div>
      {selected !== null && (
        <FindingsPanel dockyardId={selected} refreshKey={selected} initialFindingId={initialFindingId} onFindingChange={onFindingChange} showHeading={false} onError={onError} />
      )}
    </>
  );
}

function LedgerPage({
  dockyards,
  initialDockyardId,
  onSelect,
  onError,
}: {
  dockyards: Dockyard[];
  initialDockyardId: number | null;
  onSelect: (id: number) => void;
  onError: (message: string | null) => void;
}) {
  const load = useCallback((id: number) => api.evidencePage(id), []);
  const { selected, setSelected, rows, total } = useDockyardScoped<EvidenceRecord>(
    dockyards,
    load,
    onError,
    initialDockyardId,
    onSelect,
  );

  if (!dockyards.length) {
    return (
      <section className="panel">
        <EmptyState message="RedLedger records evidence produced by discovery runs." />
      </section>
    );
  }
  return (
    <>
      <div className="toolbar">
        <DockyardPicker dockyards={dockyards} selected={selected} onSelect={setSelected} />
      </div>
      <section className="panel">
        <ListNotice shown={rows.length} total={total} />
        <p className="hint">
          RedDock retains the raw tool output, the normalized result and a metadata record for every
          discovery run, each hashed with SHA-256. A detection run retains its own normalized result
          and metadata under the same evidence root, and every finding names the observations and
          hashes behind it. The full RedLedger experience arrives later.
        </p>
        {rows.length ? (
          <DataTable headers={["Run", "Kind", "Artifact", "Size", "SHA-256", "Stored"]}>
            {rows.map((record) => (
              <tr key={record.id}>
                <td>#{record.discovery_run_id}</td>
                <td>{record.kind}</td>
                <td>
                  <code>{record.relative_path}</code>
                  {record.truncated && <small className="row-error"> truncated</small>}
                </td>
                <td>{formatBytes(record.size_bytes)}</td>
                <td>
                  <code className="hash">{record.sha256.slice(0, 16)}…</code>
                </td>
                <td>{formatDate(record.created_at)}</td>
              </tr>
            ))}
          </DataTable>
        ) : (
          <EmptyState message="No evidence retained yet for this Dockyard." />
        )}
      </section>
    </>
  );
}
