import { FormEvent, useCallback, useEffect, useState } from "react";
import { api } from "./api";
import {
  DataTable,
  DockyardPicker,
  EmptyState,
  Metric,
  Planned,
  StatusPill,
} from "./components";
import { FindingsPanel } from "./Findings";
import { formatBytes, formatDate } from "./format";
import { AssetTable, Workspace } from "./Workspace";
import type {
  Adapter,
  Asset,
  Detector,
  DiscoveryRun,
  Dockyard,
  EvidenceRecord,
  Finding,
  Health,
  Version,
} from "./types";

type Page =
  | "Dashboard"
  | "Dockyards"
  | "Assets"
  | "Findings"
  | "RedPath"
  | "RedLedger"
  | "Reports"
  | "Settings";

const pages: Page[] = [
  "Dashboard",
  "Dockyards",
  "Assets",
  "Findings",
  "RedPath",
  "RedLedger",
  "Reports",
  "Settings",
];

// Phase 3 adds approval-gated validation inside each Dockyard; correlation and reporting remain planned.
const availablePages = new Set<Page>([
  "Dashboard",
  "Dockyards",
  "Assets",
  "Findings",
  "RedLedger",
]);

export function App() {
  const [page, setPage] = useState<Page>("Dashboard");
  const [dockyards, setDockyards] = useState<Dockyard[]>([]);
  const [adapters, setAdapters] = useState<Adapter[]>([]);
  const [detectors, setDetectors] = useState<Detector[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [version, setVersion] = useState<Version | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Dockyard | null>(null);

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
      setSelected(created);
      form.reset();
      setError(null);
    } catch {
      setError("Could not create the Dockyard. Please try again.");
    }
  }

  function open(item: Page) {
    setPage(item);
    setSelected(null);
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <span className="brand-mark">R</span>
          <span>RedDock</span>
        </div>
        <p className="tagline">Discover. Validate. Prove.</p>
        <nav aria-label="Primary navigation">
          {pages.map((item) => (
            <button
              key={item}
              className={page === item ? "nav-item active" : "nav-item"}
              onClick={() => open(item)}
            >
              {item}
              {!availablePages.has(item) && <span className="planned-dot" aria-label="Planned" />}
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
            {(version?.phase ?? "Phase 3 — Validation").toUpperCase()}
          </span>
        </header>
        {error && (
          <div className="alert" role="alert">
            {error}
          </div>
        )}
        {page === "Dashboard" && (
          <Dashboard
            dockyards={dockyards}
            health={health}
            openDockyards={() => open("Dockyards")}
            onError={setError}
          />
        )}
        {page === "Dockyards" &&
          (selected ? (
            <Workspace
              dockyard={selected}
              adapters={adapters}
              detectors={detectors}
              onBack={() => setSelected(null)}
              onError={setError}
            />
          ) : (
            <Dockyards dockyards={dockyards} setSelected={setSelected} onCreate={createDockyard} />
          ))}
        {page === "Assets" && <AssetsPage dockyards={dockyards} onError={setError} />}
        {page === "Findings" && <FindingsPage dockyards={dockyards} onError={setError} />}
        {page === "RedLedger" && <LedgerPage dockyards={dockyards} onError={setError} />}
        {!availablePages.has(page) && <Planned page={page} />}
      </main>
    </div>
  );
}

function Dashboard({
  dockyards,
  health,
  openDockyards,
  onError,
}: {
  dockyards: Dockyard[];
  health: Health | null;
  openDockyards: () => void;
  onError: (message: string | null) => void;
}) {
  const [runs, setRuns] = useState<DiscoveryRun[]>([]);
  const [assetCount, setAssetCount] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    if (!dockyards.length) return;
    Promise.all(dockyards.map((dockyard) => api.discoveries(dockyard.id)))
      .then((results) => setRuns(results.flat().sort((left, right) => right.id - left.id)))
      .catch(() => onError("Could not load recent discovery activity."));
    Promise.all(dockyards.map((dockyard) => api.assets(dockyard.id)))
      .then((results) => setAssetCount(results.flat().length))
      .catch(() => onError("Could not load the asset inventory."));
    Promise.all(dockyards.map((dockyard) => api.findings(dockyard.id, { status: "open" })))
      .then((results) => setFindings(results.flat()))
      .catch(() => onError("Could not load open findings."));
  }, [dockyards, onError]);

  return (
    <>
      <section className="hero">
        <div>
          <p className="eyebrow">AUTHORIZED ASSESSMENT WORKSPACE</p>
          <h2>Scoped discovery, evidence-backed findings, and controlled validation.</h2>
          <p>
            Every target passes DockGuard before contact. Detection reads only recorded evidence,
            while validation requires a separately documented approval and rechecks scope just before
            its fixed, non-destructive HTTP-origin probe.
          </p>
        </div>
        <button className="primary-button" onClick={openDockyards}>
          Manage Dockyards
        </button>
      </section>
      <section className="metrics">
        <Metric
          label="System status"
          value={health?.status === "healthy" ? "Healthy" : "Checking"}
          tone="success"
        />
        <Metric label="Dockyards" value={String(dockyards.length)} />
        <Metric label="Assets discovered" value={String(assetCount)} />
        <Metric label="Discovery runs" value={String(runs.length)} />
        <Metric
          label="Open findings"
          value={String(findings.length)}
          note="Produced by a detector, from recorded observations"
        />
      </section>
      <section className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">ENGAGEMENT WORKSPACES</p>
            <h2>Recent Dockyards</h2>
          </div>
          <button className="text-button" onClick={openDockyards}>
            View all
          </button>
        </div>
        {dockyards.length ? (
          <DockyardList dockyards={dockyards.slice(0, 5)} onSelect={openDockyards} />
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
          <DataTable headers={["Run", "Target", "Adapter", "Status", "Requested"]}>
            {runs.slice(0, 8).map((run) => (
              <tr key={`${run.dockyard_id}-${run.id}`}>
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
  load: (id: number) => Promise<T[]>,
  onError: (message: string | null) => void,
) {
  const [selected, setSelected] = useState<number | null>(null);
  const [rows, setRows] = useState<T[]>([]);

  useEffect(() => {
    if (selected === null && dockyards.length) setSelected(dockyards[0].id);
  }, [dockyards, selected]);

  useEffect(() => {
    if (selected === null) return;
    load(selected)
      .then(setRows)
      .catch((problem) =>
        onError(problem instanceof Error ? problem.message : "Could not load this Dockyard."),
      );
  }, [selected, load, onError]);

  return { selected, setSelected, rows };
}

function AssetsPage({
  dockyards,
  onError,
}: {
  dockyards: Dockyard[];
  onError: (message: string | null) => void;
}) {
  const load = useCallback((id: number) => api.assets(id), []);
  const { selected, setSelected, rows } = useDockyardScoped<Asset>(dockyards, load, onError);

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
      <AssetTable assets={rows} />
    </>
  );
}

function FindingsPage({
  dockyards,
  onError,
}: {
  dockyards: Dockyard[];
  onError: (message: string | null) => void;
}) {
  const [selected, setSelected] = useState<number | null>(null);

  useEffect(() => {
    if (selected === null && dockyards.length) setSelected(dockyards[0].id);
  }, [dockyards, selected]);

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
        <DockyardPicker dockyards={dockyards} selected={selected} onSelect={setSelected} />
      </div>
      {selected !== null && (
        <FindingsPanel dockyardId={selected} refreshKey={selected} onError={onError} />
      )}
    </>
  );
}

function LedgerPage({
  dockyards,
  onError,
}: {
  dockyards: Dockyard[];
  onError: (message: string | null) => void;
}) {
  const load = useCallback((id: number) => api.evidence(id), []);
  const { selected, setSelected, rows } = useDockyardScoped<EvidenceRecord>(
    dockyards,
    load,
    onError,
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
