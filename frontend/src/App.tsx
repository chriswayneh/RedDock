import { FormEvent, useEffect, useState } from "react";
import { api } from "./api";
import type { Dockyard, Health, Version } from "./types";

type Page = "Dashboard" | "Dockyards" | "Assets" | "Findings" | "RedPath" | "RedLedger" | "Reports" | "Settings";
const pages: Page[] = ["Dashboard", "Dockyards", "Assets", "Findings", "RedPath", "RedLedger", "Reports", "Settings"];

function formatDate(value: string) {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function App() {
  const [page, setPage] = useState<Page>("Dashboard");
  const [dockyards, setDockyards] = useState<Dockyard[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [version, setVersion] = useState<Version | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Dockyard | null>(null);

  async function refresh() {
    try {
      const [nextHealth, nextVersion, nextDockyards] = await Promise.all([api.health(), api.version(), api.dockyards()]);
      setHealth(nextHealth);
      setVersion(nextVersion);
      setDockyards(nextDockyards);
      setError(null);
    } catch {
      setError("RedDock Core is unavailable. Check the container status and try again.");
    }
  }

  useEffect(() => { void refresh(); }, []);

  async function createDockyard(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const name = String(data.get("name") || "");
    const description = String(data.get("description") || "");
    if (!name.trim()) return;
    try {
      const created = await api.createDockyard(name, description);
      setDockyards((current) => [created, ...current]);
      setSelected(created);
      event.currentTarget.reset();
      setError(null);
    } catch {
      setError("Could not create the Dockyard. Please try again.");
    }
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span className="brand-mark">R</span><span>RedDock</span></div>
        <p className="tagline">Discover. Validate. Prove.</p>
        <nav aria-label="Primary navigation">
          {pages.map((item) => <button key={item} className={page === item ? "nav-item active" : "nav-item"} onClick={() => { setPage(item); setSelected(null); }}>{item}{!['Dashboard', 'Dockyards'].includes(item) && <span className="planned-dot" aria-label="Planned" />}</button>)}
        </nav>
        <div className="sidebar-footer"><span className={health?.status === "healthy" ? "status-dot online" : "status-dot"} /> Core {health?.status === "healthy" ? "online" : "checking"}</div>
      </aside>
      <main>
        <header><div><p className="eyebrow">REDDOCK CORE {version ? `· v${version.version}` : ""}</p><h1>{page}</h1></div><span className="phase-pill">PHASE 0 · FOUNDATION</span></header>
        {error && <div className="alert" role="alert">{error}</div>}
        {page === "Dashboard" && <Dashboard dockyards={dockyards} health={health} openDockyards={() => setPage("Dockyards")} />}
        {page === "Dockyards" && <Dockyards dockyards={dockyards} selected={selected} setSelected={setSelected} onCreate={createDockyard} />}
        {!['Dashboard', 'Dockyards'].includes(page) && <Planned page={page} />}
      </main>
    </div>
  );
}

function Dashboard({ dockyards, health, openDockyards }: { dockyards: Dockyard[]; health: Health | null; openDockyards: () => void }) {
  return <>
    <section className="hero"><div><p className="eyebrow">AUTHORIZED ASSESSMENT WORKSPACE</p><h2>A controlled foundation for security validation.</h2><p>RedDock is online, local, and intentionally limited to safe Phase 0 workflows.</p></div><button className="primary-button" onClick={openDockyards}>Manage Dockyards</button></section>
    <section className="metrics">
      <Metric label="System status" value={health?.status === "healthy" ? "Healthy" : "Checking"} tone="success" />
      <Metric label="Dockyards" value={String(dockyards.length)} />
      <Metric label="Security metrics" value="Unavailable" tone="warning" />
    </section>
    <section className="panel"><div className="section-heading"><div><p className="eyebrow">ENGAGEMENT WORKSPACES</p><h2>Recent Dockyards</h2></div><button className="text-button" onClick={openDockyards}>View all</button></div>
      {dockyards.length ? <DockyardList dockyards={dockyards.slice(0, 5)} onSelect={openDockyards} /> : <EmptyState message="No Dockyards yet. Create an authorized engagement workspace to begin." />}
    </section>
  </>;
}

function Dockyards({ dockyards, selected, setSelected, onCreate }: { dockyards: Dockyard[]; selected: Dockyard | null; setSelected: (dockyard: Dockyard | null) => void; onCreate: (event: FormEvent<HTMLFormElement>) => Promise<void> }) {
  return <div className="dockyard-layout"><section className="panel"><div className="section-heading"><div><p className="eyebrow">AUTHORIZED WORKSPACES</p><h2>Dockyards</h2></div><span className="count-chip">{dockyards.length}</span></div><form className="dockyard-form" onSubmit={(event) => void onCreate(event)}><label>Name<input name="name" required maxLength={120} placeholder="e.g. Q3 application review" /></label><label>Description <span>(optional)</span><textarea name="description" maxLength={2000} placeholder="A short, authorized engagement description." rows={3} /></label><button className="primary-button" type="submit">Create Dockyard</button></form><div className="list-wrap">{dockyards.length ? <DockyardList dockyards={dockyards} onSelect={(dockyard) => setSelected(dockyard)} /> : <EmptyState message="This is where your authorized engagement workspaces will appear." />}</div></section>
    <section className="panel detail-panel">{selected ? <><p className="eyebrow">DOCKYARD #{selected.id}</p><h2>{selected.name}</h2><span className="draft-pill">{selected.status}</span><p className="detail-copy">{selected.description || "No description provided."}</p><dl><div><dt>Created</dt><dd>{formatDate(selected.created_at)}</dd></div><div><dt>Scope</dt><dd>Not configured in Phase 0</dd></div><div><dt>Activity</dt><dd>No tools enabled</dd></div></dl></> : <EmptyState message="Select a Dockyard to view its Phase 0 details." />}</section></div>;
}

function DockyardList({ dockyards, onSelect }: { dockyards: Dockyard[]; onSelect: (dockyard: Dockyard) => void }) {
  return <div className="dockyard-list">{dockyards.map((dockyard) => <button className="dockyard-row" key={dockyard.id} onClick={() => onSelect(dockyard)}><span className="row-icon">D</span><span className="row-main"><strong>{dockyard.name}</strong><small>{dockyard.description || "No description"}</small></span><span className="row-meta"><span className="draft-pill">{dockyard.status}</span><small>{formatDate(dockyard.updated_at)}</small></span></button>)}</div>;
}

function Metric({ label, value, tone }: { label: string; value: string; tone?: "success" | "warning" }) { return <article className="metric"><p>{label}</p><strong className={tone ? `tone-${tone}` : ""}>{value}</strong>{label === "Security metrics" && <small>Available after future detection work</small>}</article>; }
function EmptyState({ message }: { message: string }) { return <div className="empty-state"><span>◇</span><p>{message}</p></div>; }
function Planned({ page }: { page: Page }) { return <section className="planned-state"><span>◇</span><p className="eyebrow">PLANNED CAPABILITY</p><h2>{page} is not available yet.</h2><p>RedDock does not simulate security results. This module will arrive in a later roadmap phase with evidence and policy controls.</p></section>; }

