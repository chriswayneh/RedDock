import { FormEvent, useCallback, useEffect, useState } from "react";
import { api } from "./api";
import { DataTable, DecisionPanel, EmptyState, StatusPill } from "./components";
import { formatDate, humanize, kindLabel, plural } from "./format";
import type {
  Adapter,
  Asset,
  DiscoveryRun,
  Dockyard,
  Observation,
  ScopeEntry,
  ScopeEvaluation,
  ServiceRow,
} from "./types";

const tabs = ["Scope", "Discovery", "Assets", "Services", "Observations", "Runs"] as const;
type Tab = (typeof tabs)[number];

const ACTIVE = new Set(["pending", "running"]);

export function Workspace({
  dockyard,
  adapters,
  onBack,
  onError,
}: {
  dockyard: Dockyard;
  adapters: Adapter[];
  onBack: () => void;
  onError: (message: string | null) => void;
}) {
  const [tab, setTab] = useState<Tab>("Scope");
  const [scope, setScope] = useState<ScopeEntry[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [services, setServices] = useState<ServiceRow[]>([]);
  const [observations, setObservations] = useState<Observation[]>([]);
  const [runs, setRuns] = useState<DiscoveryRun[]>([]);

  const refresh = useCallback(async () => {
    try {
      const [nextScope, nextAssets, nextServices, nextObservations, nextRuns] = await Promise.all([
        api.scope(dockyard.id),
        api.assets(dockyard.id),
        api.services(dockyard.id),
        api.observations(dockyard.id),
        api.discoveries(dockyard.id),
      ]);
      setScope(nextScope);
      setAssets(nextAssets);
      setServices(nextServices);
      setObservations(nextObservations);
      setRuns(nextRuns);
      onError(null);
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not load the Dockyard workspace.");
    }
  }, [dockyard.id, onError]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  // A run executes in the background, so poll only while one is in flight.
  useEffect(() => {
    if (!runs.some((run) => ACTIVE.has(run.status))) return;
    const timer = setInterval(() => void refresh(), 2000);
    return () => clearInterval(timer);
  }, [runs, refresh]);

  return (
    <>
      <section className="panel workspace-header">
        <div>
          <button className="text-button" onClick={onBack}>
            ← All Dockyards
          </button>
          <h2>{dockyard.name}</h2>
          <p className="detail-copy">{dockyard.description || "No description provided."}</p>
        </div>
        <div className="workspace-counts">
          <span>{plural(scope.length, "scope entry", "scope entries")}</span>
          <span>{plural(assets.length, "asset")}</span>
          <span>{plural(services.length, "service")}</span>
          <span>{plural(runs.length, "discovery run")}</span>
        </div>
      </section>

      <nav className="tabs" aria-label="Dockyard sections">
        {tabs.map((item) => (
          <button
            key={item}
            className={tab === item ? "tab active" : "tab"}
            onClick={() => setTab(item)}
          >
            {item}
          </button>
        ))}
      </nav>

      {tab === "Scope" && (
        <ScopePanel
          dockyardId={dockyard.id}
          scope={scope}
          onChanged={refresh}
          onError={onError}
        />
      )}
      {tab === "Discovery" && (
        <DiscoveryPanel
          dockyardId={dockyard.id}
          adapters={adapters}
          scopeCount={scope.length}
          onStarted={refresh}
          onError={onError}
        />
      )}
      {tab === "Assets" && <AssetTable assets={assets} />}
      {tab === "Services" && <ServiceTable services={services} />}
      {tab === "Observations" && <ObservationList observations={observations} />}
      {tab === "Runs" && <RunTable runs={runs} />}
    </>
  );
}

function ScopePanel({
  dockyardId,
  scope,
  onChanged,
  onError,
}: {
  dockyardId: number;
  scope: ScopeEntry[];
  onChanged: () => Promise<void>;
  onError: (message: string | null) => void;
}) {
  const [evaluation, setEvaluation] = useState<ScopeEvaluation | null>(null);

  async function addEntry(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const data = new FormData(form);
    const target = String(data.get("target") || "").trim();
    const rule = String(data.get("rule") || "include") as "include" | "exclude";
    if (!target) return;
    try {
      await api.addScope(dockyardId, rule, target);
      form.reset();
      onError(null);
      await onChanged();
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not add the scope entry.");
    }
  }

  async function removeEntry(entryId: number) {
    try {
      await api.removeScope(dockyardId, entryId);
      await onChanged();
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not remove the scope entry.");
    }
  }

  async function testTarget(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const target = String(new FormData(event.currentTarget).get("candidate") || "").trim();
    if (!target) return;
    try {
      setEvaluation(await api.evaluate(dockyardId, target));
      onError(null);
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not evaluate the target.");
    }
  }

  const included = scope.filter((entry) => entry.rule === "include");
  const excluded = scope.filter((entry) => entry.rule === "exclude");

  return (
    <div className="split-layout">
      <section className="panel">
        <div className="section-heading">
          <div>
            <p className="eyebrow">AUTHORIZED SCOPE</p>
            <h2>Scope entries</h2>
          </div>
          <span className="count-chip">{scope.length}</span>
        </div>
        <form className="dockyard-form inline-form" onSubmit={(event) => void addEntry(event)}>
          <label>
            Target
            <input
              name="target"
              required
              maxLength={255}
              placeholder="192.168.1.0/24, app.lab.local or http://127.0.0.1:8080"
            />
          </label>
          <label>
            Rule
            <select name="rule" defaultValue="include">
              <option value="include">Include</option>
              <option value="exclude">Exclude</option>
            </select>
          </label>
          <button className="primary-button" type="submit">
            Add entry
          </button>
        </form>
        <p className="hint">
          Phase 1 accepts an IPv4 or IPv6 address, a network no larger than 256 addresses, an exact
          hostname or an HTTP origin. Hostnames match exactly; there is no wildcard expansion.
        </p>

        <ScopeList title="Included" entries={included} onRemove={removeEntry} />
        <ScopeList title="Excluded" entries={excluded} onRemove={removeEntry} />
      </section>

      <section className="panel detail-panel">
        <p className="eyebrow">DOCKGUARD</p>
        <h2>Test a target</h2>
        <form className="dockyard-form" onSubmit={(event) => void testTarget(event)}>
          <label>
            Candidate target
            <input name="candidate" required maxLength={255} placeholder="192.168.1.10" />
          </label>
          <button className="primary-button" type="submit">
            Evaluate
          </button>
        </form>
        {evaluation ? (
          <DecisionPanel evaluation={evaluation} />
        ) : (
          <EmptyState message="DockGuard evaluates every target before any tool runs. Test one here." />
        )}
      </section>
    </div>
  );
}

function ScopeList({
  title,
  entries,
  onRemove,
}: {
  title: string;
  entries: ScopeEntry[];
  onRemove: (id: number) => Promise<void>;
}) {
  return (
    <div className="scope-group">
      <h3>{title}</h3>
      {entries.length ? (
        <ul className="scope-list">
          {entries.map((entry) => (
            <li key={entry.id}>
              <code>{entry.value}</code>
              <small>{kindLabel(entry.kind)}</small>
              <button
                className="text-button"
                onClick={() => void onRemove(entry.id)}
                aria-label={`Remove ${entry.value}`}
              >
                Remove
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <p className="hint">None.</p>
      )}
    </div>
  );
}

function DiscoveryPanel({
  dockyardId,
  adapters,
  scopeCount,
  onStarted,
  onError,
}: {
  dockyardId: number;
  adapters: Adapter[];
  scopeCount: number;
  onStarted: () => Promise<void>;
  onError: (message: string | null) => void;
}) {
  const [target, setTarget] = useState("");
  const [adapterName, setAdapterName] = useState(adapters[0]?.name ?? "");
  const [profile, setProfile] = useState(adapters[0]?.profiles[0]?.name ?? "");
  const [preview, setPreview] = useState<ScopeEvaluation | null>(null);
  const [busy, setBusy] = useState(false);

  const adapter = adapters.find((item) => item.name === adapterName) ?? adapters[0];

  useEffect(() => {
    setProfile(adapter?.profiles[0]?.name ?? "");
  }, [adapter]);

  // The preview belongs to one exact target; changing the target invalidates it.
  const ready = preview?.allowed === true && preview.target === target.trim();

  async function check() {
    if (!target.trim()) return;
    try {
      setPreview(await api.evaluate(dockyardId, target.trim(), true));
      onError(null);
    } catch (error) {
      onError(error instanceof Error ? error.message : "Could not evaluate the target.");
    }
  }

  async function launch() {
    if (!ready || !adapter) return;
    setBusy(true);
    const outcome = await api.startDiscovery(dockyardId, target.trim(), adapter.name, profile);
    setBusy(false);
    if ("error" in outcome) {
      onError(outcome.error);
      return;
    }
    if (!outcome.accepted) {
      onError(`DockGuard denied this run: ${outcome.run.decision_reason}`);
      return;
    }
    onError(null);
    await onStarted();
  }

  if (scopeCount === 0) {
    return (
      <section className="panel">
        <EmptyState message="Define an authorized scope before running discovery. RedDock will not act on a Dockyard that has no scope." />
      </section>
    );
  }

  return (
    <div className="split-layout">
      <section className="panel">
        <p className="eyebrow">DISCOVERY</p>
        <h2>Run scoped discovery</h2>
        <div className="dockyard-form">
          <label>
            Target
            <input
              value={target}
              maxLength={255}
              placeholder="127.0.0.1"
              onChange={(event) => {
                setTarget(event.target.value);
                setPreview(null);
              }}
            />
          </label>
          <label>
            Adapter
            <select value={adapterName} onChange={(event) => setAdapterName(event.target.value)}>
              {adapters.map((item) => (
                <option key={item.name} value={item.name}>
                  {item.title}
                </option>
              ))}
            </select>
          </label>
          <label>
            Discovery profile
            <select value={profile} onChange={(event) => setProfile(event.target.value)}>
              {adapter?.profiles.map((item) => (
                <option key={item.name} value={item.name}>
                  {item.title}
                </option>
              ))}
            </select>
          </label>
          <p className="hint">
            {adapter?.profiles.find((item) => item.name === profile)?.description}
          </p>
          <div className="button-row">
            <button className="secondary-button" onClick={() => void check()} type="button">
              Check with DockGuard
            </button>
            <button
              className="primary-button"
              onClick={() => void launch()}
              type="button"
              disabled={!ready || busy}
            >
              {busy ? "Starting…" : "Run discovery"}
            </button>
          </div>
          {!ready && (
            <p className="hint">
              A target must pass DockGuard before it can be launched. The server enforces this
              again when the run starts.
            </p>
          )}
        </div>
      </section>
      <section className="panel detail-panel">
        <p className="eyebrow">DOCKGUARD PREVIEW</p>
        <h2>Decision</h2>
        {preview ? (
          <DecisionPanel evaluation={preview} />
        ) : (
          <EmptyState message="Check a target to see the decision and the reason behind it." />
        )}
      </section>
    </div>
  );
}

export function AssetTable({ assets }: { assets: Asset[] }) {
  if (!assets.length) {
    return (
      <section className="panel">
        <EmptyState message="No assets yet. Run a scoped discovery to build the inventory." />
      </section>
    );
  }
  return (
    <section className="panel">
      <DataTable headers={["Asset", "Type", "Address", "Hostname", "Services", "First seen", "Last seen"]}>
        {assets.map((asset) => (
          <tr key={asset.id}>
            <td>
              <strong>{asset.display_name}</strong>
            </td>
            <td>{kindLabel(asset.asset_type)}</td>
            <td>{asset.ip_address ?? "—"}</td>
            <td>{asset.hostname ?? "—"}</td>
            <td>{asset.service_count}</td>
            <td>{formatDate(asset.first_seen)}</td>
            <td>{formatDate(asset.last_seen)}</td>
          </tr>
        ))}
      </DataTable>
    </section>
  );
}

function ServiceTable({ services }: { services: ServiceRow[] }) {
  if (!services.length) {
    return (
      <section className="panel">
        <EmptyState message="No services recorded yet." />
      </section>
    );
  }
  return (
    <section className="panel">
      <DataTable headers={["Asset", "Endpoint", "State", "Service", "Product", "Version", "Last seen"]}>
        {services.map((service) => (
          <tr key={service.id}>
            <td>{service.asset_label}</td>
            <td>
              <code>
                {service.transport.toUpperCase()}/{service.port}
              </code>
            </td>
            <td>{service.state}</td>
            <td>{service.service_name ?? "Unidentified"}</td>
            <td>{service.product ?? "—"}</td>
            <td>{service.version ?? "—"}</td>
            <td>{formatDate(service.last_seen)}</td>
          </tr>
        ))}
      </DataTable>
    </section>
  );
}

function ObservationList({ observations }: { observations: Observation[] }) {
  if (!observations.length) {
    return (
      <section className="panel">
        <EmptyState message="No observations recorded yet." />
      </section>
    );
  }
  return (
    <section className="panel">
      <p className="hint">
        An observation records what an adapter saw. It is not a finding and carries no severity;
        interpretation arrives in a later phase.
      </p>
      <DataTable headers={["Observed", "Adapter", "Type", "Summary", "Confidence", "Run"]}>
        {observations.map((observation) => (
          <tr key={observation.id}>
            <td>{formatDate(observation.observed_at)}</td>
            <td>{observation.adapter}</td>
            <td>{humanize(observation.observation_type)}</td>
            <td>{observation.summary}</td>
            <td>{humanize(observation.confidence)}</td>
            <td>{observation.discovery_run_id ?? "—"}</td>
          </tr>
        ))}
      </DataTable>
    </section>
  );
}

function RunTable({ runs }: { runs: DiscoveryRun[] }) {
  if (!runs.length) {
    return (
      <section className="panel">
        <EmptyState message="No discovery runs yet." />
      </section>
    );
  }
  return (
    <section className="panel">
      <DataTable
        headers={["Run", "Target", "Adapter", "Profile", "Status", "Decision", "Results", "Started"]}
      >
        {runs.map((run) => (
          <tr key={run.id}>
            <td>#{run.id}</td>
            <td>
              <code>{run.normalized_target ?? run.requested_target}</code>
            </td>
            <td>{run.adapter}</td>
            <td>{humanize(run.profile)}</td>
            <td>
              <StatusPill status={run.status} />
            </td>
            <td title={run.decision_reason}>{humanize(run.decision)}</td>
            <td>
              {plural(run.asset_count, "asset")} · {plural(run.service_count, "service")} ·{" "}
              {plural(run.observation_count, "observation")}
              {run.error && <div className="row-error">{run.error}</div>}
            </td>
            <td>{formatDate(run.started_at ?? run.created_at)}</td>
          </tr>
        ))}
      </DataTable>
    </section>
  );
}
