import { useEffect, useState } from "react";
import { api } from "./api";
import type { LabStatus, Settings } from "./types";

export function SettingsPage({ onError }: { onError: (message: string | null) => void }) {
  const [facts, setFacts] = useState<{ settings: Settings; lab: LabStatus } | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let active = true;
    Promise.all([api.settings(), api.labStatus()]).then(([settings, lab]) => {
      if (active) setFacts({ settings, lab });
    }).catch(() => { if (active) { setFailed(true); onError("Could not load settings."); } });
    return () => { active = false; };
  }, [onError]);
  if (!facts) return <p role="status">{failed ? "Settings are unavailable. Refresh to try again." : "Loading settings..."}</p>;
  const { settings, lab } = facts;
  return <section className="panel detail-panel">
    <p className="hint">Current configuration. These values are read-only.</p>
    <dl>
      <div><dt>Application</dt><dd>{settings.name}</dd></div>
      <div><dt>Version</dt><dd>{settings.version}</dd></div>
      <div><dt>Phase</dt><dd>{settings.phase}</dd></div>
      <div><dt>Deployment mode</dt><dd>{settings.deployment_mode}</dd></div>
      <div><dt>Lab deployment gate</dt><dd>{lab.deployment_enabled ? "Enabled" : "Disabled"}</dd></div>
      <div><dt>Intelligence</dt><dd>{settings.intelligence_configured ? "Configured" : "Not configured"}</dd></div>
    </dl>
  </section>;
}
