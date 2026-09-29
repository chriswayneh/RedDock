import { useEffect, useState } from "react";
import { api } from "./api";
import type { AssessmentCoverage } from "./types";

export function Coverage({ dockyardId, refreshKey = 0 }: { dockyardId: number; refreshKey?: number }) {
  const [coverage, setCoverage] = useState<AssessmentCoverage | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let active = true;
    setCoverage(null);
    setFailed(false);
    api.coverage(dockyardId).then((result) => { if (active) setCoverage(result); })
      .catch(() => { if (active) setFailed(true); });
    return () => { active = false; };
  }, [dockyardId, refreshKey]);
  const labels = { checked: "Checked", collected: "Detection needed", not_checked: "Not checked" };
  return (
    <section className="coverage-summary" aria-label="Assessment coverage">
      <h3>What was checked?</h3>
      {coverage ? <>
        <ul className="coverage-list">
          {coverage.checks.map((check) => <li key={check.id}>
            <span>{check.title}</span>
            <strong>{labels[check.status]}</strong>
            <small>{check.reviewed_observation_count} reviewed / {check.observation_count} collected observations</small>
          </li>)}
        </ul>
        <p className="hint">{coverage.limitation}</p>
        <details>
          <summary>What this release does not test</summary>
          <p className="hint">{coverage.unsupported.join(", ")}.</p>
        </details>
      </> : <p role="status">{failed ? "Coverage could not be loaded. Refresh to try again." : "Loading coverage..."}</p>}
    </section>
  );
}
