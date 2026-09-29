import { Coverage } from "./Coverage";
import { pageUrl } from "./routes";
import type { WorkspaceTab } from "./routes";

export const LOCAL_WALKTHROUGH_TARGET = "http://reddock-ingress:8080";

export function Assessment({ dockyardId, onStep }: {
  dockyardId: number;
  onStep: (tab: WorkspaceTab) => void;
}) {
  return <section className="panel">
    <p className="eyebrow">START HERE</p>
    <h2>Your assessment, step by step</h2>
    <p>Follow these steps in order. Each action stays under your control.</p>
    <ol className="assessment-steps">
      <li><div><strong>Define the allowed target</strong><p>Review the include and exclude rules before collecting anything.</p></div>
        <button className="secondary-button" onClick={() => onStep("Scope")}>Review scope</button></li>
      <li><div><strong>Collect observations</strong><p>Choose a target and profile, check it with DockGuard, then run discovery.</p></div>
        <button className="secondary-button" onClick={() => onStep("Discovery")}>Open discovery</button></li>
      <li><div><strong>Look for findings</strong><p>After discovery finishes, run detection on the stored observations.</p></div>
        <button className="secondary-button" onClick={() => onStep("Detection")}>Open detection</button></li>
      <li><div><strong>Review the result</strong><p>Read the findings, evidence, and coverage below. Zero findings does not mean secure.</p></div>
        <button className="secondary-button" onClick={() => onStep("Findings")}>Review findings</button></li>
      <li><div><strong>Save your report</strong><p>Generate reports after active runs finish. Keep exported evidence private.</p></div>
        <a className="secondary-button" href={pageUrl("Reports", dockyardId)}>Open reports</a></li>
    </ol>
    <Coverage dockyardId={dockyardId} />
    <details className="walkthrough-help">
      <summary>Using the local walkthrough?</summary>
      <p>Choose the HTTP adapter and HTTP probe profile for <code>{LOCAL_WALKTHROUGH_TARGET}</code>.
        This checks RedDock's own proxy inside Compose. It does not check your computer or network.</p>
    </details>
  </section>;
}
