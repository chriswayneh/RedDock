# Screenshots

[Back to RedDock](../../README.md) · [Try the local demo](../GETTING_STARTED.md)

## A quick product tour

Click a view to open its full-size screenshot. These are examples, not a claim that your first run will find the same issues.

| View | What you get from it |
| --- | --- |
| [Dashboard](dashboard.png) | See your workspaces and recent checking activity. |
| [Workspace](workspace.png) | Define what is allowed before running a check. |
| [Detection](detection.png) | See which rules turn recorded observations into findings. |
| [Findings](findings.png) | Understand an issue and inspect its supporting evidence. |
| [RedPath](redpath.png) | Explore the relationships between assets and findings. |
| [Reporting](reporting.png) | Prepare a management summary and technical handoff. |
| [Readable manifest](manifest-view.png) | Browse the evidence files without reading raw JSON. |
| [Swagger API explorer](swagger.png) | Let technical users inspect and interact with the API. |
| [Lab controls](lab-mode.png) | Inspect separate authorization for limited lab capabilities. |
| [Detector provenance](plugin-provenance.png) | Identify where an optional custom detection rule came from. |

## Capture provenance and privacy

`dashboard.png`, `workspace.png`, `detection.png`, `findings.png`, `redpath.png`, `reporting.png`, `manifest-view.png`, `swagger.png`, `lab-mode.png`, and `plugin-provenance.png` are real, scrubbed captures of RedDock running locally against loopback. When replacing them, use an empty Dockyard list or clearly fictional local sample data; do not capture host paths, browser tabs, personal information, or authorized-engagement details.

The current captures use fictional workspaces, a loopback scope, and a deliberately out-of-scope target so the DockGuard denial is visible. The findings, RedPath graph, and reports shown are produced by RedDock against its own origin inside the container, so nothing outside the machine was contacted to make them. The manifest capture shows the readable HTML view while preserving the adjacent raw-JSON option. The Swagger capture shows the application-generated OpenAPI contract. README images link to their full-resolution files.

The gallery was refreshed from the rebuilt `master` application after commit
`cb6b862`; `plugin-provenance.png` retains the separately configured, data-only
plugin capture because the default package intentionally loads built-in
detectors only.

The README intentionally does not present a mockup as a product screenshot.
