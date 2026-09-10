# RedDock screenshot tour

[Back to RedDock](../../README.md) · [Try the local demo](../GETTING_STARTED.md)

## A quick tour

Click a view to open its full-size screenshot. These are examples, not a claim that your first run will find the same issues.

| View | What it shows |
| --- | --- |
| [Dashboard](dashboard.png) | See your workspaces and recent checking activity. |
| [Workspace](workspace.png) | Define what is allowed before running a check. |
| [Detection](detection.png) | See which rules turn recorded observations into findings. |
| [Findings](findings.png) | Filter issues and read complete first-seen and last-seen dates. |
| [Finding detail](finding-detail.png) | Bookmark an issue and inspect its explanation and evidence. |
| [Settings](settings.png) | Read the current version and deployment gates without exposing secrets. |
| [RedPath](redpath.png) | Explore the relationships between assets and findings. |
| [Reporting](reporting.png) | Read a plain-language summary and a technical report. |
| [Readable manifest](manifest-view.png) | Browse the evidence files without reading raw JSON. |
| [Swagger API explorer](swagger.png) | Inspect and interact with the API when explicitly enabled locally. |
| [Lab controls](lab-mode.png) | Inspect separate authorization for limited lab capabilities. |
| [Detector provenance](plugin-provenance.png) | Identify where an optional custom detection rule came from. |

## Capture provenance and privacy

Every image in the table is a real, scrubbed capture of RedDock running locally.
The gallery uses fictional workspaces, throwaway data, and loopback scope. The
findings, RedPath graph, reports, and manifest came from RedDock checking its own
local service; no outside system was contacted. The plugin image uses a
separately configured data-only detector because the default package loads only
built-in detectors. None of the screenshots is a mockup.

When replacing a screenshot, use empty or clearly fictional data. Do not capture
host paths, other browser tabs, personal information, credentials, or real
assessment details. README images link to their full-resolution files.
