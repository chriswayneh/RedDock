# Screenshots

`dashboard.png`, `workspace.png`, `detection.png`, `findings.png`, `redpath.png`, `reporting.png`, `manifest-view.png`, `swagger.png`, `lab-mode.png`, and `plugin-provenance.png` are real, scrubbed captures of RedDock running locally against loopback. When replacing them, use an empty Dockyard list or clearly fictional local sample data; do not capture host paths, browser tabs, personal information, or authorized-engagement details.

The current captures use fictional workspaces, a loopback scope, and a deliberately out-of-scope target so the DockGuard denial is visible. The findings, RedPath graph, and reports shown are produced by RedDock against its own origin inside the container, so nothing outside the machine was contacted to make them. The manifest capture shows the readable HTML view while preserving the adjacent raw-JSON option. The Swagger capture shows the application-generated OpenAPI contract. README images link to their full-resolution files.

The gallery was refreshed from the rebuilt `master` application after commit
`cb6b862`; `plugin-provenance.png` retains the separately configured, data-only
plugin capture because the default package intentionally loads built-in
detectors only.

The README intentionally does not present a mockup as a product screenshot.
