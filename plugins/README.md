# RedDock detector plugins

Phase 7 detector plugins are bounded JSON data, not executable code. A manifest
may compare one scalar field from an observation RedDock already retained with
one fixed value. RedDock performs the comparison and constructs the finding;
the manifest receives no filesystem, network, database, process, import,
template, target, or tool capability.

The format is `reddock.detector-plugin/1`. See the
[JSON Schema](../docs/schemas/detector-plugin-v1.schema.json) and the
[example](examples/example-server.json.example).

## Install

Place reviewed `*.json` manifests in a deployment-owned directory, mount that
directory read-only into the container, and set the process-level configuration:

```yaml
services:
  reddock:
    environment:
      REDDOCK_DETECTOR_PLUGIN_DIR: /etc/reddock/detectors
    volumes:
      - ./my-reviewed-detectors:/etc/reddock/detectors:ro
```

Restart RedDock after any manifest change. The complete set is validated and
frozen at startup; malformed, oversized, duplicated, or unknown content stops
the application rather than being ignored. `GET /api/detectors` publishes each
plugin's exact manifest SHA-256 and a content-addressed detector version.

## Trust and review

A manifest cannot execute code, but it can still author a misleading finding.
Treat it as policy: review its claims, pin its SHA-256 in deployment records,
test it against representative observations, and accept changes through the
same review process as source code. Never put credentials or engagement data in
a manifest. Detector strings can appear in findings and DockPacks.

Hard limits are fixed in RedDock: 16 manifests, 256 KiB per manifest, and 50
rules per manifest. Symlinks, duplicate JSON keys, duplicate IDs, unknown
fields, empty rule sets, and identifiers outside the plugin namespace are
rejected.
