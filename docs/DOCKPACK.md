# DockPack format

A DockPack is RedDock's portable Phase 6 report and evidence export. It is a
standard, uncompressed ZIP file built from one immutable Dockyard snapshot. The
reporting runner creates the package locally and never contacts a target, model,
upload service, or other destination.

## Layout

```text
dockpack.json
reports/
  technical.json
  technical.md
  executive.md
evidence/
  manifest.json
  discovery/<run-id>/...
  detection/<run-id>/metadata.json
  detection/<run-id>/normalized/result.json
  validation/<run-id>/...
  correlation/<run-id>/metadata.json
  correlation/<run-id>/normalized/result.json
  intelligence/<run-id>/...
```

`reports/technical.json` is the canonical snapshot used to render both Markdown
reports. Schema `reddock.reporting/2` includes bounded authorization and lab
policy-ledger history alongside inventory, findings, validation, correlation,
and intelligence state. `evidence/manifest.json` binds the Dockyard ID, RedDock version, scope
snapshot hash, cited run IDs, and every finding claim to the retained evidence
that supports it. Its file inventory records each source phase, run ID, original
RedLedger-relative path, portable archive path, media type, byte count, SHA-256,
and truncation state. Because Phase 6 has no filters, `skipped_findings` is always
empty; a finding with unavailable evidence fails the report rather than being
silently skipped.

`dockpack.json` uses schema `reddock.dockpack/1` and contains the SHA-256 and
byte count of every other archive member. It also records
`snapshot_sha256`, which must equal the hash of `reports/technical.json`.
`dockpack.json` does not list itself because a file cannot contain its own
cryptographic hash.

## Reproducibility

RedDock orders every snapshot collection and serializes JSON with stable keys.
Archive member names are sorted; timestamps are fixed at 1980-01-01; Unix file
modes and ZIP storage are fixed. Reporting history is excluded from source
state, and database inputs are captured under one explicit consistent
transaction. Two report runs over unchanged retained state therefore have identical
report hashes and byte-identical DockPack files.

A changed finding, status, approval, lab policy event, run, source artifact, or completed advice
is a changed snapshot and should produce a different package.

## Verification

Before extracting an untrusted DockPack, verify its paths and hashes. This
standard-library Python example reads members without writing them to disk:

```python
import hashlib
import json
import pathlib
import zipfile

package = pathlib.Path("reddock-dockpack.zip")
with zipfile.ZipFile(package) as archive:
    names = archive.namelist()
    assert names == sorted(names)
    assert len(names) == len(set(names))
    assert all(
        not name.startswith(("/", "\\"))
        and "\\" not in name
        and ".." not in pathlib.PurePosixPath(name).parts
        for name in names
    )
    manifest = json.loads(archive.read("dockpack.json"))
    assert manifest["schema"] == "reddock.dockpack/1"
    assert hashlib.sha256(archive.read("reports/technical.json")).hexdigest() == (
        manifest["snapshot_sha256"]
    )
    for member in manifest["members"]:
        payload = archive.read(member["path"])
        assert len(payload) == member["bytes"]
        assert hashlib.sha256(payload).hexdigest() == member["sha256"]
```

The API also verifies the retained DockPack SHA-256 immediately before serving a
download. That protects the RedDock-side copy; the receiving operator remains
responsible for verifying and securely handling any copy that leaves RedDock.

## Handling

A DockPack may expose authorized targets, internal addresses, service banners,
findings, validation or lab authorization notes, lab policy decisions, model advice, and other engagement data.
It contains no deliberate session cookies or provider credentials, but it must
still be treated as sensitive assessment material. Review it before sharing,
apply appropriate access controls and retention policy, and do not publish it
merely because the format is portable. Retained strings are enclosed in
delimiter-safe Markdown code spans, but recipients should still treat report
files as untrusted documents when using third-party renderers.
