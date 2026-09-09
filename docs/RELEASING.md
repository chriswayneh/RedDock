# Release process

[Back to the documentation index](README.md)

RedDock releases are published from one reviewed commit on `master`. The release
workflow refuses a version tag unless all package metadata, the application API,
the README, roadmap, and changelog agree on the same version.

## What the workflow publishes

After the complete backend, frontend, and production-container smoke checks
pass, the workflow:

1. Builds one production image for AMD64 and ARM64.
2. Publishes versioned and `latest` tags to GitHub Container Registry.
3. Adds GitHub build-provenance attestation for the exact image digest.
4. Creates the matching GitHub Release with generated change notes.

The workflow grants write access only to its publish job. All referenced actions
are pinned to full commit hashes. A failed architecture build publishes neither
the multi-platform manifest nor the GitHub Release.

## Prepare a release

1. Change the version in `backend/pyproject.toml`, `backend/app/config.py`,
   `frontend/package.json`, and both root version fields in
   `frontend/package-lock.json`.
2. Move the completed changelog entries into a versioned section.
3. Update README and roadmap release status and links.
4. Run the full checks in [CONTRIBUTING.md](../CONTRIBUTING.md).
5. Merge the reviewed release-preparation pull request into `master` and confirm
   all required GitHub checks pass.
6. Create one annotated `vMAJOR.MINOR.PATCH` tag on that exact merge commit and
   push only that tag to `origin`.

Do not retag, force-push, or publish from a feature branch. If verification
fails, fix the source on a new branch and create a new reviewed commit before
trying again.
