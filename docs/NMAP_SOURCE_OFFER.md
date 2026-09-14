# Nmap corresponding source

RedDock container images include the Debian-packaged Nmap binary. Nmap remains
under its own license; the repository's MIT License does not replace those
terms.

See [Third-party notices](../THIRD_PARTY_NOTICES.md) for the bundled component
summary.

Every image built from the security-updated source carries the matching Debian
source archives in `/usr/share/reddock-source/nmap`. `PACKAGE.txt` records the
installed binary package version and `SHA256SUMS` records the expected hashes of
the included source files. You can copy the directory from an image without
starting RedDock:

```bash
image='ghcr.io/chriswayneh/reddock:vX.Y.Z'
container_id=$(docker create "$image")
trap 'docker rm -f "$container_id" >/dev/null 2>&1 || true' EXIT INT TERM
docker cp "${container_id}:/usr/share/reddock-source/nmap" ./nmap-source
docker rm "$container_id"
trap - EXIT INT TERM
```

If you received a RedDock image without those files, open a GitHub issue with
the image digest and release tag. The project owner will provide the
corresponding source used for that image for at least three years after its
distribution.

Upstream licensing and source details are available from the [Nmap project](https://nmap.org/npsl/)
and [Debian Sources](https://sources.debian.org/src/nmap/).

This document describes the project's distribution practice and is not legal
advice.
