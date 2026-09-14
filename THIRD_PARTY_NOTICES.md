# Third-party notices

RedDock is licensed under the MIT License. Components distributed with its
container image keep their own licenses and copyright terms.

## Nmap

The RedDock runtime image installs the Debian-packaged Nmap network exploration
tool and security/port scanner. Nmap is Copyright (C) 1996-2026 Nmap Software
LLC. Its own license terms govern Nmap; RedDock's MIT license does not replace
them. The packaged `/usr/share/doc/nmap/copyright` file is the authoritative
notice for the exact Debian build in the image.

- Project: <https://nmap.org/>
- License and source information: <https://nmap.org/npsl/>
- Debian package source: <https://sources.debian.org/src/nmap/>

The image records the installed package version in
`/usr/share/reddock-source/nmap/PACKAGE.txt` and includes the matching Debian
source archives and checksums in that directory. See `docs/NMAP_SOURCE_OFFER.md`.

This notice is informational and is not legal advice.
