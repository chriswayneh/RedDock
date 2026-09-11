# SQLite backup and restore

[Back to the documentation index](README.md)

This procedure protects the default, local RedDock package: its SQLite database
and the retained RedLedger evidence in the `reddock-data` volume. It does not
back up PostgreSQL, Ollama models, source code, or configuration outside that
volume. PostgreSQL operators must use a PostgreSQL-native, transactionally
consistent backup procedure instead.

RedDock backups are ZIP-compatible `.rdbackup` files. They are **not encrypted**.
Treat them as sensitive assessment data and never commit them. The default
`./backups` directory is convenient for evaluation, but Git ignore rules are not
an access-control boundary. Move durable copies to encrypted storage protected
by the host's access controls, or set an external backup directory as described
below.

## What RedDock verifies

Creation and verification fail closed unless all of these checks pass:

- RedDock is explicitly declared offline and no SQLite journal, WAL, or shared
  memory sidecar exists.
- The SQLite database passes `quick_check` and `foreign_key_check` and names a
  database migration revision this RedDock build understands. Every table and
  column required by that exact revision must also be present.
- Every regular database and evidence file is listed once under a portable,
  traversal-safe path, with bounded counts and sizes and a SHA-256 digest.
- Database evidence records and completed-run artifact hashes resolve to files
  in the backup with the expected sizes and hashes. Validation-package
  manifests are parsed too, so their raw HTTP recheck, normalized result, and
  metadata declarations cannot bless a missing or changed artifact.
- The manifest is strict UTF-8 JSON, archive members use the fixed private file
  mode, and links, device-like entries, encryption, unsupported compression,
  case aliases, and undeclared files are refused.

Verification extracts only the archived database into private temporary storage
for its SQLite checks. A database is limited to 2 GiB and the complete
uncompressed backup to 4 GiB. The maintenance container provides an 8 GiB
temporary filesystem so a maximum-size streamed archive, extracted database,
and bounded overhead do not compete for the same last bytes.

## Prepare a backup directory

The maintenance overlay uses `./backups` by default. That directory and
`.rdbackup` files are ignored by Git.

PowerShell:

```powershell
New-Item -ItemType Directory -Force .\backups | Out-Null
```

On Windows, `./backups` inherits the checkout directory's NTFS permissions.
Use it only for evaluation unless those permissions are appropriate. Store real
backups in a BitLocker- or otherwise encrypted location whose NTFS ACL grants
access only to the intended operator and administrators. POSIX `0600` mode bits
inside a Docker bind mount do not replace Windows access controls.

Bash or zsh on Linux (keep the directory private and make exported files belong
to your host account):

```bash
mkdir -p -m 700 ./backups
export REDDOCK_MAINTENANCE_UID="$(id -u)"
```

### Keep the same Compose project name

The application and maintenance commands must use the same Compose project name
so they address the same `reddock-data` volume. The examples below assume you
started RedDock from this checkout without `-p` or `COMPOSE_PROJECT_NAME`.

If you started it with a custom name such as `-p my-reddock`, add that exact
option immediately after `docker compose` in every stop, backup, restore,
recovery, and restart command. If you set `COMPOSE_PROJECT_NAME`, keep the same
value set for the entire procedure. Do not continue if you are unsure which
project owns the data volume.

To use another existing directory, set `REDDOCK_BACKUP_DIR` to its absolute
path before each Compose command. Keep `REDDOCK_MAINTENANCE_UID` set on Linux
for every backup and verification command. The container then reads the
application-owned volume through the image's stable RedDock group (GID 999)
while the exported
`0600` archive is owned by your host user; no world-writable host directory is
needed. The image pins both the RedDock UID and GID to 999 and CI checks that
contract. Docker Desktop users should leave this variable unset.

PowerShell:

```powershell
$env:REDDOCK_BACKUP_DIR = (Resolve-Path 'D:\RedDock Backups').Path
```

Bash or zsh:

```bash
export REDDOCK_BACKUP_DIR="/secure/reddock-backups"
export REDDOCK_MAINTENANCE_UID="$(id -u)"
```

## Create an offline backup

1. Stop the default SQLite application without deleting its volume:

   ```bash
   docker compose down
   docker compose ps
   ```

   `docker compose ps` must show no running RedDock application. Do not use
   `down -v`; that deletes the volume being backed up. If you launched RedDock
   under another Compose project name or from another checkout, stop that exact
   project and carry its project name through every maintenance command as
   described above. The maintenance command cannot detect unrelated containers
   or host processes that still have the database open.

2. Create a new, uniquely named backup:

   ```bash
   docker compose -f compose.yaml -f compose.maintenance.yaml build reddock-backup
   docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-backup create --data-dir /var/lib/reddock --output /backups/reddock-2026-09-10.rdbackup --confirm-offline
   ```

   The maintenance container has no network, ports, Linux capabilities, or
   writable root filesystem. For creation, the RedDock data volume is read-only
   and only the backup directory and a bounded sticky temporary filesystem are
   writable. Each operation still creates its own private `0700` temporary
   directory. On POSIX hosts, the command creates the archive as `0600` from its
   first byte. It verifies the archive before publishing it and prints the
   SHA-256 on every platform.

3. Save the printed SHA-256 separately from the backup. Optionally confirm it on
   the host with `Get-FileHash` in PowerShell or `sha256sum` on Linux.

An existing output is never silently replaced. Prefer a new dated name. The
lower-level command has `--confirm-overwrite` for a deliberate replacement, but
normal rotation should retain multiple known-good backups.

With Make, the equivalent shortcut is:

```bash
make backup-sqlite BACKUP_FILE=reddock-2026-09-10.rdbackup
```

## Verify a stored backup

Verification needs no RedDock data-volume access, and the backup directory is
mounted read-only on Docker Desktop. On a fresh recovery host, build the pinned
maintenance image before the first verification:

```bash
docker compose -f compose.yaml -f compose.maintenance.yaml build reddock-verify
```

First compare the archive's current SHA-256 with the trusted value saved when
the backup was created. Do not restore it if the values differ:

```powershell
Get-FileHash .\backups\reddock-2026-09-10.rdbackup -Algorithm SHA256
```

```bash
sha256sum ./backups/reddock-2026-09-10.rdbackup
```

Then run RedDock's internal verification. In PowerShell, use the mounted path
directly:

```powershell
docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-verify verify --archive /backups/reddock-2026-09-10.rdbackup
```

On Linux, retain the host-owned `0600` mode and stream the file over standard
input. `-T` disables terminal allocation so no bytes are transformed. RedDock
spools at most the fixed archive limit into a private `0600` seekable temporary
file, then verifies and extracts through that same opened archive identity:

```bash
docker compose -f compose.yaml -f compose.maintenance.yaml run -T --rm --no-deps reddock-verify verify --archive - < ./backups/reddock-2026-09-10.rdbackup
```

Or use:

```bash
make verify-sqlite-backup BACKUP_FILE=reddock-2026-09-10.rdbackup
```

Verify backups after copying them to another disk and as part of periodic
recovery drills. A successful check proves the archive is internally consistent
and compatible with this build; it does not prove the storage medium will remain
available.

## Restore and test recovery

Restoring replaces the current database and evidence set. First create and
verify a fresh backup of the current state, then keep the application stopped.

PowerShell / Docker Desktop:

```powershell
docker compose down
docker compose -f compose.yaml -f compose.maintenance.yaml build reddock-verify reddock-restore
docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-verify verify --archive /backups/reddock-2026-09-10.rdbackup
docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-restore restore --data-dir /var/lib/reddock --archive /backups/reddock-2026-09-10.rdbackup --confirm-offline --confirm-replace
docker compose up -d --build --wait --wait-timeout 120
docker compose ps
```

Linux (stream the private host file into both commands):

```bash
docker compose down
docker compose -f compose.yaml -f compose.maintenance.yaml build reddock-verify reddock-restore
docker compose -f compose.yaml -f compose.maintenance.yaml run -T --rm --no-deps reddock-verify verify --archive - < ./backups/reddock-2026-09-10.rdbackup
docker compose -f compose.yaml -f compose.maintenance.yaml run -T --rm --no-deps reddock-restore restore --data-dir /var/lib/reddock --archive - --confirm-offline --confirm-replace < ./backups/reddock-2026-09-10.rdbackup
docker compose up -d --build --wait --wait-timeout 120
docker compose ps
```

For the restore service, the archive directory is read-only and only the data
volume is writable. RedDock fully validates and stages the archive before it
moves current data. Each path replacement is atomic on the volume, and an
ordinary failure rolls both paths back.

The database and evidence directory are two filesystem paths, so RedDock does
**not** claim that their replacement is a single crash-atomic filesystem
operation. A recovery marker records prepared versus committed state. If the
process or host stops between replacements, application startup fails closed
until the explicit recovery command either rolls the prepared change back or
finishes cleanup of a committed change.

First inspect the recovery state without authorizing either destructive action.
This command reports `prepared` or `committed` and tells you which confirmation
is required. Its exit code is `2` because no action was authorized; that is
expected for this inspection step:

```bash
docker compose -f compose.yaml -f compose.maintenance.yaml build reddock-recover
docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-recover recover --data-dir /var/lib/reddock --confirm-offline
```

For a `prepared` restore, use `--confirm-rollback` to restore the previous
database and evidence. For a `committed` restore, inspect the restored pair and
use `--confirm-finalize` to keep it and permanently delete the previous rollback
copies. The two confirmations are mutually exclusive:

```bash
# Prepared state only: return to the previous data.
docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-recover recover --data-dir /var/lib/reddock --confirm-offline --confirm-rollback

# Committed state only: keep restored data and delete the old rollback copies.
docker compose -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-recover recover --data-dir /var/lib/reddock --confirm-offline --confirm-finalize
```

Then start RedDock and require database readiness before inspection:

```bash
docker compose up -d --build --wait --wait-timeout 120
docker compose ps
```

The `--wait` option returns successfully only after the `reddock` service is
healthy. If it times out, inspect `docker compose logs reddock`; an incomplete
restore marker must be resolved with the recovery command before startup can
continue.

Open [http://localhost:8080](http://localhost:8080) after the wait succeeds.
Confirm expected Dockyard counts, open several findings, view raw evidence, and
download a known report or DockPack. A real recovery drill should do this on a
disposable copy of the volume before the backup is relied on.

### Disposable readiness drill

This compact drill proves that a backup restores into a fresh volume and reaches
database readiness. It does not provide the visual inspection described above.
The drill generates a new project name, refuses to reuse an existing container
or volume, never mounts the normal RedDock volume, and gives the test container
no network access.

Linux:

```bash
set -euo pipefail
export REDDOCK_MAINTENANCE_UID="$(id -u)"
export REDDOCK_DRILL_PROJECT="reddock-drill-$(tr -d '-' < /proc/sys/kernel/random/uuid | cut -c1-12)"
export REDDOCK_DRILL_CONTAINER="${REDDOCK_DRILL_PROJECT}-ready"
if docker container inspect "$REDDOCK_DRILL_CONTAINER" >/dev/null 2>&1 || docker volume inspect "${REDDOCK_DRILL_PROJECT}_reddock-data" >/dev/null 2>&1; then echo "Refusing to reuse existing drill resources" >&2; exit 1; fi
cleanup_reddock_drill() {
  docker rm -f "$REDDOCK_DRILL_CONTAINER" 2>/dev/null || true
  docker compose -p "$REDDOCK_DRILL_PROJECT" -f compose.yaml -f compose.maintenance.yaml down -v --remove-orphans
}
trap cleanup_reddock_drill EXIT
docker compose -p "$REDDOCK_DRILL_PROJECT" -f compose.yaml -f compose.maintenance.yaml build reddock-restore
docker compose -p "$REDDOCK_DRILL_PROJECT" -f compose.yaml -f compose.maintenance.yaml run -T --rm --no-deps reddock-restore restore --data-dir /var/lib/reddock --archive - --confirm-offline --confirm-replace < ./backups/reddock-2026-09-10.rdbackup
docker run -d --name "$REDDOCK_DRILL_CONTAINER" --network none --cap-drop ALL --security-opt no-new-privileges -v "${REDDOCK_DRILL_PROJECT}_reddock-data:/var/lib/reddock" reddock:maintenance
ready=false
for attempt in $(seq 1 20); do
  if docker exec "$REDDOCK_DRILL_CONTAINER" python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/api/ready')"; then ready=true; break; fi
  sleep 2
done
if [ "$ready" != true ]; then
  docker logs "$REDDOCK_DRILL_CONTAINER"
  exit 1
fi
cleanup_reddock_drill
trap - EXIT
```

PowerShell:

```powershell
$drill = 'reddock-drill-' + ([guid]::NewGuid().ToString('N').Substring(0, 12))
$container = "$drill-ready"
$null = docker container inspect $container 2>$null
if ($LASTEXITCODE -eq 0) { throw 'Refusing to reuse an existing drill container' }
$null = docker volume inspect "${drill}_reddock-data" 2>$null
if ($LASTEXITCODE -eq 0) { throw 'Refusing to reuse an existing drill volume' }
function Remove-RedDockDrill {
    docker rm -f $container 2>$null
    docker compose -p $drill -f compose.yaml -f compose.maintenance.yaml down -v --remove-orphans
}
docker compose -p $drill -f compose.yaml -f compose.maintenance.yaml build reddock-restore
if ($LASTEXITCODE -ne 0) { Remove-RedDockDrill; throw 'Disposable image build failed' }
docker compose -p $drill -f compose.yaml -f compose.maintenance.yaml run --rm --no-deps reddock-restore restore --data-dir /var/lib/reddock --archive /backups/reddock-2026-09-10.rdbackup --confirm-offline --confirm-replace
if ($LASTEXITCODE -ne 0) { Remove-RedDockDrill; throw 'Disposable restore failed' }
docker run -d --name $container --network none --cap-drop ALL --security-opt no-new-privileges -v "${drill}_reddock-data:/var/lib/reddock" reddock:maintenance
if ($LASTEXITCODE -ne 0) { Remove-RedDockDrill; throw 'Disposable startup failed' }
$ready = $false
for ($attempt = 1; $attempt -le 20; $attempt++) {
    docker exec $container python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:8080/api/ready')"
    if ($LASTEXITCODE -eq 0) { $ready = $true; break }
    Start-Sleep -Seconds 2
}
if (-not $ready) {
    docker logs $container
    Remove-RedDockDrill
    throw 'Disposable RedDock did not become ready'
}
Remove-RedDockDrill
```

Initial connection failures during either readiness loop are expected while the
restored application starts. A successful loop means `/api/ready` answered within
about 40 seconds. Run cleanup only with the exact disposable project name you
chose. `down -v` is destructive to that project's volume and must never be
substituted into the normal backup procedure.

With Make, restore and recovery shortcuts are:

```bash
make restore-sqlite-backup BACKUP_FILE=reddock-2026-09-10.rdbackup
make recover-sqlite-restore
make rollback-sqlite-restore
make finalize-sqlite-restore
```

The first recovery shortcut only reports the required state-specific action and
therefore exits unsuccessfully. Run only the matching rollback or finalize
shortcut after reviewing that report.

## Host-native command

Developers with the backend installed under Python 3.13 can run the same tool
from the `backend` directory:

```bash
python -m app.backup --help
```

Use host paths for `--data-dir`, `--output`, and `--archive`. The same explicit
offline, overwrite, replacement, and recovery confirmations apply. Compose is
the normal operator path because it fixes mounts and removes network access.

On POSIX filesystems, RedDock flushes staged files, archive files, restore
markers, and their parent directories in state-machine order. This supports
recovery after process or host interruption within the guarantees of the
filesystem and storage hardware; it still is not a single atomic replacement.
Native Windows Python can flush file contents but does not provide the same
directory-fsync primitive, so ordinary process-failure rollback is supported
but sudden power-loss ordering is not promised. Docker Desktop stores the named
volume inside its Linux environment, though whole-host power-loss behavior still
depends on Docker Desktop and the host filesystem. A `0600` mode is enforced on
POSIX; on Windows, also protect the archive directory with an appropriate NTFS
ACL because POSIX mode bits are not an NTFS access-control boundary.
