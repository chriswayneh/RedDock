# Start here: your first RedDock assessment

[Back to RedDock](../README.md) · [All documentation](README.md) · [Screenshots](screenshots/README.md)

RedDock helps you collect security observations, explain what they mean, and share the evidence. This guide runs a small demonstration against RedDock itself. You do not need to write code, scan your home network, or sign up for an AI service.

By the end, you will have:

- RedDock running only on your computer
- a demonstration Dockyard with recorded observations and findings
- a RedPath view and downloadable report package
- a safe way to stop and resume without deleting your data

## Before you start

- Use a computer where you are allowed to install and run software.
- Install [Docker Desktop](https://docs.docker.com/desktop/) (or Docker Engine with Compose on Linux) and [Git](https://git-scm.com/downloads). Start Docker before continuing.
- Allow time and disk space for the first build. It downloads application dependencies; speed varies by computer and internet connection.
- Keep RedDock local. There is no working user login or shared-user protection yet. Do not open a router port, public tunnel, or internet-facing deployment.

## 1. Download and start

Open PowerShell on Windows or Terminal on macOS/Linux. Paste these commands one at a time and press Enter after each:

```bash
git clone https://github.com/chriswayneh/RedDock.git
cd RedDock
docker compose up --build
```

The first command downloads the project. The second enters its folder. The third builds and starts it. These commands use the latest `master` checkout, which includes unfinished Phase 8 work; the latest tagged release is v0.8.0.

Leave that terminal open. Startup is complete when the output says the application is running and the health check has settled. Then open [RedDock in your browser](http://localhost:8080). An empty dashboard is expected: the app does not scan anything until you ask it to, and it does not come populated with someone else's data.

If you already downloaded the repository, use its existing folder instead of cloning a second copy.

> **Keep RedDock on your computer.** Use the Compose command above. It binds RedDock to `127.0.0.1:8080`, which keeps the current account-free API on your machine. Do not publish it to your network or the internet.

Advanced network settings such as `docker run -p 8080:8080`, a `0.0.0.0`
bind, a public tunnel, or a reverse proxy can expose the API. Those setups are
not supported while sign-in is unfinished.

## 2. Create a demonstration workspace

1. Open **Dockyards** and create a Dockyard named `My first local demo`. A Dockyard is simply a workspace for one assessment.
2. Open that workspace's **Scope** tab. Add an **include** entry for exactly `http://127.0.0.1:8080`.
3. Use the scope check on the same target. DockGuard should return `ALLOWED`.

Scope is your allowlist, not permission from a system's owner. For real assessments you must separately obtain authorization. In this example, `127.0.0.1` means the application container itself, so the check stays inside your local RedDock setup. It does not assess the rest of your computer or network.

## 3. Collect observations and look for findings

1. Open **Discovery**.
2. Choose the **HTTP** adapter and the `http_probe` profile.
3. Enter `http://127.0.0.1:8080`.
4. Select **Check with DockGuard**. This tab needs its own check even if you already checked the target under Scope.
5. When the result says `ALLOWED`, select **Run discovery**.
6. Wait for the run to finish. **Assets**, **Services**, and **Observations** now show what RedDock recorded.
7. Open **Detection** and select **Run detection**. Then open **Findings** to inspect the results and their evidence.

A finding is a rule's conclusion, not proof that someone can break in. A missing security header is not the same as a compromised server. Zero findings is also a valid result; it means these checks did not produce findings, not that the system has no vulnerabilities. Results may differ from screenshots as the application changes.

**Validation** is optional. Only eligible open HTTP header findings can be rechecked. Creating a request does not run it; a separate approval note authorizes the limited probe. You can skip it for this tour.

## 4. See the relationships and take the report with you

1. Open **RedPath**, select your Dockyard, and choose **Run correlation**. Inspect the graph and click a relationship to see why it exists. Small or clean assessments may have few relationships.
2. Open **Reporting**, select the same Dockyard, and choose **Generate report set** after source runs finish.
3. Read the executive and technical previews. Open the readable manifest for a list of supporting files, or download the **DockPack** ZIP to retain the reports and evidence together.

The plain-language report summarizes the result. The technical report and source files show the details behind it. File hashes act like digital fingerprints that reveal changed bytes; they do not prove that every conclusion is correct or certify security. Treat real assessment exports as sensitive and review them before sharing.

Click the RedDock name/logo to return to the main dashboard.

## 5. Stop now, resume later

In the terminal running RedDock, press **Ctrl+C**. Then run:

```bash
docker compose down
```

Your default local database and evidence stay in Docker's named data volume. To resume, open a terminal in the same RedDock folder and run `docker compose up --build`, then reopen the browser link.

Do not add `-v` to the shutdown command unless you intend to delete that stored data. Docker volume cleanup can also delete it. Persistent storage is not a backup; do not make this local setup the only copy of important assessment evidence.

## Finding your way around

Each page has its own browser address. Bookmark a Dockyard tab or a finding to
return to it after a refresh. Browser Back and Forward work, and the RedDock logo
returns to the dashboard. Assets, Findings, and RedLedger remember the Dockyard
in the address, so switching pages keeps the same workspace.

The dashboard counts all matching records, not just the first page. Inventory,
evidence, findings, lab audit, and run-history pages show the visible row range
and offer Previous and Next buttons when there are more than 100 records.
Settings is a read-only summary of the version, local deployment mode, lab gate,
and whether AI is configured. It does not show keys or passwords and cannot
change those settings.

## Optional API explorer

You do not need Swagger to use RedDock. Developers can enable it by adding this
line to a local, untracked `.env` file beside `compose.yaml`:

```text
REDDOCK_API_DOCS_ENABLED=true
```

Run `docker compose up -d --build` again, then open
[Swagger](http://localhost:8080/docs). The schema is at `/openapi.json` and ReDoc
is at `/redoc`. To disable them, remove the line or set it to `false`, then run
the same Compose command again. They return 404 when disabled.

Swagger can call the same actions as the app, including starting authorized
discovery. This switch is not authentication. Keep the supported Compose
loopback bind; never publish this local-mode service to your network.

## Do I need AI?

No. Start with the normal package above. Discovery, findings, validation, RedPath, and reporting work without an LLM (an AI language model).

For optional advice, the [local AI guide](LOCAL_AI.md) explains the Ollama bundle with Qwen3.5 4B, other compatible models, and cloud providers. The bundle downloads model files separately and needs extra storage and computing resources. You review the evidence packet and approve transmission before advice is requested. Cloud providers receive that approved packet; AI is not an autonomous scanner.

## If something does not work

| What you see | What to try |
| --- | --- |
| `git` or `docker` is not recognized | Install the missing prerequisite and reopen your terminal. |
| Docker cannot connect to its engine | Start Docker Desktop and wait until its engine is ready. |
| The browser cannot reach RedDock | Wait for the build/startup to finish; use `http://localhost:8080`, not HTTPS. Check the terminal for errors. |
| Port 8080 is already in use | Stop the other application using that port if it is yours and safe to stop. Do not broaden RedDock's network binding to work around it. |
| DockGuard denies the demo | Check that the include entry and discovery target both match `http://127.0.0.1:8080` exactly, and no exclusion blocks it. Do not disable the guard. |
| Detection or reports are empty | Confirm discovery completed and detection ran in the same Dockyard. Empty findings can be legitimate. |
| Reporting refuses a run | Finish active source runs first and read the displayed error. Missing or altered evidence must not be bypassed. |

For help, collect the error and your Docker version. Review logs and screenshots for private targets, tokens, and personal data before posting a [bug report](https://github.com/chriswayneh/RedDock/issues). Report security vulnerabilities [privately](../SECURITY.md), not in public issues.

## The names, translated

| Name | Plain English |
| --- | --- |
| Dockyard | A workspace for one assessment. |
| Scope / DockGuard | The allowed targets and the server-side rule checker that enforces them. |
| Discovery / observation | A controlled check and a record of what it saw. |
| Detection / finding | A rule evaluating stored observations and the issue it reports. |
| Validation | A separately approved, limited recheck of an eligible finding. |
| RedPath | A picture of evidence-supported relationships, not a prediction of a break-in. |
| RedLedger | The retained evidence records behind the work. |
| Manifest / DockPack | The evidence file list and the portable ZIP containing the report package. |
| Swagger / API | An interactive technical interface for developers; not needed for this walkthrough. |

## What comes next?

Try the local demo before adding real, explicitly authorized targets. RedDock is currently best used in small, controlled environments. [Phase 8](../ROADMAP.md#phase-8-production-polish) still has known work around authentication and production operations. Working accounts, SSO, and shared-user deployments are not available yet.
