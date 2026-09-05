# Local and configurable AI

RedDock's intelligence feature is optional, advice-only, and disabled by
default. The recommended local starting point is
[Qwen3.5 4B](https://huggingface.co/Qwen/Qwen3.5-4B) through
[Ollama](https://ollama.com/library/qwen3.5). It is a small Apache-2.0-licensed
model with a practical local footprint; its current Ollama package is
approximately 3.4 GB. RedDock packages an optional pinned Ollama runtime and
model-provisioning workflow, but model weights are downloaded into a local
named volume rather than committed to Git or baked into the RedDock image.

The recommendation is a default, not a lock-in. RedDock uses the narrow
OpenAI-compatible `/chat/completions` contract, so an operator can select a
different Ollama model, LM Studio, vLLM, or a cloud endpoint that implements the
same response shape. Provider destination, model, and credential remain trusted
process configuration. They are never accepted by the RedDock API or UI.

## Two packages, one codebase

The no-LLM core is the default:

```bash
docker compose up --build
```

Every product feature except optional Intelligence works in this shape. It has
no model runtime, model download, model network path, or AI memory footprint.

The local-AI bundle is explicit:

```bash
docker compose -f compose.yaml -f compose.ollama.yaml up --build
```

It starts Ollama on the private Compose network, downloads `qwen3.5:4b` on the
first run, and stores the model in the `reddock-ollama` volume. Ollama has no
host port, so only services on that Compose network can reach it. Later starts
reuse the volume. The pinned Ollama image supports AMD64 and ARM64; model speed
and memory requirements still depend on the host.

To remove the containers while retaining RedDock data and model weights:

```bash
docker compose -f compose.yaml -f compose.ollama.yaml down
```

Removing `reddock-ollama` deletes the downloaded model and requires a new
download. Removing `reddock-data` deletes RedDock's database and evidence; keep
those lifecycle decisions separate.

## Choose another Ollama model

Set the model before the first bundled start (or before recreating the model
initializer):

```powershell
$env:REDDOCK_LLM_MODEL = "qwen3.5:9b"
docker compose -f compose.yaml -f compose.ollama.yaml up --build
```

```bash
REDDOCK_LLM_MODEL=qwen3.5:9b \
  docker compose -f compose.yaml -f compose.ollama.yaml up --build
```

The value is passed to both RedDock and the model initializer. Review a model's
license, provenance, resource requirements, and data behavior before using it.

## Any compatible provider

To use an existing Ollama, LM Studio, vLLM, or cloud provider instead of the
bundle, supply these variables to the RedDock container through a private local
Compose override, orchestrator secret, or other deployment configuration:

| Variable | Required | Meaning |
| --- | --- | --- |
| `REDDOCK_LLM_BASE_URL` | Yes | OpenAI-compatible API base ending before `/chat/completions` |
| `REDDOCK_LLM_MODEL` | Yes | Provider-specific model identifier |
| `REDDOCK_LLM_API_KEY` | Provider-dependent | Bearer credential; never stored or returned by RedDock |

Credentialed and non-local endpoints must use HTTPS. HTTP is accepted only for
loopback, `host.docker.internal`, or the fixed private Compose service name
`ollama`, and only without a credential. Redirects are refused.
Keep secrets out of committed Compose files and shell history; use a secret
manager where possible.

## What the model can and cannot do

Creating an intelligence run freezes and hashes the exact evidence-linked
packet without contacting the provider. The UI displays that packet and its
destination. Only a second action with an approval note sends it. Output must
match RedDock's strict schema and cite only finding IDs and evidence hashes from
the reviewed packet.

The model receives no tools, shell, database, credentials, target selector,
DockGuard access, or state-changing API. Its output is retained advice and
cannot alter findings, start discovery or validation, change scope, or apply a
remediation. RedDock remains fully functional when no provider is configured.
