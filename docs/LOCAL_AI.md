# Local and configurable AI

RedDock's intelligence feature is optional, advice-only, and disabled by
default. The recommended local starting point is
[Qwen3.5 4B](https://huggingface.co/Qwen/Qwen3.5-4B) through
[Ollama](https://ollama.com/library/qwen3.5). It is a small Apache-2.0-licensed
model with a practical local footprint; the Ollama package is approximately
3.4 GB. Model weights are never bundled with RedDock.

The recommendation is a default, not a lock-in. RedDock uses the narrow
OpenAI-compatible `/chat/completions` contract, so an operator can select a
different Ollama model, LM Studio, vLLM, or a cloud endpoint that implements the
same response shape. Provider destination, model, and credential remain trusted
process configuration. They are never accepted by the RedDock API or UI.

## Recommended Ollama setup

Install Ollama using its official instructions, then fetch and start the model:

```bash
ollama pull qwen3.5:4b
ollama serve
```

Run RedDock with the opt-in Compose override:

```bash
docker compose -f compose.yaml -f compose.ollama.yaml up --build
```

The override uses `http://host.docker.internal:11434/v1` and defaults to
`qwen3.5:4b`. To use another installed model:

```powershell
$env:REDDOCK_LLM_MODEL = "qwen3.5:9b"
docker compose -f compose.yaml -f compose.ollama.yaml up --build
```

```bash
REDDOCK_LLM_MODEL=qwen3.5:9b \
  docker compose -f compose.yaml -f compose.ollama.yaml up --build
```

The host mapping works with Docker Desktop and is explicitly added for Linux
Docker. Ollama must listen on an interface reachable from the container. Do not
expose it to an untrusted network.

## Any compatible provider

Supply these variables to the RedDock container through a local Compose
override, orchestrator secret, or other deployment configuration:

| Variable | Required | Meaning |
| --- | --- | --- |
| `REDDOCK_LLM_BASE_URL` | Yes | OpenAI-compatible API base ending before `/chat/completions` |
| `REDDOCK_LLM_MODEL` | Yes | Provider-specific model identifier |
| `REDDOCK_LLM_API_KEY` | Provider-dependent | Bearer credential; never stored or returned by RedDock |

Credentialed and non-local endpoints must use HTTPS. HTTP is accepted only for
loopback or `host.docker.internal` without a credential. Redirects are refused.
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
