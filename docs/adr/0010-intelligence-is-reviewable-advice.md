# ADR 0010: Intelligence is reviewable advice

- Status: Accepted
- Date: 2026-09-04

## Context

RedDock's first four phases produce deterministic, evidence-linked state. An
optional language model can help an operator prioritize findings and turn the
existing remediation guidance into a practical sequence, but model output is
untrusted and may be wrong. Sending assessment data to a provider is also a
separate disclosure decision from running RedDock against an authorized target.

Giving a model tools, targets, credentials, commands, or a way to change a
finding would collapse the boundaries RedDock is designed to preserve. Hiding
the exact prompt behind a single action would also prevent an operator from
making an informed data-sharing decision.

## Decision

Intelligence is disabled until an operator configures an OpenAI-compatible
provider and model through process environment variables. Provider credentials
are never accepted by the API, stored in SQLite or evidence, returned to the
browser, or written to logs.

Creating an intelligence run makes no provider request. It selects active
evidence-linked findings from the latest completed correlation run, creates the
exact versioned JSON packet that could be sent, stores it in RedLedger, hashes
it, and leaves the run `pending_approval`. The browser displays that packet and
the configured destination. A separate request with a local approval note is
required to send it.

Approval is bound to the provider, model, destination, and local/external
classification and prompt version recorded when the packet was created. If any
of them changes, the run cannot be approved. The retained packet hash is checked
again and one approval atomically claims the send. External destinations require
HTTPS; loopback destinations may use HTTP only without a credential. Redirects
are refused, requests have a fixed total deadline, and provider responses are
size-bounded.

The packet contains no arbitrary operator prompt. It contains only stored
finding fields and their retained evidence hashes, plus fixed instructions that
treat every evidence string as untrusted data. The model receives no tools,
shell, target-selection surface, DockGuard capability, or remediation action.

Responses must match a strict schema: a summary, bounded priority entries,
remediation steps, evidence hashes, and limitations. Every referenced finding
ID and hash must already exist in the approved packet, and duplicate finding
entries are rejected. A malformed or out-of-packet response fails the run as a
whole. A valid response is retained and hashed as advice; it does not create,
edit, resolve, suppress, accept, validate, or correlate a finding.

## Consequences

- RedDock remains fully useful with no model configured.
- The operator can inspect the exact data and destination before disclosure.
- Model advice is attributable to a prompt version, provider identity, input
  hash, output hash, approval note, and timestamps.
- Prompt injection in stored target data has no action channel and cannot add
  references outside the reviewed packet.
- A configured cloud provider still receives the approved assessment packet;
  the UI labels that boundary explicitly, and the operator is responsible for
  the provider's data-handling terms.
- Phase 5 provides prioritization and remediation advice, not autonomous action.
