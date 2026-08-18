# ADR 0005: DockGuard fails closed and never widens scope

**Status:** Accepted

DockGuard denies anything it cannot positively place inside a Dockyard's declared scope, and it is evaluated server-side twice: when a run is requested and again immediately before the adapter is invoked.

Two consequences are deliberate. A hostname is authorized by name only — it is never authorized because it resolves into an authorized network, and there is no wildcard or subdomain expansion — so DNS changes cannot silently widen an engagement. Resolution exists only so that an address the operator deliberately excluded cannot be reached through a name that points at it, and so the contacted address is recorded as evidence.

A scope entry may not cover more than 256 addresses, which makes accidental large-network scanning impossible rather than merely discouraged. An operator with a larger authorized range adds several narrow entries, which is a reviewable act.
