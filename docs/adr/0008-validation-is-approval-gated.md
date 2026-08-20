# ADR 0008: Validation is approval-gated and bounded

**Status:** Accepted

Phase 3 must be able to revisit a narrow class of finding without quietly
turning a conclusion engine into an unrestricted assessment tool. The first
validation profile therefore is intentionally not a menu of tools or a target
form. It is one fixed HTTP-origin recheck, available only for an open
`http.security_headers` finding that already names a recorded HTTP-origin
asset.

Creating a validation run records a request and its first DockGuard decision;
it does not contact a target. A separate local operator action supplies a
short approval note. Only then does RedDock resolve the finding's recorded
origin through DockGuard again and, if it is still allowed, reuse the existing
HTTP probe. Scope can change between the two steps, so the second decision is
the one that governs contact. A denied attempt is retained as a completed
audit record precisely because no contact occurred.

The validator accepts no user-selected target, payload, credential, cookie,
command, scanner flag, or response parser. The underlying probe sends a
bodyless `HEAD` request, falls back to one `GET` only for `405` or `501`, does
not follow redirects, and reads no response body. This is enough to confirm or
not reproduce the limited transport/header conclusions it owns; unclear
responses are explicitly `indeterminate` rather than forced into a result.

Approval records an operator decision but is not external authorization.
DockGuard stays the technical control that fails closed against the declared
scope. Each completed recheck retains raw output, a normalized outcome,
metadata including both the approval and policy decision, and a manifest of
artifact hashes. The package makes it possible to show what was requested,
what was approved, why contact was or was not allowed, and what the fixed
probe observed without treating the validation outcome as an exploit result.
