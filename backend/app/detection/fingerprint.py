"""Stable finding identity.

A fingerprint answers one question: is this the same underlying issue RedDock
already knows about? It is a SHA-256 over a canonical string built only from
concepts that do not move between runs, processes or restarts. Python's built-in
`hash()` is deliberately not used: it is randomized per process, so it would
make a finding look new every time RedDock restarted.

Two things are left out on purpose:

- The detector version, so improving a rule does not fork its history.
- The Dockyard, because the finding is a property of the issue. Isolation
  between Dockyards comes from the uniqueness constraint on
  (dockyard_id, fingerprint), not from the hash.
"""

from hashlib import sha256

FINGERPRINT_SCHEMA = "reddock.finding/1"

#: A separator that cannot appear in any component, so no combination of values
#: can be made to collide by moving a delimiter into a field.
_SEPARATOR = "\x1f"
_ABSENT = "-"


def fingerprint(
    *,
    detector: str,
    rule_id: str,
    asset_type: str | None,
    asset_identity: str | None,
    transport: str | None,
    port: int | None,
    scope_key: str = "",
) -> str:
    """The deterministic identity of one finding."""
    endpoint = f"{transport}/{port}" if transport and port is not None else _ABSENT
    parts = (
        FINGERPRINT_SCHEMA,
        detector,
        rule_id,
        asset_type or _ABSENT,
        asset_identity or _ABSENT,
        endpoint,
        scope_key or _ABSENT,
    )
    return sha256(_SEPARATOR.join(parts).encode("utf-8")).hexdigest()
