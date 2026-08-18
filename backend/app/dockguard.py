"""DockGuard: RedDock's scope enforcement boundary.

DockGuard answers one question deterministically: may this Dockyard act on this
target? It fails closed — anything it cannot positively place inside the
authorized scope is denied, and it never widens scope as a side effect of
resolving, containing or matching a target.
"""

import ipaddress
import socket
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum

from app.config import get_settings
from app.targets import Target, TargetError, TargetKind, is_address_text, normalize_target

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
Resolver = Callable[[str], tuple[str, ...]]


class ScopeRuleType(StrEnum):
    INCLUDE = "include"
    EXCLUDE = "exclude"


class Decision(StrEnum):
    ALLOWED = "allowed"
    DENIED_OUT_OF_SCOPE = "denied_out_of_scope"
    DENIED_EXCLUDED = "denied_excluded"
    INVALID_TARGET = "invalid_target"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """One authorized-scope statement, already normalized when it was stored."""

    rule: ScopeRuleType
    value: str

    def target(self) -> Target:
        return normalize_target(self.value)


@dataclass(frozen=True, slots=True)
class Evaluation:
    """A DockGuard decision plus the facts that produced it."""

    decision: Decision
    target: str
    reason: str
    normalized_target: str | None = None
    target_kind: str | None = None
    matched_rule: str | None = None
    resolved_addresses: tuple[str, ...] = ()
    excluded_addresses: tuple[str, ...] = ()

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOWED


class ScopeRejected(ValueError):
    """Raised when a scope entry cannot be accepted into a Dockyard."""


def normalize_scope_value(raw: str) -> Target:
    """Normalize a scope entry and reject entries that are dangerously broad."""
    target = normalize_target(raw)
    network = target.network()
    if network is not None and network.num_addresses > get_settings().max_network_addresses:
        raise ScopeRejected(
            f"{target.value} covers {network.num_addresses} addresses; Phase 1 allows at most "
            f"{get_settings().max_network_addresses} per scope entry (IPv4 /24 or IPv6 /120)"
        )
    return target


def system_resolver(hostname: str) -> tuple[str, ...]:
    """Resolve a hostname to a bounded, de-duplicated list of addresses."""
    infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    addresses = tuple(dict.fromkeys(str(info[4][0]) for info in infos))
    return addresses[: get_settings().max_resolved_addresses]


def evaluate(
    requested: str,
    rules: Sequence[ScopeRule],
    *,
    resolver: Resolver | None = None,
) -> Evaluation:
    """Evaluate a requested target against a Dockyard's scope.

    Passing a resolver opts in to DNS: a named target is resolved so that the
    addresses behind it can be checked against exclusions and recorded as
    evidence. Resolution never authorizes anything by itself.
    """
    try:
        target = normalize_target(requested)
    except TargetError as error:
        return Evaluation(
            decision=Decision.INVALID_TARGET,
            target=requested,
            reason=str(error),
        )

    includes = [rule for rule in rules if rule.rule is ScopeRuleType.INCLUDE]
    excludes = [rule for rule in rules if rule.rule is ScopeRuleType.EXCLUDE]
    base = {
        "target": requested,
        "normalized_target": target.value,
        "target_kind": str(target.kind),
    }

    if not includes:
        return Evaluation(
            decision=Decision.DENIED_OUT_OF_SCOPE,
            reason="This Dockyard has no authorized scope entries",
            **base,
        )

    excluded_by = _first_match(target, excludes)
    if excluded_by is not None:
        return Evaluation(
            decision=Decision.DENIED_EXCLUDED,
            reason=f"Target matches Dockyard exclusion {excluded_by.value}",
            matched_rule=excluded_by.value,
            **base,
        )

    included_by = _first_match(target, includes)
    if included_by is None:
        return Evaluation(
            decision=Decision.DENIED_OUT_OF_SCOPE,
            reason="Target is not covered by any authorized scope entry",
            **base,
        )

    if target.is_network:
        overlapping = _overlapping_exclusions(target, excludes)
        if _fully_excluded(target, overlapping):
            return Evaluation(
                decision=Decision.DENIED_EXCLUDED,
                reason="Every address in the requested network is excluded",
                matched_rule=included_by.value,
                **base,
            )
        return Evaluation(
            decision=Decision.ALLOWED,
            reason=f"Target is covered by authorized scope entry {included_by.value}",
            matched_rule=included_by.value,
            excluded_addresses=tuple(rule.value for rule in overlapping),
            **base,
        )

    if target.is_named and resolver is not None:
        return _evaluate_named(target, included_by, excludes, resolver, base)

    return Evaluation(
        decision=Decision.ALLOWED,
        reason=f"Target is covered by authorized scope entry {included_by.value}",
        matched_rule=included_by.value,
        **base,
    )


def _evaluate_named(
    target: Target,
    included_by: ScopeRule,
    excludes: Sequence[ScopeRule],
    resolver: Resolver,
    base: dict[str, str],
) -> Evaluation:
    try:
        addresses = resolver(target.host)
    except OSError as error:
        return Evaluation(
            decision=Decision.UNRESOLVED,
            reason=f"{target.host} could not be resolved: {error.strerror or 'lookup failed'}",
            matched_rule=included_by.value,
            **base,
        )
    if not addresses:
        return Evaluation(
            decision=Decision.UNRESOLVED,
            reason=f"{target.host} did not resolve to any address",
            matched_rule=included_by.value,
            **base,
        )

    # A name is authorized by name only. Resolution exists so that an address
    # the operator deliberately excluded cannot be reached through a name that
    # happens to point at it.
    blocked = [address for address in addresses if _excluded_address(address, excludes)]
    if blocked:
        return Evaluation(
            decision=Decision.DENIED_EXCLUDED,
            reason=f"{target.host} resolves to excluded address {blocked[0]}",
            matched_rule=included_by.value,
            resolved_addresses=addresses,
            **base,
        )
    return Evaluation(
        decision=Decision.ALLOWED,
        reason=f"Target is covered by authorized scope entry {included_by.value}",
        matched_rule=included_by.value,
        resolved_addresses=addresses,
        **base,
    )


def _first_match(target: Target, rules: Iterable[ScopeRule]) -> ScopeRule | None:
    for rule in rules:
        try:
            if _matches(target, rule.target()):
                return rule
        except TargetError:
            # A stored rule that no longer normalizes cannot authorize anything;
            # skipping it keeps evaluation fail-closed rather than crashing.
            continue
    return None


def _matches(target: Target, rule: Target) -> bool:
    """Decide whether a scope entry covers a target.

    Address space and names are deliberately separate universes: a hostname is
    never authorized because it resolves into an authorized network, and an
    address is never authorized because some name points at it.
    """
    if target.kind is TargetKind.URL and rule.kind is TargetKind.URL:
        return target.value == rule.value
    if rule.kind is TargetKind.URL:
        return False

    target_network = target.network()
    rule_network = rule.network()
    if target_network is not None and rule_network is not None:
        return target_network.version == rule_network.version and target_network.subnet_of(
            rule_network
        )
    if target_network is not None or rule_network is not None:
        return False
    return target.host == rule.host


def _overlapping_exclusions(target: Target, excludes: Sequence[ScopeRule]) -> list[ScopeRule]:
    network = target.network()
    if network is None:
        return []
    overlapping = []
    for rule in excludes:
        try:
            rule_network = rule.target().network()
        except TargetError:
            continue
        if rule_network is not None and rule_network.version == network.version:
            if network.overlaps(rule_network):
                overlapping.append(rule)
    return overlapping


def _fully_excluded(target: Target, overlapping: Sequence[ScopeRule]) -> bool:
    network = target.network()
    if network is None:
        return False
    remaining: list[IPNetwork] = [network]
    for rule in overlapping:
        excluded = rule.target().network()
        if excluded is None:
            continue
        remaining = _subtract(remaining, excluded)
        if not remaining:
            return True
    return False


def _subtract(networks: Sequence[IPNetwork], excluded: IPNetwork) -> list[IPNetwork]:
    result: list[IPNetwork] = []
    for network in networks:
        if not network.overlaps(excluded):
            result.append(network)
        elif not excluded.supernet_of(network):
            result.extend(network.address_exclude(excluded))
    return result


def _excluded_address(address: str, excludes: Sequence[ScopeRule]) -> bool:
    if not is_address_text(address):
        return False
    parsed = ipaddress.ip_address(address)
    for rule in excludes:
        try:
            rule_network = rule.target().network()
        except TargetError:
            continue
        if rule_network is not None and rule_network.version == parsed.version:
            if parsed in rule_network:
                return True
    return False
