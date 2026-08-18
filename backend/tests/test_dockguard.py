import socket

import pytest

from app.dockguard import (
    Decision,
    ScopeRejected,
    ScopeRule,
    ScopeRuleType,
    evaluate,
    normalize_scope_value,
)
from app.targets import TargetError


def include(*values: str) -> list[ScopeRule]:
    return [ScopeRule(rule=ScopeRuleType.INCLUDE, value=value) for value in values]


def exclude(*values: str) -> list[ScopeRule]:
    return [ScopeRule(rule=ScopeRuleType.EXCLUDE, value=value) for value in values]


def resolving(**mapping: tuple[str, ...]):
    def resolver(hostname: str) -> tuple[str, ...]:
        if hostname not in mapping:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return mapping[hostname]

    return resolver


def test_exact_address_inside_scope_is_allowed():
    evaluation = evaluate("192.168.1.10", include("192.168.1.10"))
    assert evaluation.decision is Decision.ALLOWED
    assert evaluation.matched_rule == "192.168.1.10"


def test_address_inside_an_authorized_network_is_allowed():
    evaluation = evaluate("192.168.1.42", include("192.168.1.0/24"))
    assert evaluation.allowed


def test_address_outside_scope_is_denied():
    evaluation = evaluate("10.0.0.5", include("192.168.1.0/24"))
    assert evaluation.decision is Decision.DENIED_OUT_OF_SCOPE


def test_empty_scope_denies_everything():
    evaluation = evaluate("192.168.1.10", [])
    assert evaluation.decision is Decision.DENIED_OUT_OF_SCOPE
    assert "no authorized scope" in evaluation.reason


def test_exclusion_overrides_inclusion():
    rules = include("192.168.1.0/24") + exclude("192.168.1.10")
    evaluation = evaluate("192.168.1.10", rules)
    assert evaluation.decision is Decision.DENIED_EXCLUDED
    assert evaluation.matched_rule == "192.168.1.10"


def test_malformed_target_is_invalid_not_denied():
    evaluation = evaluate("--script=vuln", include("192.168.1.0/24"))
    assert evaluation.decision is Decision.INVALID_TARGET


def test_network_request_must_be_contained_by_an_authorized_network():
    assert evaluate("192.168.1.0/25", include("192.168.1.0/24")).allowed
    assert not evaluate("192.168.0.0/16", include("192.168.1.0/24")).allowed


def test_network_request_carries_overlapping_exclusions_to_the_adapter():
    rules = include("192.168.1.0/24") + exclude("192.168.1.1", "192.168.1.10")
    evaluation = evaluate("192.168.1.0/24", rules)
    assert evaluation.allowed
    assert evaluation.excluded_addresses == ("192.168.1.1", "192.168.1.10")


def test_fully_excluded_network_is_denied():
    rules = include("192.168.1.0/25") + exclude("192.168.1.0/26", "192.168.1.64/26")
    assert evaluate("192.168.1.0/25", rules).decision is Decision.DENIED_EXCLUDED


def test_hostname_matching_is_exact_and_normalized():
    rules = include("app.lab.local")
    assert evaluate("APP.Lab.Local.", rules).allowed
    # No wildcard or subdomain expansion exists in Phase 1.
    assert not evaluate("api.app.lab.local", rules).allowed


def test_a_hostname_is_not_authorized_by_the_network_it_resolves_into():
    evaluation = evaluate(
        "app.lab.local",
        include("192.168.1.0/24"),
        resolver=resolving(**{"app.lab.local": ("192.168.1.10",)}),
    )
    assert evaluation.decision is Decision.DENIED_OUT_OF_SCOPE


def test_an_address_is_not_authorized_by_a_hostname_that_points_at_it():
    assert not evaluate("192.168.1.10", include("app.lab.local")).allowed


def test_scoped_hostname_records_its_resolved_addresses():
    evaluation = evaluate(
        "app.lab.local",
        include("app.lab.local"),
        resolver=resolving(**{"app.lab.local": ("192.168.1.10", "192.168.1.11")}),
    )
    assert evaluation.allowed
    assert evaluation.resolved_addresses == ("192.168.1.10", "192.168.1.11")


def test_scoped_hostname_resolving_to_an_excluded_address_is_denied():
    rules = include("app.lab.local") + exclude("192.168.1.10")
    evaluation = evaluate(
        "app.lab.local",
        rules,
        resolver=resolving(**{"app.lab.local": ("192.168.1.10",)}),
    )
    assert evaluation.decision is Decision.DENIED_EXCLUDED
    assert "192.168.1.10" in evaluation.reason


def test_unresolvable_hostname_fails_closed():
    evaluation = evaluate("app.lab.local", include("app.lab.local"), resolver=resolving())
    assert evaluation.decision is Decision.UNRESOLVED


def test_url_is_authorized_by_its_host_or_by_an_exact_origin():
    assert evaluate("http://127.0.0.1:8080", include("127.0.0.1")).allowed
    assert evaluate("http://127.0.0.1:8080", include("http://127.0.0.1:8080")).allowed
    # An origin entry authorizes that origin only, not a different port.
    assert not evaluate("http://127.0.0.1:9090", include("http://127.0.0.1:8080")).allowed


def test_excluded_host_also_denies_its_urls():
    rules = include("127.0.0.1") + exclude("127.0.0.1")
    assert evaluate("http://127.0.0.1:8080", rules).decision is Decision.DENIED_EXCLUDED


@pytest.mark.parametrize("value", ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"])
def test_dangerously_broad_scope_entries_are_rejected(value: str):
    with pytest.raises(ScopeRejected):
        normalize_scope_value(value)


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0"])
def test_the_whole_internet_is_never_a_valid_scope_entry(value: str):
    with pytest.raises(TargetError):
        normalize_scope_value(value)


def test_a_slash_24_is_the_widest_accepted_ipv4_entry():
    assert normalize_scope_value("192.168.1.0/24").value == "192.168.1.0/24"
