import pytest

from app.targets import TargetError, TargetKind, normalize_target


@pytest.mark.parametrize(
    ("raw", "expected", "kind"),
    [
        ("192.168.1.10", "192.168.1.10", TargetKind.IPV4),
        (" 192.168.1.10 ", "192.168.1.10", TargetKind.IPV4),
        ("192.168.1.37/24", "192.168.1.0/24", TargetKind.IPV4_NETWORK),
        ("2001:DB8::1", "2001:db8::1", TargetKind.IPV6),
        ("2001:db8::/120", "2001:db8::/120", TargetKind.IPV6_NETWORK),
        ("APP.Lab.Local.", "app.lab.local", TargetKind.HOSTNAME),
        ("localhost", "localhost", TargetKind.HOSTNAME),
    ],
)
def test_targets_are_canonicalized(raw: str, expected: str, kind: TargetKind):
    target = normalize_target(raw)
    assert (target.value, target.kind) == (expected, kind)


@pytest.mark.parametrize(
    ("raw", "expected", "port"),
    [
        ("http://app.lab.local/admin?x=1#top", "http://app.lab.local", 80),
        ("https://app.lab.local:8443/", "https://app.lab.local:8443", 8443),
        ("HTTPS://APP.LAB.LOCAL", "https://app.lab.local", 443),
        ("http://127.0.0.1:8080", "http://127.0.0.1:8080", 8080),
    ],
)
def test_urls_normalize_to_an_origin(raw: str, expected: str, port: int):
    target = normalize_target(raw)
    assert target.kind is TargetKind.URL
    assert (target.value, target.port) == (expected, port)


def test_international_hostnames_become_idna_labels():
    assert normalize_target("münchen.lab.local").value == "xn--mnchen-3ya.lab.local"


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "192.168.1.999",
        "010.1.1.1",  # leading zeros are ambiguous, not octal
        "3232235777",  # integer form must never become 192.168.1.1
        "192.168.1.0/33",
        "192.168.1.0/abc",
        "-oN/tmp/output",
        "--script=vuln",
        "192.168.1.1; ls",
        "$(whoami)",
        "app.lab.local/../../etc/passwd",
        "ftp://app.lab.local",
        "http://user:secret@app.lab.local",
        "http://",
        "lab..local",
        "app.lab.local\n192.168.1.1",
        "0.0.0.0",
        "224.0.0.1",
        "a" * 300,
    ],
)
def test_unsafe_or_malformed_targets_are_rejected(raw: str):
    with pytest.raises(TargetError):
        normalize_target(raw)


def test_named_targets_are_flagged_for_resolution():
    assert normalize_target("app.lab.local").is_named
    assert normalize_target("https://app.lab.local").is_named
    assert not normalize_target("http://127.0.0.1").is_named
    assert not normalize_target("192.168.1.0/24").is_named
