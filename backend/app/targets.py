"""Target parsing and normalization.

Every operator-supplied target passes through here before DockGuard evaluates
it and long before an adapter builds a command line. Normalization gives scope
comparison a single canonical form and, just as importantly, guarantees that
the strings which later reach a tool argument vector are restricted to a small
character set that cannot be mistaken for a flag.
"""

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

MAX_TARGET_LENGTH = 255
MAX_HOSTNAME_LENGTH = 253

_IPV4_TEXT = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_PREFIX = re.compile(r"^\d{1,3}$")
# Canonical targets may only contain characters that are meaningless to a shell
# and can never begin an option, which is what makes argument injection through
# a target string impossible rather than merely unlikely.
_SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]*$")

_DEFAULT_PORTS = {"http": 80, "https": 443}


class TargetKind(StrEnum):
    IPV4 = "ipv4"
    IPV4_NETWORK = "ipv4_network"
    IPV6 = "ipv6"
    IPV6_NETWORK = "ipv6_network"
    HOSTNAME = "hostname"
    URL = "url"


class TargetError(ValueError):
    """Raised when a target cannot be normalized into a canonical form."""


@dataclass(frozen=True, slots=True)
class Target:
    """A canonical target: the only representation the rest of RedDock uses."""

    kind: TargetKind
    value: str
    host: str
    scheme: str | None = None
    port: int | None = None

    @property
    def is_network(self) -> bool:
        return self.kind in (TargetKind.IPV4_NETWORK, TargetKind.IPV6_NETWORK)

    @property
    def is_address(self) -> bool:
        return self.kind in (TargetKind.IPV4, TargetKind.IPV6)

    @property
    def is_named(self) -> bool:
        """True when reaching this target requires DNS resolution."""
        return self.kind is TargetKind.HOSTNAME or (
            self.kind is TargetKind.URL and not is_address_text(self.host)
        )

    def network(self) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        """The address space this target covers, or None for named targets."""
        if self.is_network or self.is_address:
            return ipaddress.ip_network(self.value)
        if self.kind is TargetKind.URL and is_address_text(self.host):
            return ipaddress.ip_network(self.host)
        return None


def normalize_target(raw: str) -> Target:
    """Normalize operator input, raising TargetError for anything ambiguous."""
    if not isinstance(raw, str):
        raise TargetError("Target must be text")
    text = raw.strip()
    if not text:
        raise TargetError("Target must not be empty")
    if len(text) > MAX_TARGET_LENGTH:
        raise TargetError(f"Target must be {MAX_TARGET_LENGTH} characters or fewer")
    if any(_is_forbidden_character(character) for character in text):
        raise TargetError("Target must not contain whitespace or control characters")

    if "://" in text:
        return _normalize_url(text)
    if "/" in text:
        return _normalize_network(text)
    address = _parse_address(text)
    if address is not None:
        return _address_target(address)
    return _hostname_target(_normalize_hostname(text))


def _is_forbidden_character(character: str) -> bool:
    return character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F


def _normalize_url(text: str) -> Target:
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in _DEFAULT_PORTS:
        raise TargetError("Only http and https URLs are supported")
    if parts.username or parts.password:
        raise TargetError("URLs must not embed credentials")
    try:
        hostname, port = parts.hostname, parts.port
    except ValueError as error:
        raise TargetError("URL host or port is invalid") from error
    if not hostname:
        raise TargetError("URL must include a host")
    if port is not None and not 1 <= port <= 65535:
        raise TargetError("URL port must be between 1 and 65535")

    address = _parse_address(hostname)
    if address is not None:
        _reject_unusable_address(address)
        host = str(address)
        rendered = f"[{host}]" if address.version == 6 else host
    else:
        host = _normalize_hostname(hostname)
        rendered = host

    # Paths, queries and fragments are dropped: RedDock probes an origin and
    # never a location, so retaining them would imply a capability RedDock does
    # not have and would widen what a stored target string can carry.
    port_suffix = "" if port in (None, _DEFAULT_PORTS[scheme]) else f":{port}"
    _assert_safe_token(host)
    return Target(
        kind=TargetKind.URL,
        value=f"{scheme}://{rendered}{port_suffix}",
        host=host,
        scheme=scheme,
        port=port or _DEFAULT_PORTS[scheme],
    )


def _normalize_network(text: str) -> Target:
    address_text, _, prefix_text = text.partition("/")
    if not _PREFIX.match(prefix_text):
        raise TargetError("Network prefix must be a decimal length such as /24")
    address = _parse_address(address_text)
    if address is None:
        raise TargetError("Network must start with an IPv4 or IPv6 address")
    try:
        network = ipaddress.ip_network(f"{address}/{prefix_text}", strict=False)
    except ValueError as error:
        raise TargetError(f"Invalid network: {error}") from error
    if network.network_address.is_unspecified:
        raise TargetError(
            "A default route such as 0.0.0.0/0 or ::/0 is never an authorized target"
        )
    if network.is_multicast:
        raise TargetError("Multicast networks are not valid targets")
    value = str(network)
    _assert_safe_token(value)
    kind = TargetKind.IPV4_NETWORK if network.version == 4 else TargetKind.IPV6_NETWORK
    return Target(kind=kind, value=value, host=value)


def _address_target(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Target:
    _reject_unusable_address(address)
    value = str(address)
    _assert_safe_token(value)
    kind = TargetKind.IPV4 if address.version == 4 else TargetKind.IPV6
    return Target(kind=kind, value=value, host=value)


def _hostname_target(hostname: str) -> Target:
    _assert_safe_token(hostname)
    return Target(kind=TargetKind.HOSTNAME, value=hostname, host=hostname)


def _reject_unusable_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if address.is_unspecified:
        raise TargetError("The unspecified address is not a valid target")
    if address.is_multicast:
        raise TargetError("Multicast addresses are not valid targets")


def _parse_address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse strict textual IP forms only.

    The ipaddress module also accepts integer and packed forms, which would let
    3232235777 silently become 192.168.1.1 and defeat scope comparison, so the
    textual shape is checked before parsing.
    """
    if _IPV4_TEXT.match(text):
        try:
            return ipaddress.IPv4Address(text)
        except ValueError:
            return None
    if ":" in text:
        if "%" in text:
            raise TargetError("IPv6 zone identifiers are not supported")
        try:
            return ipaddress.IPv6Address(text)
        except ValueError:
            return None
    return None


def is_address_text(text: str) -> bool:
    """True when the text is a strict IPv4 or IPv6 address literal."""
    try:
        return _parse_address(text) is not None
    except TargetError:
        return False


def _normalize_hostname(text: str) -> str:
    hostname = text.strip().rstrip(".").lower()
    if not hostname:
        raise TargetError("Hostname must not be empty")
    normalized = [_normalize_label(label) for label in hostname.split(".")]
    result = ".".join(normalized)
    if len(result) > MAX_HOSTNAME_LENGTH:
        raise TargetError(f"Hostname must be {MAX_HOSTNAME_LENGTH} characters or fewer")
    if normalized[-1].isdigit():
        raise TargetError("Hostname must not end in a numeric label")
    return result


def _normalize_label(label: str) -> str:
    if not label:
        raise TargetError("Hostname must not contain empty labels")
    if not label.isascii():
        try:
            label = label.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise TargetError("Hostname contains an invalid international label") from error
    if not _LABEL.match(label):
        raise TargetError(f"Invalid hostname label: {label}")
    return label


def _assert_safe_token(value: str) -> None:
    if not is_safe_token(value):
        raise TargetError("Target contains characters that are not permitted")


def is_safe_token(value: str) -> bool:
    """Argument-safety check reused by adapters before building an argv."""
    return bool(_SAFE_TOKEN.match(value))
