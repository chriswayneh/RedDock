"""CVE enrichment: the boundary, and the smallest honest implementation.

RedDock does not fetch CVE data. It has no vulnerability feed, no scheduled
download and no network dependency at startup or during a detection run. What it
has is a boundary: a detector may ask whether a catalogue associates an observed
product and version with published CVE identifiers, and it gets back references
that carry their own provenance.

Three rules make that defensible rather than misleading:

1. An association is not a conclusion. A catalogue match never creates a
   finding, never raises a severity and never changes a status. It is attached
   to a finding that already stood on its own evidence.
2. Only exact matches are reported. Phase 2 matches a normalized product name
   and an identical version string. It does not interpret version ranges,
   because guessing at a range is how a tool starts inventing vulnerabilities.
3. Absence is not failure. With no catalogue configured, enrichment is simply
   unavailable and detection produces exactly the same findings.

The catalogue is a local JSON file an operator supplies through
`REDDOCK_CVE_CATALOG`. Nothing is downloaded, and a catalogue that cannot be
read or parsed is reported on the detection run as a warning rather than
failing it.
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from app.config import get_settings
from app.detection.base import CveReference, Enrichment

logger = logging.getLogger("reddock.detection")

CATALOG_SCHEMA = "reddock.cve-catalog/1"
EXACT_VERSION = "exact_version"

_MAX_CVE_ID = 32
_MAX_URL = 255


class CatalogError(ValueError):
    """Raised when a supplied catalogue cannot be accepted."""


def normalize_product(value: str) -> str:
    """One canonical product key, so casing and spacing cannot cause a miss."""
    return " ".join(value.split()).casefold()


def normalize_version(value: str) -> str:
    return value.strip().casefold()


class NoEnrichment(Enrichment):
    """The default: RedDock knows of no catalogue, and says so."""

    id = "none"
    version = None
    available = False

    def lookup(self, product: str, version: str) -> tuple[CveReference, ...]:
        return ()


@dataclass(frozen=True, slots=True)
class _Entry:
    cve_ids: tuple[str, ...]
    product: str
    version: str
    url: str | None


class LocalCatalogEnrichment(Enrichment):
    """Exact product and version lookups against a local operator catalogue."""

    id = "local_catalog"
    available = True

    def __init__(self, source: str, version: str | None, entries: dict[tuple[str, str], _Entry]):
        self.source = source
        self.version = version
        self._entries = entries

    def __len__(self) -> int:
        return len(self._entries)

    def lookup(self, product: str, version: str) -> tuple[CveReference, ...]:
        entry = self._entries.get((normalize_product(product), normalize_version(version)))
        if entry is None:
            return ()
        return tuple(
            CveReference(
                cve_id=cve_id,
                source=self.source,
                source_version=self.version,
                match_type=EXACT_VERSION,
                matched_product=entry.product,
                matched_version=entry.version,
                url=entry.url,
            )
            for cve_id in entry.cve_ids
        )


def parse_catalog(document: object) -> LocalCatalogEnrichment:
    """Turn a catalogue document into a lookup, rejecting anything unexpected."""
    settings = get_settings()
    if not isinstance(document, dict):
        raise CatalogError("A CVE catalogue must be a JSON object")
    if document.get("schema") != CATALOG_SCHEMA:
        raise CatalogError(f"A CVE catalogue must declare schema {CATALOG_SCHEMA}")
    raw_entries = document.get("entries")
    if not isinstance(raw_entries, list):
        raise CatalogError("A CVE catalogue must contain an entries array")
    if len(raw_entries) > settings.max_cve_catalog_entries:
        raise CatalogError(
            f"A CVE catalogue may hold at most {settings.max_cve_catalog_entries} entries"
        )

    source = _text(document.get("source"), "source") or "operator-supplied"
    version = _text(document.get("version"), "version")
    entries: dict[tuple[str, str], _Entry] = {}
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict):
            raise CatalogError(f"Catalogue entry {index} is not an object")
        product = _text(raw.get("product"), "product")
        entry_version = _text(raw.get("version"), "version")
        if not product or not entry_version:
            raise CatalogError(f"Catalogue entry {index} needs a product and a version")
        cve_ids = _cve_ids(raw.get("cve"), index)
        url = _text(raw.get("url"), "url", limit=_MAX_URL)
        if url and not url.startswith(("http://", "https://")):
            raise CatalogError(f"Catalogue entry {index} has a url that is not http or https")
        entries[(normalize_product(product), normalize_version(entry_version))] = _Entry(
            cve_ids=cve_ids, product=product, version=entry_version, url=url
        )
    return LocalCatalogEnrichment(source=source, version=version, entries=entries)


def load_enrichment() -> tuple[Enrichment, str | None]:
    """Load the configured catalogue, or explain why enrichment is unavailable.

    Returns the enrichment to use and an optional warning. A missing, unreadable
    or malformed catalogue is never fatal: detection continues with enrichment
    switched off, which is the same behaviour as having configured none.
    """
    settings = get_settings()
    configured = settings.cve_catalog_path
    if not configured:
        return NoEnrichment(), None

    path = Path(configured)
    try:
        if not path.is_file():
            return NoEnrichment(), f"CVE catalogue {configured} does not exist"
        size = path.stat().st_size
        if size > settings.max_cve_catalog_bytes:
            return NoEnrichment(), (
                f"CVE catalogue {configured} is {size} bytes; the limit is "
                f"{settings.max_cve_catalog_bytes}"
            )
        catalog = parse_catalog(json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, CatalogError) as error:
        logger.warning("CVE catalogue %s was not loaded: %s", configured, error)
        return NoEnrichment(), f"CVE catalogue {configured} was not loaded: {error}"
    return catalog, None


def _text(value: object, field: str, limit: int = 120) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise CatalogError(f"Catalogue field {field} must be text")
    cleaned = value.strip()
    if len(cleaned) > limit:
        raise CatalogError(f"Catalogue field {field} must be {limit} characters or fewer")
    return cleaned or None


def _cve_ids(value: object, index: int) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise CatalogError(f"Catalogue entry {index} needs a non-empty cve array")
    identifiers = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise CatalogError(f"Catalogue entry {index} has a CVE identifier that is not text")
        identifier = item.strip()
        if len(identifier) > _MAX_CVE_ID:
            raise CatalogError(f"Catalogue entry {index} has an over-long CVE identifier")
        identifiers.append(identifier)
    # Sorted and de-duplicated so the same catalogue always enriches identically.
    return tuple(sorted(dict.fromkeys(identifiers)))
