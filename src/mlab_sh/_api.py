"""Everything the sync and async clients share.

Each endpoint is written once, as a method that describes the request
(``_Request``) and hands it to ``_json`` / ``_text``. The sync client returns
the result, the async one an awaitable of it; the type parameters say which.
Only calls that chain several requests (bash analysis, the ``wait_for_*``
helpers, ``get_limits``) are written twice, in ``client.py``.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Generic, Literal, TypeVar, Union
from urllib.parse import quote

import httpx

from .errors import (
    APIError,
    AuthenticationError,
    ForbiddenError,
    InputError,
    MaintenanceError,
    MlabError,
    NotFoundError,
    Quota,
    QuotaError,
)

__version__ = "1.0.0"

DEFAULT_BASE_URL = "https://mlab.sh"
DEFAULT_VULN_URL = "https://vuln.mlab.sh"
DEFAULT_ACTORS_URL = "https://actors.mlab.sh"
MODULES_CATALOG_URL = "https://raw.githubusercontent.com/mlab-sh/mlab-cli/main/modules.json"

USER_AGENT = f"mlab-sh-python/{__version__}"

#: Attempts for a replayable request, the first one included.
MAX_ATTEMPTS = 3
#: Longest ``Retry-After`` sat through rather than raising ``QuotaError``.
MAX_RETRY_AFTER = 30.0

LIMIT_TYPES = ("domain", "ip", "file", "crypto")

Host = Literal["api", "root", "vuln", "actors", "absolute"]
#: ``safe``: GET, replayed on network errors, 5xx and short 429s.
#: ``cooldown``: metered POST the server refused with a short 429 (nothing spent).
#: ``none``: never replayed (a scan launch would be billed twice).
Retry = Literal["safe", "cooldown", "none"]

FileInput = Union[str, "os.PathLike[str]", bytes]


@dataclass
class _Request:
    method: str
    host: Host
    path: str
    params: dict[str, Any] = field(default_factory=dict)
    json: Any = None
    content: bytes | None = None
    files: dict[str, tuple[str, bytes]] | None = None
    retry: Retry = "safe"


def _seg(value: str) -> str:
    """Quote one path segment."""
    return quote(value, safe="")


def _params(**kwargs: Any) -> dict[str, Any]:
    """Drop unset filters; booleans travel as ``1``."""
    out: dict[str, Any] = {}
    for key, value in kwargs.items():
        if value is None or value is False:
            continue
        out[key] = "1" if value is True else value
    return out


def read_file(source: FileInput, filename: str | None) -> tuple[str, bytes]:
    """Path or bytes to ``(filename, content)``."""
    if isinstance(source, bytes):
        return filename or "upload.bin", source
    path = os.fspath(source)
    with open(path, "rb") as fh:
        return filename or os.path.basename(path), fh.read()


# ── Errors ───────────────────────────────────────────────────────────────


def _parse(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def extract_message(status: int | None, body: Any, text: str) -> str:
    """The human sentence out of an error body, whatever host sent it."""
    if isinstance(body, dict):
        err = body.get("error")
        msg = body.get("message")
        # /upload/file: {"success": false, "error": {"code": 400, "message": "..."}}
        if isinstance(err, dict):
            err = err.get("message")
        err = err if isinstance(err, str) and err else None
        msg = msg if isinstance(msg, str) and msg else None
        # vuln.mlab.sh puts a machine code in `error` and the sentence in
        # `message`; the main API puts the sentence in `error`.
        if err and msg and " " not in err:
            found: str | None = msg
        else:
            found = err or msg
        if found:
            upgrade = body.get("upgrade")
            if isinstance(upgrade, dict) and isinstance(upgrade.get("message"), str):
                return f"{found} {upgrade['message']}"
            return found
    trimmed = text.strip()
    if trimmed and len(trimmed) <= 200 and not trimmed.startswith("{"):
        return trimmed
    return f"HTTP {status}" if status else "unexpected answer"


def error_for(
    status: int | None,
    text: str,
    *,
    retry_after: float | None = None,
    quota: Quota | None = None,
) -> APIError:
    """Map a status and a body onto the exception a caller can branch on.

    The status alone is not enough: the API answers 400 for quota,
    maintenance and bad input alike, so the message decides.
    """
    body = _parse(text)
    message = extract_message(status, body, text)
    code = ""
    if isinstance(body, dict) and isinstance(body.get("error"), str):
        code = body["error"]

    if status == 401:
        return AuthenticationError(
            f"{message}: the API key is unknown, expired or revoked "
            "(keys expire after 90 days by default). An owner or admin can "
            "create a new one in the organization settings.",
            status=status,
            body=body,
        )
    if status == 403:
        return ForbiddenError(message, status=status, body=body)
    if status == 429:
        return QuotaError(message, status=status, body=body, retry_after=retry_after, quota=quota)

    m = re.sub(r"[_-]", " ", f"{code} {message}".lower())
    if "limit reached" in m or "quota" in m or "too many" in m:
        return QuotaError(message, status=status, body=body, retry_after=retry_after, quota=quota)
    if "maintenance" in m:
        return MaintenanceError(message, status=status, body=body)
    if any(k in m for k in ("unauthorized", "api key", "auth required", "invalid token", "invalid api")):
        return AuthenticationError(message, status=status, body=body)
    if any(k in m for k in ("no scan found", "not found", "no results")):
        return NotFoundError(message, status=status, body=body)
    if any(k in m for k in ("invalid", "please provide", "not a recognized", "unsupported")):
        return InputError(message, status=status, body=body)
    if status == 404:
        return NotFoundError(message, status=status, body=body)
    return APIError(message, status=status, body=body)


def retry_after(resp: httpx.Response) -> float | None:
    raw = resp.headers.get("retry-after", "").strip()
    return float(raw) if raw.isdigit() else None


def quota_from(resp: httpx.Response) -> Quota | None:
    h = resp.headers
    try:
        return Quota(
            limit=int(h["x-ratelimit-limit"]),
            remaining=int(h["x-ratelimit-remaining"]),
            resource=h.get("x-ratelimit-resource", ""),
            window_seconds=int(h.get("x-ratelimit-window", "0")),
        )
    except (KeyError, ValueError):
        return None


def retry_delay(req: _Request, attempt: int, resp: httpx.Response | None) -> float | None:
    """Seconds to wait before replaying, or ``None`` to stop here.

    ``resp`` is ``None`` when the attempt failed at the transport level.
    """
    if attempt >= MAX_ATTEMPTS or req.retry == "none":
        return None
    backoff = 0.3 * 2.0 ** (attempt - 1)
    if resp is None:
        return backoff if req.retry == "safe" else None
    if resp.status_code == 429:
        delay = retry_after(resp)
        return delay if delay is not None and delay <= MAX_RETRY_AFTER else None
    if resp.status_code >= 500 and req.retry == "safe":
        return backoff
    return None


# ── Search ───────────────────────────────────────────────────────────────


class Target(str, Enum):
    """What ``detect_target`` recognised a value as."""

    CVE = "cve"
    IP = "ip"
    MAC = "mac"
    EMAIL = "email"
    HASH = "hash"
    CRYPTO = "crypto"
    URL = "url"
    PHONE = "phone"
    DOMAIN = "domain"
    UNKNOWN = "unknown"


_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_MAC = re.compile(r"[0-9A-Fa-f]{2}([:-][0-9A-Fa-f]{2}){5}")
_HEX = re.compile(r"[0-9A-Fa-f]+")
_LABEL = re.compile(r"[A-Za-z0-9_-]{1,63}")


def _is_domain(s: str) -> bool:
    if not s or len(s) > 253 or "." not in s or s.startswith(".") or s.endswith("."):
        return False
    labels = s.split(".")
    tld = labels[-1]
    # A numeric TLD is a malformed IP, never a domain.
    if len(tld) < 2 or not (tld.isascii() and tld.isalpha()):
        return False
    return all(_LABEL.fullmatch(lab) and not lab.startswith("-") and not lab.endswith("-") for lab in labels)


def _is_crypto(s: str) -> bool:
    if s[:2].lower() == "0x":
        return len(s) == 42 and bool(_HEX.fullmatch(s[2:]))
    if s.startswith(("bc1", "tb1")) and 14 <= len(s) <= 74:
        return s.isascii() and s.isalnum()
    if s[:1] in ("1", "3") and 26 <= len(s) <= 35:
        return s.isascii() and s.isalnum() and not any(c in "0OIl" for c in s)
    return False


def _is_phone(s: str) -> bool:
    if not s.startswith("+"):
        return False
    digits = re.sub(r"[\s.-]", "", s[1:])
    return 6 <= len(digits) <= 15 and digits.isascii() and digits.isdigit()


def detect_target(value: str) -> Target:
    """Recognise an IP, domain, URL, hash, email, phone, MAC, crypto address
    or CVE id, with the same rules as ``mlab search``."""
    s = value.strip()
    if not s:
        return Target.UNKNOWN
    if _CVE.fullmatch(s):
        return Target.CVE
    try:
        ipaddress.ip_address(s)
        return Target.IP
    except ValueError:
        pass
    if _MAC.fullmatch(s):
        return Target.MAC
    local, at, domain = s.partition("@")
    if at and local and "@" not in domain and _is_domain(domain):
        return Target.EMAIL
    if len(s) in (32, 40, 64, 128) and _HEX.fullmatch(s):
        return Target.HASH
    if _is_crypto(s):
        return Target.CRYPTO
    if "://" in s or "/" in s:
        return Target.URL
    if _is_phone(s):
        return Target.PHONE
    if _is_domain(s):
        return Target.DOMAIN
    return Target.UNKNOWN


# ── Endpoints ────────────────────────────────────────────────────────────

J = TypeVar("J")  # what a JSON call returns: Any, or Awaitable[Any]
T = TypeVar("T")  # what a text call returns: str, or Awaitable[str]


def _env(name: str) -> str | None:
    value = os.environ.get(name, "").strip()
    return value or None


class _Core(Generic[J, T]):
    """Configuration, request plumbing, and the main API's single-request endpoints."""

    def __init__(
        self,
        api_key: str | None = None,
        *,
        base_url: str | None = None,
        vuln_url: str | None = None,
        actors_url: str | None = None,
        vuln_token: str | None = None,
        timeout: float = 60.0,
    ) -> None:
        self.api_key = (api_key or "").strip() or _env("MLAB_API_KEY")
        self.base_url = (base_url or _env("MLAB_HOSTNAME") or DEFAULT_BASE_URL).rstrip("/")
        self.vuln_url = (vuln_url or _env("MLAB_CVE_HOSTNAME") or DEFAULT_VULN_URL).rstrip("/")
        self.actors_url = (actors_url or _env("MLAB_ACTORS_HOSTNAME") or DEFAULT_ACTORS_URL).rstrip("/")
        self.vuln_token = (vuln_token or "").strip() or _env("MLAB_VULN_TOKEN")
        self.timeout = timeout
        #: Quota from the last answer that carried ``X-RateLimit-*`` headers.
        self.last_quota: Quota | None = None
        #: CVE database on vuln.mlab.sh (no key needed).
        self.cve: CveAPI[J, T] = CveAPI(self)
        #: SBOM and package vulnerability scans on vuln.mlab.sh.
        self.vuln: VulnAPI[J, T] = VulnAPI(self)
        #: Threat actors on actors.mlab.sh (no key needed).
        self.actors: ActorsAPI[J, T] = ActorsAPI(self)
        #: Catalogue of the ``mlab-*`` CLI modules.
        self.modules: ModulesAPI[J, T] = ModulesAPI(self)

    # -- plumbing ---------------------------------------------------------

    def _url(self, req: _Request) -> str:
        if req.host == "api":
            return f"{self.base_url}/api/v1{req.path}"
        if req.host == "root":
            return f"{self.base_url}{req.path}"
        if req.host == "vuln":
            return f"{self.vuln_url}{req.path}"
        if req.host == "actors":
            return f"{self.actors_url}{req.path}"
        return req.path

    def _headers(self, req: _Request) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
        if req.host in ("api", "root") and self.api_key:
            headers["Authorization"] = f"token {self.api_key}"
        elif req.host == "vuln" and self.vuln_token:
            headers["Authorization"] = f"Bearer {self.vuln_token}"
        if req.content is not None:
            headers["Content-Type"] = "application/octet-stream"
        return headers

    def _request_kwargs(self, req: _Request) -> Mapping[str, Any]:
        return {
            "method": req.method,
            "url": self._url(req),
            "params": req.params or None,
            "json": req.json,
            "content": req.content,
            "files": req.files,
            "headers": self._headers(req),
        }

    def _result(self, req: _Request, resp: httpx.Response, as_text: bool) -> Any:
        """Turn a final answer into a value, or raise the matching error."""
        quota = quota_from(resp)
        if quota is not None:
            self.last_quota = quota
        text = resp.text
        if resp.status_code >= 400:
            raise error_for(resp.status_code, text, retry_after=retry_after(resp), quota=quota)
        if as_text:
            return text
        body = _parse(text)
        if body is None and text.strip() not in ("null", ""):
            raise MlabError(f"unreadable answer from {self._url(req)}: not JSON")
        # vuln.mlab.sh and actors.mlab.sh report failures inside a 200.
        if req.host in ("vuln", "actors") and isinstance(body, dict) and isinstance(body.get("error"), str):
            raise error_for(None, text)
        return body

    def _json(self, req: _Request) -> J:
        raise NotImplementedError

    def _text(self, req: _Request) -> T:
        raise NotImplementedError

    # -- account ----------------------------------------------------------

    def whoami(self) -> J:
        """Who the key belongs to: ``organization``, ``plan`` and ``auth``."""
        return self._json(_Request("GET", "api", "/"))

    def get_limit(self, scan_type: str) -> J:
        """Quota for one scan type (``domain``, ``ip``, ``file`` or ``crypto``):
        ``{"scan_type", "remaining", "total"}``."""
        if scan_type not in LIMIT_TYPES:
            raise ValueError(f"scan_type must be one of {', '.join(LIMIT_TYPES)}")
        return self._json(_Request("GET", "api", f"/limit/{scan_type}"))

    # -- lookups (scope scan.lookup) ----------------------------------------

    def lookup_ip(self, ip: str) -> J:
        """Reputation, geolocation and network data for an IPv4 or IPv6 address."""
        return self._json(_Request("GET", "api", "/scan/ip", _params(ip=ip)))

    def lookup_url(self, url: str, *, resolve: bool = False) -> J:
        """Analyse a URL. ``resolve=True`` makes the server fetch it to follow
        redirects (off by default: it contacts the target)."""
        return self._json(_Request("GET", "api", "/scan/url", _params(url=url, resolve=resolve)))

    def lookup_hash(self, hash: str) -> J:
        """Look up one MD5, SHA-1 or SHA-256 digest."""
        return self._json(_Request("GET", "api", "/scan/hash", _params(hash=hash)))

    def lookup_hashes(self, hashes: Sequence[str]) -> J:
        """Look up several digests in one call: ``{"results": [...]}``."""
        return self._json(_Request("POST", "api", "/scan/hash", json={"hashes": list(hashes)}, retry="none"))

    def lookup_email(self, email: str) -> J:
        """Mailbox type, provider, disposable and role flags for an address."""
        return self._json(_Request("GET", "api", "/scan/email", _params(email=email)))

    def lookup_phone(self, number: str) -> J:
        """Validity, region, line type and operator for a number (E.164 is best)."""
        return self._json(_Request("GET", "api", "/scan/phone", _params(number=number)))

    def lookup_mac(self, mac: str) -> J:
        """Vendor (OUI) and address flags for a MAC address in any notation."""
        return self._json(_Request("GET", "api", "/scan/mac", _params(mac=mac)))

    def lookup_crypto(self, address: str, *, chain: str | None = None) -> J:
        """Look up a wallet or contract address. Without ``chain`` the API
        detects it from the address."""
        return self._json(_Request("GET", "api", "/scan/crypto", _params(address=address, chain=chain)))

    def lookup_crypto_addresses(self, addresses: Sequence[str], *, chain: str | None = None) -> J:
        """Look up several addresses in one call: ``{"results": [...]}``."""
        payload: dict[str, Any] = {"addresses": list(addresses)}
        if chain:
            payload["chain"] = chain
        return self._json(_Request("POST", "api", "/scan/crypto", json=payload, retry="none"))

    def extract_iocs(
        self,
        text: str,
        *,
        country: str | None = None,
        risk: Literal["fast", "deep"] | None = None,
    ) -> J:
        """Extract indicators from free text (a report, an email, a log).

        ``country`` picks a smishing keyword pack (``fr``, ``uk``...);
        ``risk`` adds scoring, ``fast`` (local) or ``deep`` (network).
        """
        if not text.strip():
            raise ValueError("text is empty")
        return self._json(
            _Request(
                "POST",
                "api",
                "/scan/ioc",
                _params(country=country, risk=risk),
                json={"text": text},
                retry="none",
            )
        )

    # -- domain (scope scan.domain) -----------------------------------------

    def scan_domain(self, domain: str) -> J:
        """Launch a domain scan. Follow it with ``wait_for_domain_scan``."""
        return self._json(_Request("POST", "api", "/scan/domain", json={"domain": domain}, retry="none"))

    def get_domain_status(self, domain: str) -> J:
        """``{"status": ...}`` of the latest scan of ``domain``."""
        return self._json(_Request("GET", "api", "/scan/domain/status", _params(domain=domain)))

    def get_domain_report(self, domain: str) -> J:
        """The v2 report (``schema: "domain-report/2"``): grade, findings,
        DNS, mail, TLS, web, subdomains. Fields are only ever added."""
        return self._json(_Request("GET", "api", "/scan/domain/report", _params(domain=domain)))

    def get_domain_results(self, domain: str) -> J:
        """The legacy v1 results, frozen upstream. Prefer ``get_domain_report``."""
        return self._json(_Request("GET", "api", "/scan/domain/results", _params(domain=domain)))

    def capture_network(self, url: str) -> J:
        """Load ``url`` in a real browser and list the requests it makes."""
        return self._json(_Request("GET", "api", "/scan/domain/loadnetworkrequest", _params(url=url)))

    def get_ssl(self, domain: str) -> J:
        """Certificates seen for ``domain``."""
        return self._json(_Request("GET", "api", "/domain/ssl", _params(domain=domain)))

    # -- files (scope scan.file) --------------------------------------------

    def upload_file(self, file: FileInput, *, filename: str | None = None) -> J:
        """Upload a file (path or bytes) for analysis: ``{"sha256", "filename", ...}``.

        Follow it with ``wait_for_file_scan(sha256)``. 10 MB on the Free
        plan, 100 MB on paid plans.
        """
        name, content = read_file(file, filename)
        return self._json(
            _Request("POST", "root", "/upload/file", files={"file": (name, content)}, retry="none")
        )

    def get_file_results(self, sha256: str) -> J:
        """Analysis summary: ``status``, ``tools_done``/``tools_total``, findings."""
        return self._json(_Request("GET", "api", "/scan/file/results", _params(sha256=sha256)))

    def get_file_tool_output(self, sha256: str, tool: str) -> J:
        """One tool's raw output: ``{"output", "is_json", ...}``."""
        return self._json(_Request("GET", "api", "/scan/file/output", _params(sha256=sha256, tool=tool)))

    def get_bash_report(self, sha256: str) -> J:
        """Stored analysis of a shell script, by the hash ``analyze_bash`` returned."""
        return self._json(_Request("GET", "api", "/scan/file/bash", _params(sha256=sha256)))

    # -- search -----------------------------------------------------------------

    def search(self, query: str) -> J:
        """Detect what ``query`` is and run the matching lookup.

        A domain reads the existing report and never starts a scan.
        Raises ``ValueError`` when the value is not recognised.
        """
        value = query.strip()
        target = detect_target(value)
        if target is Target.CVE:
            return self.cve.get(value)
        if target is Target.IP:
            return self.lookup_ip(value)
        if target is Target.MAC:
            return self.lookup_mac(value)
        if target is Target.EMAIL:
            return self.lookup_email(value)
        if target is Target.HASH:
            return self.lookup_hash(value)
        if target is Target.CRYPTO:
            return self.lookup_crypto(value)
        if target is Target.URL:
            return self.lookup_url(value)
        if target is Target.PHONE:
            return self.lookup_phone(value)
        if target is Target.DOMAIN:
            return self.get_domain_report(value)
        raise ValueError(f"could not tell what {value!r} is")

    def report_url(self, query: str) -> str | None:
        """The web report for a value, on the host that owns it (``mlab open``)."""
        value = query.strip()
        target = detect_target(value)
        if target is Target.UNKNOWN:
            return None
        if target is Target.CVE:
            return f"{self.vuln_url}/cve/{value.upper()}"
        if target is Target.URL:
            return f"{self.base_url}/url?q={_seg(value)}"
        return f"{self.base_url}/{target.value}/{_seg(value)}"


def _cve_filters(
    query: str,
    severity: str | None,
    date_start: str | None,
    date_end: str | None,
    vendor: str | None,
    cwe: str | None,
    min_cvss: float | None,
    kev_only: bool,
    exact: bool,
) -> dict[str, Any]:
    """Filters shared by search, CSV export and RSS, under the server's names."""
    params: dict[str, Any] = {"q": query}
    params.update(
        _params(
            severity=severity,
            dateStart=date_start,
            dateEnd=date_end,
            vendor=vendor,
            cwe=cwe,
            minCvss=min_cvss,
            kevOnly=kev_only,
            exact=exact,
        )
    )
    return params


class _Sub(Generic[J, T]):
    def __init__(self, core: _Core[J, T]) -> None:
        self._core = core


class CveAPI(_Sub[J, T]):
    """``client.cve``: the CVE database on vuln.mlab.sh."""

    def search(
        self,
        query: str = "",
        *,
        severity: str | None = None,
        date_start: str | None = None,
        date_end: str | None = None,
        vendor: str | None = None,
        cwe: str | None = None,
        min_cvss: float | None = None,
        kev_only: bool = False,
        exact: bool = False,
        page: int = 0,
        limit: int | None = None,
    ) -> J:
        """Search CVEs. Dates are ``YYYY-MM-DD``; ``page`` starts at 0,
        ``limit`` is at most 100."""
        params = _cve_filters(query, severity, date_start, date_end, vendor, cwe, min_cvss, kev_only, exact)
        params.update(_params(page=page or None, limit=limit))
        return self._core._json(_Request("GET", "vuln", "/api/v1/cve", params))

    def latest(self) -> J:
        """CVEs published in the last 7 days."""
        return self._core._json(_Request("GET", "vuln", "/api/v1/cve/latest"))

    def get(self, cve_id: str) -> J:
        """One CVE: CVSS, EPSS, KEV status, weaknesses, references."""
        return self._core._json(_Request("GET", "vuln", f"/api/v1/cve/{_seg(cve_id.upper())}"))

    def dump(
        self,
        *,
        date_start: str | None = None,
        date_end: str | None = None,
        min_cvss: float | None = None,
    ) -> J:
        """Bulk CVE extract. Rate limited per IP; a short ``Retry-After`` is honoured."""
        params = _params(dateStart=date_start, dateEnd=date_end, minCvss=min_cvss)
        return self._core._json(_Request("GET", "vuln", "/api/v1/cve/dump", params))

    def stats(self) -> J:
        """Database statistics."""
        return self._core._json(_Request("GET", "vuln", "/api/v1/stats"))

    def sources(self) -> J:
        """Advisory sources the database is built from."""
        return self._core._json(_Request("GET", "vuln", "/api/v1/sources"))

    def advisories(
        self,
        *,
        cve: str | None = None,
        country: str | None = None,
        limit: int | None = None,
    ) -> J:
        """National advisories, for one CVE or by country."""
        params = _params(cve=cve, country=country, limit=limit)
        return self._core._json(_Request("GET", "vuln", "/api/v1/advisories", params))

    def vendor_months(self, vendor: str, year: int) -> J:
        """CVE count per month for a vendor: ``{"months": [12 counts]}``."""
        path = f"/api/v1/vendor/{_seg(vendor)}/months"
        return self._core._json(_Request("GET", "vuln", path, _params(year=year)))

    def export(
        self,
        query: str = "",
        *,
        format: Literal["csv", "rss"] = "csv",
        severity: str | None = None,
        date_start: str | None = None,
        date_end: str | None = None,
        vendor: str | None = None,
        cwe: str | None = None,
        min_cvss: float | None = None,
        kev_only: bool = False,
        exact: bool = False,
    ) -> T:
        """A search as CSV or as an RSS feed, returned as text."""
        if format not in ("csv", "rss"):
            raise ValueError("format must be 'csv' or 'rss'")
        path = "/rss" if format == "rss" else "/export/csv"
        params = _cve_filters(query, severity, date_start, date_end, vendor, cwe, min_cvss, kev_only, exact)
        return self._core._text(_Request("GET", "vuln", path, params))


class VulnAPI(_Sub[J, T]):
    """``client.vuln``: dependency vulnerability scans on vuln.mlab.sh."""

    def scan_manifest(
        self,
        file: FileInput,
        *,
        filename: str | None = None,
        format: str | None = None,
    ) -> J:
        """Scan a lockfile or SBOM (path or bytes) for known vulnerabilities.

        The format (npm, cargo, pip, CycloneDX...) is detected server-side
        from the content and ``filename``; ``format`` forces it. A
        ``vuln_token`` raises the quota.
        """
        name, content = read_file(file, filename)
        params = _params(filename=name, format=format)
        return self._core._json(
            _Request("POST", "vuln", "/api/v2/scan", params, content=content, retry="cooldown")
        )

    def scan_manifest_url(self, url: str, *, format: str | None = None) -> J:
        """Have the server fetch and scan a lockfile at ``url``."""
        return self._core._json(_Request("GET", "vuln", "/api/v2/scan", _params(url=url, format=format)))

    def query(self, package: str, *, version: str | None = None) -> J:
        """Known vulnerabilities of one package (OSV-compatible).

        ``package`` is a purl (``pkg:cargo/time``) or ``ecosystem/name``
        (``crates.io/time``).
        """
        if package.startswith("pkg:"):
            pkg: dict[str, str] = {"purl": package}
        else:
            ecosystem, _, name = package.partition("/")
            if not ecosystem or not name:
                raise ValueError(
                    f"{package!r} is not a package coordinate: use a purl "
                    "(pkg:cargo/time) or ecosystem/name (crates.io/time)"
                )
            pkg = {"ecosystem": ecosystem, "name": name}
        payload: dict[str, Any] = {"package": pkg}
        if version:
            payload["version"] = version
        return self._core._json(_Request("POST", "vuln", "/api/v2/query", json=payload, retry="none"))


class ActorsAPI(_Sub[J, T]):
    """``client.actors``: threat actor intelligence on actors.mlab.sh.

    Data: ETDA Threat Group Cards and MITRE ATT&CK, CC BY-NC-SA 4.0.
    """

    def list(
        self,
        *,
        origin: str | None = None,
        motivation: str | None = None,
        sector: str | None = None,
        updated_since: str | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> J:
        """Threat actors: ``{"items", "total", "offset", "limit"}``."""
        params = _params(
            origin=origin,
            motivation=motivation,
            sector=sector,
            updated_since=updated_since,
            limit=limit,
            offset=offset or None,
        )
        return self._core._json(_Request("GET", "actors", "/api/v1/actors", params))

    def get(self, slug: str) -> J:
        """One actor's profile: ``{"actor": {...}}``."""
        return self._core._json(_Request("GET", "actors", f"/api/v1/actors/{_seg(slug)}"))

    def by_cve(self, cve_id: str) -> J:
        """Actors documented exploiting a CVE: ``{"actors": [...], "vuln_url"}``."""
        return self._core._json(_Request("GET", "actors", f"/api/v1/cves/{_seg(cve_id.upper())}/actors"))

    def stix(self, slug: str) -> J:
        """STIX 2.1 bundle for one actor."""
        return self._core._json(_Request("GET", "actors", f"/actors/{_seg(slug)}.stix.json"))

    def export(self, *, format: Literal["csv", "jsonl"] = "csv") -> T:
        """Every actor as CSV or JSON Lines, returned as text."""
        if format not in ("csv", "jsonl"):
            raise ValueError("format must be 'csv' or 'jsonl'")
        return self._core._text(_Request("GET", "actors", f"/export/actors.{format}"))


class ModulesAPI(_Sub[J, T]):
    """``client.modules``: the ``mlab-*`` CLI modules."""

    def available(self) -> J:
        """The module catalogue: ``{"schema", "modules": [{"name", "repo", ...}]}``."""
        return self._core._json(_Request("GET", "absolute", MODULES_CATALOG_URL))
