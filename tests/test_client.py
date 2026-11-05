from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import respx

from mlab_sh import (
    APIError,
    AsyncClient,
    AuthenticationError,
    Client,
    ForbiddenError,
    InputError,
    MaintenanceError,
    NetworkError,
    NotFoundError,
    Quota,
    QuotaError,
    ScanFailedError,
    ScanTimeoutError,
    Target,
    detect_target,
)

API = "https://mlab.test/api/v1"
VULN = "https://vuln.test"
ACTORS = "https://actors.test"


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch: pytest.MonkeyPatch) -> None:
    async def instant(_: float) -> None:
        return None

    monkeypatch.setattr("mlab_sh.client.time.sleep", lambda _: None)
    monkeypatch.setattr("mlab_sh.client.asyncio.sleep", instant)


@pytest.fixture
def client() -> Iterator[Client]:
    with Client("k3y", base_url="https://mlab.test/", vuln_url=VULN, actors_url=ACTORS, vuln_token="vt") as c:
        yield c


def _body(route: respx.Route, n: int = -1) -> Any:
    return json.loads(route.calls[n].request.content)


# ── configuration ────────────────────────────────────────────────────


def test_key_and_hosts_come_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MLAB_API_KEY", "envkey")
    monkeypatch.setenv("MLAB_HOSTNAME", "https://self.hosted/")
    c = Client()
    assert c.api_key == "envkey"
    assert c.base_url == "https://self.hosted"
    assert Client("explicit").api_key == "explicit"


@respx.mock
def test_main_api_sends_the_token_scheme_and_aux_hosts_the_bearer(client: Client) -> None:
    main = respx.get(f"{API}/").respond(json={"organization": "acme", "auth": "api_key"})
    cve = respx.get(f"{VULN}/api/v1/cve/CVE-2024-1234").respond(json={"id": "CVE-2024-1234"})
    actors = respx.get(f"{ACTORS}/api/v1/actors/apt28").respond(json={"actor": {}})
    assert client.whoami()["organization"] == "acme"
    client.cve.get("cve-2024-1234")
    client.actors.get("apt28")
    assert main.calls[0].request.headers["Authorization"] == "token k3y"
    assert cve.calls[0].request.headers["Authorization"] == "Bearer vt"
    assert "Authorization" not in actors.calls[0].request.headers


@respx.mock
def test_no_key_means_no_authorization_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MLAB_API_KEY", raising=False)
    route = respx.get("https://mlab.sh/api/v1/scan/ip").respond(json={})
    Client().lookup_ip("1.1.1.1")
    assert "Authorization" not in route.calls[0].request.headers


# ── payloads ─────────────────────────────────────────────────────────


@respx.mock
def test_lookups_hit_the_documented_routes(client: Client) -> None:
    routes = {
        "ip": respx.get(f"{API}/scan/ip", params={"ip": "8.8.8.8"}),
        "url": respx.get(f"{API}/scan/url", params={"url": "https://x.y/a", "resolve": "1"}),
        "hash": respx.get(f"{API}/scan/hash", params={"hash": "a" * 64}),
        "email": respx.get(f"{API}/scan/email", params={"email": "a@b.co"}),
        "phone": respx.get(f"{API}/scan/phone", params={"number": "+33612345678"}),
        "mac": respx.get(f"{API}/scan/mac", params={"mac": "00:11:22:33:44:55"}),
        "crypto": respx.get(f"{API}/scan/crypto", params={"address": "0xabc", "chain": "eth"}),
        "ssl": respx.get(f"{API}/domain/ssl", params={"domain": "example.com"}),
        "net": respx.get(f"{API}/scan/domain/loadnetworkrequest", params={"url": "https://e.com"}),
    }
    for r in routes.values():
        r.respond(json={"ok": True})
    client.lookup_ip("8.8.8.8")
    client.lookup_url("https://x.y/a", resolve=True)
    client.lookup_hash("a" * 64)
    client.lookup_email("a@b.co")
    client.lookup_phone("+33612345678")
    client.lookup_mac("00:11:22:33:44:55")
    client.lookup_crypto("0xabc", chain="eth")
    client.get_ssl("example.com")
    client.capture_network("https://e.com")
    assert all(r.called for r in routes.values())


@respx.mock
def test_bulk_lookups_and_ioc_extraction_post_json(client: Client) -> None:
    hashes = respx.post(f"{API}/scan/hash").respond(json={"results": []})
    crypto = respx.post(f"{API}/scan/crypto").respond(json={"results": []})
    ioc = respx.post(f"{API}/scan/ioc", params={"country": "fr", "risk": "deep"}).respond(
        json={"ioc_total": 1}
    )
    client.lookup_hashes(["a" * 32, "b" * 32])
    client.lookup_crypto_addresses(["0x1", "0x2"], chain="eth")
    client.extract_iocs("see 1.2.3.4", country="fr", risk="deep")
    assert _body(hashes) == {"hashes": ["a" * 32, "b" * 32]}
    assert _body(crypto) == {"addresses": ["0x1", "0x2"], "chain": "eth"}
    assert _body(ioc) == {"text": "see 1.2.3.4"}
    with pytest.raises(ValueError):
        client.extract_iocs("   ")


@respx.mock
def test_bash_analysis_posts_base64_then_reads_the_report(client: Client) -> None:
    post = respx.post(f"{API}/scan/file/bash").respond(json={"sha256": "abc"})
    get = respx.get(f"{API}/scan/file/bash", params={"sha256": "abc"}).respond(json={"risk": "high"})
    assert client.analyze_bash(b"curl x | sh")["risk"] == "high"
    assert _body(post) == {
        "content_b64": base64.b64encode(b"curl x | sh").decode(),
        "filename": "script.sh",
    }
    assert get.called


@respx.mock
def test_file_upload_goes_to_the_site_root_as_multipart(client: Client, tmp_path: Path) -> None:
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"MZ\x90\x00")
    route = respx.post("https://mlab.test/upload/file").respond(json={"sha256": "f00", "success": True})
    assert client.upload_file(sample)["sha256"] == "f00"
    req = route.calls[0].request
    assert req.headers["Content-Type"].startswith("multipart/form-data")
    assert b'filename="sample.exe"' in req.content and b"MZ\x90\x00" in req.content


@respx.mock
def test_file_output_and_limits(client: Client) -> None:
    respx.get(f"{API}/scan/file/output", params={"sha256": "f", "tool": "yara"}).respond(
        json={"output": "x", "is_json": False}
    )
    for t in ("domain", "ip", "file", "crypto"):
        respx.get(f"{API}/limit/{t}").respond(json={"scan_type": t, "remaining": 1, "total": 2})
    assert client.get_file_tool_output("f", "yara")["output"] == "x"
    assert client.get_limits()["crypto"]["total"] == 2
    with pytest.raises(ValueError):
        client.get_limit("nope")


@respx.mock
def test_cve_routes_and_filters(client: Client) -> None:
    search = respx.get(
        f"{VULN}/api/v1/cve",
        params={"q": "openssl", "severity": "HIGH", "minCvss": "7.5", "kevOnly": "1", "page": "2"},
    ).respond(json={"cves": []})
    csv = respx.get(f"{VULN}/export/csv", params={"q": "x", "vendor": "acme"}).respond(text="id,score\n")
    rss = respx.get(f"{VULN}/rss").respond(text="<rss/>")
    respx.get(f"{VULN}/api/v1/cve/latest").respond(json={"cves": []})
    respx.get(f"{VULN}/api/v1/cve/dump", params={"dateStart": "2024-01-01"}).respond(json=[])
    respx.get(f"{VULN}/api/v1/stats").respond(json={})
    respx.get(f"{VULN}/api/v1/sources").respond(json=[])
    respx.get(f"{VULN}/api/v1/advisories", params={"cve": "CVE-1"}).respond(json={"advisories": []})
    respx.get(f"{VULN}/api/v1/vendor/micro%20soft/months", params={"year": "2024"}).respond(
        json={"months": [0] * 12}
    )
    client.cve.search("openssl", severity="HIGH", min_cvss=7.5, kev_only=True, page=2)
    assert client.cve.export("x", vendor="acme") == "id,score\n"
    assert client.cve.export(format="rss") == "<rss/>"
    client.cve.latest()
    client.cve.dump(date_start="2024-01-01")
    client.cve.stats()
    client.cve.sources()
    client.cve.advisories(cve="CVE-1")
    assert len(client.cve.vendor_months("micro soft", 2024)["months"]) == 12
    assert search.called and csv.called and rss.called


@respx.mock
def test_sbom_and_package_queries(client: Client) -> None:
    raw = respx.post(f"{VULN}/api/v2/scan", params={"filename": "Cargo.lock"}).respond(json={"scans": []})
    url = respx.get(f"{VULN}/api/v2/scan", params={"url": "https://x/lock"}).respond(json={})
    query = respx.post(f"{VULN}/api/v2/query").respond(json={"vulns": []})
    client.vuln.scan_manifest(b"[[package]]", filename="Cargo.lock")
    client.vuln.scan_manifest_url("https://x/lock")
    client.vuln.query("crates.io/time", version="0.1.0")
    client.vuln.query("pkg:cargo/time")
    assert raw.calls[0].request.content == b"[[package]]"
    assert raw.calls[0].request.headers["Content-Type"] == "application/octet-stream"
    assert url.called
    assert _body(query, 0) == {"package": {"ecosystem": "crates.io", "name": "time"}, "version": "0.1.0"}
    assert _body(query, 1) == {"package": {"purl": "pkg:cargo/time"}}
    with pytest.raises(ValueError):
        client.vuln.query("time")


@respx.mock
def test_actor_routes(client: Client) -> None:
    respx.get(f"{ACTORS}/api/v1/actors", params={"origin": "Russia", "offset": "20"}).respond(
        json={"items": [], "total": 0}
    )
    respx.get(f"{ACTORS}/api/v1/cves/CVE-2023-1/actors").respond(json={"actors": []})
    respx.get(f"{ACTORS}/actors/apt28.stix.json").respond(json={"type": "bundle"})
    respx.get(f"{ACTORS}/export/actors.jsonl").respond(text='{"slug":"apt28"}\n')
    assert client.actors.list(origin="Russia", offset=20)["total"] == 0
    assert client.actors.by_cve("cve-2023-1")["actors"] == []
    assert client.actors.stix("apt28")["type"] == "bundle"
    assert client.actors.export(format="jsonl").startswith("{")


@respx.mock
def test_modules_catalog(client: Client) -> None:
    respx.get("https://raw.githubusercontent.com/mlab-sh/mlab-cli/main/modules.json").respond(
        text='{"schema":1,"modules":[{"name":"unifi"}]}', headers={"Content-Type": "text/plain"}
    )
    assert client.modules.available()["modules"][0]["name"] == "unifi"


# ── errors and quota ─────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("status", "body", "kind"),
    [
        (401, {"error": "Unauthorized"}, AuthenticationError),
        (403, {"error": "This API key does not have the 'scan.domain' permission"}, ForbiddenError),
        (429, {"error": "limit"}, QuotaError),
        (400, {"error": "Scan limit reached. Please try again later."}, QuotaError),
        (400, {"error": "Service temporarily unavailable for maintenance."}, MaintenanceError),
        (400, {"error": "Provided domain is invalid."}, InputError),
        (400, {"error": "No scan found for the provided domain."}, NotFoundError),
        (404, {"error": "Not found"}, NotFoundError),
        (
            400,
            {"success": False, "error": {"code": 400, "message": "unsupported file type"}},
            InputError,
        ),
        (418, {"weird": True}, APIError),
    ],
)
@respx.mock
def test_errors_are_typed(client: Client, status: int, body: Any, kind: type[APIError]) -> None:
    respx.get(f"{API}/scan/domain/report").respond(status, json=body)
    with pytest.raises(kind) as info:
        client.get_domain_report("example.com")
    assert info.value.status == status


@respx.mock
def test_401_explains_expiry_and_403_keeps_the_server_sentence(client: Client) -> None:
    respx.get(f"{API}/").respond(401, json={"error": "Unauthorized"})
    respx.get(f"{API}/scan/ip").respond(
        403, json={"error": "This API key does not have the 'scan.lookup' permission (IOC lookups)."}
    )
    with pytest.raises(AuthenticationError, match="90 days"):
        client.whoami()
    with pytest.raises(ForbiddenError, match=r"'scan\.lookup' permission") as info:
        client.lookup_ip("1.1.1.1")
    assert info.value.scope == "scan.lookup"


@respx.mock
def test_quota_headers_are_exposed_and_attached_to_429(client: Client) -> None:
    headers = {
        "X-RateLimit-Limit": "100",
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Resource": "ip",
        "X-RateLimit-Window": "86400",
    }
    respx.get(f"{API}/scan/ip").mock(
        side_effect=[
            httpx.Response(200, json={}, headers={**headers, "X-RateLimit-Remaining": "1"}),
            httpx.Response(
                429, json={"error": "IP lookup limit reached."}, headers={**headers, "Retry-After": "3600"}
            ),
        ]
    )
    client.lookup_ip("1.1.1.1")
    assert client.last_quota == Quota(limit=100, remaining=1, resource="ip", window_seconds=86400)
    with pytest.raises(QuotaError) as info:
        client.lookup_ip("1.1.1.1")
    assert info.value.retry_after == 3600
    assert info.value.quota is not None and info.value.quota.remaining == 0


@respx.mock
def test_errors_inside_a_200_on_aux_hosts(client: Client) -> None:
    respx.get(f"{ACTORS}/api/v1/actors/nobody").respond(json={"error": "not_found"})
    respx.get(f"{VULN}/api/v1/cve/CVE-1").respond(json={"error": "invalid_cve_id"})
    with pytest.raises(NotFoundError):
        client.actors.get("nobody")
    with pytest.raises(InputError):
        client.cve.get("CVE-1")


@respx.mock
def test_vuln_code_and_sentence_and_upgrade_hint(client: Client) -> None:
    respx.post(f"{VULN}/api/v2/query").respond(
        429,
        json={
            "error": "cooldown",
            "message": "Retry in 70 seconds.",
            "upgrade": {"message": "Create a free account."},
        },
        headers={"Retry-After": "70"},
    )
    with pytest.raises(QuotaError, match=r"Retry in 70 seconds\. Create a free account\."):
        client.vuln.query("pkg:npm/left-pad")


# ── retries ──────────────────────────────────────────────────────────


@respx.mock
def test_gets_are_retried_on_5xx_and_network_errors(client: Client) -> None:
    route = respx.get(f"{API}/scan/mac").mock(
        side_effect=[httpx.ConnectError("boom"), httpx.Response(502), httpx.Response(200, json={"v": 1})]
    )
    assert client.lookup_mac("00:11:22:33:44:55") == {"v": 1}
    assert route.call_count == 3


@respx.mock
def test_network_errors_surface_after_the_last_attempt(client: Client) -> None:
    respx.get(f"{API}/scan/mac").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(NetworkError, match="refused"):
        client.lookup_mac("x")


@respx.mock
def test_scan_launches_are_never_replayed(client: Client) -> None:
    route = respx.post(f"{API}/scan/domain").mock(side_effect=httpx.ConnectError("reset"))
    with pytest.raises(NetworkError):
        client.scan_domain("example.com")
    assert route.call_count == 1


@respx.mock
def test_short_retry_after_is_honoured_and_sbom_cooldown_replayed(client: Client) -> None:
    route = respx.post(f"{VULN}/api/v2/scan").mock(
        side_effect=[
            httpx.Response(429, json={"error": "cooldown"}, headers={"Retry-After": "3"}),
            httpx.Response(200, json={}),
        ]
    )
    client.vuln.scan_manifest(b"x", filename="package-lock.json")
    assert route.call_count == 2


# ── wait helpers ─────────────────────────────────────────────────────


@respx.mock
def test_wait_for_domain_scan_returns_the_v2_report(client: Client) -> None:
    respx.post(f"{API}/scan/domain").respond(json={"status": "pending"})
    status = respx.get(f"{API}/scan/domain/status").mock(
        side_effect=[
            httpx.Response(200, json={"status": "pending"}),
            httpx.Response(503),
            httpx.Response(200, json={"status": "running"}),
            httpx.Response(200, json={"status": "success"}),
        ]
    )
    respx.get(f"{API}/scan/domain/report").respond(json={"schema": "domain-report/2", "status": "completed"})
    client.scan_domain("example.com")
    seen: list[str] = []
    report = client.wait_for_domain_scan("example.com", on_progress=lambda p: seen.append(p["status"]))
    assert seen == ["pending", "running", "success"]
    assert report["schema"] == "domain-report/2"
    assert status.call_count == 4


@respx.mock
def test_wait_for_domain_scan_legacy_reads_v1(client: Client) -> None:
    respx.get(f"{API}/scan/domain/status").respond(json={"status": "success"})
    respx.get(f"{API}/scan/domain/results").respond(json={"results": {}})
    assert client.wait_for_domain_scan("e.com", legacy=True) == {"results": {}}


@respx.mock
def test_wait_for_domain_scan_raises_on_failure(client: Client) -> None:
    respx.get(f"{API}/scan/domain/status").respond(json={"status": "success"})
    respx.get(f"{API}/scan/domain/report").respond(json={"status": "failed"})
    with pytest.raises(ScanFailedError) as info:
        client.wait_for_domain_scan("e.com")
    assert info.value.result == {"status": "failed"}


@respx.mock
def test_wait_for_domain_scan_stops_on_an_auth_error(client: Client) -> None:
    respx.get(f"{API}/scan/domain/status").respond(401, json={"error": "Unauthorized"})
    with pytest.raises(AuthenticationError):
        client.wait_for_domain_scan("e.com")


@respx.mock
def test_wait_times_out(client: Client) -> None:
    respx.get(f"{API}/scan/domain/status").respond(json={"status": "pending"})
    with pytest.raises(ScanTimeoutError) as info:
        client.wait_for_domain_scan("e.com", timeout=0.05, interval=0.01)
    assert info.value.last_status == "pending"


@respx.mock
def test_wait_for_file_scan(client: Client) -> None:
    respx.get(f"{API}/scan/file/results").mock(
        side_effect=[
            httpx.Response(404, json={"error": "Not found"}),
            httpx.Response(200, json={"status": "in_progress", "tools_done": 1, "tools_total": 3}),
            httpx.Response(200, json={"status": "completed"}),
        ]
    )
    assert client.wait_for_file_scan("f00")["status"] == "completed"


@respx.mock
def test_wait_for_file_scan_raises_on_failure(client: Client) -> None:
    respx.get(f"{API}/scan/file/results").respond(json={"status": "failed"})
    with pytest.raises(ScanFailedError):
        client.wait_for_file_scan("f00")


# ── search ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("value", "target"),
    [
        ("CVE-2024-3094", Target.CVE),
        ("8.8.8.8", Target.IP),
        ("2001:db8::1", Target.IP),
        ("00-11-22-AA-BB-CC", Target.MAC),
        ("someone@example.com", Target.EMAIL),
        ("d41d8cd98f00b204e9800998ecf8427e", Target.HASH),
        ("0x" + "a" * 40, Target.CRYPTO),
        ("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", Target.CRYPTO),
        ("https://example.com/login", Target.URL),
        ("+33 6 12 34 56 78", Target.PHONE),
        ("example.com", Target.DOMAIN),
        ("1.2.3.999", Target.UNKNOWN),
        (".example.com", Target.UNKNOWN),
        ("hello", Target.UNKNOWN),
    ],
)
def test_detect_target(value: str, target: Target) -> None:
    assert detect_target(value) is target


@respx.mock
def test_search_routes_a_domain_to_the_report_never_a_scan(client: Client) -> None:
    report = respx.get(f"{API}/scan/domain/report").respond(json={"status": "completed"})
    client.search(" example.com ")
    assert report.called
    with pytest.raises(ValueError):
        client.search("???")


def test_report_url(client: Client) -> None:
    assert client.report_url("cve-2024-1234") == f"{VULN}/cve/CVE-2024-1234"
    assert client.report_url("8.8.8.8") == "https://mlab.test/ip/8.8.8.8"
    assert client.report_url("https://a.b/c") == "https://mlab.test/url?q=https%3A%2F%2Fa.b%2Fc"
    assert client.report_url("nope") is None


# ── async ────────────────────────────────────────────────────────────


@respx.mock
async def test_async_client_mirrors_the_sync_one() -> None:
    respx.get(f"{API}/scan/ip").respond(json={"ip": "1.1.1.1"})
    respx.get(f"{API}/scan/domain/status").respond(json={"status": "success"})
    respx.get(f"{API}/scan/domain/report").respond(json={"status": "partial"})
    respx.post(f"{API}/scan/file/bash").respond(json={"sha256": "s"})
    respx.get(f"{API}/scan/file/bash").respond(json={"risk": "low"})
    respx.get(f"{API}/scan/file/results").respond(json={"status": "partial"})
    for t in ("domain", "ip", "file", "crypto"):
        respx.get(f"{API}/limit/{t}").respond(json={"total": 1})
    respx.get(f"{API}/").respond(403, json={"error": "This organization is locked."})
    async with AsyncClient("k", base_url="https://mlab.test") as c:
        assert (await c.lookup_ip("1.1.1.1"))["ip"] == "1.1.1.1"
        assert (await c.wait_for_domain_scan("e.com"))["status"] == "partial"
        assert (await c.analyze_bash(b"echo hi"))["risk"] == "low"
        assert (await c.wait_for_file_scan("s"))["status"] == "partial"
        assert set(await c.get_limits()) == {"domain", "ip", "file", "crypto"}
        with pytest.raises(ForbiddenError, match="locked"):
            await c.whoami()
