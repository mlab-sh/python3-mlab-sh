# python3-mlab-sh

Official Python client for [mlab.sh](https://mlab.sh): IOC lookups, domain and
file scans, shell-script analysis, CVEs (vuln.mlab.sh), SBOM scanning and threat
actors (actors.mlab.sh). It covers everything the [`mlab` CLI](https://github.com/mlab-sh/mlab-cli)
does, with a blocking `Client` and an asyncio `AsyncClient` that share the same
methods.

- Python 3.9+, one runtime dependency: [`httpx`](https://www.python-httpx.org/)
- Fully typed (`py.typed`), checked with `mypy --strict`
- Typed exceptions, quota from the `X-RateLimit-*` headers, safe retries
- Helpers that wait for a domain or file scan to finish

```bash
pip install mlab-sh
```

## Authentication

Create an API key in your organization settings on mlab.sh, then pass it or set
`MLAB_API_KEY`:

```python
from mlab_sh import Client

mlab = Client("mlab_xxx")   # or Client() with MLAB_API_KEY set
print(mlab.whoami())        # {"organization": "...", "plan": "...", "auth": "api_key"}
```

The key is sent as `Authorization: token <key>`. Without a key the main API
applies the anonymous quota. Keys expire after **90 days** by default; an
expired, revoked or unknown key raises `AuthenticationError`.

Each key carries scopes. A call outside them raises `ForbiddenError`
with the server's message naming the missing permission:

| Scope | Methods |
|---|---|
| `scan.lookup` | `lookup_*`, `extract_iocs` |
| `scan.domain` | `scan_domain`, `get_domain_*`, `wait_for_domain_scan`, `capture_network` |
| `scan.file` | `upload_file`, `get_file_*`, `wait_for_file_scan`, `analyze_bash`, `get_bash_report` |

vuln.mlab.sh and actors.mlab.sh need no key. An optional personal vuln token
(`vuln_token=` or `MLAB_VULN_TOKEN`, sent as a Bearer token) raises the SBOM
scan quota.

### Configuration

| Argument | Environment | Default |
|---|---|---|
| `api_key` | `MLAB_API_KEY` | none (anonymous) |
| `base_url` | `MLAB_HOSTNAME` | `https://mlab.sh` |
| `vuln_url` | `MLAB_CVE_HOSTNAME` | `https://vuln.mlab.sh` |
| `actors_url` | `MLAB_ACTORS_HOSTNAME` | `https://actors.mlab.sh` |
| `vuln_token` | `MLAB_VULN_TOKEN` | none |
| `timeout` | | `60` seconds |

These are the variables the CLI reads, so one environment drives both. For a
self-hosted instance, set `base_url` to the site root; the client adds `/api/v1`
itself.

```python
with Client(base_url="https://mlab.example.org") as mlab:
    ...
```

## Lookups

```python
mlab.lookup_ip("8.8.8.8")
mlab.lookup_url("https://example.com/login")
mlab.lookup_url("https://bit.ly/x", resolve=True)       # the server follows redirects
mlab.lookup_hash("44d88612fea8a8f36de82e1278abb02f")
mlab.lookup_hashes(["44d886...", "e3b0c4..."])          # one call, {"results": [...]}
mlab.lookup_email("someone@example.com")
mlab.lookup_phone("+33612345678")
mlab.lookup_mac("00:1A:2B:3C:4D:5E")
mlab.lookup_crypto("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
mlab.lookup_crypto("0x...", chain="eth")                # chain is detected when omitted
mlab.lookup_crypto_addresses(["0x...", "0x..."], chain="eth")
```

### IOC extraction

```python
with open("incident.txt") as fh:
    iocs = mlab.extract_iocs(fh.read())
print(iocs["ioc_total"], iocs["iocs"])

mlab.extract_iocs(sms_text, country="fr", risk="deep")  # risk: "fast" (local) or "deep" (network)
```

### Search

`search` recognises what a value is (IP, domain, URL, hash, email, phone, MAC,
crypto address or CVE) and runs the matching lookup. A domain reads the existing
report and never launches a scan.

```python
from mlab_sh import Target, detect_target

detect_target("CVE-2024-3094")    # Target.CVE
mlab.search("8.8.8.8")            # same as lookup_ip
mlab.report_url("example.com")       # "https://mlab.sh/domain/example.com"
```

## Domain scans

```python
mlab.scan_domain("example.com")                    # launch
report = mlab.wait_for_domain_scan("example.com")  # poll, then fetch the v2 report

print(report["schema"])   # "domain-report/2"
print(report["status"])   # "completed" or "partial"
```

`wait_for_domain_scan` polls with a growing interval (`interval=2` s up to
`max_interval=15` s), calls `on_progress` with every status it reads, tolerates
a few network or 5xx blips, raises `ScanFailedError` when the scan failed and
`ScanTimeoutError` after `timeout` seconds (15 minutes by default).

```python
mlab.get_domain_status("example.com")    # {"status": "pending" | ... | "success"}
mlab.get_domain_report("example.com")    # v2 report
mlab.get_domain_results("example.com")   # legacy v1 results, frozen upstream
mlab.wait_for_domain_scan("example.com", legacy=True, timeout=600, on_progress=print)
mlab.get_ssl("example.com")              # certificates
mlab.capture_network("https://example.com")   # requests a real browser makes
```

## File scans

```python
upload = mlab.upload_file("invoice.pdf")  # path or bytes
results = mlab.wait_for_file_scan(upload["sha256"])
print(results["status"], results["tools_done"], results["tools_total"])

mlab.get_file_results(upload["sha256"])
mlab.get_file_tool_output(upload["sha256"], "yara")  # one tool's raw output
```

Uploads go to `/upload/file` at the site root (10 MB on the Free plan, 100 MB on
paid plans). `wait_for_file_scan` returns on `completed` or `partial` and raises
`ScanFailedError` on `failed`.

## Shell scripts

```python
report = mlab.analyze_bash("install.sh")            # path
report = mlab.analyze_bash(b"curl http://x | sh")   # or the script's bytes
mlab.get_bash_report(sha256)                        # read a stored analysis again
```

## Quotas

```python
mlab.get_limit("domain")   # {"scan_type": "domain", "remaining": 98, "total": 100}
mlab.get_limits()          # {"domain": ..., "ip": ..., "file": ..., "crypto": ...}

mlab.lookup_ip("1.1.1.1")
mlab.last_quota  # Quota(limit=100, remaining=97, resource="ip", window_seconds=86400)
```

`last_quota` is refreshed from the `X-RateLimit-Limit/Remaining/Resource/Window`
headers of every metered answer.

## CVEs: `client.cve` (vuln.mlab.sh)

```python
mlab.cve.search("openssl", severity="CRITICAL", min_cvss=9, kev_only=True, limit=50)
mlab.cve.search("log4j", date_start="2021-12-01", date_end="2021-12-31", page=1)
mlab.cve.latest()                      # last 7 days
mlab.cve.get("CVE-2024-3094")
mlab.cve.stats()
mlab.cve.sources()
mlab.cve.advisories(cve="CVE-2024-3094")
mlab.cve.advisories(country="fr", limit=20)
mlab.cve.vendor_months("microsoft", 2024)
mlab.cve.dump(date_start="2024-01-01", min_cvss=7)   # bulk, rate limited per IP

csv_text = mlab.cve.export("openssl", severity="HIGH")
rss_text = mlab.cve.export("openssl", format="rss")
```

## SBOM and package vulnerabilities: `client.vuln`

```python
mlab.vuln.scan_manifest("package-lock.json")              # Cargo.lock, requirements.txt, go.sum, CycloneDX...
mlab.vuln.scan_manifest(lock_bytes, filename="Cargo.lock")
mlab.vuln.scan_manifest_url("https://raw.githubusercontent.com/org/repo/main/Cargo.lock")

mlab.vuln.query("pkg:cargo/time", version="0.1.0")  # purl
mlab.vuln.query("crates.io/time", version="0.1.0")  # ecosystem/name
```

## Threat actors: `client.actors` (actors.mlab.sh)

```python
mlab.actors.list(origin="Russia", motivation="Espionage", limit=20, offset=0)
mlab.actors.get("apt28")
mlab.actors.by_cve("CVE-2023-23397")   # actors documented exploiting it
mlab.actors.stix("apt28")            # STIX 2.1 bundle
mlab.actors.export(format="jsonl")      # or "csv", as text
```

Actor data: ETDA Threat Group Cards and MITRE ATT&CK, CC BY-NC-SA 4.0.

## CLI modules: `client.modules`

```python
mlab.modules.available()   # catalogue of the mlab-* CLI modules (unifi, mikrotik, proxmox...)
```

## Async

`AsyncClient` has the same constructor and methods; every call is awaited.

```python
import asyncio
from mlab_sh import AsyncClient

async def main() -> None:
    async with AsyncClient() as mlab:
        ips = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
        results = await asyncio.gather(*(mlab.lookup_ip(ip) for ip in ips))
        await mlab.scan_domain("example.com")
        report = await mlab.wait_for_domain_scan("example.com")

asyncio.run(main())
```

## Errors

```text
MlabError
├── NetworkError              no HTTP answer (DNS, TLS, refused, timeout)
├── APIError                  .status, .body
│   ├── AuthenticationError   401: unknown, expired or revoked key
│   ├── ForbiddenError        403: missing scope (.scope), organization locked
│   ├── QuotaError            429 or "limit reached": .retry_after, .quota
│   ├── NotFoundError         no such scan, CVE, actor
│   ├── InputError            malformed or unsupported input
│   └── MaintenanceError      platform in maintenance
├── ScanFailedError           a waited scan failed: .result
└── ScanTimeoutError          a wait gave up: .last_status
```

```python
from mlab_sh import ForbiddenError, QuotaError

try:
    mlab.scan_domain("example.com")
except ForbiddenError as e:
    print(e.message)          # names the missing permission
except QuotaError as e:
    print(e.retry_after, e.quota)
```

GET requests are retried up to 3 times on network errors, 5xx and a 429 whose
`Retry-After` is 30 s or less. Scan launches and other POSTs are never replayed,
so a quota is never spent twice (the SBOM upload is replayed only after a short
429 cooldown, where nothing was spent).

## Development

```bash
pip install -e '.[dev]'
pytest
ruff check . && ruff format --check .
mypy
```

The integration test runs against a live instance and is skipped otherwise:

```bash
MLAB_TEST_BASE_URL=http://localhost:8080 MLAB_TEST_API_KEY=... pytest -m integration
```

## License

GPL-3.0, see [LICENSE](LICENSE).
