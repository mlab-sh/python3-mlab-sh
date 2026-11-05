# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-05

### Added

- `Client` (blocking) and `AsyncClient` (asyncio) on httpx, with the same methods.
- Configuration from arguments or `MLAB_API_KEY`, `MLAB_HOSTNAME`, `MLAB_CVE_HOSTNAME`,
  `MLAB_ACTORS_HOSTNAME`, `MLAB_VULN_TOKEN`; base URL for self-hosted instances.
- Lookups: IP, URL (with `resolve`), hash and bulk hashes, email, phone, MAC, crypto and bulk
  crypto, IOC extraction (`country`, `risk`), shell-script analysis, network capture, SSL.
- Domain scans: launch, status, v2 report (`domain-report/2`), legacy v1 results,
  `wait_for_domain_scan` (`interval`, `max_interval`, `on_progress`, `legacy`).
- File scans: `upload_file` to `/upload/file`, results, per-tool output, `wait_for_file_scan`.
- Quotas: `get_limit`, `get_limits`, and `client.last_quota` from the `X-RateLimit-*` headers.
- `client.cve` (vuln.mlab.sh): CVE search, latest, detail, dump, stats, sources, advisories, vendor months,
  CSV/RSS export. `client.vuln`: manifest/SBOM scan (file or URL), package query.
- `client.actors` (actors.mlab.sh): list, profile, actors by CVE, STIX bundle, CSV/JSONL export.
- `search`, `detect_target` and `report_url`, with the CLI's detection rules; `client.modules.available()`.
- Typed exceptions: `AuthenticationError` (401), `ForbiddenError` (403, with the missing `scope`),
  `QuotaError` (429 or limit reached), `NotFoundError`, `InputError`,
  `MaintenanceError`, `NetworkError`, `ScanFailedError`, `ScanTimeoutError`.
- Retries for GETs (network errors, 5xx, short `Retry-After`); POSTs are never replayed.

[1.0.0]: https://github.com/mlab-sh/python3-mlab-sh/releases/tag/v1.0.0
