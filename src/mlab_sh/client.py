"""``Client`` (blocking) and ``AsyncClient`` (asyncio), both on httpx."""

from __future__ import annotations

import asyncio
import base64
import time
from collections.abc import Awaitable, Callable
from types import TracebackType
from typing import Any, cast

import httpx

from ._api import LIMIT_TYPES, FileInput, _Core, _Request, read_file, retry_delay
from .errors import (
    APIError,
    NetworkError,
    NotFoundError,
    ScanFailedError,
    ScanTimeoutError,
)

_DOMAIN_FAILED = ("failed", "fail", "error")
_FILE_DONE = ("completed", "partial")
#: Consecutive transient errors (network, 5xx) a wait survives.
_MAX_POLL_ERRORS = 5

#: Called with every payload a ``wait_for_*`` helper polls (status or results).
Progress = Callable[[Any], None]


class _Poller:
    """Deadline, growing interval and error budget of a ``wait_for_*`` loop."""

    def __init__(
        self,
        what: str,
        timeout: float,
        interval: float,
        max_interval: float,
        on_progress: Progress | None,
    ) -> None:
        self.what = what
        self.start = time.monotonic()
        self.deadline = self.start + timeout
        self.interval = interval
        self.ceiling = max(max_interval, interval)
        self.on_progress = on_progress
        self.errors = 0
        self.status = "pending"

    def ok(self, status: str, payload: Any) -> None:
        self.errors = 0
        self.status = status
        if self.on_progress is not None:
            self.on_progress(payload)

    def failed(self, exc: Exception) -> None:
        """Absorb a transient error, re-raise anything retrying cannot fix."""
        transient = isinstance(exc, NetworkError) or type(exc) is APIError
        self.errors += 1
        if not transient or self.errors >= _MAX_POLL_ERRORS:
            raise exc

    def delay(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            elapsed = round(time.monotonic() - self.start)
            raise ScanTimeoutError(
                f"{self.what}: gave up after {elapsed}s (last status: {self.status})",
                self.status,
            )
        delay = min(self.interval, remaining)
        self.interval = min(self.interval * 1.5, self.ceiling)
        return delay


def _status(payload: Any, default: str) -> str:
    if isinstance(payload, dict) and isinstance(payload.get("status"), str):
        return str(payload["status"])
    return default


def _bash_payload(file: FileInput, filename: str | None) -> dict[str, str]:
    name, content = read_file(file, filename or ("script.sh" if isinstance(file, bytes) else None))
    if not content:
        raise ValueError("the script is empty")
    return {"content_b64": base64.b64encode(content).decode(), "filename": name}


def _bash_sha(posted: Any) -> str:
    sha = posted.get("sha256") if isinstance(posted, dict) else None
    if not isinstance(sha, str) or not sha:
        raise APIError("the API accepted the script but returned no hash", body=posted)
    return sha


def _domain_failed(domain: str, report: Any) -> ScanFailedError:
    return ScanFailedError(f"the scan of {domain} failed", report)


class Client(_Core[Any, str]):
    """Blocking client for mlab.sh, vuln.mlab.sh and actors.mlab.sh.

    ``api_key`` defaults to ``$MLAB_API_KEY``; without one the main API
    applies the anonymous quota. ``base_url`` (``$MLAB_HOSTNAME``) points at
    a self-hosted instance; ``vuln_url``, ``actors_url`` and ``vuln_token``
    follow ``$MLAB_CVE_HOSTNAME``, ``$MLAB_ACTORS_HOSTNAME`` and
    ``$MLAB_VULN_TOKEN``.
    """

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
        super().__init__(
            api_key,
            base_url=base_url,
            vuln_url=vuln_url,
            actors_url=actors_url,
            vuln_token=vuln_token,
            timeout=timeout,
        )
        self._http = httpx.Client(timeout=timeout)

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Client:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def _send(self, req: _Request) -> httpx.Response:
        attempt = 1
        while True:
            try:
                resp = self._http.request(**self._request_kwargs(req))
            except httpx.TransportError as e:
                delay = retry_delay(req, attempt, None)
                if delay is None:
                    raise NetworkError(f"{req.method} {self._url(req)}: {e}") from e
            else:
                delay = retry_delay(req, attempt, resp)
                if delay is None:
                    return resp
            time.sleep(delay)
            attempt += 1

    def _json(self, req: _Request) -> Any:
        return self._result(req, self._send(req), as_text=False)

    def _text(self, req: _Request) -> str:
        return cast(str, self._result(req, self._send(req), as_text=True))

    def get_limits(self) -> dict[str, Any]:
        """Quota of every scan type, keyed ``domain``, ``ip``, ``file``, ``crypto``."""
        return {t: self.get_limit(t) for t in LIMIT_TYPES}

    def analyze_bash(self, file: FileInput, *, filename: str | None = None) -> Any:
        """Analyse a shell script (path, or bytes of the script) and return the
        stored report: suspicious patterns, indicators, risk."""
        posted = self._json(
            _Request("POST", "api", "/scan/file/bash", json=_bash_payload(file, filename), retry="none")
        )
        return self.get_bash_report(_bash_sha(posted))

    def wait_for_domain_scan(
        self,
        domain: str,
        *,
        timeout: float = 900.0,
        interval: float = 2.0,
        max_interval: float = 15.0,
        on_progress: Progress | None = None,
        legacy: bool = False,
    ) -> Any:
        """Poll a launched domain scan until it ends, then return its report
        (v2, or v1 with ``legacy=True``).

        Polls every ``interval`` seconds, growing by half each time up to
        ``max_interval``; ``on_progress`` receives each status payload.
        Raises ``ScanFailedError`` when the scan failed and
        ``ScanTimeoutError`` after ``timeout`` seconds. A partial report is
        returned: check its ``status``.
        """
        poll = _Poller(f"domain scan of {domain}", timeout, interval, max_interval, on_progress)
        while poll.status != "success":
            time.sleep(poll.delay())
            try:
                payload = self.get_domain_status(domain)
            except (NetworkError, APIError) as e:
                poll.failed(e)
                continue
            status = _status(payload, poll.status)
            if status in _DOMAIN_FAILED:
                raise _domain_failed(domain, None)
            poll.ok(status, payload)
        if legacy:
            return self.get_domain_results(domain)
        report = self.get_domain_report(domain)
        if _status(report, "") == "failed":
            raise _domain_failed(domain, report)
        return report

    def wait_for_file_scan(
        self,
        sha256: str,
        *,
        timeout: float = 900.0,
        interval: float = 2.0,
        max_interval: float = 15.0,
        on_progress: Progress | None = None,
    ) -> Any:
        """Poll a file analysis until ``completed`` or ``partial`` and return
        the results. Raises ``ScanFailedError`` on ``failed`` and
        ``ScanTimeoutError`` after ``timeout`` seconds."""
        poll = _Poller(f"file scan of {sha256}", timeout, interval, max_interval, on_progress)
        while True:
            try:
                results = self.get_file_results(sha256)
            except (NetworkError, APIError) as e:
                # Not found only means the analysis has no record yet.
                if not isinstance(e, NotFoundError):
                    poll.failed(e)
            else:
                status = _status(results, "pending")
                if status == "failed":
                    raise ScanFailedError(f"the analysis of {sha256} failed", results)
                if status in _FILE_DONE:
                    return results
                poll.ok(status, results)
            time.sleep(poll.delay())


class AsyncClient(_Core[Awaitable[Any], Awaitable[str]]):
    """asyncio twin of ``Client``: same constructor, same methods, awaited."""

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
        super().__init__(
            api_key,
            base_url=base_url,
            vuln_url=vuln_url,
            actors_url=actors_url,
            vuln_token=vuln_token,
            timeout=timeout,
        )
        self._http = httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def _send(self, req: _Request) -> httpx.Response:
        attempt = 1
        while True:
            try:
                resp = await self._http.request(**self._request_kwargs(req))
            except httpx.TransportError as e:
                delay = retry_delay(req, attempt, None)
                if delay is None:
                    raise NetworkError(f"{req.method} {self._url(req)}: {e}") from e
            else:
                delay = retry_delay(req, attempt, resp)
                if delay is None:
                    return resp
            await asyncio.sleep(delay)
            attempt += 1

    async def _json(self, req: _Request) -> Any:
        return self._result(req, await self._send(req), as_text=False)

    async def _text(self, req: _Request) -> str:
        return cast(str, self._result(req, await self._send(req), as_text=True))

    async def get_limits(self) -> dict[str, Any]:
        """Quota of every scan type, keyed ``domain``, ``ip``, ``file``, ``crypto``."""
        values = await asyncio.gather(*(self.get_limit(t) for t in LIMIT_TYPES))
        return dict(zip(LIMIT_TYPES, values))

    async def analyze_bash(self, file: FileInput, *, filename: str | None = None) -> Any:
        """See ``Client.analyze_bash``."""
        posted = await self._json(
            _Request("POST", "api", "/scan/file/bash", json=_bash_payload(file, filename), retry="none")
        )
        return await self.get_bash_report(_bash_sha(posted))

    async def wait_for_domain_scan(
        self,
        domain: str,
        *,
        timeout: float = 900.0,
        interval: float = 2.0,
        max_interval: float = 15.0,
        on_progress: Progress | None = None,
        legacy: bool = False,
    ) -> Any:
        """See ``Client.wait_for_domain_scan``."""
        poll = _Poller(f"domain scan of {domain}", timeout, interval, max_interval, on_progress)
        while poll.status != "success":
            await asyncio.sleep(poll.delay())
            try:
                payload = await self.get_domain_status(domain)
            except (NetworkError, APIError) as e:
                poll.failed(e)
                continue
            status = _status(payload, poll.status)
            if status in _DOMAIN_FAILED:
                raise _domain_failed(domain, None)
            poll.ok(status, payload)
        if legacy:
            return await self.get_domain_results(domain)
        report = await self.get_domain_report(domain)
        if _status(report, "") == "failed":
            raise _domain_failed(domain, report)
        return report

    async def wait_for_file_scan(
        self,
        sha256: str,
        *,
        timeout: float = 900.0,
        interval: float = 2.0,
        max_interval: float = 15.0,
        on_progress: Progress | None = None,
    ) -> Any:
        """See ``Client.wait_for_file_scan``."""
        poll = _Poller(f"file scan of {sha256}", timeout, interval, max_interval, on_progress)
        while True:
            try:
                results = await self.get_file_results(sha256)
            except (NetworkError, APIError) as e:
                if not isinstance(e, NotFoundError):
                    poll.failed(e)
            else:
                status = _status(results, "pending")
                if status == "failed":
                    raise ScanFailedError(f"the analysis of {sha256} failed", results)
                if status in _FILE_DONE:
                    return results
                poll.ok(status, results)
            await asyncio.sleep(poll.delay())
