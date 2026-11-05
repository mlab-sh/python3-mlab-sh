"""Typed exceptions raised by the mlab.sh clients.

The API answers 400 for almost every refusal (quota spent, maintenance, bad
input) with the reason in ``{"error": "..."}``; the clients read that reason
once and raise the matching class, so callers branch on types, not strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Quota:
    """Scan quota, read from the ``X-RateLimit-*`` headers of the last answer.

    ``window_seconds`` is the length of the rolling window in seconds.
    """

    limit: int
    remaining: int
    resource: str
    window_seconds: int


class MlabError(Exception):
    """Base class of every error raised by this package."""

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class NetworkError(MlabError):
    """No HTTP answer: DNS, TLS, connection refused or timeout."""


class APIError(MlabError):
    """The server answered with an error.

    ``status`` is ``None`` when the error came inside a 200, which
    vuln.mlab.sh and actors.mlab.sh do (``{"error": "not_found"}``).
    """

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        body: Any = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class AuthenticationError(APIError):
    """401: the API key is unknown, expired or revoked.

    Keys expire after 90 days by default; an owner or admin creates a new
    one in the organization settings.
    """


class ForbiddenError(APIError):
    """403: the key lacks a scope (``scan.lookup``, ``scan.domain``,
    ``scan.file``...) or the organization is locked. ``message`` is the
    server's own sentence; ``scope`` is the permission it names, if any."""

    def __init__(self, message: str, *, status: int | None = None, body: Any = None) -> None:
        super().__init__(message, status=status, body=body)
        found = re.search(r"'([a-z]+(?:\.[a-z]+)?)' permission", message)
        self.scope: str | None = found.group(1) if found else None


class QuotaError(APIError):
    """429, or a 400 saying the scan limit is reached."""

    def __init__(
        self,
        message: str,
        *,
        status: int | None = None,
        body: Any = None,
        retry_after: float | None = None,
        quota: Quota | None = None,
    ) -> None:
        super().__init__(message, status=status, body=body)
        self.retry_after = retry_after
        self.quota = quota


class NotFoundError(APIError):
    """No such record: unknown scan, CVE, actor or route."""


class InputError(APIError):
    """The input was refused as malformed or unsupported."""


class MaintenanceError(APIError):
    """The platform is in maintenance; retry in a few minutes."""


class ScanFailedError(MlabError):
    """A domain or file scan ended in ``failed``. ``result`` is the last
    payload read (report or file results), when there is one."""

    def __init__(self, message: str, result: Any = None) -> None:
        super().__init__(message)
        self.result = result


class ScanTimeoutError(MlabError):
    """A ``wait_for_*`` helper gave up before the scan finished."""

    def __init__(self, message: str, last_status: str) -> None:
        super().__init__(message)
        self.last_status = last_status
