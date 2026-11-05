"""Smoke test against a live instance, skipped unless configured.

    MLAB_TEST_BASE_URL=http://localhost:8080 MLAB_TEST_API_KEY=... pytest -m integration

Only read-only calls: nothing here launches a scan or spends quota beyond
one IP lookup.
"""

from __future__ import annotations

import os

import pytest

from mlab_sh import AuthenticationError, Client

BASE_URL = os.environ.get("MLAB_TEST_BASE_URL", "")
API_KEY = os.environ.get("MLAB_TEST_API_KEY", "")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not (BASE_URL and API_KEY), reason="MLAB_TEST_BASE_URL and MLAB_TEST_API_KEY not set"),
]


def test_live_instance() -> None:
    with Client(API_KEY, base_url=BASE_URL) as mlab:
        assert mlab.whoami().get("auth") == "api_key"
        limit = mlab.get_limit("ip")
        assert {"remaining", "total"} <= set(limit)
        mlab.lookup_ip("8.8.8.8")
        assert mlab.last_quota is None or mlab.last_quota.resource == "ip"


def test_live_instance_refuses_an_unknown_key() -> None:
    with Client("not-a-real-key", base_url=BASE_URL) as mlab, pytest.raises(AuthenticationError):
        mlab.whoami()
