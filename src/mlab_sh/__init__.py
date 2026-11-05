"""Official Python client for mlab.sh threat intelligence.

from mlab_sh import Client

with Client() as mlab:          # key from $MLAB_API_KEY
    print(mlab.lookup_ip("8.8.8.8"))
"""

from ._api import (
    DEFAULT_ACTORS_URL,
    DEFAULT_BASE_URL,
    DEFAULT_VULN_URL,
    Target,
    __version__,
    detect_target,
)
from .client import AsyncClient, Client
from .errors import (
    APIError,
    AuthenticationError,
    ForbiddenError,
    InputError,
    MaintenanceError,
    MlabError,
    NetworkError,
    NotFoundError,
    Quota,
    QuotaError,
    ScanFailedError,
    ScanTimeoutError,
)

__all__ = [
    "DEFAULT_ACTORS_URL",
    "DEFAULT_BASE_URL",
    "DEFAULT_VULN_URL",
    "APIError",
    "AsyncClient",
    "AuthenticationError",
    "Client",
    "ForbiddenError",
    "InputError",
    "MaintenanceError",
    "MlabError",
    "NetworkError",
    "NotFoundError",
    "Quota",
    "QuotaError",
    "ScanFailedError",
    "ScanTimeoutError",
    "Target",
    "__version__",
    "detect_target",
]
