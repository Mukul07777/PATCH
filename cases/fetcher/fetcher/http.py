"""Resilient HTTP helpers (written against urllib3 1.26)."""
import io

import urllib3
from urllib3.response import HTTPResponse
from urllib3.util.retry import Retry

IDEMPOTENT = Retry.DEFAULT_METHOD_WHITELIST | frozenset(["POST"])


def build_retry(total=3):
    return Retry(total=total, backoff_factor=0.5, status_forcelist=[502, 503, 504], method_whitelist=IDEMPOTENT)


def build_pool(total=3):
    return urllib3.PoolManager(retries=build_retry(total), timeout=urllib3.Timeout(connect=2.0, read=5.0))


def response_headers(resp):
    """Lower-cased header dict for logging."""
    return {k.lower(): v for k, v in resp.getheaders().items()}


def content_type(resp):
    return (resp.getheader("Content-Type") or "").split(";")[0].strip()


def fake_response(body=b"{}", headers=None, status=200):
    """Offline response object for tests and dry runs."""
    return HTTPResponse(body=io.BytesIO(body), headers=headers or {}, status=status, preload_content=False)
