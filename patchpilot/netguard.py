"""Outbound-request guard for user-configured destinations (webhook / Slack URLs, the SMTP host): SSRF protection.

A destination is allowed only when every address its host resolves to is a public unicast address: loopback,
private (RFC 1918 / ULA), link-local (incl. cloud metadata 169.254.169.254), shared CGNAT, reserved, multicast and
unspecified addresses are refused, for IPv4, IPv6 and IPv4-mapped IPv6 alike. The check runs when a channel or
SMTP host is saved and again at connect time, and the connection is made to the exact address that passed the
check (the IP is pinned), so a DNS answer that changes between check and connect (rebinding) cannot reach an
internal host. Redirects are never followed. On-prem installs that deliberately post to internal hosts set
PATCHPILOT_ALLOW_PRIVATE_WEBHOOKS=1.

The LLM base URL is deliberately NOT guarded: a self-hosted NIM / vLLM endpoint is usually on a private network.
Only admins can change it (Settings), and the connection test only reports success or failure.
"""
import ipaddress
import os
import socket

import httpcore
import httpx


class Blocked(Exception):
    """The destination is not allowed (or cannot be resolved). The message is safe to show to admins."""


def allow_private():
    return os.getenv("PATCHPILOT_ALLOW_PRIVATE_WEBHOOKS", "") == "1"


def _resolve(host, port):
    """Every address `host` resolves to (tests replace this to stay offline)."""
    return [ai[4][0] for ai in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)]


def is_public(ip):
    try:
        a = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(a, ipaddress.IPv6Address):
        if a.ipv4_mapped:
            a = a.ipv4_mapped
        elif a.sixtofour:
            a = a.sixtofour
        elif a.teredo:
            a = a.teredo[1]
    bad = (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast
           or a.is_unspecified or not a.is_global)
    return not bad


def check_host(host, port):
    """The addresses `host` resolves to, all of them allowed; raises Blocked otherwise."""
    host = (host or "").strip("[]")
    if not host:
        raise Blocked("no host")
    try:
        ips = _resolve(host, port)
    except (OSError, UnicodeError):
        raise Blocked(f"{host} cannot be resolved") from None
    if not ips:
        raise Blocked(f"{host} cannot be resolved")
    if not allow_private() and any(not is_public(ip) for ip in ips):
        raise Blocked(f"{host} resolves to a private, loopback or reserved address "
                      "(set PATCHPILOT_ALLOW_PRIVATE_WEBHOOKS=1 to allow internal destinations)")
    return ips


def check_url(url):
    u = httpx.URL(url)
    if u.scheme not in ("http", "https"):
        raise Blocked("only http(s) URLs are allowed")
    return check_host(u.host, u.port or (443 if u.scheme == "https" else 80))


class _PinnedBackend(httpcore.SyncBackend):
    """Resolve + check at connect time and connect to the checked IP (TLS still verifies the host name)."""

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        ip = check_host(host, port)[0]
        return super().connect_tcp(ip, port, timeout=timeout, local_address=local_address,
                                   socket_options=socket_options)


class _ResponseStream(httpx.SyncByteStream):
    def __init__(self, resp):
        self._resp = resp

    def __iter__(self):
        with _map_errors():
            yield from self._resp.stream

    def close(self):
        self._resp.close()


class _map_errors:
    """Re-raise httpcore errors as the matching httpx errors, like httpx's own transport does."""
    _MAP = ((httpcore.ConnectTimeout, httpx.ConnectTimeout), (httpcore.ReadTimeout, httpx.ReadTimeout),
            (httpcore.WriteTimeout, httpx.WriteTimeout), (httpcore.PoolTimeout, httpx.PoolTimeout),
            (httpcore.ConnectError, httpx.ConnectError), (httpcore.ReadError, httpx.ReadError),
            (httpcore.WriteError, httpx.WriteError), (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
            (httpcore.LocalProtocolError, httpx.LocalProtocolError), (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol),
            (httpcore.ProtocolError, httpx.ProtocolError), (httpcore.NetworkError, httpx.NetworkError),
            (httpcore.TimeoutException, httpx.TimeoutException))

    def __enter__(self):
        return self

    def __exit__(self, typ, exc, tb):
        if exc is None or isinstance(exc, Blocked):
            return False
        for src, dst in self._MAP:
            if isinstance(exc, src):
                raise dst(str(exc)) from exc
        return False


class PinnedTransport(httpx.BaseTransport):
    """An httpx transport built only from public httpx/httpcore APIs: an httpcore pool whose network backend
    checks and pins every connection (see _PinnedBackend). No retries, no proxies."""

    def __init__(self):
        self._pool = httpcore.ConnectionPool(ssl_context=httpx.create_ssl_context(), network_backend=_PinnedBackend(),
                                             retries=0)

    def handle_request(self, request):
        req = httpcore.Request(
            method=request.method,
            url=httpcore.URL(scheme=request.url.raw_scheme, host=request.url.raw_host, port=request.url.port,
                             target=request.url.raw_path),
            headers=request.headers.raw, content=request.stream, extensions=request.extensions)
        with _map_errors():
            resp = self._pool.handle_request(req)
        return httpx.Response(status_code=resp.status, headers=resp.headers, stream=_ResponseStream(resp),
                              extensions=resp.extensions)

    def close(self):
        self._pool.close()


def client(timeout=15):
    """An httpx client for guarded destinations: pinned, checked connections, no redirects, no env proxies."""
    return httpx.Client(transport=PinnedTransport(), timeout=timeout, follow_redirects=False, trust_env=False)


def smtp_class(base):
    """A subclass of smtplib.SMTP / SMTP_SSL whose socket goes to the checked, pinned address of the host."""
    def _get_socket(self, host, port, timeout):
        ip = check_host(host, port)[0]
        return base._get_socket(self, ip, port, timeout)  # SMTP_SSL keeps self._host for SNI / cert checks
    return type("Guarded" + base.__name__, (base,), {"_get_socket": _get_socket})
