"""Fetch response headers from a live URL using only urllib."""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass

from . import __version__
from .headers import HeaderSet

DEFAULT_UA = f"nexus-jala/{__version__} (security header audit)"


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    headers: HeaderSet

    @property
    def https(self) -> bool:
        return self.final_url.lower().startswith("https://")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def normalise_url(url: str) -> str:
    url = url.strip()
    if "://" not in url:
        url = "https://" + url
    return url


def fetch_headers(url: str, timeout: float = 10.0, verify: bool = True, follow: bool = True,
                  user_agent: str = DEFAULT_UA) -> FetchResult:
    """GET ``url`` and return its response headers (the body is not read).

    HTTP error statuses (4xx/5xx) are not treated as failures: their headers
    are audited like any other response.
    """
    url = normalise_url(url)
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    handlers = [urllib.request.HTTPSHandler(context=context)]
    if not follow:
        handlers.append(_NoRedirect())
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, method="GET", headers={
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    })
    try:
        response = opener.open(request, timeout=timeout)
    except urllib.error.HTTPError as err:
        final = err.geturl() or url
        return FetchResult(url, final, err.code, HeaderSet(err.headers.items() if err.headers else []))
    try:
        return FetchResult(url, response.geturl(), response.status, HeaderSet(response.headers.items()))
    finally:
        response.close()
