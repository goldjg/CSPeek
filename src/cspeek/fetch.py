"""HTTP retrieval of CSP headers.

Uses urllib with bounded timeouts and a deterministic redirect cap.
The fetcher is injectable so tests can mock responses without network.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urljoin

from .models import FetchResult

DEFAULT_TIMEOUT = 10.0
MAX_REDIRECTS = 10
USER_AGENT = "CSPeek/0.2 (+https://github.com/goldjg/CSPeek)"

CSP_HEADER = "Content-Security-Policy"
CSP_RO_HEADER = "Content-Security-Policy-Report-Only"


@dataclass
class HttpResponse:
    """Normalised HTTP response used internally and by test fakes."""

    status: int
    headers: dict[str, str]
    body: str = ""

    def header(self, name: str) -> str | None:
        for key, value in self.headers.items():
            if key.lower() == name.lower():
                return value
        return None


def _urllib_fetch(url: str, timeout: float) -> HttpResponse:
    """Fetch a single URL without following redirects."""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: N802
            return None

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(262144).decode("utf-8", errors="replace")
            return HttpResponse(
                status=response.status,
                headers=dict(response.headers.items()),
                body=body,
            )
    except urllib.error.HTTPError as exc:
        # Redirect and error statuses arrive here because redirects are disabled.
        return HttpResponse(
            status=exc.code,
            headers=dict(exc.headers.items()) if exc.headers else {},
            body="",
        )


def fetch_url(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    fetcher=None,
    max_redirects: int = MAX_REDIRECTS,
) -> FetchResult:
    """Retrieve *url*, following up to *max_redirects* redirects.

    *fetcher* is a callable ``(url, timeout) -> HttpResponse`` used for
    testing; the default performs a real request via urllib.
    """
    fetch = fetcher or _urllib_fetch
    current = url
    redirects = 0
    try:
        while True:
            response = fetch(current, timeout)
            if response.status in (301, 302, 303, 307, 308):
                location = response.header("Location")
                if not location:
                    break
                if redirects >= max_redirects:
                    return FetchResult(
                        input_url=url,
                        final_url=current,
                        status_code=response.status,
                        redirects=redirects,
                        error=f"redirect limit ({max_redirects}) exceeded",
                    )
                current = urljoin(current, location)
                redirects += 1
                continue
            break
        return FetchResult(
            input_url=url,
            final_url=current,
            status_code=response.status,
            csp=response.header(CSP_HEADER),
            csp_report_only=response.header(CSP_RO_HEADER),
            redirects=redirects,
            body=response.body,
            content_type=response.header("Content-Type") or "",
        )
    except Exception as exc:  # noqa: BLE001 - convert to recorded error
        return FetchResult(
            input_url=url,
            final_url=current,
            redirects=redirects,
            error=f"{type(exc).__name__}: {exc}",
        )
