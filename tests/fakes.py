"""Shared fake HTTP fetcher for tests. No network access."""

from __future__ import annotations

from csp_scanner.fetch import HttpResponse


class FakeFetcher:
    """Callable ``(url, timeout) -> HttpResponse`` backed by a dict.

    Records requested URLs for assertions.
    """

    def __init__(self, responses: dict[str, HttpResponse]):
        self.responses = responses
        self.requested: list[str] = []

    def __call__(self, url: str, timeout: float) -> HttpResponse:
        self.requested.append(url)
        if url not in self.responses:
            raise OSError(f"connection refused: {url}")
        return self.responses[url]


def html_response(
    body: str = "",
    csp: str | None = None,
    csp_ro: str | None = None,
    status: int = 200,
    extra_headers: dict[str, str] | None = None,
) -> HttpResponse:
    headers = {"Content-Type": "text/html; charset=utf-8"}
    if csp is not None:
        headers["Content-Security-Policy"] = csp
    if csp_ro is not None:
        headers["Content-Security-Policy-Report-Only"] = csp_ro
    if extra_headers:
        headers.update(extra_headers)
    return HttpResponse(status=status, headers=headers, body=body)


def redirect_response(location: str, status: int = 302) -> HttpResponse:
    return HttpResponse(status=status, headers={"Location": location})
