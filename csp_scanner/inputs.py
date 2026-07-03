"""URL and file input handling.

Normalises obvious input issues (missing scheme, surrounding whitespace)
without inventing risky behaviour. Only http and https schemes are
accepted.
"""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

ALLOWED_SCHEMES = ("http", "https")


class InputError(ValueError):
    """Raised when a URL or input file cannot be used."""


def normalise_url(raw: str) -> str:
    """Return a normalised absolute URL, defaulting to https://.

    Raises InputError for empty values or unsupported schemes.
    """
    url = raw.strip()
    if not url:
        raise InputError("empty URL")
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise InputError(f"unsupported scheme {parsed.scheme!r} in {raw!r}")
    if not parsed.netloc:
        raise InputError(f"no host in {raw!r}")
    try:
        host, port = parsed.hostname, parsed.port
    except ValueError as exc:
        raise InputError(f"invalid host/port in {raw!r}: {exc}") from exc
    if not host:
        raise InputError(f"no host in {raw!r}")
    return url


def load_targets(url: str | None = None, input_file: str | None = None) -> list[str]:
    """Build a de-duplicated, order-preserving target list.

    Accepts a single URL and/or a file of URLs (one per line, `#` comments
    and blank lines ignored).
    """
    raw: list[str] = []
    if url:
        raw.append(url)
    if input_file:
        path = Path(input_file)
        if not path.is_file():
            raise InputError(f"input file not found: {input_file}")
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                raw.append(line)
    if not raw:
        raise InputError("no targets supplied")
    seen: set[str] = set()
    targets: list[str] = []
    for item in raw:
        normalised = normalise_url(item)
        if normalised not in seen:
            seen.add(normalised)
            targets.append(normalised)
    return targets
