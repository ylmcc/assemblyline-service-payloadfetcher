"""Pure text-extraction logic: find candidate payload URLs embedded in a script.

No AL4 imports, no network calls. Kept separate from payload_fetcher.py so it can be
unit-tested directly against literal strings.
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'`|;&<>()]+")
INTERP_RE = re.compile(r"\$\{?\w+\}?")
TRAILING_PUNCT_RE = re.compile(r"[.,)\]]+$")

# Tokens that indicate a download-and-execute command context, checked on the same line
# as the matched URL.
_DOWNLOAD_TOKENS = ("wget", "curl")
_PIPE_TO_SHELL_RE = re.compile(r"\|\s*(?:/bin/)?(?:ba)?sh\b")

# AL4 represents a directly-submitted URL (accepts: uri/.*) as a small synthetic text
# file: "# Assemblyline URI file\nuri: <url>\n". A line matching this shape is the
# submission's own target, not something discovered inside script content -- worth its
# own distinct context label rather than the generic "unknown" fallback.
_URI_SUBMISSION_LINE_RE = re.compile(r"^\s*uri:\s*https?://", re.IGNORECASE)


@dataclass
class ExtractedURL:
    raw: str
    url: str
    host: str
    context: str
    has_shell_interpolation: bool
    truncated_template: str | None = None


def _context_for_line(line: str) -> str:
    if _URI_SUBMISSION_LINE_RE.match(line):
        return "submitted_url"
    if _PIPE_TO_SHELL_RE.search(line):
        return "curl|sh"
    lowered = line.lower()
    for token in _DOWNLOAD_TOKENS:
        if token in lowered:
            return token
    return "unknown"


def _truncate_at_interpolation(url: str) -> str:
    match = INTERP_RE.search(url)
    return url[: match.start()] if match else url


def extract_urls(text: str) -> list[ExtractedURL]:
    results: list[ExtractedURL] = []
    for line in text.splitlines():
        for m in URL_RE.finditer(line):
            raw = m.group(0)
            url = TRAILING_PUNCT_RE.sub("", raw)
            # Drop a trailing pipe-to-shell (and anything after it) that URL_RE may have
            # swallowed as part of the "non-whitespace" match, e.g. "http://h/x|sh".
            pipe_idx = url.find("|")
            if pipe_idx != -1:
                url = url[:pipe_idx]
            has_interp = bool(INTERP_RE.search(url))
            truncated = _truncate_at_interpolation(url) if has_interp else None
            host = urlparse(url).hostname or ""
            results.append(
                ExtractedURL(
                    raw=raw,
                    url=url,
                    host=host,
                    context=_context_for_line(line),
                    has_shell_interpolation=has_interp,
                    truncated_template=truncated,
                )
            )
    return results


def dedupe_and_cap(candidates: list[ExtractedURL], max_urls: int) -> tuple[list[ExtractedURL], int]:
    """Dedupe by (lowercased host, path), preserve first-appearance order, cap at max_urls.

    Returns (kept, dropped_count).
    """
    seen: set[tuple[str, str]] = set()
    deduped: list[ExtractedURL] = []
    for c in candidates:
        parsed = urlparse(c.url)
        key = (parsed.hostname.lower() if parsed.hostname else "", parsed.path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(c)
    kept = deduped[:max_urls]
    dropped = max(0, len(deduped) - max_urls)
    return kept, dropped


def group_by_host(candidates: list[ExtractedURL]) -> dict[tuple[str, str], list[ExtractedURL]]:
    groups: dict[tuple[str, str], list[ExtractedURL]] = defaultdict(list)
    for c in candidates:
        parsed = urlparse(c.url)
        groups[(parsed.scheme, (parsed.hostname or "").lower())].append(c)
    return groups


def has_multi_arch_loader_pattern(candidates: list[ExtractedURL], threshold: int = 4) -> bool:
    return any(len(members) >= threshold for members in group_by_host(candidates).values())
