"""PayloadFetcher: extracts candidate payload URLs from a script and fetches them
directly, classifying the response by its real bytes (not the URL's extension) so
AssemblyLine can recursively analyze whatever a dropper/loader script actually pulls
down.

Never executes or interprets fetched (or submitted) content. See README.md for the
safety rationale (SSRF guarding on every redirect hop, size/timeout/redirect caps).
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlparse

from assemblyline.common.identify import Identify
from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import (
    Heuristic,
    Result,
    ResultSection,
    ResultTableSection,
    ResultURLSection,
    TableRow,
)
from assemblyline_v4_service.common.task import PARENT_RELATION

from payload_fetcher.extraction import dedupe_and_cap, extract_urls, has_multi_arch_loader_pattern
from payload_fetcher.fetcher import fetch_url

_MISMATCH_PRONE_EXTENSIONS = {".php", ".html", ".htm", ".txt", ".asp", ".aspx", ".jsp"}
_RISKY_SIGNATURES = {"executable", "script"}


def _classify_signature(sniffed_type: str) -> str:
    if sniffed_type.startswith("executable"):
        return "executable"
    if sniffed_type.startswith(("code/shell", "code/python", "code/perl", "code/batch", "code/ps1")):
        return "script"
    if sniffed_type.startswith(("code/php", "code/html", "text/")):
        return "webshell_or_html"
    return "other"


class PayloadFetcher(ServiceBase):
    def __init__(self, config=None) -> None:
        super().__init__(config)
        self.identify = None

    def start(self) -> None:
        self.identify = Identify(use_cache=False)

    def execute(self, request: ServiceRequest) -> None:
        text = request.file_contents.decode("utf-8", errors="ignore")
        candidates = extract_urls(text)

        max_urls = request.get_param("max_urls")
        dry_run = request.get_param("dry_run")
        fetch_timeout = request.get_param("fetch_timeout_seconds")
        max_size = request.get_param("max_download_size_mb") * 1024 * 1024
        max_redirects = request.get_param("max_redirects")
        user_agent = request.get_param("user_agent")

        kept, dropped = dedupe_and_cap(candidates, max_urls)
        to_fetch = [c for c in kept if not c.has_shell_interpolation]
        templated = [c for c in kept if c.has_shell_interpolation]

        result = Result()
        audit_log = {
            "extracted_count": len(candidates),
            "kept_count": len(kept),
            "dropped_by_cap": dropped,
            "to_fetch": [c.url for c in to_fetch],
            "templated_not_dispatched": [c.truncated_template for c in templated],
            "fetches": [],
        }

        if kept:
            url_section = ResultURLSection("Candidate URLs extracted from script")
            for c in to_fetch:
                url_section.add_url(c.url, name=c.context)
            for c in templated:
                url_section.add_url(c.truncated_template or c.raw, name=f"{c.context} (templated, not fetched)")
            result.add_section(url_section)

        if dropped:
            note = ResultSection(
                "URL cap reached",
                body=f"{dropped} additional candidate URL(s) were found but not dispatched "
                     f"because the 'max_urls' limit ({max_urls}) was reached.",
            )
            result.add_section(note)

        if has_multi_arch_loader_pattern(to_fetch):
            multi_arch = ResultSection(
                "Multi-architecture loader pattern detected",
                body="Four or more architecture-specific payload URLs were found on a single host, "
                     "matching the shape of a Mirai/Gafgyt-style multi-arch loader.",
            )
            multi_arch.set_heuristic(2, signature="multi_arch_loader")
            result.add_section(multi_arch)

        if templated:
            templated_section = ResultSection(
                "Templated URLs not dispatched",
                body="The following URL(s) contain an unresolved shell variable/glob and were "
                     "reported but not fetched literally:\n"
                     + "\n".join(c.truncated_template or c.raw for c in templated),
            )
            heur6 = Heuristic(6)
            for c in templated:
                heur6.add_signature_id("templated_url")
            templated_section.set_heuristic(heur6)
            result.add_section(templated_section)

        heur1 = None
        heur3 = None
        heur4 = None
        heur5 = None
        table = ResultTableSection("Fetch results") if to_fetch else None

        for c in to_fetch:
            if dry_run:
                table.add_row(TableRow(url=c.url, context=c.context, outcome="skipped(dry_run)"))
                audit_log["fetches"].append({"url": c.url, "outcome": "skipped(dry_run)"})
                continue

            fr = fetch_url(c.url, self.working_directory, fetch_timeout, max_size, max_redirects, user_agent)

            if not fr.ok:
                if fr.error.startswith("ssrf_blocked"):
                    table.add_row(TableRow(url=c.url, context=c.context, outcome="blocked", reason=fr.error))
                    heur3 = heur3 or Heuristic(3)
                    heur3.add_signature_id("ssrf_blocked")
                else:
                    table.add_row(TableRow(url=c.url, context=c.context, outcome="failed", reason=fr.error))
                    heur5 = heur5 or Heuristic(5)
                    heur5.add_signature_id(fr.error.split(":", 1)[0])
                audit_log["fetches"].append({"url": c.url, "outcome": "failed", "reason": fr.error})
                continue

            file_info = self.identify.fileinfo(fr.body_path, skip_fuzzy_hashes=True, calculate_entropy=False)
            sniffed_type = file_info["type"]
            signature = _classify_signature(sniffed_type)

            url_ext = os.path.splitext(urlparse(c.url).path)[1].lower()
            type_mismatch = url_ext in _MISMATCH_PRONE_EXTENSIONS and signature in _RISKY_SIGNATURES

            display_name = f"{fr.sha256}{url_ext}" if url_ext else fr.sha256
            request.add_extracted(
                fr.body_path,
                display_name,
                f"Payload downloaded from {c.url}",
                parent_relation=PARENT_RELATION.DOWNLOADED,
            )

            table.add_row(TableRow(
                url=c.url,
                context=c.context,
                outcome="fetched",
                http_status=fr.http_status,
                content_type_header=fr.content_type_header or "",
                sniffed_type=sniffed_type,
                size=fr.size,
                sha256=fr.sha256,
            ))

            heur1 = heur1 or Heuristic(1)
            heur1.add_signature_id(signature)
            if type_mismatch:
                heur4 = heur4 or Heuristic(4)
                heur4.add_signature_id("type_mismatch")

            audit_log["fetches"].append({
                "url": c.url, "outcome": "fetched", "http_status": fr.http_status,
                "sniffed_type": sniffed_type, "size": fr.size, "sha256": fr.sha256,
                "type_mismatch": type_mismatch,
            })

        if table is not None:
            if heur1:
                table.set_heuristic(heur1)
            result.add_section(table)

        if heur3:
            ssrf_section = ResultSection(
                "SSRF-risk targets blocked",
                body="One or more extracted URLs (or a redirect target) resolved to a "
                     "private/loopback/link-local/metadata address and were not fetched.",
            )
            ssrf_section.set_heuristic(heur3)
            result.add_section(ssrf_section)

        if heur4:
            mismatch_section = ResultSection(
                "Fetched content type does not match URL's apparent extension",
                body="At least one URL's extension (e.g. .php) did not match what was actually "
                     "served (an executable or script) — a known evasion pattern. See the "
                     "'Fetch results' table for details.",
            )
            mismatch_section.set_heuristic(heur4)
            result.add_section(mismatch_section)

        if heur5:
            failed_section = ResultSection(
                "Unreachable targets",
                body="One or more extracted URLs could not be fetched (timeout, connection "
                     "error, oversize response, or too many redirects).",
            )
            failed_section.set_heuristic(heur5)
            result.add_section(failed_section)

        log_path = os.path.join(self.working_directory, "url_fetch_log.json")
        with open(log_path, "w") as f:
            json.dump(audit_log, f, indent=2)
        request.add_supplementary(log_path, "url_fetch_log.json", "Full extraction/fetch audit log")

        request.result = result
