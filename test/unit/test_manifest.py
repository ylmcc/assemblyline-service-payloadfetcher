"""Sanity checks on service_manifest.yml's `accepts` regex.

This exact bug class -- an `accepts`/`filetype` regex quietly failing to match a
file type AL4 actually uses, so the service never even runs -- has hit multiple
services in this project (see the `filetype: "*"` invalid-regex bug found
independently in every sibling service, and this repo's own `accepts` missing
`uri/.*` entirely, which meant a directly-submitted URL never ran PayloadFetcher
at all -- confirmed on a live submission, "6KaatdO1iTjzYt9O6WJTga"). A small
regression test here is cheap insurance against it happening again.
"""
import re
from pathlib import Path

import yaml

MANIFEST_PATH = Path(__file__).parent.parent.parent / "service_manifest.yml"


def _accepts_pattern() -> re.Pattern:
    manifest = yaml.safe_load(MANIFEST_PATH.read_text())
    return re.compile(manifest["accepts"])


def test_accepts_matches_script_and_text_types():
    pattern = _accepts_pattern()
    assert pattern.fullmatch("code/shell")
    assert pattern.fullmatch("code/php")
    assert pattern.fullmatch("text/plain")


def test_accepts_matches_directly_submitted_url_type():
    # The bug this test guards against: a user submitting a bare URL for scanning
    # (not a file containing one) gets AL4's uri/* file type, which the old
    # "code/.*|text/plain" accepts regex did not match at all.
    pattern = _accepts_pattern()
    assert pattern.fullmatch("uri/https")
    assert pattern.fullmatch("uri/http")


def test_accepts_does_not_match_empty_or_metadata():
    pattern = _accepts_pattern()
    assert not pattern.fullmatch("empty")
    assert not pattern.fullmatch("metadata/whatever")


def test_accepts_does_not_match_html():
    # The bug this test guards against: a fetched web page is sniffed as code/html,
    # which the old "code/.*" accepts regex matched -- so AL4 re-dispatched
    # PayloadFetcher onto its own downloaded HTML, which extracted the page's
    # ordinary embedded asset/link URLs (images, other pages) as if they were
    # dropper payload URLs and fetched those too, snowballing recursively until
    # AL4's own submission-wide extraction/depth limit killed it. Confirmed on a
    # live submission ("3ymlEk2P5hoohHsvONTkoh"): 528 extracted files and
    # "MAX DEPTH REACHED" / FAIL_NONRECOVERABLE errors from a single input file.
    # service_manifest.yml also sets recursion_prevention: [PayloadFetcher] as a
    # second, platform-level guard against this same self-feeding loop.
    pattern = _accepts_pattern()
    assert not pattern.fullmatch("code/html")


def test_recursion_prevention_lists_self():
    manifest = yaml.safe_load(MANIFEST_PATH.read_text())
    assert manifest.get("recursion_prevention") == ["PayloadFetcher"]
