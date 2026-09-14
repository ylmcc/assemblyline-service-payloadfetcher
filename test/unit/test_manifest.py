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
