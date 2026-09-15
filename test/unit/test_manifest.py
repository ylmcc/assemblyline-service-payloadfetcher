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


def _manifest() -> dict:
    return yaml.safe_load(MANIFEST_PATH.read_text())


def _accepts_pattern() -> re.Pattern:
    return re.compile(_manifest()["accepts"])


def _rejects_pattern() -> re.Pattern:
    return re.compile(_manifest()["rejects"])


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


def test_html_is_rejected_not_excluded_via_accepts_lookahead():
    # The bug this test guards against, in two parts:
    #
    # 1) A fetched web page is sniffed as code/html, which the plain "code/.*"
    #    accepts regex matches -- so AL4 re-dispatched PayloadFetcher onto its own
    #    downloaded HTML, which extracted the page's ordinary embedded asset/link
    #    URLs (images, other pages) as if they were dropper payload URLs and
    #    fetched those too, snowballing recursively until AL4's own
    #    submission-wide extraction/depth limit killed it. Confirmed on a live
    #    submission ("3ymlEk2P5hoohHsvONTkoh"): 528 extracted files and
    #    "MAX DEPTH REACHED" / FAIL_NONRECOVERABLE errors from one input file.
    #
    # 2) The first fix used a negative-lookahead accepts regex
    #    ("code/(?!html).*") to exclude it. That compiles fine under Python's
    #    `re`, which is all the local test suite checked -- but AL4's actual
    #    dispatcher is written in Rust and its `regex` crate does not support
    #    look-around at all, so that regex crashed dispatch for EVERY
    #    submission cluster-wide the moment this manifest was deployed. Fixed
    #    by excluding code/html via `rejects` (a plain literal, no lookaround)
    #    instead, with `recursion_prevention: [PayloadFetcher]` as a second,
    #    platform-level guard against this same self-feeding loop.
    assert _accepts_pattern().fullmatch("code/html")  # accepts stays broad and lookaround-free
    assert _rejects_pattern().fullmatch("code/html")  # rejects is what actually excludes it


def test_accepts_and_rejects_contain_no_lookaround():
    # Rust's `regex` crate (used by AL4's real dispatcher) has no look-around support
    # at all -- Python's `re`, which the rest of this test file uses, happily accepts
    # it, so a lookahead/lookbehind regex can pass every local/CI test and still crash
    # dispatch for every submission cluster-wide the moment it's deployed (see
    # test_html_is_rejected_not_excluded_via_accepts_lookahead above for exactly that
    # happening). Guard against it landing in this manifest, or any other service's,
    # ever again.
    manifest = _manifest()
    for field in ("accepts", "rejects"):
        pattern = manifest[field]
        assert "(?=" not in pattern, f"{field} uses a lookahead, unsupported by AL4's Rust dispatcher: {pattern}"
        assert "(?!" not in pattern, f"{field} uses a negative lookahead, unsupported by AL4's Rust dispatcher: {pattern}"
        assert "(?<" not in pattern, f"{field} uses a lookbehind, unsupported by AL4's Rust dispatcher: {pattern}"


def test_recursion_prevention_lists_self():
    manifest = _manifest()
    assert manifest.get("recursion_prevention") == ["PayloadFetcher"]


def test_user_agent_param_list_matches_pool():
    # service_manifest.yml's user_agent dropdown and payload_fetcher/user_agents.py's
    # REALISTIC_USER_AGENTS are two representations of the same pool, kept in sync
    # deliberately rather than automatically (the manifest is what an analyst edits
    # to customize the pool; the Python list is what pick_user_agent() actually
    # selects from at runtime). This test is the tripwire for them drifting apart.
    from payload_fetcher.user_agents import RANDOM_SENTINEL, REALISTIC_USER_AGENTS

    manifest = _manifest()
    param = next(p for p in manifest["submission_params"] if p["name"] == "user_agent")
    assert param["type"] == "list"
    assert param["default"] == RANDOM_SENTINEL
    assert param["value"] == RANDOM_SENTINEL
    assert param["list"][0] == RANDOM_SENTINEL
    assert param["list"][1:] == REALISTIC_USER_AGENTS
