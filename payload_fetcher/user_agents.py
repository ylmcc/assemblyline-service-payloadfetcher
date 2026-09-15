"""A small pool of realistic, current-generation browser User-Agent strings.

Some malware-hosting infrastructure fingerprints requests and serves a decoy/empty
response (or blocks outright) to obviously-non-browser or sandbox-identifying User-
Agent strings, so a fetcher that self-identifies (e.g. "AssemblyLine PayloadFetcher")
can end up analyzing a sinkhole page instead of the real payload. Picking a realistic
browser UA makes the fetch blend in as ordinary traffic instead.

One UA is picked once per execute() call (not per URL) so a single submission's
fetches look like one consistent browser session rather than a different browser on
every request, which is itself a tell.
"""
from __future__ import annotations

import random

# service_manifest.yml's `user_agent` submission param exposes this same pool as a
# dropdown (type: list) plus this sentinel, so an analyst can pin one specific UA
# through the AL4 UI/API instead of a random pick -- see payload_fetcher.py.
# test/unit/test_manifest.py enforces that the manifest's list stays in sync with
# REALISTIC_USER_AGENTS below.
RANDOM_SENTINEL = "(random)"

# Chrome/Windows, Chrome/macOS, Firefox/Windows, Firefox/Linux, Safari/macOS,
# Edge/Windows, Chrome/Android, Safari/iOS -- a small spread of common, current
# desktop and mobile browser/OS combinations. Customize this pool by editing both
# this list and the matching `user_agent` submission_param `list:` field in
# service_manifest.yml (kept in sync deliberately, not automatically -- see
# test/unit/test_manifest.py::test_user_agent_param_list_matches_pool).
REALISTIC_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/128.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.5 Mobile/15E148 Safari/604.1",
]


def pick_user_agent() -> str:
    return random.choice(REALISTIC_USER_AGENTS)
