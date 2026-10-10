"""Regressions for crashes seen on real submissions (2026-10-10). Hostnames are .test only;
no real DNS or HTTP is used."""
from unittest.mock import MagicMock, patch

from payload_fetcher.ssrf_guard import resolve_and_check


def test_overlong_hostname_label_is_a_failed_check_not_a_crash():
    # A >63-char label makes socket.getaddrinfo's IDNA step raise UnicodeError.
    result = resolve_and_check("a" * 70 + ".test")
    assert not result.blocked
    assert result.reason.startswith("invalid_hostname")


def test_template_truncated_to_a_bare_scheme_does_not_fail_the_result(tmp_path):
    from payload_fetcher.fetcher import FetchResult
    from payload_fetcher.payload_fetcher import PayloadFetcher

    params = {
        "max_urls": 10, "dry_run": False, "fetch_timeout_seconds": 5, "max_download_size_mb": 1,
        "max_redirects": 3, "user_agent": "test-agent", "verify_ssl": False,
    }
    request = MagicMock()
    request.file_contents = b"wget http://$HOST/payload.bin\nwget https://ok.test/payload.bin\n"
    request.get_param.side_effect = params.__getitem__
    svc = PayloadFetcher.__new__(PayloadFetcher)
    svc.identify = MagicMock()
    fake = FetchResult(False, "https://ok.test/payload.bin", None, None, None, 0, None, "timeout")
    with patch("payload_fetcher.payload_fetcher.fetch_url", return_value=fake), \
            patch.object(PayloadFetcher, "working_directory", new=str(tmp_path), create=True):
        svc.execute(request)

    urls = next(s for s in request.result.sections if s.title_text == "Candidate URLs extracted from script")
    assert [s.title_text for s in urls.subsections] == ["Candidates AL could not render as URLs"]
    assert "http://" in urls.subsections[0].body
