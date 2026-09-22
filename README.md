# PayloadFetcher

Docker Hub: [kylemc54321/assemblyline-service-payloadfetcher](https://hub.docker.com/r/kylemc54321/assemblyline-service-payloadfetcher)

An AssemblyLine v4 service that extracts candidate payload URLs/IPs embedded in scripts
(shell, PHP, etc.) and directly fetches them, classifying the response by its **real
bytes**, not the URL's apparent extension. This matters because in the wild, a `.php`-named
endpoint can serve an executable payload meant to be `chmod +x`'d and cron-run, while a
sibling endpoint on the same host is meant to be piped straight into `sh` — the extension
tells you nothing reliable about what's actually served.

Fetched content becomes a new extracted child file (`PARENT_RELATION.DOWNLOADED`) so the
rest of the AssemblyLine pipeline can recursively analyze it.

## Safety

- **This service never executes or interprets anything it fetches or is given.** It only
  streams bytes to disk, hashes them, and identifies them via AssemblyLine's own
  `assemblyline.common.identify.Identify` (magic-byte based). No `subprocess` execution of
  any downloaded or submitted content, ever.
- **SSRF protection on every redirect hop**, not just the initial request: before
  connecting to any host — including a redirect target — its resolved IP(s) are checked
  against private/loopback/link-local/multicast/reserved ranges and the cloud metadata
  address `169.254.169.254`. A malicious server can otherwise use an HTTP redirect to pivot
  the fetch into internal infrastructure.
- **Resource limits**: per-fetch connect/read timeout, a hard streamed-download byte cap
  (aborted mid-stream), a capped number of redirects, and a capped number of URLs fetched
  per submission (deduped first).
- **`verify_ssl=false` weakens only certificate validation.** The per-hop SSRF check,
  redirect cap, size cap and timeouts are identical whether it is on or off; the fetched
  bytes were never trusted in the first place (they are only hashed and identified).
- **Known limitation**: the SSRF check is a point-in-time DNS resolution at fetch time, not
  full protection against DNS-rebinding (re-resolving to a different address between the
  check and the actual connection). Full rebinding protection (e.g. pinning the checked IP
  for the literal socket connection) is out of scope for this version.

## Deployment note

This service deliberately reaches out to live, often-malicious infrastructure. It should
be deployed with `docker_config.allow_internet_access: true` on a network-isolated,
analysis-only egress path — not a path that shares routing with production/internal
infrastructure.

## Submission parameters

| Param | Default | Purpose |
|---|---|---|
| `max_urls` | 10 | Cap on distinct URLs fetched per submission (after dedup). |
| `fetch_timeout_seconds` | 10 | Connect/read timeout per fetch. |
| `max_download_size_mb` | 25 | Hard cap on a single fetched response, enforced while streaming. |
| `max_redirects` | 3 | Max redirect hops followed (each re-checked for SSRF). |
| `user_agent` | `(random)` | UA header sent on fetches: a fixed browser UA from the dropdown, or a random pick (once per submission). |
| `verify_ssl` | false | Verify TLS certificates on HTTPS fetches (every redirect hop). Off by default because malware hosts commonly use self-signed or expired certificates, which would otherwise prevent the payload being retrieved. When off, urllib3's `InsecureRequestWarning` is suppressed (scoped to the fetch call, not process-wide) and the "Fetch results" section carries a "TLS certificate verification" note. When on, a certificate/handshake failure is reported as `ssl_error: ...` (distinct from `connection_error`) with a hint to resubmit with `verify_ssl=false`. |
| `dry_run` | false | Extract and report candidate URLs but skip the actual network fetch. |

## Development

This system's Python is externally managed (PEP 668); use an isolated virtualenv:

```bash
python3 -m venv .venv
.venv/bin/pip install assemblyline-v4-service assemblyline-service-utilities pytest requests requests-mock cryptography pyyaml
.venv/bin/pytest test/
```

Tests that stand up a local self-signed HTTPS stub (`test/unit/test_verify_ssl.py`) need
`cryptography` and skip themselves without it.

No test in this repo ever executes a sample, fetches a real URL, or resolves a real
hostname — the network layer is mocked (`requests_mock`) and DNS resolution is mocked
(`unittest.mock.patch("socket.getaddrinfo")`) throughout. Test fixtures use RFC 5737
documentation-range IP addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
never real/live malicious infrastructure.
