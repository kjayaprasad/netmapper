# Changelog

## 1.1.0

- Add bounded UDP scanning with `open`, `closed`, `filtered`, and `open|filtered` states.
- Send DNS and NTP probes on ports 53 and 123; use an empty datagram for other UDP ports.
- Add `--scan-mode tcp|udp|both` and optional TCP service banner collection with `-s` / `--service-detection`.
- Include transport protocol, captured banner/version evidence, and UDP ambiguity counts in reports.
- Publish architecture-specific Debian packages as downloadable GitHub Release assets when a `v*` tag is pushed.

## 0.1.0

- Initial TCP connect scanner with CIDR and DNS target resolution, bounded concurrency, common-port selection, table/JSON output, and Debian packaging.