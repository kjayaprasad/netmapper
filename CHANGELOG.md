# Changelog

## 1.2.1

- Problem solved: scan output did not distinguish possible edge/WAF clues from confirmed firewall identification, and filtered results lacked an explicit uncertainty summary.
- Added opt-in `--firewall-detection` for heuristic HTTP header signatures and filtering observations in table/JSON reports.
- Added `X-Powered-By` to captured HTTP service evidence; product matches remain possible indicators, not verified fingerprints.
- Changed GitHub release naming to follow the pushed version tag.

## 1.2.0

- Add bounded UDP scanning with `open`, `closed`, `filtered`, and `open|filtered` states.
- Send DNS and NTP probes on ports 53 and 123; use an empty datagram for other UDP ports.
- Add `--scan-mode tcp|udp|both` and optional TCP service banner collection.
- Add full-port selection, terminal-only orange port highlighting, and an original SVG logo.
- Build a standalone Debian package named `netmapper.dpkg` without an Nmap runtime dependency.

## 0.1.0

- Initial TCP connect scanner with CIDR and DNS target resolution, bounded concurrency, common-port selection, table/JSON output, and Debian packaging.
