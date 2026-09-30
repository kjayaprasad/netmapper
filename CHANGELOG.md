# Changelog

## 1.2.0

- Add bounded UDP scanning with `open`, `closed`, `filtered`, and `open|filtered` states.
- Send DNS and NTP probes on ports 53 and 123; use an empty datagram for other UDP ports.
- Add `--scan-mode tcp|udp|both` and optional TCP service banner collection.
- Add full-port selection, terminal-only orange port highlighting, and an original SVG logo.
- Build a standalone Debian package named `netmapper.dpkg` without an Nmap runtime dependency.

## 0.1.0

- Initial TCP connect scanner with CIDR and DNS target resolution, bounded concurrency, common-port selection, table/JSON output, and Debian packaging.
