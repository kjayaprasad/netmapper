# Changelog

## 2.0.0

- Problem addressed: Netmapper previously lacked raw packet TCP scanning, route discovery, target-oriented scan profiles, and any native path for running compatible Nmap script files.
- Public history of known issues addressed: 0.1.0 established bounded TCP scanning and structured output; 1.2.0 added UDP state detection and full-port selection; 1.2.1 clarified uncertain firewall/WAF observations; 1.2.2 added IPv4 SYN scans, low-confidence OS-family hints, traceroute, profiles, and the initial embedded script support.
- Added a vendored Lua 5.4 runtime with memory/instruction limits, default `.nse` discovery in `/usr/share/nmap/scripts/`, named-script selection, and the `-nS` all-scripts switch. The Nmap executable is not invoked.
- Added raw SYN reply correlation and measured RTT, table/JSON traceroute output, profile-plus-custom-port selection, and updated 2.0.0 Debian packaging.
- Renamed the Debian package to `netmapperv2` with Debian version `2.0.0.0`; the Cargo version and GitHub release tag remain valid SemVer `2.0.0` / `v2.0.0`. The package declares replacement of the prior `netmapperv1` package.
- Impact: expands standalone reconnaissance and evidence collection for authorized assessments while preserving connect/UDP defaults and explicit uncertainty in the findings.
- Known issues carried forward: NSE compatibility is a subset and many scripts requiring Nmap-specific APIs will be reported unsupported; disruptive categories are blocked; raw packet features are Linux/IPv4-only; OS hints and service evidence remain heuristic and are not guaranteed 99% accurate.

## 1.2.2

- Problem solved: the scanner lacked packet-level TCP scanning, route visibility, and target-oriented workflows beyond connect probes and manually selected ports.
- Added bounded Linux IPv4 raw SYN scanning and low-confidence OS-family hints from reply TTL/window values.
- Added opt-in IPv4 UDP traceroute and table/JSON hop reporting.
- Added `quick`, `web`, `database`, `infrastructure`, and `full` profiles; `-p` can add ports while preserving existing selectors.
- Added a sandboxed embedded Lua NSE compatibility engine, defaulting to `/usr/share/nmap/scripts/`; `-nS` selects all discovered scripts and `--nse-script` selects one.
- Blocked intrusive NSE categories and bounded script execution; unsupported Nmap APIs are reported rather than claimed as completed.
- Retained connect/UDP defaults and documented that service/OS/vulnerability results are not comprehensive or guaranteed 99% accurate.

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
