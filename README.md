# netmapper

![Netmapper radar-and-route logo](assets/netmapper.svg)

`netmapper` is an independent Kali-oriented network scanner for authorized assessments. It does not invoke Nmap or require Nmap to be installed. It accepts IP addresses, CIDR networks, and DNS names; scans selected TCP and/or UDP ports; and reports state, latency, port-name hints, and optional service evidence.

Netmapper 2.1.0 is a standalone scanner for authorized assessments. It does not invoke the Nmap executable. This release bundles the NSE script and Lua library corpus in Debian packages, adds sandboxed loading of pure-Lua helpers, and shows open and filtered ports in its table output. It is not at full Nmap feature parity.

Only scan systems and networks that you own or are explicitly authorized to assess. Scans can trigger monitoring alerts and may be restricted by network policy.

## Capabilities

- Resolve IPv4/IPv6 addresses, IPv4/IPv6 CIDRs, and DNS names.
- Select TCP, UDP, or both protocols with `--scan-mode`.
- Select `connect` or Linux raw IPv4 `syn` TCP scanning with `--tcp-scan-type`.
- Select target-oriented `quick`, `web`, `database`, `infrastructure`, and `full` port profiles with `--profile`.
- Select ports using individual numbers, comma-separated lists, and inclusive ranges; `-p` adds ports to a chosen profile.
- Start with a built-in set of 100 commonly used ports, select a prefix with `--top-ports`, or scan all ports with `--all-ports`.
- Send a DNS query to UDP/53 and an NTP request to UDP/123; other UDP ports receive an empty datagram.
- Optionally collect passive TCP banners and plaintext HTTP response headers with `--service-detection`, including alternate HTTP port 3000.
- Estimate broad OS families from observed SYN/ACK TTL and TCP window values; hints are explicitly low-confidence.
- Run IPv4 UDP traceroute with `--traceroute` and include hop outcomes in table or JSON output.
- Run selected read-only HTTP checks for security headers, `Server`, and `X-Powered-By` with repeatable `--script` options.
- Run bundled `.nse` scripts from `/usr/share/netmapper/nse/scripts/`; the package also includes the NSE Lua library tree at `/usr/share/netmapper/nse/nselib/`. `-nS` selects all discovered scripts, and `--nse-script <NAME>` selects one script.
- Optionally inspect plaintext HTTP response headers for possible WAF/CDN/proxy signatures with `--firewall-detection`.
- Report filtering uncertainty without claiming a firewall product or version from timeouts.
- Bound concurrent probes and configure the per-probe timeout.
- Display open and filtered ports in an Nmap-style table, with open ports first; closed ports are omitted from the table. JSON retains every result.
- Write output to a selected file.
- Build a standalone Kali/Debian package (`netmapper.dpkg`) containing the binary, complete NSE scripts and Lua library corpus, man page, and original SVG icon.
- Keep scan size bounded: at most 4,096 resolved addresses and 1,000,000 target-port probes per run.

## Project Status And Impact

Version 2.1.0 builds on the bounded TCP/UDP scanner, raw SYN probes, OS-family hints, traceroute, target profiles, and embedded script runtime introduced in 2.0.0. It adds the packaged NSE corpus and broader pure-Lua module loading, but does not replace Nmap where complete service fingerprints, OS databases, IPv6 raw scans, or full NSE behavior are required.

### Version 2.1.0 Release Notes

Compared with 2.0.0:

**Problems solved**
- Debian installs no longer need a separate Nmap script corpus at runtime; the package includes the NSE scripts and `nselib` files.
- Filtered ports are no longer hidden from the default human-readable results.
- Scripts that rely on pure-Lua helper modules can now load those modules from the bundled `nselib` directory within the existing sandbox.

**Features added or changed**
- The package installs NSE files under `/usr/share/netmapper/nse/`; `--nse-script-dir` still allows a custom script directory.
- The embedded Lua engine can load bounded pure-Lua modules while keeping native Nmap APIs and local filesystem access unavailable.
- Table output shows open and filtered results, with open ports first; filtered results include available probe reasons. JSON continues to include every state.
- `--all-ports` scans ports 1-65535, and `-p` accepts explicit high-numbered ports. This documents existing port selection rather than changing its range.

**Removed**
- Removed the `--show-all` CLI option. Closed ports are omitted from table rows and summarized, while remaining available in JSON and scan totals.
- No valid port numbers or TCP/UDP scan modes were removed.

**Still limited**
- Bundling every script does not make every script executable. NSE compatibility remains a subset, and scripts requiring unsupported Nmap APIs are skipped or reported unsupported.

### Cumulative Feature History

- **0.1.0:** Introduced TCP connect scanning, IP/CIDR/DNS target resolution, common-port selection, bounded concurrency, table and JSON output, and Debian packaging.
- **1.2.0:** Added UDP scanning with `open`, `closed`, `filtered`, and `open|filtered` states; DNS/NTP probes; TCP banner collection; protocol selection; full-port scanning; terminal port highlighting; and the SVG logo.
- **1.2.1:** Added heuristic HTTP firewall/WAF indicators, filtering uncertainty reporting, and `X-Powered-By` service evidence. These remain unverified clues, not product identification.
- **1.2.2 / 2.0.0:** Added Linux IPv4 SYN scanning and RTT measurement, low-confidence OS-family hints, IPv4 UDP traceroute, scan profiles, custom ports alongside profiles, HTTP checks, alternate HTTP probing on port 3000, and a sandboxed Lua NSE compatibility engine with named/all-script selection. The package identity became `netmapperv2`.
- **2.1.0:** Bundled the NSE scripts and Lua libraries in the Debian package, added bounded pure-Lua `nselib` loading, made filtered ports visible by default, and removed closed per-port table rows and the `--show-all` option.

### Changes Since v1.2.1

- Added Linux IPv4 TCP SYN scanning with measured reply latency and cautious OS-family hints; the existing connect scan remains the default.
- Added IPv4 UDP traceroute with hop data in table and JSON output.
- Added `quick`, `web`, `database`, `infrastructure`, and `full` profiles; custom `-p` ports can extend a profile.
- Added an embedded, resource-limited Lua engine for a subset of NSE scripts; version 2.0.0 discovered scripts from `/usr/share/nmap/scripts/` when that corpus was installed.
- Improved alternate HTTP detection on TCP/3000, including `X-Powered-By` evidence.
- Renamed the Debian package to `netmapperv2` version `2.0.0.0`; the Rust/Cargo and Git tag version is `2.0.0`.
- Retained v1.2.1 TCP/UDP scanning, bounded probe limits, JSON output, and heuristic firewall/WAF reporting.

The tool favors evidence over forced conclusions. A port can remain filtered or inconclusive, OS hints are heuristic, and script compatibility is reported rather than assumed. Do not use a “99% accurate” claim without a representative, independently labeled benchmark.

### Known Issues And Next Changes

- The Lua engine implements only a small NSE compatibility surface. Scripts requiring unsupported Nmap modules/APIs are skipped and counted; `-nS` selects all files but does not mean every script can run.
- Raw SYN scanning, OS hints, and traceroute currently support Linux IPv4 only.
- Service detection is limited to passive banners and selected plaintext HTTP evidence (including port 3000); TLS-aware and database/service-specific fingerprints remain future work.
- OS family estimates use a small set of TCP reply characteristics; validated fingerprint datasets and confidence scoring remain future work.
- The next useful milestones are broader safe NSE module compatibility, TLS-aware service probes, better OS fingerprint validation, IPv6 raw networking, and public recall/precision benchmarks before making accuracy claims.

The Debian package has no Nmap executable dependency and bundles the script and `nselib` trees from the build machine's `/usr/share/nmap/` directory. The Debian package build requires `nmap-common` (or an equivalent corpus); set `NETMAPPER_NMAP_DATA_DIR` to a directory containing `scripts/` and `nselib/` to use another source. Packaged users can run `-nS` without installing Nmap separately. The sandbox supports only a subset of NSE APIs, so bundling every script does not mean every script is executable.

## Requirements

- Rust 1.88 or newer and Cargo for building from source.
- Linux, macOS, or Windows for source builds. The Debian packaging script targets Debian-compatible Linux systems with `dpkg-deb`, `objdump`, and the Nmap NSE corpus (`nmap-common`) available.
- Network access to the authorized targets.

TCP connect and UDP port scans use ordinary sockets. Raw TCP SYN scanning and UDP traceroute require Linux plus `CAP_NET_RAW` or root privileges. Those raw features currently support IPv4 only; regular target resolution and connect/UDP port scans support IPv4 and IPv6. Local firewall policy, routing, NAT, packet loss, and remote rate limiting can affect observed results. UDP silence is inherently ambiguous and is reported as `open|filtered`, not as definitively open or filtered.

## Build and test

```sh
cargo test --locked
cargo build --release --locked
```

Show command help:

```sh
cargo run -- --help
```

## Examples

Scan the built-in 100-port set on a single host:

```sh
netmapper --target 192.0.2.15
```

Scan a DNS name and an address, selecting common web and administration ports:

```sh
netmapper -t app.example.test -t 192.0.2.20 -p 22,80,443,8000-8100
```

Scan every TCP port on one authorized target (ports 1-65535), including high-numbered ports:

```sh
netmapper --target 192.0.2.15 --all-ports
```

Select individual high-numbered ports directly:

```sh
netmapper --target 192.0.2.15 -p 10000,65000
```

Scan a small authorized subnet with bounded concurrency and a longer timeout:

```sh
netmapper --target 192.0.2.0/28 --ports 1-1024 --concurrency 256 --timeout-ms 1500
```

Use a web profile and add a nonstandard application port:

```sh
netmapper -t 192.0.2.15 --profile web -p 9000 --service-detection
```

Run a Linux IPv4 SYN scan and traceroute (requires `CAP_NET_RAW` or root):

```sh
sudo netmapper -t 192.0.2.15 --tcp-scan-type syn --traceroute -p 22,80,443
```

Run selected read-only HTTP checks:

```sh
netmapper -t 192.0.2.15 -p 80 --script http-security-headers --script http-server-header
```

Run every discovered NSE script on open TCP endpoints:

```sh
sudo netmapper -t 192.0.2.15 -p 80,443 -nS
```

Select one installed NSE script and override the default script directory:

```sh
netmapper -t 192.0.2.15 -p 80 --nse-script http-security-headers
```

Scan DNS and NTP over UDP:

```sh
netmapper -t 192.0.2.15 --scan-mode udp -p 53,123
```

Scan both protocols and collect lightweight TCP banners:

```sh
netmapper -t 192.0.2.15 --scan-mode both -p 22,53,80,123,443 -s
```

Inspect supported HTTP response headers for possible edge/WAF indicators:

```sh
netmapper -t 192.0.2.15 -p 80,8080 --firewall-detection
```

Write machine-readable JSON:

```sh
netmapper -t 192.0.2.15 -p 22,80,443 --format json --output scan.json
```

The example addresses use the documentation-only `192.0.2.0/24` range. Replace them only with targets in your authorized scope.

## Result interpretation

- **open**: the TCP connection completed successfully. This confirms a listener accepted a connection at scan time; it does not identify or validate the application protocol.
- **closed**: the remote stack actively refused the TCP connection.
- **filtered**: the attempt timed out or failed for another reason that did not establish an open connection or an explicit refusal. This is an inference, not proof that a firewall caused the result.

The `service` field is a static port-number hint. When enabled, `version` contains HTTP status and available `Server`/`X-Powered-By` headers, or the first line of a passive TCP banner; this is not a comprehensive service fingerprint database. SYN-scan OS hints infer broad families from TTL/window values and are low-confidence, not OS identification. Traceroute uses UDP probes and ICMP responses, is IPv4-only, and may show missing hops when routers filter or rate-limit ICMP. `--script` runs built-in read-only HTTP checks. `--nse-script` and `-nS` use a sandboxed embedded Lua engine with a bounded instruction budget and a limited set of NSE modules (`http`, `shortport`, and `stdnse`). Unsupported Nmap APIs are reported; `brute`, `dos`, `fuzzer`, and `intrusive` categories are blocked. This is not full NSE compatibility, and neither vulnerability findings nor OS/service hints are guaranteed to be 99% accurate. `--firewall-detection` adds possible signatures for Cloudflare, Akamai, Imperva, Sucuri, F5, and Amazon CloudFront, plus generic proxy/cache headers. These may indicate a CDN or reverse proxy rather than a WAF; headers can be hidden, changed, or spoofed, and do not verify product versions. HTTP checks use bounded requests on supported plaintext HTTP ports only; HTTPS/TLS fingerprinting is not implemented. Filtered/inconclusive results may be caused by firewall rules, host policy, routing, or packet loss; they cannot identify a firewall. Latency is measured in milliseconds.

## CLI reference

| Option | Default | Description |
| --- | --- | --- |
| `-t`, `--target <TARGET>...` | Required | IP address, CIDR, or DNS name; repeat for multiple targets. |
| `-p`, `--ports <PORTS>` | Common-port set | Any valid port list, e.g. `22,53,80,443,65000`, or inclusive range, e.g. `1-65535`. |
| `--top-ports <N>` | `100` | Use the first N entries from the built-in common-port set (1-100); conflicts with `--ports`. This list is not claimed to match Nmap's ranking. |
| `--all-ports` | Disabled | Scan ports 1-65535 for selected protocol(s); conflicts with `--ports` and `--top-ports`. |
| `-c`, `--concurrency <N>` | `512` | Maximum simultaneous probes per protocol (1-8192). |
| `--timeout-ms <MS>` | `1000` | Per-probe timeout (50-60000 milliseconds). |
| `--scan-mode <MODE>` | `tcp` | `tcp`, `udp`, or `both`. |
| `--tcp-scan-type <TYPE>` | `connect` | `connect` or raw `syn`; SYN requires Linux and `CAP_NET_RAW` or root, and currently supports IPv4 only. |
| `--profile <PROFILE>` | None | `quick`, `web`, `database`, `infrastructure`, or `full`; profiles choose ports and may be extended with `-p`. |
| `--traceroute` | Disabled | Run IPv4 UDP traceroute to each target; Linux and `CAP_NET_RAW` or root required. |
| `-s`, `--service-detection` | Disabled | Collect supported plaintext HTTP headers or passive TCP banners from open ports. |
| `--script <CHECK>` | None | Repeatable built-in read-only HTTP checks: `http-security-headers`, `http-server-header`, `http-powered-by-header`. |
| `--nse-script <NAME>` | None | Run a named `.nse` script from the configured directory using the embedded sandbox. |
| `-nS` | Disabled | Try every `.nse` script on matching open TCP ports; unsupported scripts are reported and intrusive categories are blocked. |
| `--nse-script-dir <DIR>` | `/usr/share/netmapper/nse/scripts` | Set the NSE script directory; no Nmap executable is invoked. |
| `--firewall-detection` | Disabled | Inspect supported plaintext HTTP responses for heuristic WAF/CDN/proxy signatures and report inconclusive filtering observations; requires TCP. |
| `--format <FORMAT>` | `table` | `table` or `json`. |
| `-o`, `--output <FILE>` | Standard output | Write formatted output to a file. |
| `-h`, `--help` | | Print help. |
| `-V`, `--version` | | Print version. |

Port zero is rejected. Duplicate ports are removed, results are sorted by address and port, descending ranges are rejected, and oversized scans are refused before probes begin. `--all-ports` covers ports 1-65535; broader target sets remain bounded by the 1,000,000-probe safety limit.

For `--scan-mode both`, the probe limit counts each target/port pair once per protocol. With UDP, a response indicates `open`, an ICMP port-unreachable error indicates `closed`, and timeout indicates `open|filtered`.

## Debian package

Build a Debian package from the source tree:

```sh
./scripts/build-deb.sh
```

The versioned Debian package is written as `dist/netmapperv2_2.1.0_amd64.deb` (the architecture suffix varies) and copied to the parent `network-tools` directory. For compatibility, the build also writes `dist/netmapper.dpkg` and `../netmapper.dpkg`. The package identity is `netmapperv2`, Debian version `2.1.0`; it replaces the previous `netmapperv1` package and installs `/usr/bin/netmapper`, the man page, app icon, and NSE corpus. It does not depend on the Nmap executable. Cargo uses SemVer `2.1.0`; tag this release `v2.1.0`.

```sh
sudo dpkg -i ./dist/netmapperv2_2.1.0_amd64.deb
netmapper --help
man netmapper
```

The build requires Cargo, Rust, `dpkg-deb`, and `objdump` from `binutils`; it does not require `cargo-deb`. The package records the highest GLIBC symbol version required by the built executable. Build on the oldest Debian/Ubuntu release you intend to support to avoid linking against a newer system C library than your users have.

## Repository checks

GitHub Actions runs formatting, tests, Clippy, and a Debian package build on pushes and pull requests. Locally, run:

```sh
cargo fmt --all -- --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
./scripts/build-deb.sh
```

Every push builds a Debian archive workflow artifact. Pushing the tag `v2.1.0` creates a GitHub Release, attaches the versioned `.deb`, and publishes the matching `2.1.0` `CHANGELOG.md` section. Existing release tags are retained. Add a changelog section describing the problem solved, changes, and carried-forward issues for each release.

## Limitations and roadmap

TCP connect probes can create a completed connection on open ports. UDP silence remains ambiguous. Raw SYN scanning, OS-family hints, and traceroute require Linux raw-socket privileges and currently support IPv4 only. Service/version evidence is limited and OS hints are heuristic. The embedded NSE engine supports a limited module/API subset, blocks intrusive categories, and cannot provide universal script compatibility or a guaranteed detection accuracy. Firewall/WAF observations are heuristic and limited to plaintext HTTP headers and scan outcomes; no firewall product/version is established, and the scanner does not provide firewall-evasion guidance. Netmapper does not claim full Nmap feature parity. Contributions should preserve bounded resource use, explicit scope, and transparent result interpretation.