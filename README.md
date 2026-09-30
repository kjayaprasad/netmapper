# netmapper

![Netmapper radar-and-route logo](assets/netmapper.svg)

`netmapper` is an independent Kali-oriented network scanner for authorized assessments. It does not invoke Nmap or require Nmap to be installed. It accepts IP addresses, CIDR networks, and DNS names; scans selected TCP and/or UDP ports; and reports state, latency, port-name hints, and optional TCP banner evidence.

Netmapper is not yet at Nmap feature parity. It currently implements TCP connect probes, UDP request/response probes, bounded concurrency, IPv4/IPv6 target resolution, selected or full port ranges, HTTP/passive TCP banner collection, and table/JSON reports. It does not currently implement raw packet scan types, OS fingerprinting, comprehensive service/version probes, traceroute, or a script engine. Those are substantial independent features; do not interpret the presence of a CLI option as a substitute for them.

Only scan systems and networks that you own or are explicitly authorized to assess. Scans can trigger monitoring alerts and may be restricted by network policy.

## Capabilities

- Resolve IPv4/IPv6 addresses, IPv4/IPv6 CIDRs, and DNS names.
- Select TCP, UDP, or both protocols with `--scan-mode`.
- Select ports using individual numbers, comma-separated lists, and inclusive ranges.
- Start with a built-in set of 100 commonly used ports, select a prefix with `--top-ports`, or scan all ports with `--all-ports`.
- Send a DNS query to UDP/53 and an NTP request to UDP/123; other UDP ports receive an empty datagram.
- Optionally collect TCP banners and HTTP response headers with `--service-detection`.
- Bound concurrent probes and configure the per-probe timeout.
- Display port states and banner evidence in a readable table or JSON.
- Write output to a selected file.
- Build a standalone Kali/Debian package (`netmapper.dpkg`) containing the binary, man page, and original SVG icon.
- Keep scan size bounded: at most 4,096 resolved addresses and 1,000,000 target-port probes per run.

## Requirements

- Rust stable and Cargo for building from source.
- Linux, macOS, or Windows for source builds. The Debian packaging script targets Debian-compatible Linux systems with `dpkg-deb` installed.
- Network access to the authorized targets.

The scanner uses ordinary TCP connect calls and UDP sockets and does not require raw-socket privileges. Local firewall policy, routing, NAT, packet loss, and remote rate limiting can affect observed results. UDP silence is inherently ambiguous and is reported as `open|filtered`, not as definitively open or filtered.

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

Scan a small authorized subnet with bounded concurrency and a longer timeout:

```sh
netmapper --target 192.0.2.0/28 --ports 1-1024 --concurrency 256 --timeout-ms 1500
```

Scan DNS and NTP over UDP:

```sh
netmapper -t 192.0.2.15 --scan-mode udp -p 53,123
```

Scan both protocols and collect lightweight TCP banners:

```sh
netmapper -t 192.0.2.15 --scan-mode both -p 22,53,80,123,443 -s
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

The `service` field is a static port-number hint. When enabled, `version` contains a captured HTTP status/server header or the first line of a passive TCP banner; this is evidence, not a comprehensive service fingerprint. Latency is measured in milliseconds.

## CLI reference

| Option | Default | Description |
| --- | --- | --- |
| `-t`, `--target <TARGET>...` | Required | IP address, CIDR, or DNS name; repeat for multiple targets. |
| `-p`, `--ports <PORTS>` | Common-port set | Port list, e.g. `22,53,80,443`, or inclusive range, e.g. `1-1024`. |
| `--top-ports <N>` | `100` | Use the first N entries from the built-in common-port set (1-100); conflicts with `--ports`. This list is not claimed to match Nmap's ranking. |
| `--all-ports` | Disabled | Scan ports 1-65535 for selected protocol(s); conflicts with `--ports` and `--top-ports`. |
| `-c`, `--concurrency <N>` | `512` | Maximum simultaneous probes per protocol (1-8192). |
| `--timeout-ms <MS>` | `1000` | Per-probe timeout (50-60000 milliseconds). |
| `--scan-mode <MODE>` | `tcp` | `tcp`, `udp`, or `both`. |
| `-s`, `--service-detection` | Disabled | Collect HTTP headers or passive banners from open TCP ports. |
| `--format <FORMAT>` | `table` | `table` or `json`. |
| `-o`, `--output <FILE>` | Standard output | Write formatted output to a file. |
| `-h`, `--help` | | Print help. |
| `-V`, `--version` | | Print version. |

Port zero is rejected. Duplicate ports are removed, results are sorted by address and port, descending ranges are rejected, and oversized scans are refused before probes begin. Both-protocol full-port scans are limited by the 1,000,000-probe safety limit.

For `--scan-mode both`, the probe limit counts each target/port pair once per protocol. With UDP, a response indicates `open`, an ICMP port-unreachable error indicates `closed`, and timeout indicates `open|filtered`.

## Debian package

Build a Debian package from the source tree:

```sh
./scripts/build-deb.sh
```

The standalone Debian archive is written as `dist/netmapper.dpkg` and copied to `../netmapper.dpkg` (the parent `network-tools` directory in this workspace). The package identity is `netmapperv1` version `1.2.0`; it installs `/usr/bin/netmapper`, the man page, and the app icon. It does not depend on Nmap. Install and inspect it with:

```sh
sudo dpkg -i ./dist/netmapper.dpkg
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

Every push builds a Debian archive workflow artifact. Pushing a version tag such as `v1.2.0` also creates a GitHub Release and attaches the package. The package version is read from `Cargo.toml`; update it and add a `CHANGELOG.md` entry for each release.

## Limitations and roadmap

TCP connect probes can create a completed connection on open ports. UDP silence remains ambiguous. Netmapper is an independent project and does not claim full Nmap feature parity; adding raw packet scanning, robust service fingerprints, OS detection, and a standalone extensible script engine requires separate implementation and validation. Contributions should preserve bounded resource use, explicit scope, and transparent result interpretation.