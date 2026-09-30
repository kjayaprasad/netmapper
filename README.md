# netmapper

`netmapper` is a concurrent TCP connect scanner for authorized network inventory. It accepts IP addresses, CIDR networks, and DNS names; scans selected TCP ports; and reports each probe as `open`, `closed`, or `filtered` with a latency, common service-name hint, and reason where available.

This is an early, focused scanner, not a drop-in replacement for every Nmap capability. It does not currently perform raw SYN scans, UDP scans, service/version probes, OS fingerprinting, traceroute, NSE scripts, or Nmap XML output. The service column is based on conventional port numbers only; no application protocol is contacted beyond the TCP connection attempt.

Only scan systems and networks that you own or are explicitly authorized to assess. Scanning can trigger monitoring alerts and may be restricted by network policy.

## Capabilities

- Resolve IPv4/IPv6 addresses, IPv4/IPv6 CIDRs, and DNS names.
- Select ports using individual numbers, comma-separated lists, and inclusive ranges.
- Start with a built-in set of 100 commonly used TCP ports, or select a prefix with `--top-ports`.
- Bound concurrent connection attempts and configure the per-port timeout.
- Display every probed port, including closed and filtered results, in a terminal table or JSON.
- Write output to a selected file.
- Build an architecture-specific Debian package containing the binary and man page.
- Keep scan size bounded: at most 4,096 resolved addresses and 1,000,000 target-port probes per run.

## Requirements

- Rust stable and Cargo for building from source.
- Linux, macOS, or Windows for source builds. The Debian packaging script targets Debian-compatible Linux systems with `dpkg-deb` installed.
- Network access to the authorized targets.

The scanner uses ordinary TCP connect calls and does not require raw-socket privileges. Local firewall policy, routing, NAT, packet loss, and remote rate limiting can affect observed results.

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

Write machine-readable JSON:

```sh
netmapper -t 192.0.2.15 -p 22,80,443 --format json --output scan.json
```

The example addresses use the documentation-only `192.0.2.0/24` range. Replace them only with targets in your authorized scope.

## Result interpretation

- **open**: the TCP connection completed successfully. This confirms a listener accepted a connection at scan time; it does not identify or validate the application protocol.
- **closed**: the remote stack actively refused the TCP connection.
- **filtered**: the attempt timed out or failed for another reason that did not establish an open connection or an explicit refusal. This is an inference, not proof that a firewall caused the result.

The `service` field is a static port-number hint. It is not service detection. Latency is the elapsed time for the connection attempt, in milliseconds.

## CLI reference

| Option | Default | Description |
| --- | --- | --- |
| `-t`, `--target <TARGET>...` | Required | IP address, CIDR, or DNS name; repeat for multiple targets. |
| `-p`, `--ports <PORTS>` | Common-port set | TCP port list, e.g. `22,80,443`, or inclusive range, e.g. `1-1024`. |
| `--top-ports <N>` | `100` | Use the first N entries from the built-in common-port set (1-100); conflicts with `--ports`. This list is not claimed to match Nmap's ranking. |
| `-c`, `--concurrency <N>` | `512` | Maximum simultaneous probes (1-8192). |
| `--timeout-ms <MS>` | `1000` | Per-port timeout (50-60000 milliseconds). |
| `--format <FORMAT>` | `table` | `table` or `json`. |
| `-o`, `--output <FILE>` | Standard output | Write formatted output to a file. |
| `-h`, `--help` | | Print help. |
| `-V`, `--version` | | Print version. |

Port zero is rejected. Duplicate ports are removed, results are sorted by address and port, descending ranges are rejected, and oversized scans are refused before probes begin.

## Debian package

Build a `.deb` from the source tree:

```sh
./scripts/build-deb.sh
```

The package is written to `dist/` and contains `/usr/bin/netmapper` and `/usr/share/man/man1/netmapper.1`. Install and inspect it with:

```sh
sudo apt install ./dist/netmapper_0.1.0_$(dpkg --print-architecture).deb
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

## Limitations and roadmap

The scanner currently uses TCP connect semantics only. It is not stealthy and can create a completed connection on open ports. It has no raw packet engine, UDP state inference, service banner collection, OS detection, script engine, or firewall evasion. A production Nmap replacement would need those separately designed, tested capabilities and broader platform coverage. Contributions should preserve bounded resource use, explicit scope, and transparent state classification.