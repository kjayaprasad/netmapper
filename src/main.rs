use std::{ffi::OsString, fs, io::IsTerminal, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use netmapper::{
    common_ports, list_nse_scripts, make_report_with_traceroutes, parse_ports, resolve_targets,
    run_nse_scripts_for_endpoint, scan_tcp_with_type, scan_udp, traceroute, HttpScript,
    TcpScanOptions, TcpScanType, DEFAULT_NSE_SCRIPT_DIRECTORY, MAX_NSE_EXECUTIONS, MAX_PROBES,
};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScanMode {
    Tcp,
    Udp,
    Both,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TcpScanOption {
    Connect,
    Syn,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScanProfile {
    Quick,
    Web,
    Database,
    Infrastructure,
    Full,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum ScriptOption {
    #[value(name = "http-security-headers")]
    SecurityHeaders,
    #[value(name = "http-server-header")]
    ServerHeader,
    #[value(name = "http-powered-by-header")]
    PoweredByHeader,
}

#[derive(Debug, Parser)]
#[command(
    name = "netmapper",
    version,
    about = "Independent, bounded TCP and UDP network scanner",
    long_about = "Resolve IP addresses, CIDRs, and DNS names, then scan selected TCP and/or UDP ports with bounded probes. Optional service detection collects protocol banners; firewall detection reports heuristic HTTP edge and filtering indicators.",
    after_long_help = "Use -nS to try all .nse scripts in /usr/share/nmap/scripts on matching open TCP ports; unsupported scripts are reported and intrusive categories are blocked.\n\nOnly scan networks and systems you own or are explicitly authorized to assess. Netmapper is an independent scanner and does not invoke or require Nmap."
)]
struct Args {
    /// Authorized IP address, CIDR network, or DNS name. Repeat for multiple targets.
    #[arg(short, long, required = true, num_args = 1.., value_name = "TARGET")]
    target: Vec<String>,

    /// Add a target-focused port preset; port selectors can add to or expand this profile.
    #[arg(long, value_enum)]
    profile: Option<ScanProfile>,

    /// Ports to probe, e.g. 22,53,80,443 or 1-1024; applies to selected scan protocols.
    #[arg(
        short = 'p',
        long,
        value_name = "PORTS",
        conflicts_with_all = ["top_ports", "all_ports"]
    )]
    ports: Option<String>,

    /// Scan the first N built-in common ports (1-100; default: 100; not Nmap's ranked list).
    #[arg(long, conflicts_with_all = ["ports", "all_ports"])]
    top_ports: Option<usize>,

    /// Scan ports 1-65535 for selected protocols, subject to the one-million-probe limit.
    #[arg(long, conflicts_with_all = ["ports", "top_ports"])]
    all_ports: bool,

    /// Maximum simultaneous probes per protocol (1-8192; higher values increase traffic; default: 512).
    #[arg(short = 'c', long)]
    concurrency: Option<usize>,

    /// Per-probe connection/response timeout in milliseconds (50-60000; default: 1000).
    #[arg(long, value_parser = clap::value_parser!(u64).range(50..=60000))]
    timeout_ms: Option<u64>,

    /// Select TCP connect probes, UDP probes, or both (default: tcp).
    #[arg(long, value_enum)]
    scan_mode: Option<ScanMode>,

    /// Select a normal TCP connect scan or a raw IPv4 SYN scan (Linux, CAP_NET_RAW/root).
    #[arg(long, value_enum, default_value = "connect")]
    tcp_scan_type: TcpScanOption,

    /// Run IPv4 UDP traceroute (Linux, CAP_NET_RAW/root; at most 30 hops per target).
    #[arg(long)]
    traceroute: bool,

    /// Collect HTTP headers on supported plaintext ports or passive TCP banners from open ports.
    #[arg(short = 's', long)]
    service_detection: bool,

    /// Compare supported plaintext HTTP response headers with heuristic WAF/CDN/proxy signatures.
    #[arg(long)]
    firewall_detection: bool,

    /// Run a built-in read-only HTTP check; repeat to select multiple checks.
    #[arg(long, value_enum, action = clap::ArgAction::Append)]
    script: Vec<ScriptOption>,

    /// Run an installed NSE script by name (without the .nse suffix); repeatable.
    #[arg(long = "nse-script", value_name = "NAME", action = clap::ArgAction::Append)]
    nse_scripts: Vec<String>,

    /// Script directory; defaults to /usr/share/nmap/scripts.
    #[arg(long = "nse-script-dir", default_value = DEFAULT_NSE_SCRIPT_DIRECTORY, value_name = "DIR")]
    nse_script_directory: PathBuf,

    #[arg(long = "nse-scripts-all", hide = true)]
    nse_scripts_all: bool,

    /// Output a human-readable table or machine-readable JSON.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// Write results to a file instead of standard output; existing files are replaced.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse_from(normalize_nse_all_flag(std::env::args_os()));
    let top_ports = args.top_ports.unwrap_or(100);
    let concurrency = args.concurrency.unwrap_or(512);
    let timeout_ms = args.timeout_ms.unwrap_or(1000);
    let scan_mode = args.scan_mode.unwrap_or(ScanMode::Tcp);
    let format = args.format.unwrap_or(OutputFormat::Table);
    if !(1..=100).contains(&top_ports) {
        bail!("--top-ports must be between 1 and 100");
    }
    if !(1..=8192).contains(&concurrency) {
        bail!("--concurrency must be between 1 and 8192");
    }
    let profile_detects_services = matches!(
        args.profile,
        Some(ScanProfile::Web | ScanProfile::Database | ScanProfile::Infrastructure)
    );
    let profile_detects_firewall = matches!(args.profile, Some(ScanProfile::Web));
    if (args.firewall_detection
        || !args.script.is_empty()
        || !args.nse_scripts.is_empty()
        || args.nse_scripts_all
        || profile_detects_firewall)
        && matches!(scan_mode, ScanMode::Udp)
    {
        bail!("HTTP service and firewall detection require TCP probes; remove --scan-mode udp or select tcp/both");
    }
    if matches!(args.tcp_scan_type, TcpScanOption::Syn) && matches!(scan_mode, ScanMode::Udp) {
        bail!("--tcp-scan-type syn requires TCP probes; choose --scan-mode tcp or both");
    }

    let targets = resolve_targets(&args.target).await?;
    if args.traceroute && targets.iter().any(|target| !target.is_ipv4()) {
        bail!("--traceroute currently supports IPv4 targets only");
    }
    let ports = select_ports(
        args.profile,
        args.ports.as_deref(),
        args.top_ports,
        args.all_ports,
        top_ports,
    )?;
    let probe_count = targets
        .len()
        .checked_mul(ports.len())
        .and_then(|count| {
            if matches!(scan_mode, ScanMode::Both) {
                count.checked_mul(2)
            } else {
                Some(count)
            }
        })
        .context("probe count overflow")?;
    if probe_count > MAX_PROBES {
        bail!("scan would run {probe_count} probes; reduce targets or ports (limit: {MAX_PROBES})");
    }

    eprintln!(
        "Scanning {} target address(es), {} port(s) over {:?}, {} probe(s)...",
        targets.len(),
        ports.len(),
        scan_mode,
        probe_count
    );
    let timeout = Duration::from_millis(timeout_ms);
    let nse_scripts = if args.nse_scripts_all {
        list_nse_scripts(&args.nse_script_directory)?
    } else {
        args.nse_scripts.clone()
    };
    let scripts = args
        .script
        .iter()
        .map(|script| match script {
            ScriptOption::SecurityHeaders => HttpScript::SecurityHeaders,
            ScriptOption::ServerHeader => HttpScript::ServerHeader,
            ScriptOption::PoweredByHeader => HttpScript::PoweredByHeader,
        })
        .collect::<Vec<_>>();
    let mut results = Vec::with_capacity(probe_count);
    if matches!(scan_mode, ScanMode::Tcp | ScanMode::Both) {
        results.extend(
            scan_tcp_with_type(
                &targets,
                &ports,
                concurrency,
                timeout,
                TcpScanOptions {
                    scan_type: match args.tcp_scan_type {
                        TcpScanOption::Connect => TcpScanType::Connect,
                        TcpScanOption::Syn => TcpScanType::Syn,
                    },
                    detect_version: args.service_detection
                        || args.firewall_detection
                        || profile_detects_services
                        || !scripts.is_empty(),
                    detect_firewall: args.firewall_detection || profile_detects_firewall,
                    scripts: &scripts,
                },
            )
            .await?,
        );
    }
    if matches!(scan_mode, ScanMode::Udp | ScanMode::Both) {
        results.extend(scan_udp(&targets, &ports, concurrency, timeout).await?);
    }
    if !nse_scripts.is_empty() {
        let mut executions = 0usize;
        for result in results
            .iter_mut()
            .filter(|result| result.protocol == "tcp" && result.state == netmapper::PortState::Open)
        {
            if executions >= MAX_NSE_EXECUTIONS {
                result.indicators.push(format!(
                    "NSE execution limit reached ({MAX_NSE_EXECUTIONS}); remaining open ports were not checked."
                ));
                continue;
            }
            result.indicators.extend(
                run_nse_scripts_for_endpoint(
                    &args.nse_script_directory,
                    &nse_scripts,
                    result.target,
                    result.port,
                    result.service,
                    timeout.min(Duration::from_secs(3)),
                )
                .await,
            );
            executions += nse_scripts.len();
        }
    }
    let mut traceroutes = Vec::new();
    if args.traceroute {
        for target in &targets {
            traceroutes.push(traceroute(*target, 30, timeout).await?);
        }
    }
    let report = make_report_with_traceroutes(results, targets.len(), traceroutes);
    let output = match format {
        OutputFormat::Table => format_table(&report, std::io::stdout().is_terminal()),
        OutputFormat::Json => serde_json::to_string_pretty(&report)?,
    };

    if let Some(path) = args.output {
        fs::write(&path, output).with_context(|| format!("could not write {}", path.display()))?;
        eprintln!("Results written to {}", path.display());
    } else {
        println!("{output}");
    }
    Ok(())
}

fn normalize_nse_all_flag(arguments: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    arguments
        .into_iter()
        .map(|argument| {
            if argument == "-nS" {
                OsString::from("--nse-scripts-all")
            } else {
                argument
            }
        })
        .collect()
}

fn format_port_cell(port: u16, color: bool, width: usize) -> String {
    let digits = port.to_string();
    let padding = " ".repeat(width.saturating_sub(digits.len()));
    if color {
        format!("\x1b[38;5;208m{digits}\x1b[0m{padding}")
    } else {
        format!("{digits}{padding}")
    }
}

fn select_ports(
    profile: Option<ScanProfile>,
    explicit_ports: Option<&str>,
    top_ports: Option<usize>,
    all_ports: bool,
    default_top_ports: usize,
) -> Result<Vec<u16>> {
    let mut ports = profile.map_or_else(Vec::new, profile_ports);
    if all_ports {
        ports.extend(1..=u16::MAX);
    } else if let Some(count) = top_ports {
        ports.extend(common_ports(count));
    } else if profile.is_none() && explicit_ports.is_none() {
        ports.extend(common_ports(default_top_ports));
    }
    if let Some(specification) = explicit_ports {
        ports.extend(parse_ports(specification)?);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn profile_ports(profile: ScanProfile) -> Vec<u16> {
    match profile {
        ScanProfile::Quick => common_ports(20),
        ScanProfile::Web => vec![80, 443, 8000, 8008, 8080, 8081, 8443, 8888],
        ScanProfile::Database => vec![1433, 1521, 3306, 5432, 5433, 5984, 6379, 9042, 27017],
        ScanProfile::Infrastructure => vec![
            21, 22, 23, 25, 53, 88, 110, 123, 135, 139, 389, 443, 445, 464, 500, 514, 587, 636,
            1433, 2049, 3268, 3389, 5060, 5432, 5900, 5985, 5986, 8080, 8443,
        ],
        ScanProfile::Full => (1..=u16::MAX).collect(),
    }
}

fn format_table(report: &netmapper::ScanReport, color_ports: bool) -> String {
    let mut output =
        String::from("TARGET          PROTO PORT   STATE          SERVICE          VERSION                                  OS HINT                                           LATENCY   REASON  INDICATORS\n");
    for result in &report.results {
        let reason = result.reason.as_deref().unwrap_or("-");
        let version = result.version.as_deref().unwrap_or("-");
        let os_hint = result.os_hint.as_deref().unwrap_or("-");
        let indicators = if result.indicators.is_empty() {
            "-".to_string()
        } else {
            result.indicators.join("; ")
        };
        let port = format_port_cell(result.port, color_ports, 6);
        output.push_str(&format!(
            "{:<15} {:<5} {} {:<14} {:<16} {:<40} {:<48} {:>5} ms  {}  {}\n",
            result.target,
            result.protocol,
            port,
            match result.state {
                netmapper::PortState::Open => "open",
                netmapper::PortState::Closed => "closed",
                netmapper::PortState::Filtered => "filtered",
                netmapper::PortState::OpenFiltered => "open|filtered",
            },
            result.service,
            version,
            os_hint,
            result.latency_ms,
            reason,
            indicators
        ));
    }
    output.push_str(&format!(
        "\n{} target(s), {} probe(s): {} open, {} closed, {} filtered, {} open|filtered\n",
        report.summary.targets,
        report.summary.probes,
        report.summary.open,
        report.summary.closed,
        report.summary.filtered,
        report.summary.open_filtered
    ));
    output.push_str(&format!(
        "Filtering assessment: {}\n",
        report.summary.filtering_assessment
    ));
    for route in &report.traceroutes {
        output.push_str(&format!(
            "\nTraceroute to {} (reached: {}):\n",
            route.target, route.reached
        ));
        for hop in &route.hops {
            let address = hop
                .address
                .map_or_else(|| "*".to_string(), |address| address.to_string());
            let latency = hop
                .latency_ms
                .map_or_else(|| "*".to_string(), |latency| format!("{latency} ms"));
            output.push_str(&format!(
                "  {:>2}  {:<39} {:>8}  {}\n",
                hop.ttl, address, latency, hop.outcome
            ));
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colors_only_the_port_value_when_enabled() {
        let port = format_port_cell(443, true, 6);
        assert_eq!(port, "\x1b[38;5;208m443\x1b[0m   ");
    }

    #[test]
    fn leaves_port_plain_when_color_is_disabled() {
        assert_eq!(format_port_cell(443, false, 6), "443   ");
    }

    #[test]
    fn normalizes_uppercase_nse_all_flag() {
        let arguments = ["netmapper", "-nS", "--help"]
            .into_iter()
            .map(OsString::from);
        let normalized = normalize_nse_all_flag(arguments);
        assert_eq!(normalized[1], "--nse-scripts-all");
    }

    #[test]
    fn custom_ports_are_added_to_a_profile_and_deduplicated() {
        let ports =
            select_ports(Some(ScanProfile::Web), Some("443,9000"), None, false, 100).unwrap();
        assert!(ports.contains(&80));
        assert!(ports.contains(&443));
        assert!(ports.contains(&9000));
        assert_eq!(ports.iter().filter(|port| **port == 443).count(), 1);
    }

    #[test]
    fn explicit_port_selectors_still_work_without_a_profile() {
        assert_eq!(
            select_ports(None, Some("22,80"), None, false, 100).unwrap(),
            [22, 80]
        );
        assert_eq!(
            select_ports(None, None, Some(5), false, 100).unwrap(),
            common_ports(5)
        );
        assert_eq!(
            select_ports(None, None, None, true, 100).unwrap().len(),
            65_535
        );
    }
}
