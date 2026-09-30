use std::{fs, io::IsTerminal, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use netmapper::{
    common_ports, make_report, parse_ports, resolve_targets, scan_tcp_with_detection, scan_udp,
    MAX_PROBES,
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

#[derive(Debug, Parser)]
#[command(
    name = "netmapper",
    version,
    about = "Independent, bounded TCP and UDP network scanner",
    long_about = "Resolve IP addresses, CIDRs, and DNS names, then scan selected TCP and/or UDP ports with bounded probes. Optional TCP service detection collects protocol banners.",
    after_long_help = "Only scan networks and systems you own or are explicitly authorized to assess. Netmapper is an independent scanner and does not invoke or require Nmap."
)]
struct Args {
    /// Target IP address, CIDR network, or DNS name. Repeat for multiple targets.
    #[arg(short, long, required = true, num_args = 1.., value_name = "TARGET")]
    target: Vec<String>,

    /// Ports, e.g. 22,53,80,443 or 1-1024.
    #[arg(
        short = 'p',
        long,
        value_name = "PORTS",
        conflicts_with_all = ["top_ports", "all_ports"]
    )]
    ports: Option<String>,

    /// Number of built-in common ports to scan (1-100; default: 100).
    #[arg(long, conflicts_with_all = ["ports", "all_ports"])]
    top_ports: Option<usize>,

    /// Scan all 1-65535 ports for the selected protocol(s).
    #[arg(long, conflicts_with_all = ["ports", "top_ports"])]
    all_ports: bool,

    /// Maximum simultaneous probes per protocol (default: 512).
    #[arg(short = 'c', long)]
    concurrency: Option<usize>,

    /// Per-probe timeout in milliseconds (default: 1000).
    #[arg(long, value_parser = clap::value_parser!(u64).range(50..=60000))]
    timeout_ms: Option<u64>,

    /// Select TCP, UDP, or both transport protocols (default: tcp).
    #[arg(long, value_enum)]
    scan_mode: Option<ScanMode>,

    /// Collect HTTP headers or passive TCP banners from open ports.
    #[arg(short = 's', long)]
    service_detection: bool,

    /// Output format.
    #[arg(long, value_enum)]
    format: Option<OutputFormat>,

    /// Write results to a file instead of standard output.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
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

    let targets = resolve_targets(&args.target).await?;
    let ports = match args.ports {
        Some(specification) => parse_ports(&specification)?,
        None if args.all_ports => (1..=u16::MAX).collect(),
        None => common_ports(top_ports),
    };
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
    let mut results = Vec::with_capacity(probe_count);
    if matches!(scan_mode, ScanMode::Tcp | ScanMode::Both) {
        results.extend(
            scan_tcp_with_detection(
                &targets,
                &ports,
                concurrency,
                timeout,
                args.service_detection,
            )
            .await?,
        );
    }
    if matches!(scan_mode, ScanMode::Udp | ScanMode::Both) {
        results.extend(scan_udp(&targets, &ports, concurrency, timeout).await?);
    }
    let report = make_report(results, targets.len());
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

fn format_port_cell(port: u16, color: bool, width: usize) -> String {
    let digits = port.to_string();
    let padding = " ".repeat(width.saturating_sub(digits.len()));
    if color {
        format!("\x1b[38;5;208m{digits}\x1b[0m{padding}")
    } else {
        format!("{digits}{padding}")
    }
}

fn format_table(report: &netmapper::ScanReport, color_ports: bool) -> String {
    let mut output =
        String::from("TARGET          PROTO PORT   STATE          SERVICE          VERSION                                  LATENCY   REASON\n");
    for result in &report.results {
        let reason = result.reason.as_deref().unwrap_or("-");
        let version = result.version.as_deref().unwrap_or("-");
        let port = format_port_cell(result.port, color_ports, 6);
        output.push_str(&format!(
            "{:<15} {:<5} {} {:<14} {:<16} {:<40} {:>5} ms  {}\n",
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
            result.latency_ms,
            reason
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
}
