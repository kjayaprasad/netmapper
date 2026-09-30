use std::{fs, path::PathBuf, time::Duration};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use netmapper::{common_ports, make_report, parse_ports, resolve_targets, scan_tcp, MAX_PROBES};

#[derive(Clone, Copy, Debug, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "netmapper",
    version,
    about = "Concurrent TCP port scanner for authorized network inventory",
    long_about = "Resolve IP addresses, CIDRs, and DNS names, then classify TCP ports as open, closed, or filtered using bounded TCP connect probes.",
    after_long_help = "Only scan networks and systems you own or are explicitly authorized to assess. This tool performs TCP connect scans; it does not implement raw SYN scans, UDP scanning, OS fingerprinting, or Nmap scripts."
)]
struct Args {
    /// Target IP address, CIDR network, or DNS name. Repeat for multiple targets.
    #[arg(short, long, required = true, num_args = 1.., value_name = "TARGET")]
    target: Vec<String>,

    /// TCP ports, e.g. 22,80,443 or 1-1024. Defaults to the built-in common-port set.
    #[arg(short = 'p', long, value_name = "PORTS", conflicts_with = "top_ports")]
    ports: Option<String>,

    /// Number of built-in common ports to scan (1-100; default: 100).
    #[arg(long, default_value_t = 100, conflicts_with = "ports")]
    top_ports: usize,

    /// Maximum simultaneous TCP connection attempts (default: 512).
    #[arg(short = 'c', long, default_value_t = 512)]
    concurrency: usize,

    /// Per-port connect timeout in milliseconds (default: 1000).
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(50..=60000))]
    timeout_ms: u64,

    /// Output format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Table)]
    format: OutputFormat,

    /// Write results to a file instead of standard output.
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    if !(1..=100).contains(&args.top_ports) {
        bail!("--top-ports must be between 1 and 100");
    }
    if !(1..=8192).contains(&args.concurrency) {
        bail!("--concurrency must be between 1 and 8192");
    }
    let targets = resolve_targets(&args.target).await?;
    let ports = match args.ports {
        Some(specification) => parse_ports(&specification)?,
        None => common_ports(args.top_ports),
    };
    let probe_count = targets
        .len()
        .checked_mul(ports.len())
        .context("probe count overflow")?;
    if probe_count > MAX_PROBES {
        bail!("scan would run {probe_count} probes; reduce targets or ports (limit: {MAX_PROBES})");
    }

    eprintln!(
        "Scanning {} target address(es), {} TCP port(s), {} probe(s)...",
        targets.len(),
        ports.len(),
        probe_count
    );
    let results = scan_tcp(
        &targets,
        &ports,
        args.concurrency,
        Duration::from_millis(args.timeout_ms),
    )
    .await?;
    let report = make_report(results, targets.len());
    let output = match args.format {
        OutputFormat::Table => format_table(&report),
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

fn format_table(report: &netmapper::ScanReport) -> String {
    let mut output =
        String::from("TARGET          PORT   STATE     SERVICE          LATENCY   REASON\n");
    for result in &report.results {
        let reason = result.reason.as_deref().unwrap_or("-");
        output.push_str(&format!(
            "{:<15} {:<6} {:<9} {:<16} {:>5} ms  {}\n",
            result.target,
            result.port,
            format!("{:?}", result.state).to_lowercase(),
            result.service,
            result.latency_ms,
            reason
        ));
    }
    output.push_str(&format!(
        "\n{} target(s), {} TCP probe(s): {} open, {} closed, {} filtered\n",
        report.summary.targets,
        report.summary.probes,
        report.summary.open,
        report.summary.closed,
        report.summary.filtered
    ));
    output
}
