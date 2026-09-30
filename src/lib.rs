use std::{
    collections::BTreeSet,
    io::ErrorKind,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use serde::Serialize;
use tokio::{
    net::{lookup_host, TcpStream},
    task::JoinSet,
    time::timeout,
};

pub const MAX_TARGETS: usize = 4_096;
pub const MAX_PROBES: usize = 1_000_000;

const COMMON_PORTS: [u16; 100] = [
    7, 9, 13, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 179, 199, 389, 443, 445, 465, 514,
    515, 587, 631, 636, 873, 993, 995, 1_024, 1_025, 1_026, 1_027, 1_028, 1_111, 1_312, 1_433,
    1_520, 1_521, 1_723, 1_881, 1_900, 2_000, 2_001, 2_048, 2_049, 2_121, 2_222, 2_378, 2_480,
    2_600, 3_000, 3_123, 3_128, 3_300, 3_306, 3_389, 3_987, 4_444, 4_449, 4_898, 5_000, 5_001,
    5_003, 5_009, 5_051, 5_060, 5_101, 5_190, 5_357, 5_432, 5_631, 5_666, 5_800, 5_900, 6_000,
    6_001, 6_646, 7_070, 8_000, 8_008, 8_009, 8_080, 8_081, 8_443, 8_888, 9_100, 9_999, 10_000,
    10_001, 10_010, 20_000, 32_768, 40_000, 49_152, 49_153, 49_154, 49_155, 49_156, 49_157, 49_158,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub service: &'static str,
    pub state: PortState,
    pub latency_ms: u128,
    pub reason: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub targets: usize,
    pub probes: usize,
    pub open: usize,
    pub closed: usize,
    pub filtered: usize,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub scanner: &'static str,
    pub version: &'static str,
    pub summary: ScanSummary,
    pub results: Vec<ScanResult>,
}

pub fn common_ports(count: usize) -> Vec<u16> {
    COMMON_PORTS.iter().copied().take(count).collect()
}

pub fn parse_ports(specification: &str) -> Result<Vec<u16>> {
    let mut ports = BTreeSet::new();
    for item in specification.split(',') {
        let item = item.trim();
        if item.is_empty() {
            bail!("port list contains an empty item");
        }
        if let Some((start, end)) = item.split_once('-') {
            let start = parse_port(start)?;
            let end = parse_port(end)?;
            if start > end {
                bail!("invalid descending port range: {item}");
            }
            ports.extend(start..=end);
        } else {
            ports.insert(parse_port(item)?);
        }
    }
    if ports.is_empty() {
        bail!("at least one port is required");
    }
    Ok(ports.into_iter().collect())
}

fn parse_port(value: &str) -> Result<u16> {
    let port: u16 = value
        .parse()
        .with_context(|| format!("invalid port number: {value}"))?;
    if port == 0 {
        bail!("port 0 is not a valid TCP destination port");
    }
    Ok(port)
}

pub async fn resolve_targets(specifications: &[String]) -> Result<Vec<IpAddr>> {
    let mut targets = BTreeSet::new();
    for specification in specifications {
        if let Ok(address) = specification.parse::<IpAddr>() {
            targets.insert(address);
        } else if let Ok(network) = specification.parse::<IpNet>() {
            for address in network.hosts() {
                targets.insert(address);
                if targets.len() > MAX_TARGETS {
                    bail!("target list exceeds the {MAX_TARGETS}-address safety limit");
                }
            }
        } else {
            let addresses = lookup_host((specification.as_str(), 0))
                .await
                .with_context(|| format!("could not resolve target: {specification}"))?;
            let before = targets.len();
            targets.extend(addresses.map(|address| address.ip()));
            if targets.len() > MAX_TARGETS {
                bail!("target list exceeds the {MAX_TARGETS}-address safety limit");
            }
            if targets.len() == before {
                bail!("target resolved to no IP addresses: {specification}");
            }
        }
        if targets.len() > MAX_TARGETS {
            bail!("target list exceeds the {MAX_TARGETS}-address safety limit");
        }
    }
    if targets.is_empty() {
        bail!("no target addresses were resolved");
    }
    Ok(targets.into_iter().collect())
}

pub async fn scan_tcp(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
) -> Result<Vec<ScanResult>> {
    if targets.is_empty() {
        bail!("at least one target address is required");
    }
    if ports.is_empty() {
        bail!("at least one TCP port is required");
    }
    if ports.contains(&0) {
        bail!("port 0 is not a valid TCP destination port");
    }
    let total = targets
        .len()
        .checked_mul(ports.len())
        .context("probe count overflow")?;
    if total > MAX_PROBES {
        bail!("scan would run {total} probes; reduce targets or ports (limit: {MAX_PROBES})");
    }
    if concurrency == 0 {
        bail!("concurrency must be greater than zero");
    }

    let mut jobs = JoinSet::new();
    let mut next = 0;
    let mut results = Vec::with_capacity(total);
    while next < total || !jobs.is_empty() {
        while next < total && jobs.len() < concurrency {
            let target = targets[next / ports.len()];
            let port = ports[next % ports.len()];
            next += 1;
            jobs.spawn(probe(target, port, timeout_duration));
        }
        if let Some(result) = jobs.join_next().await {
            results.push(result.context("TCP probe task failed")?);
        }
    }
    results.sort_by_key(|result| (result.target, result.port));
    Ok(results)
}

async fn probe(target: IpAddr, port: u16, timeout_duration: Duration) -> ScanResult {
    let started = Instant::now();
    let address = SocketAddr::new(target, port);
    let result = timeout(timeout_duration, TcpStream::connect(address)).await;
    let (state, reason) = classify_connect_result(result, timeout_duration);
    ScanResult {
        target,
        port,
        service: service_name(port),
        state,
        latency_ms: started.elapsed().as_millis(),
        reason,
    }
}

fn classify_connect_result(
    result: std::result::Result<std::io::Result<TcpStream>, tokio::time::error::Elapsed>,
    timeout_duration: Duration,
) -> (PortState, Option<String>) {
    match result {
        Ok(Ok(stream)) => {
            drop(stream);
            (PortState::Open, None)
        }
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => {
            (PortState::Closed, Some(error.to_string()))
        }
        Ok(Err(error)) => (PortState::Filtered, Some(error.to_string())),
        Err(_) => (
            PortState::Filtered,
            Some(format!(
                "connection timed out after {} ms",
                timeout_duration.as_millis()
            )),
        ),
    }
}

pub fn service_name(port: u16) -> &'static str {
    match port {
        21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "domain",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        135 => "msrpc",
        139 => "netbios-ssn",
        143 => "imap",
        389 => "ldap",
        443 => "https",
        445 => "microsoft-ds",
        587 => "submission",
        631 => "ipp",
        636 => "ldaps",
        993 => "imaps",
        995 => "pop3s",
        1433 => "ms-sql-s",
        1521 => "oracle",
        3306 => "mysql",
        3389 => "ms-wbt-server",
        5432 => "postgresql",
        5900 => "vnc",
        6379 => "redis",
        8080 => "http-proxy",
        8443 => "https-alt",
        _ => "unknown",
    }
}

pub fn make_report(results: Vec<ScanResult>, target_count: usize) -> ScanReport {
    let open = results
        .iter()
        .filter(|result| result.state == PortState::Open)
        .count();
    let closed = results
        .iter()
        .filter(|result| result.state == PortState::Closed)
        .count();
    let filtered = results
        .iter()
        .filter(|result| result.state == PortState::Filtered)
        .count();
    ScanReport {
        scanner: "netmapper",
        version: env!("CARGO_PKG_VERSION"),
        summary: ScanSummary {
            targets: target_count,
            probes: results.len(),
            open,
            closed,
            filtered,
        },
        results,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_ports_ranges_and_duplicates() {
        assert_eq!(
            parse_ports("80,443,8000-8002,443").unwrap(),
            [80, 443, 8000, 8001, 8002]
        );
    }

    #[test]
    fn rejects_invalid_ports_and_ranges() {
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("65536").is_err());
        assert!(parse_ports("90-80").is_err());
        assert!(parse_ports("22,,80").is_err());
    }

    #[test]
    fn returns_requested_number_of_common_ports() {
        assert_eq!(common_ports(20).len(), 20);
        assert_eq!(common_ports(100).len(), 100);
    }

    #[tokio::test]
    async fn classifies_open_and_closed_loopback_ports() {
        let open_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open_port = open_listener.local_addr().unwrap().port();
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let results = scan_tcp(
            &[IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            &[open_port, closed_port],
            2,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        assert!(results
            .iter()
            .any(|result| result.port == open_port && result.state == PortState::Open));
        assert!(results
            .iter()
            .any(|result| result.port == closed_port && result.state == PortState::Closed));
    }

    #[tokio::test]
    async fn classifies_timed_out_connect_as_filtered() {
        let result = timeout(
            Duration::ZERO,
            std::future::pending::<std::io::Result<TcpStream>>(),
        )
        .await;
        assert_eq!(
            classify_connect_result(result, Duration::ZERO).0,
            PortState::Filtered
        );
    }

    #[tokio::test]
    async fn rejects_empty_probe_inputs() {
        let target = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        assert!(scan_tcp(&[target], &[], 1, Duration::from_millis(100))
            .await
            .is_err());
        assert!(scan_tcp(&[], &[80], 1, Duration::from_millis(100))
            .await
            .is_err());
    }
}
