use std::{
    collections::{BTreeMap, BTreeSet},
    io::ErrorKind,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use pnet_packet::{
    icmp::{IcmpPacket, IcmpTypes},
    ip::IpNextHeaderProtocols,
    ipv4::Ipv4Packet,
    tcp::{self, MutableTcpPacket, TcpFlags, TcpPacket},
    udp::{MutableUdpPacket, UdpPacket},
    Packet,
};
use pnet_transport::{
    ipv4_packet_iter, transport_channel, TransportChannelType, TransportProtocol,
};
use serde::Serialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{lookup_host, TcpStream, UdpSocket},
    task::{spawn_blocking, JoinSet},
    time::timeout,
};

mod nse;

pub use nse::{
    list_nse_scripts, run_nse_file, run_nse_scripts_for_endpoint, ScriptHttpResponse,
    DEFAULT_NSE_SCRIPT_DIRECTORY, MAX_NSE_EXECUTIONS,
};

pub const MAX_TARGETS: usize = 4_096;
pub const MAX_PROBES: usize = 1_000_000;

const PLAINTEXT_HTTP_PORTS: &[u16] = &[80, 3000, 8000, 8008, 8080, 8081, 8888];

fn is_plaintext_http_port(port: u16) -> bool {
    PLAINTEXT_HTTP_PORTS.contains(&port)
}

const COMMON_PORTS: [u16; 100] = [
    7, 9, 13, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 179, 199, 389, 443, 445, 465, 514,
    515, 587, 631, 636, 873, 993, 995, 1_024, 1_025, 1_026, 1_027, 1_028, 1_111, 1_312, 1_433,
    1_520, 1_521, 1_723, 1_881, 1_900, 2_000, 2_001, 2_048, 2_049, 2_121, 2_222, 2_378, 2_480,
    2_600, 3_000, 3_123, 3_128, 3_300, 3_306, 3_389, 3_987, 4_444, 4_449, 4_898, 5_000, 5_001,
    5_003, 5_009, 5_051, 5_060, 5_101, 5_190, 5_357, 5_432, 5_631, 5_666, 5_800, 5_900, 6_000,
    6_001, 6_646, 7_070, 8_000, 8_008, 8_009, 8_080, 8_081, 8_443, 8_888, 9_100, 9_999, 10_000,
    10_001, 10_010, 20_000, 32_768, 40_000, 49_152, 49_153, 49_154, 49_155, 49_156, 49_157, 49_158,
];

const DNS_QUERY: [u8; 29] = [
    0x4e, 0x4d, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e', b'x', b'a',
    b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
];
const NTP_QUERY: [u8; 48] = [0x1b; 48];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    #[serde(rename = "open|filtered")]
    OpenFiltered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TcpScanType {
    Connect,
    Syn,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpScript {
    SecurityHeaders,
    ServerHeader,
    PoweredByHeader,
}

#[derive(Clone, Copy, Debug)]
pub struct TcpScanOptions<'a> {
    pub scan_type: TcpScanType,
    pub detect_version: bool,
    pub detect_firewall: bool,
    pub scripts: &'a [HttpScript],
}

#[derive(Clone, Debug, Serialize)]
pub struct ScanResult {
    pub target: IpAddr,
    pub protocol: &'static str,
    pub port: u16,
    pub service: &'static str,
    pub version: Option<String>,
    pub os_hint: Option<String>,
    pub indicators: Vec<String>,
    pub state: PortState,
    pub latency_ms: u128,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct TracerouteHop {
    pub ttl: u8,
    pub address: Option<IpAddr>,
    pub latency_ms: Option<u128>,
    pub outcome: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct TracerouteResult {
    pub target: IpAddr,
    pub reached: bool,
    pub hops: Vec<TracerouteHop>,
}

#[derive(Debug, Serialize)]
pub struct ScanSummary {
    pub targets: usize,
    pub probes: usize,
    pub open: usize,
    pub closed: usize,
    pub filtered: usize,
    pub open_filtered: usize,
    pub filtering_assessment: String,
}

#[derive(Debug, Serialize)]
pub struct ScanReport {
    pub scanner: &'static str,
    pub version: &'static str,
    pub summary: ScanSummary,
    pub results: Vec<ScanResult>,
    pub traceroutes: Vec<TracerouteResult>,
}

pub fn common_ports(count: usize) -> Vec<u16> {
    COMMON_PORTS.iter().copied().take(count).collect()
}

pub async fn traceroute(
    target: IpAddr,
    max_hops: u8,
    timeout_duration: Duration,
) -> Result<TracerouteResult> {
    if max_hops == 0 {
        bail!("traceroute max hops must be greater than zero");
    }
    let IpAddr::V4(target) = target else {
        bail!("raw UDP traceroute currently supports IPv4 targets only");
    };
    spawn_blocking(move || traceroute_ipv4(target, max_hops, timeout_duration))
        .await
        .context("traceroute task failed")?
}

#[cfg(target_os = "linux")]
fn traceroute_ipv4(
    target: Ipv4Addr,
    max_hops: u8,
    timeout_duration: Duration,
) -> Result<TracerouteResult> {
    use std::time::Instant as StdInstant;

    const SOURCE_PORT: u16 = 33_433;
    let (mut sender, _) = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp)),
    )
    .context("could not open raw UDP socket; run with CAP_NET_RAW or as root")?;
    let (_, mut receiver) = transport_channel(
        4096,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp),
    )
    .context("could not open ICMP receive socket; run with CAP_NET_RAW or as root")?;
    let mut packets = ipv4_packet_iter(&mut receiver);
    let mut hops = Vec::new();
    let mut reached = false;

    for ttl in 1..=max_hops {
        let destination_port = SOURCE_PORT + u16::from(ttl);
        sender
            .set_ttl(ttl)
            .with_context(|| format!("could not set traceroute TTL to {ttl}"))?;
        let mut bytes = [0u8; 8];
        let mut packet = MutableUdpPacket::new(&mut bytes)
            .context("could not construct traceroute UDP packet")?;
        packet.set_source(SOURCE_PORT);
        packet.set_destination(destination_port);
        packet.set_length(8);
        packet.set_checksum(0);

        let started = StdInstant::now();
        sender
            .send_to(packet.to_immutable(), IpAddr::V4(target))
            .context("could not send traceroute probe")?;
        let deadline = started + timeout_duration;
        let mut hop = TracerouteHop {
            ttl,
            address: None,
            latency_ms: None,
            outcome: "timeout".to_string(),
        };

        loop {
            let remaining = deadline.saturating_duration_since(StdInstant::now());
            if remaining.is_zero() {
                break;
            }
            let Some((ip_packet, _)) = packets.next_with_timeout(remaining)? else {
                break;
            };
            if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Icmp {
                continue;
            }
            let Some(icmp_packet) = IcmpPacket::new(ip_packet.payload()) else {
                continue;
            };
            if !matches!(
                icmp_packet.get_icmp_type(),
                IcmpTypes::TimeExceeded | IcmpTypes::DestinationUnreachable
            ) {
                continue;
            }
            let Some(original_ip) = Ipv4Packet::new(icmp_packet.payload()) else {
                continue;
            };
            if original_ip.get_destination() != target
                || original_ip.get_next_level_protocol() != IpNextHeaderProtocols::Udp
            {
                continue;
            }
            let Some(original_udp) = UdpPacket::new(original_ip.payload()) else {
                continue;
            };
            if original_udp.get_source() != SOURCE_PORT
                || original_udp.get_destination() != destination_port
            {
                continue;
            }

            let source = ip_packet.get_source();
            let code = icmp_packet.get_icmp_code().0;
            reached = source == target
                && icmp_packet.get_icmp_type() == IcmpTypes::DestinationUnreachable
                && code == 3;
            hop.address = Some(IpAddr::V4(source));
            hop.latency_ms = Some(started.elapsed().as_millis());
            hop.outcome = match icmp_packet.get_icmp_type() {
                IcmpTypes::TimeExceeded => "time-exceeded".to_string(),
                IcmpTypes::DestinationUnreachable if reached => "reached".to_string(),
                IcmpTypes::DestinationUnreachable => format!("unreachable (ICMP code {code})"),
                _ => unreachable!(),
            };
            break;
        }
        hops.push(hop);
        if reached {
            break;
        }
    }

    Ok(TracerouteResult {
        target: IpAddr::V4(target),
        reached,
        hops,
    })
}

#[cfg(not(target_os = "linux"))]
fn traceroute_ipv4(
    _target: Ipv4Addr,
    _max_hops: u8,
    _timeout_duration: Duration,
) -> Result<TracerouteResult> {
    bail!("raw UDP traceroute is currently supported on Linux only")
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
    scan_tcp_with_detection(targets, ports, concurrency, timeout_duration, false).await
}

pub async fn scan_tcp_with_detection(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
    detect_version: bool,
) -> Result<Vec<ScanResult>> {
    scan_tcp_with_options(
        targets,
        ports,
        concurrency,
        timeout_duration,
        detect_version,
        false,
        &[],
    )
    .await
}

pub async fn scan_tcp_with_options(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
    detect_version: bool,
    detect_firewall: bool,
    scripts: &[HttpScript],
) -> Result<Vec<ScanResult>> {
    scan_tcp_with_type(
        targets,
        ports,
        concurrency,
        timeout_duration,
        TcpScanOptions {
            scan_type: TcpScanType::Connect,
            detect_version,
            detect_firewall,
            scripts,
        },
    )
    .await
}

pub async fn scan_tcp_with_type(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
    options: TcpScanOptions<'_>,
) -> Result<Vec<ScanResult>> {
    if options.scan_type == TcpScanType::Syn {
        let mut results = scan_tcp_syn(targets, ports, concurrency, timeout_duration).await?;
        if options.detect_version || options.detect_firewall || !options.scripts.is_empty() {
            for result in results
                .iter_mut()
                .filter(|result| result.state == PortState::Open)
            {
                if let Some(evidence) = identify_tcp_service(
                    SocketAddr::new(result.target, result.port),
                    result.port,
                    timeout_duration,
                    options.detect_firewall,
                    options.scripts,
                )
                .await
                {
                    result.version = evidence.version;
                    result.indicators.extend(evidence.indicators);
                }
            }
        }
        return Ok(results);
    }
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
            jobs.spawn(probe(
                target,
                port,
                timeout_duration,
                options.detect_version,
                options.detect_firewall,
                options.scripts.to_vec(),
            ));
        }
        if let Some(result) = jobs.join_next().await {
            results.push(result.context("TCP probe task failed")?);
        }
    }
    results.sort_by_key(|result| (result.target, result.port));
    Ok(results)
}

#[cfg(target_os = "linux")]
async fn scan_tcp_syn(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
) -> Result<Vec<ScanResult>> {
    if targets.is_empty() || ports.is_empty() {
        bail!("at least one target and one port are required for a SYN scan");
    }
    if ports.contains(&0) {
        bail!("port 0 is not a valid TCP destination port");
    }
    if concurrency == 0 {
        bail!("concurrency must be greater than zero");
    }
    let total = targets
        .len()
        .checked_mul(ports.len())
        .context("probe count overflow")?;
    if total > MAX_PROBES {
        bail!("scan would run {total} probes; reduce targets or ports (limit: {MAX_PROBES})");
    }
    if targets.iter().any(|target| !target.is_ipv4()) {
        bail!("the initial raw SYN implementation supports IPv4 targets only");
    }

    let mut results = Vec::with_capacity(total);
    for target in targets {
        let target = *target;
        let ports = ports.to_vec();
        let concurrency = concurrency.min(1024);
        let batch = tokio::task::spawn_blocking(move || {
            scan_ipv4_target_syn(target, &ports, concurrency, timeout_duration)
        })
        .await
        .context("SYN scanner task failed")??;
        results.extend(batch);
    }
    results.sort_by_key(|result| (result.target, result.port));
    Ok(results)
}

#[cfg(not(target_os = "linux"))]
async fn scan_tcp_syn(
    _targets: &[IpAddr],
    _ports: &[u16],
    _concurrency: usize,
    _timeout_duration: Duration,
) -> Result<Vec<ScanResult>> {
    bail!("raw SYN scans are currently supported on Linux only")
}

#[cfg(target_os = "linux")]
fn scan_ipv4_target_syn(
    target: IpAddr,
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
) -> Result<Vec<ScanResult>> {
    use std::{
        net::{SocketAddr, UdpSocket as StdUdpSocket},
        time::Instant as StdInstant,
    };

    const SOURCE_PORT_FALLBACK: u16 = 49_999;
    let target_v4 = match target {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => bail!("raw SYN scans currently support IPv4 only"),
    };
    let route_socket = StdUdpSocket::bind("0.0.0.0:0")?;
    route_socket.connect(SocketAddr::new(target, 33434))?;
    let source_ip = match route_socket.local_addr()?.ip() {
        IpAddr::V4(address) => address,
        IpAddr::V6(_) => bail!("could not select an IPv4 source address for target"),
    };
    let source_port = route_socket
        .local_addr()
        .map(|address| address.port())
        .ok()
        .filter(|port| *port != 0)
        .unwrap_or(SOURCE_PORT_FALLBACK);

    let (mut sender, _) = transport_channel(
        4096,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp)),
    )
    .context("could not open raw TCP socket; run with CAP_NET_RAW or as root")?;
    let (_, mut receiver) = transport_channel(
        4096,
        TransportChannelType::Layer3(IpNextHeaderProtocols::Tcp),
    )
    .context("could not open raw TCP receive socket; run with CAP_NET_RAW or as root")?;
    let mut packets = ipv4_packet_iter(&mut receiver);
    let mut results = Vec::with_capacity(ports.len());

    for port_batch in ports.chunks(concurrency.max(1)) {
        let mut outstanding = BTreeMap::new();
        for port in port_batch {
            let sequence = u32::from(*port) ^ u32::from(source_port);
            let mut bytes = [0u8; 20];
            let mut packet = MutableTcpPacket::new(&mut bytes[..])
                .context("could not construct TCP SYN packet")?;
            packet.set_source(source_port);
            packet.set_destination(*port);
            packet.set_sequence(sequence);
            packet.set_data_offset(5);
            packet.set_flags(TcpFlags::SYN);
            packet.set_window(64240);
            packet.set_urgent_ptr(0);
            let checksum = tcp::ipv4_checksum(&packet.to_immutable(), &source_ip, &target_v4);
            packet.set_checksum(checksum);
            sender
                .send_to(packet.to_immutable(), target)
                .with_context(|| format!("could not send SYN probe to {target}:{port}"))?;
            outstanding.insert(*port, (StdInstant::now(), sequence));
        }

        let deadline = StdInstant::now() + timeout_duration;
        while !outstanding.is_empty() {
            let remaining = deadline.saturating_duration_since(StdInstant::now());
            if remaining.is_zero() {
                break;
            }
            let received = packets.next_with_timeout(remaining)?;
            let Some((ip_packet, _)) = received else {
                break;
            };
            if ip_packet.get_source() != target_v4 {
                continue;
            }
            let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) else {
                continue;
            };
            if tcp_packet.get_destination() != source_port {
                continue;
            }
            let response_port = tcp_packet.get_source();
            let Some((_, sequence)) = outstanding.get(&response_port) else {
                continue;
            };
            let flags = tcp_packet.get_flags();
            if flags & TcpFlags::ACK != 0
                && tcp_packet.get_acknowledgement() != sequence.wrapping_add(1)
            {
                continue;
            }
            let Some((sent_at, _)) = outstanding.remove(&response_port) else {
                continue;
            };
            let state =
                if flags & (TcpFlags::SYN | TcpFlags::ACK) == (TcpFlags::SYN | TcpFlags::ACK) {
                    PortState::Open
                } else if flags & TcpFlags::RST != 0 {
                    PortState::Closed
                } else {
                    PortState::Filtered
                };
            let mut indicators = Vec::new();
            let os_hint = if state == PortState::Open {
                indicators.push(format!(
                    "TCP SYN/ACK observed; reply TTL {} and window {} were used for a low-confidence OS-family estimate.",
                    ip_packet.get_ttl(),
                    tcp_packet.get_window()
                ));
                send_tcp_reset(
                    &mut sender,
                    source_ip,
                    target_v4,
                    source_port,
                    response_port,
                    tcp_packet.get_sequence(),
                    tcp_packet.get_acknowledgement(),
                )?;
                estimate_os_family(ip_packet.get_ttl(), tcp_packet.get_window())
            } else {
                None
            };
            results.push(ScanResult {
                target,
                protocol: "tcp",
                port: response_port,
                service: service_name(response_port),
                version: None,
                os_hint,
                indicators,
                state,
                latency_ms: sent_at.elapsed().as_millis(),
                reason: Some("raw IPv4 TCP SYN response".to_string()),
            });
        }

        for port in outstanding.keys().copied() {
            results.push(ScanResult {
                target,
                protocol: "tcp",
                port,
                service: service_name(port),
                version: None,
                os_hint: None,
                indicators: vec![
                    "No SYN response before timeout; open|filtered is ambiguous.".to_string(),
                ],
                state: PortState::Filtered,
                latency_ms: timeout_duration.as_millis(),
                reason: Some("no TCP SYN response before timeout".to_string()),
            });
        }
    }
    Ok(results)
}

#[cfg(target_os = "linux")]
fn send_tcp_reset(
    sender: &mut pnet_transport::TransportSender,
    source_ip: std::net::Ipv4Addr,
    target_ip: std::net::Ipv4Addr,
    source_port: u16,
    target_port: u16,
    response_sequence: u32,
    response_acknowledgement: u32,
) -> Result<()> {
    let mut bytes = [0u8; 20];
    let mut packet =
        MutableTcpPacket::new(&mut bytes[..]).context("could not construct TCP reset")?;
    packet.set_source(source_port);
    packet.set_destination(target_port);
    packet.set_sequence(response_acknowledgement);
    packet.set_acknowledgement(response_sequence.wrapping_add(1));
    packet.set_data_offset(5);
    packet.set_flags(TcpFlags::RST | TcpFlags::ACK);
    packet.set_window(0);
    let checksum = tcp::ipv4_checksum(&packet.to_immutable(), &source_ip, &target_ip);
    packet.set_checksum(checksum);
    sender
        .send_to(packet.to_immutable(), IpAddr::V4(target_ip))
        .context("could not send TCP reset after SYN/ACK")?;
    Ok(())
}

fn estimate_os_family(ttl: u8, window: u16) -> Option<String> {
    let estimated_initial_ttl = match ttl {
        1..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        129..=255 => 255,
        _ => return None,
    };
    let family = match estimated_initial_ttl {
        32 => "embedded/network-device-like",
        64 => "Unix/Linux-like",
        128 => "Windows-like",
        _ => "network-device/other",
    };
    Some(format!(
        "Low confidence: {family}; observed TTL {ttl} (estimated initial TTL {estimated_initial_ttl}), TCP window {window}. Middleboxes and tuning can change these values."
    ))
}

async fn probe(
    target: IpAddr,
    port: u16,
    timeout_duration: Duration,
    detect_version: bool,
    detect_firewall: bool,
    scripts: Vec<HttpScript>,
) -> ScanResult {
    let started = Instant::now();
    let address = SocketAddr::new(target, port);
    let result = timeout(timeout_duration, TcpStream::connect(address)).await;
    let (state, reason) = classify_connect_result(result, timeout_duration);
    let evidence = if (detect_version || detect_firewall) && state == PortState::Open {
        identify_tcp_service(address, port, timeout_duration, detect_firewall, &scripts).await
    } else {
        None
    };
    let mut indicators = evidence
        .as_ref()
        .map_or_else(Vec::new, |evidence| evidence.indicators.clone());
    if detect_firewall && state == PortState::Filtered {
        indicators.push(
            "Possible network filtering; timeout/error is inconclusive and does not identify a device."
                .to_string(),
        );
    }
    ScanResult {
        target,
        protocol: "tcp",
        port,
        service: service_name(port),
        version: evidence.and_then(|evidence| evidence.version),
        os_hint: None,
        indicators,
        state,
        latency_ms: started.elapsed().as_millis(),
        reason,
    }
}

async fn identify_tcp_service(
    address: SocketAddr,
    port: u16,
    timeout_duration: Duration,
    detect_firewall: bool,
    scripts: &[HttpScript],
) -> Option<ServiceEvidence> {
    let mut stream = timeout(timeout_duration, TcpStream::connect(address))
        .await
        .ok()?
        .ok()?;
    if is_plaintext_http_port(port) {
        timeout(
            timeout_duration,
            stream.write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
        )
        .await
        .ok()?
        .ok()?;
    }
    let mut response = [0; 4096];
    let read_timeout = timeout_duration.min(Duration::from_millis(400));
    let length = timeout(read_timeout, stream.read(&mut response))
        .await
        .ok()?
        .ok()?;
    if length == 0 {
        return None;
    }
    let response = String::from_utf8_lossy(&response[..length]);
    let headers = response.split("\r\n\r\n").next().unwrap_or(&response);
    let first_line = headers.lines().next()?.trim();
    let (details, indicators) = if first_line.starts_with("HTTP/") {
        let mut details = vec![first_line.to_string()];
        for prefix in ["server:", "x-powered-by:"] {
            if let Some(header) = headers
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with(prefix))
            {
                details.push(header.trim().to_string());
            }
        }
        let mut indicators = if detect_firewall {
            detect_http_edge_indicators(headers)
        } else {
            Vec::new()
        };
        indicators.extend(run_http_scripts(headers, scripts));
        (details.join("; "), indicators)
    } else {
        (first_line.to_string(), Vec::new())
    };
    let details: String = details
        .chars()
        .filter(|character| !character.is_control())
        .take(160)
        .collect();
    (!details.is_empty()).then_some(ServiceEvidence {
        version: Some(details),
        indicators,
    })
}

struct ServiceEvidence {
    version: Option<String>,
    indicators: Vec<String>,
}

const HTTP_EDGE_SIGNATURES: &[(&str, &[&str])] = &[
    ("Cloudflare edge", &["cf-ray:", "server: cloudflare"]),
    ("Akamai edge", &["x-akamai-", "akamai-ghost"]),
    (
        "Imperva edge/WAF",
        &["x-iinfo:", "incap_ses", "visid_incap"],
    ),
    ("Sucuri edge/WAF", &["x-sucuri-"]),
    ("F5 edge/WAF", &["x-wa-info:"]),
    ("Amazon CloudFront edge", &["x-amz-cf-id:", "x-amz-cf-pop:"]),
];

fn detect_http_edge_indicators(headers: &str) -> Vec<String> {
    let headers = headers.to_ascii_lowercase();
    let mut indicators = BTreeSet::new();
    for (product, signatures) in HTTP_EDGE_SIGNATURES {
        if signatures
            .iter()
            .any(|signature| headers.contains(signature))
        {
            indicators.insert(format!(
                "Possible {product} header signature; this does not confirm WAF functionality or identify a version."
            ));
        }
    }
    if headers
        .lines()
        .any(|line| line.starts_with("x-waf-") || line.starts_with("x-firewall-"))
    {
        indicators.insert(
            "Possible generic WAF/firewall header; vendor and function are unverified.".to_string(),
        );
    }
    if headers.contains("via:")
        || headers.contains("x-cache:")
        || headers.contains("x-proxy-cache:")
        || headers.contains("x-served-by:")
    {
        indicators
            .insert("Possible reverse proxy or cache indicated by response headers.".to_string());
    }
    indicators.into_iter().collect()
}

fn run_http_scripts(headers: &str, scripts: &[HttpScript]) -> Vec<String> {
    let lower_headers = headers.to_ascii_lowercase();
    let mut findings = Vec::new();
    for script in scripts {
        match script {
            HttpScript::SecurityHeaders => {
                let missing = [
                    "content-security-policy:",
                    "strict-transport-security:",
                    "x-content-type-options:",
                    "x-frame-options:",
                    "referrer-policy:",
                ]
                .into_iter()
                .filter(|header| !lower_headers.contains(header))
                .collect::<Vec<_>>();
                if !missing.is_empty() {
                    findings.push(format!(
                        "http-security-headers (informational): response omitted {}",
                        missing.join(", ")
                    ));
                }
            }
            HttpScript::ServerHeader => {
                if let Some(header) = headers
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("server:"))
                {
                    findings.push(format!(
                        "http-server-header (informational): {}",
                        header.trim()
                    ));
                }
            }
            HttpScript::PoweredByHeader => {
                if let Some(header) = headers
                    .lines()
                    .find(|line| line.to_ascii_lowercase().starts_with("x-powered-by:"))
                {
                    findings.push(format!(
                        "http-powered-by-header (informational): {}",
                        header.trim()
                    ));
                }
            }
        }
    }
    findings
}

pub async fn scan_udp(
    targets: &[IpAddr],
    ports: &[u16],
    concurrency: usize,
    timeout_duration: Duration,
) -> Result<Vec<ScanResult>> {
    if targets.is_empty() {
        bail!("at least one target address is required");
    }
    if ports.is_empty() {
        bail!("at least one UDP port is required");
    }
    if ports.contains(&0) {
        bail!("port 0 is not a valid UDP destination port");
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
            jobs.spawn(probe_udp(target, port, timeout_duration));
        }
        if let Some(result) = jobs.join_next().await {
            results.push(result.context("UDP probe task failed")?);
        }
    }
    results.sort_by_key(|result| (result.target, result.port));
    Ok(results)
}

fn udp_probe_payload(port: u16) -> &'static [u8] {
    match port {
        53 => &DNS_QUERY,
        123 => &NTP_QUERY,
        _ => &[],
    }
}

async fn probe_udp(target: IpAddr, port: u16, timeout_duration: Duration) -> ScanResult {
    let started = Instant::now();
    let bind_address = match target {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    let outcome = match UdpSocket::bind(bind_address).await {
        Ok(socket) => match socket.connect(SocketAddr::new(target, port)).await {
            Ok(()) => {
                timeout(timeout_duration, async {
                    socket.send(udp_probe_payload(port)).await?;
                    let mut response = [0; 512];
                    socket.recv(&mut response).await
                })
                .await
            }
            Err(error) => Ok(Err(error)),
        },
        Err(error) => Ok(Err(error)),
    };
    let (state, reason) = match outcome {
        Ok(Ok(_)) => (PortState::Open, None),
        Ok(Err(error)) if error.kind() == ErrorKind::ConnectionRefused => {
            (PortState::Closed, Some(error.to_string()))
        }
        Ok(Err(error)) => (PortState::Filtered, Some(error.to_string())),
        Err(_) => (
            PortState::OpenFiltered,
            Some("no UDP response received before timeout".to_string()),
        ),
    };
    ScanResult {
        target,
        protocol: "udp",
        port,
        service: service_name(port),
        version: None,
        os_hint: None,
        indicators: Vec::new(),
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
        3000 => "http-alt",
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
    make_report_with_traceroutes(results, target_count, Vec::new())
}

pub fn make_report_with_traceroutes(
    results: Vec<ScanResult>,
    target_count: usize,
    traceroutes: Vec<TracerouteResult>,
) -> ScanReport {
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
    let open_filtered = results
        .iter()
        .filter(|result| result.state == PortState::OpenFiltered)
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
            open_filtered,
            filtering_assessment: if filtered + open_filtered == 0 {
                "No filtering signal observed; this does not rule out a firewall.".to_string()
            } else {
                format!(
                    "{} probe(s) were filtered or inconclusive; firewall rules, host policy, routing, or packet loss may explain the result. No device or version is identified.",
                    filtered + open_filtered
                )
            },
        },
        results,
        traceroutes,
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

    #[tokio::test]
    async fn detects_a_loopback_udp_responder() {
        let responder = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = responder.local_addr().unwrap().port();
        let responder_task = tokio::spawn(async move {
            let mut request = [0; 1];
            let (_, peer) = responder.recv_from(&mut request).await.unwrap();
            responder.send_to(b"ok", peer).await.unwrap();
        });

        let results = scan_udp(
            &[IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            &[port],
            1,
            Duration::from_secs(1),
        )
        .await
        .unwrap();
        responder_task.await.unwrap();
        assert_eq!(results[0].protocol, "udp");
        assert_eq!(results[0].state, PortState::Open);
    }

    #[test]
    fn selects_protocol_aware_udp_probes_for_dns_and_ntp() {
        assert_eq!(udp_probe_payload(53).len(), 29);
        assert_eq!(udp_probe_payload(123).len(), 48);
        assert!(udp_probe_payload(9999).is_empty());
    }

    #[tokio::test]
    async fn reads_http_server_version_banner() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 256];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(
                    b"HTTP/1.0 200 OK\r\nServer: netmapper-test/1.0\r\nX-Powered-By: Rust\r\nCF-Ray: test123\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let evidence = identify_tcp_service(address, 80, Duration::from_secs(1), false, &[])
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(
            evidence.version.as_deref(),
            Some("HTTP/1.0 200 OK; Server: netmapper-test/1.0; X-Powered-By: Rust")
        );
        assert!(evidence.indicators.is_empty());
    }

    #[tokio::test]
    async fn probes_http_on_alternate_port_3000() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0; 256];
            let _ = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request).starts_with("HEAD / HTTP/1.0"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nX-Powered-By: Next.js\r\n\r\n")
                .await
                .unwrap();
        });

        let evidence = identify_tcp_service(address, 3000, Duration::from_secs(1), false, &[])
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(
            evidence.version.as_deref(),
            Some("HTTP/1.1 200 OK; X-Powered-By: Next.js")
        );
        assert_eq!(service_name(3000), "http-alt");
    }

    #[test]
    fn finds_known_http_edge_signatures_without_claiming_certainty() {
        let indicators = detect_http_edge_indicators(
            "HTTP/1.1 403 Forbidden\r\nCF-Ray: abc123\r\nVia: cache\r\n\r\n",
        );
        assert!(indicators
            .iter()
            .any(|value| value.contains("Cloudflare edge")));
        assert!(indicators
            .iter()
            .any(|value| value.contains("Possible reverse proxy")));
        assert!(indicators.iter().all(|value| value.contains("Possible")));
    }

    #[test]
    fn ignores_unmatched_headers_for_http_edge_detection() {
        assert!(detect_http_edge_indicators("HTTP/1.1 200 OK\r\nDate: today\r\n\r\n").is_empty());
    }

    #[test]
    fn runs_only_selected_read_only_http_scripts() {
        let headers = "HTTP/1.1 200 OK\r\nServer: example/1.0\r\nX-Powered-By: Example\r\n\r\n";
        let findings = run_http_scripts(
            headers,
            &[HttpScript::SecurityHeaders, HttpScript::PoweredByHeader],
        );
        assert_eq!(findings.len(), 2);
        assert!(findings
            .iter()
            .any(|finding| finding.contains("http-powered-by-header")));
        assert!(findings
            .iter()
            .any(|finding| finding.contains("http-security-headers")));
        assert!(!findings
            .iter()
            .any(|finding| finding.contains("http-server-header")));
    }

    #[test]
    fn ttl_os_family_hints_are_explicitly_low_confidence() {
        assert!(estimate_os_family(61, 64240)
            .unwrap()
            .contains("Unix/Linux-like"));
        assert!(estimate_os_family(120, 8192)
            .unwrap()
            .contains("Windows-like"));
        assert!(estimate_os_family(0, 0).is_none());
    }
}
