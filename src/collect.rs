use crate::Config;
use crate::report::{Check, Report, State};
use serde::Deserialize;
use std::fs;
use std::io::{self, Read};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Deserialize)]
struct Route {
    dev: Option<String>,
    gateway: Option<IpAddr>,
    prefsrc: Option<IpAddr>,
    table: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct Link {
    ifname: String,
    operstate: String,
    flags: Vec<String>,
    #[serde(default)]
    stats64: Option<LinkStats>,
}

#[derive(Deserialize)]
struct LinkStats {
    rx: Counters,
    tx: Counters,
}

#[derive(Deserialize)]
struct Counters {
    errors: u64,
    dropped: u64,
}

struct Output {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

pub fn diagnose(config: &Config) -> Report {
    let start = Instant::now();
    let mut report = Report::new(config.passive);
    let mut route = None;
    report.record(start, Check::Route, || match lookup_route(config) {
        Ok(found) => {
            let detail = format!(
                "target={} dev={} gateway={} source={} table={}",
                config.target,
                found.dev.as_deref().unwrap_or("?"),
                found
                    .gateway
                    .map_or_else(|| "on-link".into(), |v| v.to_string()),
                found.prefsrc.map_or_else(|| "?".into(), |v| v.to_string()),
                found
                    .table
                    .as_ref()
                    .map_or_else(|| "default (not reported)".into(), |v| v.to_string())
            );
            route = Some(found);
            (State::Pass, detail)
        }
        Err(evidence) => evidence,
    });
    report.record(start, Check::Links, || links(config.timeout));
    report.record(start, Check::KernelTcp, tcp_counters);
    for check in [Check::Gateway, Check::Tcp, Check::Resolver] {
        report.record(start, check, || {
            if config.passive {
                return (State::Skipped, "passive capture".into());
            }
            match check {
                Check::Gateway => gateway(config, route.as_ref()),
                Check::Tcp => tcp_connect(config.target, config.timeout),
                Check::Resolver => resolve(&config.host, config.timeout),
                _ => unreachable!(),
            }
        });
    }
    report.classify();
    report
}

fn family(ip: IpAddr) -> &'static str {
    if ip.is_ipv4() { "-4" } else { "-6" }
}

fn lookup_route(config: &Config) -> Result<Route, (State, String)> {
    let ip = config.target.to_string();
    let output = command(
        "ip",
        &["-j", family(config.target), "route", "get", &ip],
        config.timeout,
    )
    .map_err(|err| (State::Unavailable, format!("route lookup for {ip}: {err}")))?;
    if !output.status.success() {
        let message = failure(&output);
        let state =
            if message.contains("Network is unreachable") || message.contains("No route to host") {
                State::Fail
            } else {
                State::Unavailable
            };
        return Err((state, format!("route lookup for {ip}: {message}")));
    }
    serde_json::from_slice::<Vec<Route>>(&output.stdout)
        .ok()
        .and_then(|routes| routes.into_iter().find(|route| route.dev.is_some()))
        .ok_or_else(|| {
            (
                State::Unavailable,
                "ip returned no usable route record".into(),
            )
        })
}

fn links(timeout: Duration) -> (State, String) {
    local_snapshot((|| {
        let output = command("ip", &["-j", "-s", "link", "show"], timeout)?;
        if !output.status.success() {
            return Err(io::Error::other(failure(&output)));
        }
        let links: Vec<Link> = serde_json::from_slice(&output.stdout)?;
        let mut lines = Vec::new();
        let total = links.len();
        for link in links.into_iter().take(32) {
            let admin_up = link.flags.iter().any(|flag| flag == "UP");
            let carrier = link.flags.iter().any(|flag| flag == "LOWER_UP");
            let mut description = format!(
                "{} state={} admin_up={} lower_up={}",
                link.ifname, link.operstate, admin_up, carrier
            );
            if let Some(stats) = link.stats64 {
                description.push_str(&format!(
                    " rx_errors={} tx_errors={} rx_dropped={} tx_dropped={}",
                    stats.rx.errors, stats.tx.errors, stats.rx.dropped, stats.tx.dropped
                ));
            }
            lines.push(description);
        }
        if total > 32 {
            lines.push(format!("{} additional interfaces omitted", total - 32));
        }
        Ok(lines.join(" | "))
    })())
}

fn tcp_counters() -> (State, String) {
    local_snapshot(fs::read_to_string("/proc/net/snmp").and_then(|text| {
        let mut rows = text.lines().filter_map(|line| line.strip_prefix("Tcp:"));
        let header = rows
            .next()
            .ok_or_else(|| io::Error::other("missing Tcp header"))?;
        let values = rows
            .next()
            .ok_or_else(|| io::Error::other("missing Tcp values"))?;
        let pairs: Vec<_> = header
            .split_whitespace()
            .zip(values.split_whitespace())
            .collect();
        let fields: Option<Vec<_>> = ["RetransSegs", "AttemptFails", "EstabResets"]
            .into_iter()
            .map(|key| {
                pairs
                    .iter()
                    .find(|(name, _)| *name == key)
                    .and_then(|(_, value)| value.parse::<u64>().ok())
                    .map(|value| format!("{key}={value}"))
            })
            .collect();
        fields
            .map(|values| format!("namespace cumulative counters: {}", values.join(" ")))
            .ok_or_else(|| io::Error::other("missing or invalid TCP counters"))
    }))
}

fn local_snapshot(result: io::Result<String>) -> (State, String) {
    match result {
        Ok(data) => (State::Pass, data),
        Err(error) => (State::Unavailable, error.to_string()),
    }
}

fn gateway(config: &Config, route: Option<&Route>) -> (State, String) {
    let Some((ip, dev)) = route.and_then(|r| r.gateway.zip(r.dev.as_deref())) else {
        return (
            State::Skipped,
            "selected route has no known IP gateway".into(),
        );
    };
    let address = ip.to_string();
    let seconds = format!("{:.3}", config.timeout.as_secs_f64());
    let result = command(
        "ping",
        &[
            family(ip),
            "-n",
            "-c",
            "1",
            "-W",
            &seconds,
            "-I",
            dev,
            "--",
            &address,
        ],
        config.timeout + Duration::from_millis(250),
    );
    let (state, detail) = match result {
        Ok(output) if output.status.success() => (State::Pass, "ICMP reply received".into()),
        Ok(output) if output.status.code() == Some(1) => (State::Fail, "no ICMP reply".into()),
        Ok(output) => (State::Unavailable, failure(&output)),
        Err(error) => (State::Unavailable, error.to_string()),
    };
    (state, format!("{address} via {dev}: {detail}"))
}

fn tcp_connect(ip: IpAddr, timeout: Duration) -> (State, String) {
    let address = SocketAddr::new(ip, 443);
    match TcpStream::connect_timeout(&address, timeout) {
        Ok(_) => (State::Pass, format!("{address}: TCP handshake completed")),
        Err(error) => (State::Fail, format!("{address}: {error}")),
    }
}

fn resolve(host: &str, timeout: Duration) -> (State, String) {
    match command("getent", &["ahosts", host], timeout) {
        Ok(output) if output.status.success() => {
            let mut ips: Vec<IpAddr> = String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter_map(|line| line.split_whitespace().next()?.parse().ok())
                .collect();
            ips.sort_unstable();
            ips.dedup();
            if ips.is_empty() {
                return (
                    State::Unavailable,
                    format!("{host}: no parseable addresses"),
                );
            }
            let resolved = ips
                .iter()
                .take(8)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            (State::Pass, format!("{host}: {resolved}"))
        }
        Ok(output) if output.status.code() == Some(2) => (
            State::Fail,
            format!("{host}: system resolver returned no address"),
        ),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => {
            (State::Fail, format!("{host}: system resolver timed out"))
        }
        Ok(output) => (State::Unavailable, format!("{host}: {}", failure(&output))),
        Err(error) => (State::Unavailable, format!("{host}: {error}")),
    }
}

fn failure(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let error = stderr.trim();
    if error.is_empty() {
        output.status.to_string()
    } else {
        error.chars().take(512).collect()
    }
}

fn command(program: &str, args: &[&str], timeout: Duration) -> io::Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let out = child.stdout.take().expect("piped stdout");
    let err = child.stderr.take().expect("piped stderr");
    let started = Instant::now();
    thread::scope(|scope| {
        let stdout = scope.spawn(move || bounded_read(out));
        let stderr = scope.spawn(move || bounded_read(err));
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) if started.elapsed() < timeout => {
                    thread::sleep(
                        Duration::from_millis(10).min(timeout.saturating_sub(started.elapsed())),
                    );
                }
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break Err(result.err().unwrap_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!("{program} exceeded {} ms", timeout.as_millis()),
                        )
                    }));
                }
            }
        }?;
        Ok(Output {
            status,
            stdout: stdout.join().expect("stdout reader finished")?,
            stderr: stderr.join().expect("stderr reader finished")?,
        })
    })
}

fn bounded_read(mut reader: impl Read) -> io::Result<Vec<u8>> {
    const LIMIT: u64 = 1024 * 1024;
    let mut data = Vec::new();
    reader.by_ref().take(LIMIT + 1).read_to_end(&mut data)?;
    if data.len() as u64 > LIMIT {
        io::copy(&mut reader, &mut io::sink())?;
        return Err(io::Error::other("probe output exceeds 1 MiB"));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_split_tunnel_route_without_gateway() {
        let route: Route =
            serde_json::from_str(r#"{"dev":"tun0","table":100,"prefsrc":"10.0.0.2"}"#).unwrap();
        assert_eq!(route.dev.as_deref(), Some("tun0"));
        assert_eq!(route.gateway, None);
        assert_eq!(route.table.unwrap(), 100);
    }

    #[test]
    fn kills_timed_out_command() {
        let err = command("sleep", &["5"], Duration::from_millis(100))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn tcp_connects_to_local_listener() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        assert!(
            TcpStream::connect_timeout(&listener.local_addr().unwrap(), Duration::from_secs(1))
                .is_ok()
        );
    }
}
