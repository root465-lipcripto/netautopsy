#![forbid(unsafe_code)]

mod collect;
mod report;

use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::process::ExitCode;

use report::Report;

const HELP: &str = "NetAutopsy — Linux network diagnostics

Usage:
  netautopsy diagnose [--passive] [--target IP] [--host NAME] [--timeout-ms N]
                       [--json | --output FILE]
  netautopsy inspect FILE
  netautopsy --version

By default, probes Cloudflare 1.1.1.1:443, the selected IPv4 gateway (ICMP)
and resolves example.com through the system resolver.
Use an IPv6 address with --target to probe that family. --passive performs
only local reads. --output saves a new private JSON file and prints a summary.
Timeout applies per probe (100–10000 ms, default 2000).";

pub(crate) struct Config {
    passive: bool,
    target: IpAddr,
    host: String,
    timeout: std::time::Duration,
}

fn main() -> ExitCode {
    match run(env::args().skip(1)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("netautopsy: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(mut args: impl Iterator<Item = String>) -> io::Result<()> {
    let command = args.next();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match command.as_deref() {
        None | Some("--help" | "-h") => writeln!(out, "{HELP}"),
        Some("--version" | "-V") if args.next().is_none() => {
            writeln!(out, "netautopsy {}", env!("CARGO_PKG_VERSION"))
        }
        Some("inspect") => {
            let path = args
                .next()
                .ok_or_else(|| invalid("inspect requires a file"))?;
            if args.next().is_some() {
                return Err(invalid("inspect accepts exactly one file"));
            }
            if !std::fs::metadata(&path)?.is_file() {
                return Err(invalid("expected a regular report file"));
            }
            let file = File::open(path)?;
            if !file.metadata()?.is_file() {
                return Err(invalid("expected a regular report file"));
            }
            let mut bytes = Vec::new();
            const LIMIT: u64 = 1024 * 1024;
            file.take(LIMIT + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 > LIMIT {
                return Err(invalid("report exceeds 1 MiB"));
            }
            let mut report: Report = serde_json::from_slice(&bytes)?;
            report.validate()?;
            report.classify();
            report.render(&mut out)
        }
        Some("diagnose") => {
            let mut config = Config {
                passive: false,
                target: IpAddr::from([1, 1, 1, 1]),
                host: "example.com".into(),
                timeout: std::time::Duration::from_secs(2),
            };
            let mut json = false;
            let mut output = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--help" | "-h" => return writeln!(out, "{HELP}"),
                    "--passive" => config.passive = true,
                    "--json" => json = true,
                    "--target" => {
                        config.target = value(&mut args, &arg)?
                            .parse()
                            .map_err(|_| invalid("--target requires an IP address"))?;
                        if config.target.is_unspecified() || config.target.is_multicast() {
                            return Err(invalid("--target requires a unicast address"));
                        }
                    }
                    "--host" => {
                        config.host = value(&mut args, &arg)?;
                        if !valid_host(&config.host) {
                            return Err(invalid(
                                "--host requires an ASCII hostname (use punycode for IDNs)",
                            ));
                        }
                    }
                    "--timeout-ms" => {
                        let ms = value(&mut args, &arg)?
                            .parse::<u64>()
                            .ok()
                            .filter(|ms| (100..=10000).contains(ms))
                            .ok_or_else(|| invalid("--timeout-ms must be between 100 and 10000"))?;
                        config.timeout = std::time::Duration::from_millis(ms);
                    }
                    "--output" if output.is_none() => output = Some(value(&mut args, &arg)?),
                    _ => return Err(invalid(format!("unknown or repeated option {arg:?}"))),
                }
            }
            if json && output.is_some() {
                return Err(invalid("choose --json or --output"));
            }
            let report = collect::diagnose(&config);
            if json {
                serde_json::to_writer_pretty(&mut out, &report)?;
                writeln!(out)
            } else {
                if let Some(path) = output {
                    let mut file = OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(path)?;
                    serde_json::to_writer_pretty(&mut file, &report)?;
                    writeln!(file)?;
                }
                report.render(&mut out)
            }
        }
        Some(other) => Err(invalid(format!("unknown command {other:?} (see --help)"))),
    }
}

fn value(args: &mut impl Iterator<Item = String>, option: &str) -> io::Result<String> {
    args.next()
        .filter(|s| !s.starts_with("--"))
        .ok_or_else(|| invalid(format!("{option} requires a value")))
}

fn invalid(text: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, text.into())
}

fn valid_host(host: &str) -> bool {
    let bare = host.strip_suffix('.').unwrap_or(host);
    bare.len() <= 253
        && bare.parse::<IpAddr>().is_err()
        && bare.split('.').all(|part| {
            !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
