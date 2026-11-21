use serde::{Deserialize, Serialize};
use std::io::{self, Write};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Check {
    Route,
    Links,
    KernelTcp,
    Gateway,
    Tcp,
    Resolver,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Pass,
    Fail,
    Unavailable,
    Skipped,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Evidence {
    pub check: Check,
    pub state: State,
    pub elapsed_ms: u64,
    pub duration_ms: u64,
    pub detail: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Report {
    pub schema: u32,
    pub started_unix_ms: u64,
    pub passive: bool,
    pub evidence: Vec<Evidence>,
    pub hypothesis: String,
}

impl Report {
    pub fn new(passive: bool) -> Self {
        Self {
            schema: 1,
            started_unix_ms: millis(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default(),
            ),
            passive,
            evidence: Vec::new(),
            hypothesis: String::new(),
        }
    }

    pub fn record(
        &mut self,
        origin: Instant,
        check: Check,
        probe: impl FnOnce() -> (State, String),
    ) {
        let start = Instant::now();
        let (state, detail) = probe();
        self.evidence.push(Evidence {
            check,
            state,
            elapsed_ms: millis(start.duration_since(origin)),
            duration_ms: millis(start.elapsed()),
            detail,
        });
    }

    pub fn validate(&self) -> io::Result<()> {
        let checks = [
            Check::Route,
            Check::Links,
            Check::KernelTcp,
            Check::Gateway,
            Check::Tcp,
            Check::Resolver,
        ];
        if self.schema != 1
            || self.evidence.len() != checks.len()
            || !self.evidence.iter().map(|event| event.check).eq(checks)
            || self
                .evidence
                .windows(2)
                .any(|w| w[0].elapsed_ms > w[1].elapsed_ms)
            || (self.passive
                && self.evidence[3..]
                    .iter()
                    .any(|event| event.state != State::Skipped))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid report schema or timeline",
            ));
        }
        Ok(())
    }

    pub fn classify(&mut self) {
        let state = |check| {
            self.evidence
                .iter()
                .find(|e| e.check == check)
                .map_or(State::Unavailable, |e| e.state)
        };
        self.hypothesis = classify(
            state(Check::Route),
            state(Check::Gateway),
            state(Check::Tcp),
            state(Check::Resolver),
            self.passive,
        )
        .into();
    }

    pub fn render(&self, out: &mut impl Write) -> io::Result<()> {
        writeln!(
            out,
            "NetAutopsy | capture {} ms UTC (Unix epoch)",
            self.started_unix_ms
        )?;
        for event in &self.evidence {
            writeln!(
                out,
                "+{:>5} ms ({:>4} ms) {:<9?} {:<11?} {}",
                event.elapsed_ms,
                event.duration_ms,
                event.check,
                event.state,
                safe_text(&event.detail)
            )?;
        }
        writeln!(out, "\nHypothesis: {}", self.hypothesis)
    }
}

fn classify(
    route: State,
    gateway: State,
    tcp: State,
    resolver: State,
    passive: bool,
) -> &'static str {
    use State::{Fail, Pass};
    match (route, gateway, tcp, resolver, passive) {
        (Fail, _, Pass, _, _) => {
            "The route lookup and TCP result disagree. Recheck policy routing or a route change during capture."
        }
        (Fail, _, _, _, _) => {
            "The local route lookup failed for the selected destination. Check interface configuration and policy routing."
        }
        (_, _, _, _, true) => {
            "Passive capture completed. End-to-end connectivity and name resolution were not tested."
        }
        (_, _, Pass, Fail, _) => {
            "Possible name resolution problem. TCP to a literal IP worked, but the system resolver could not resolve the tested name."
        }
        (_, _, Pass, Pass, _) => {
            "TCP and system name resolution worked for the tested endpoints during capture."
        }
        (_, _, Fail, Pass, _) => {
            "Name resolution worked, but the TCP endpoint failed. Check filtering, routing or endpoint availability."
        }
        (_, Pass, Fail, Fail, _) => {
            "The gateway answered. Check upstream connectivity and resolver availability."
        }
        (_, _, Fail, Fail, _) => {
            "TCP and name resolution failed. Check local routing and upstream connectivity. ICMP silence alone cannot locate the fault."
        }
        _ => "Available evidence is insufficient to isolate the fault.",
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn safe_text(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_control()
            || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            output.extend(c.escape_default());
        } else {
            output.push(c);
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_resolution_and_endpoint_failures() {
        assert!(
            classify(State::Pass, State::Fail, State::Pass, State::Fail, false)
                .contains("name resolution problem")
        );
        assert!(
            classify(State::Pass, State::Pass, State::Fail, State::Pass, false)
                .contains("endpoint failed")
        );
    }

    #[test]
    fn icmp_silence_does_not_override_healthy_tcp() {
        assert!(
            classify(State::Pass, State::Fail, State::Pass, State::Pass, false).contains("worked")
        );
    }

    #[test]
    fn safe_terminal_rendering() {
        assert_eq!(
            safe_text("text\x1b[2J\n\u{202e}"),
            "text\\u{1b}[2J\\n\\u{202e}"
        );
    }
}
