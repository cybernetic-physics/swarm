use anyhow::{Context, Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use swarm_core::RouteMode;

const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 3;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetCapTicket {
    pub schema_version: String,
    pub mode: String,
    pub session_id: String,
    pub token: String,
    pub broker_addr: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetCapProbeResult {
    pub broker_addr: String,
    pub probe_url: String,
    pub status_code: u16,
    pub ok: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct NetCapReport {
    pub route_mode: String,
    pub fail_closed: bool,
    pub fallback_to_direct: bool,
    pub ticket_path: Option<PathBuf>,
    pub probe: Option<NetCapProbeResult>,
    pub note: String,
}

pub fn evaluate_route_policy(
    route_mode: &RouteMode,
    ticket_path: Option<&Path>,
    allow_direct_fallback: bool,
    probe_url: &str,
) -> Result<NetCapReport> {
    evaluate_route_policy_with_timeout(
        route_mode,
        ticket_path,
        allow_direct_fallback,
        probe_url,
        Duration::from_secs(DEFAULT_CONNECT_TIMEOUT_SECS),
    )
}

pub fn evaluate_route_policy_with_timeout(
    route_mode: &RouteMode,
    ticket_path: Option<&Path>,
    allow_direct_fallback: bool,
    probe_url: &str,
    timeout: Duration,
) -> Result<NetCapReport> {
    match route_mode {
        RouteMode::Direct => evaluate_direct_mode(ticket_path, allow_direct_fallback),
        RouteMode::ClientExit => {
            evaluate_client_exit_mode(ticket_path, allow_direct_fallback, probe_url, timeout)
        }
    }
}

fn evaluate_direct_mode(
    ticket_path: Option<&Path>,
    allow_direct_fallback: bool,
) -> Result<NetCapReport> {
    if let Some(path) = ticket_path {
        let ticket = load_ticket(path)?;
        if ticket.mode != "direct" {
            return Err(policy_violation(format!(
                "route_mode=direct conflicts with net_cap mode={} from {}",
                ticket.mode,
                path.display()
            )));
        }
        return Ok(NetCapReport {
            route_mode: "direct".to_string(),
            fail_closed: !allow_direct_fallback,
            fallback_to_direct: false,
            ticket_path: Some(path.to_path_buf()),
            probe: None,
            note: "direct route selected with explicit direct net_cap ticket".to_string(),
        });
    }

    Ok(NetCapReport {
        route_mode: "direct".to_string(),
        fail_closed: !allow_direct_fallback,
        fallback_to_direct: false,
        ticket_path: None,
        probe: None,
        note: "direct route selected".to_string(),
    })
}

fn evaluate_client_exit_mode(
    ticket_path: Option<&Path>,
    allow_direct_fallback: bool,
    probe_url: &str,
    timeout: Duration,
) -> Result<NetCapReport> {
    let Some(path) = ticket_path else {
        if allow_direct_fallback {
            return Ok(NetCapReport {
                route_mode: "client_exit".to_string(),
                fail_closed: false,
                fallback_to_direct: true,
                ticket_path: None,
                probe: None,
                note: "client_exit requested but no ticket provided; fell back to direct egress"
                    .to_string(),
            });
        }
        return Err(policy_violation(
            "route_mode=client_exit requires --net-cap-ticket (fail-closed)",
        ));
    };

    let ticket = load_ticket(path)?;
    if ticket.mode != "proxy" {
        if allow_direct_fallback {
            return Ok(NetCapReport {
                route_mode: "client_exit".to_string(),
                fail_closed: false,
                fallback_to_direct: true,
                ticket_path: Some(path.to_path_buf()),
                probe: None,
                note: format!(
                    "client_exit ticket mode={} is unsupported for MVP; fell back to direct egress",
                    ticket.mode
                ),
            });
        }
        return Err(policy_violation(format!(
            "route_mode=client_exit requires net_cap mode=proxy, got mode={} from {}",
            ticket.mode,
            path.display()
        )));
    }

    ensure_not_expired(&ticket)?;

    match probe_proxy(&ticket, probe_url, timeout) {
        Ok(probe) => Ok(NetCapReport {
            route_mode: "client_exit".to_string(),
            fail_closed: !allow_direct_fallback,
            fallback_to_direct: false,
            ticket_path: Some(path.to_path_buf()),
            probe: Some(probe),
            note: "client_exit proxy preflight succeeded".to_string(),
        }),
        Err(err) => {
            if allow_direct_fallback {
                Ok(NetCapReport {
                    route_mode: "client_exit".to_string(),
                    fail_closed: false,
                    fallback_to_direct: true,
                    ticket_path: Some(path.to_path_buf()),
                    probe: None,
                    note: format!("client_exit proxy preflight failed; fell back to direct: {err}"),
                })
            } else {
                Err(policy_violation(format!(
                    "client_exit proxy preflight failed (fail-closed): {err}"
                )))
            }
        }
    }
}

fn policy_violation(message: impl Into<String>) -> anyhow::Error {
    anyhow!("NET_CAP_POLICY_VIOLATION: {}", message.into())
}

fn load_ticket(path: &Path) -> Result<NetCapTicket> {
    let bytes = fs::read(path).with_context(|| format!("failed reading {}", path.display()))?;
    let ticket: NetCapTicket = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;
    validate_ticket(&ticket, path)?;
    Ok(ticket)
}

fn validate_ticket(ticket: &NetCapTicket, path: &Path) -> Result<()> {
    if ticket.session_id.trim().is_empty() {
        return Err(anyhow!(
            "ticket session_id must be non-empty: {}",
            path.display()
        ));
    }
    if ticket.token.trim().is_empty() {
        return Err(anyhow!(
            "ticket token must be non-empty: {}",
            path.display()
        ));
    }
    if ticket.broker_addr.trim().is_empty() {
        return Err(anyhow!(
            "ticket broker_addr must be non-empty: {}",
            path.display()
        ));
    }
    Ok(())
}

fn ensure_not_expired(ticket: &NetCapTicket) -> Result<()> {
    let Some(expires) = ticket.expires_at_unix else {
        return Ok(());
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| anyhow!("system clock before UNIX_EPOCH: {err}"))?
        .as_secs();
    if now > expires {
        return Err(anyhow!(
            "net_cap ticket expired at {}, now={}",
            expires,
            now
        ));
    }
    Ok(())
}

fn probe_proxy(
    ticket: &NetCapTicket,
    probe_url: &str,
    timeout: Duration,
) -> Result<NetCapProbeResult> {
    let addr = ticket
        .broker_addr
        .to_socket_addrs()
        .with_context(|| format!("invalid broker_addr '{}'", ticket.broker_addr))?
        .next()
        .ok_or_else(|| anyhow!("broker_addr has no resolved socket address"))?;

    let host_header = host_header_from_url(probe_url)?;
    let auth = STANDARD.encode(format!("{}:{}", ticket.session_id, ticket.token));

    let mut stream = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("failed to connect broker {}", ticket.broker_addr))?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    let request = format!(
        "GET {probe_url} HTTP/1.1\r\nHost: {host_header}\r\nProxy-Authorization: Basic {auth}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    stream.flush()?;

    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader.read_line(&mut status_line)?;
    if status_line.trim().is_empty() {
        return Err(anyhow!(
            "empty response from broker {} during proxy preflight",
            ticket.broker_addr
        ));
    }
    let status_code = parse_status_code(&status_line)?;
    if (200..400).contains(&status_code) {
        return Ok(NetCapProbeResult {
            broker_addr: ticket.broker_addr.clone(),
            probe_url: probe_url.to_string(),
            status_code,
            ok: true,
            detail: "proxy preflight succeeded".to_string(),
        });
    }

    let mut detail = String::new();
    let _ = reader.read_line(&mut detail);
    Err(anyhow!(
        "status={} broker={} probe_url={} {}",
        status_code,
        ticket.broker_addr,
        probe_url,
        detail.trim()
    ))
}

fn host_header_from_url(url: &str) -> Result<String> {
    let remainder = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| anyhow!("probe_url must start with http:// or https://"))?;
    let authority = remainder
        .split('/')
        .next()
        .unwrap_or_default()
        .split('@')
        .next_back()
        .unwrap_or_default();
    if authority.trim().is_empty() {
        return Err(anyhow!("probe_url has empty host authority"));
    }
    Ok(authority.to_string())
}

fn parse_status_code(status_line: &str) -> Result<u16> {
    let mut parts = status_line.split_whitespace();
    let _http_version = parts
        .next()
        .ok_or_else(|| anyhow!("missing HTTP version"))?;
    let code = parts.next().ok_or_else(|| anyhow!("missing status code"))?;
    let parsed = code
        .parse::<u16>()
        .with_context(|| format!("invalid status code '{code}'"))?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;
    use swarm_proxy::{issue_ticket, run_broker, run_provider};
    use tempfile::TempDir;

    fn write_ticket(tmp: &TempDir, filename: &str, ticket: &NetCapTicket) -> PathBuf {
        let path = tmp.path().join(filename);
        fs::write(
            &path,
            serde_json::to_vec_pretty(ticket).expect("serialize ticket"),
        )
        .expect("write ticket");
        path
    }

    fn allocate_addr() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);
        addr.to_string()
    }

    fn spawn_http_ok_server() -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind upstream server");
        let addr = listener
            .local_addr()
            .expect("upstream local addr")
            .to_string();
        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else {
                    break;
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(250)))
                    .ok();
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                );
                let _ = stream.flush();
            }
        });
        addr
    }

    #[test]
    fn policy_mismatch_rejected_for_client_exit_non_proxy_ticket() {
        let tmp = TempDir::new().expect("temp dir");
        let ticket = NetCapTicket {
            schema_version: "agent_swarm-net-cap-proxy-v1".to_string(),
            mode: "wireguard".to_string(),
            session_id: "session".to_string(),
            token: "token".to_string(),
            broker_addr: "127.0.0.1:1".to_string(),
            issued_at_unix: 0,
            expires_at_unix: None,
        };
        let path = write_ticket(&tmp, "ticket-mismatch.json", &ticket);
        let err = evaluate_route_policy_with_timeout(
            &RouteMode::ClientExit,
            Some(path.as_path()),
            false,
            "http://example.com/",
            Duration::from_secs(1),
        )
        .expect_err("mode mismatch should fail closed");
        assert!(
            err.to_string()
                .contains("route_mode=client_exit requires net_cap mode=proxy")
        );
    }

    #[test]
    fn no_provider_returns_policy_violation() {
        let tmp = TempDir::new().expect("temp dir");
        let broker_addr = allocate_addr();
        thread::spawn({
            let broker_addr = broker_addr.clone();
            move || {
                let _ = run_broker(&broker_addr);
            }
        });
        thread::sleep(Duration::from_millis(120));

        let ticket = issue_ticket("session-no-provider", &broker_addr, None).expect("ticket");
        let ticket = NetCapTicket {
            schema_version: ticket.schema_version,
            mode: ticket.mode,
            session_id: ticket.session_id,
            token: ticket.token,
            broker_addr: ticket.broker_addr,
            issued_at_unix: ticket.issued_at_unix,
            expires_at_unix: ticket.expires_at_unix,
        };
        let path = write_ticket(&tmp, "ticket-no-provider.json", &ticket);

        let err = evaluate_route_policy_with_timeout(
            &RouteMode::ClientExit,
            Some(path.as_path()),
            false,
            "http://example.com/",
            Duration::from_secs(1),
        )
        .expect_err("no provider should fail closed");
        assert!(err.to_string().contains("status=503"));
    }

    #[test]
    fn wrong_token_returns_policy_violation() {
        let tmp = TempDir::new().expect("temp dir");
        let broker_addr = allocate_addr();
        thread::spawn({
            let broker_addr = broker_addr.clone();
            move || {
                let _ = run_broker(&broker_addr);
            }
        });
        thread::sleep(Duration::from_millis(120));

        let good = issue_ticket("session-wrong-token", &broker_addr, None).expect("ticket");
        let upstream_addr = spawn_http_ok_server();
        let probe_url = format!("http://{upstream_addr}/healthz");

        thread::spawn({
            let broker_addr = broker_addr.clone();
            let session_id = good.session_id.clone();
            let token = good.token.clone();
            move || {
                let _ = run_provider(&broker_addr, &session_id, &token);
            }
        });

        let good_ticket = NetCapTicket {
            schema_version: good.schema_version.clone(),
            mode: good.mode.clone(),
            session_id: good.session_id.clone(),
            token: good.token.clone(),
            broker_addr: good.broker_addr.clone(),
            issued_at_unix: good.issued_at_unix,
            expires_at_unix: good.expires_at_unix,
        };
        let good_path = write_ticket(&tmp, "ticket-good.json", &good_ticket);

        let mut provider_ready = false;
        for _ in 0..30 {
            let res = evaluate_route_policy_with_timeout(
                &RouteMode::ClientExit,
                Some(good_path.as_path()),
                false,
                &probe_url,
                Duration::from_secs(1),
            );
            match res {
                Ok(_) => {
                    provider_ready = true;
                    break;
                }
                Err(err) if err.to_string().contains("status=503") => {
                    thread::sleep(Duration::from_millis(100));
                }
                Err(err) => panic!("unexpected warmup error: {err}"),
            }
        }
        assert!(provider_ready, "provider did not become ready in time");

        let wrong_ticket = NetCapTicket {
            schema_version: good.schema_version,
            mode: good.mode,
            session_id: good.session_id,
            token: "wrong-token".to_string(),
            broker_addr: good.broker_addr,
            issued_at_unix: good.issued_at_unix,
            expires_at_unix: good.expires_at_unix,
        };
        let wrong_path = write_ticket(&tmp, "ticket-wrong.json", &wrong_ticket);
        let err = evaluate_route_policy_with_timeout(
            &RouteMode::ClientExit,
            Some(wrong_path.as_path()),
            false,
            &probe_url,
            Duration::from_secs(1),
        )
        .expect_err("wrong token should fail closed");
        assert!(err.to_string().contains("status=403"));
    }
}
