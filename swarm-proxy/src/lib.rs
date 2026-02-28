use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_PROTOCOL_LINE_BYTES: usize = 8 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;
const OPEN_TIMEOUT: Duration = Duration::from_secs(20);
const DATA_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyTicket {
    pub schema_version: String,
    pub mode: String,
    pub session_id: String,
    pub token: String,
    pub broker_addr: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: Option<u64>,
}

pub fn issue_ticket(
    session_id: &str,
    broker_addr: &str,
    expires_at_unix: Option<u64>,
) -> Result<ProxyTicket> {
    if session_id.trim().is_empty() {
        bail!("session_id must be non-empty");
    }
    if broker_addr.trim().is_empty() {
        bail!("broker_addr must be non-empty");
    }
    let issued_at_unix = now_unix();
    let token = derive_token(session_id, broker_addr, issued_at_unix);
    Ok(ProxyTicket {
        schema_version: "agent_swarm-net-cap-proxy-v1".to_string(),
        mode: "proxy".to_string(),
        session_id: session_id.to_string(),
        token,
        broker_addr: broker_addr.to_string(),
        issued_at_unix,
        expires_at_unix,
    })
}

pub fn run_broker(listen_addr: &str) -> Result<()> {
    let listener = TcpListener::bind(listen_addr)
        .with_context(|| format!("failed to bind broker listen address {listen_addr}"))?;
    let state = Arc::new(BrokerState::default());

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(err) => {
                eprintln!("broker accept error: {err}");
                continue;
            }
        };
        let state = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(err) = handle_broker_connection(stream, state) {
                eprintln!("broker connection error: {err}");
            }
        });
    }
    Ok(())
}

pub fn run_provider(broker_addr: &str, session_id: &str, token: &str) -> Result<()> {
    if session_id.trim().is_empty() {
        bail!("session_id must be non-empty");
    }
    if token.trim().is_empty() {
        bail!("token must be non-empty");
    }
    loop {
        match run_provider_once(broker_addr, session_id, token) {
            Ok(()) => {}
            Err(err) => eprintln!("provider disconnected: {err}"),
        }
        thread::sleep(Duration::from_secs(2));
    }
}

#[derive(Debug, Clone)]
struct ProviderHandle {
    token: String,
    control_writer: Arc<Mutex<TcpStream>>,
}

#[derive(Default)]
struct BrokerState {
    providers: Mutex<HashMap<String, ProviderHandle>>,
    pending_open: Mutex<HashMap<String, mpsc::Sender<Result<(), String>>>>,
    pending_data: Mutex<HashMap<String, mpsc::Sender<TcpStream>>>,
}

fn handle_broker_connection(stream: TcpStream, state: Arc<BrokerState>) -> Result<()> {
    stream.set_nodelay(true).ok();
    let mut peek = [0u8; 16];
    let n = stream.peek(&mut peek)?;
    if n == 0 {
        return Ok(());
    }
    let prefix = String::from_utf8_lossy(&peek[..n]).to_string();
    if prefix.starts_with("PROVIDER ") {
        return handle_provider_registration(stream, state);
    }
    if prefix.starts_with("DATA ") {
        return handle_provider_data(stream, state);
    }
    handle_worker_proxy(stream, state)
}

fn handle_provider_registration(mut stream: TcpStream, state: Arc<BrokerState>) -> Result<()> {
    let line = read_protocol_line(&mut stream, MAX_PROTOCOL_LINE_BYTES)?;
    let (session_id, token) = parse_provider_registration(&line)?;

    let writer = Arc::new(Mutex::new(stream.try_clone()?));
    {
        let mut providers = lock_mutex(&state.providers)?;
        providers.insert(
            session_id.clone(),
            ProviderHandle {
                token,
                control_writer: Arc::clone(&writer),
            },
        );
    }
    stream.write_all(b"OK\n")?;
    stream.flush()?;

    let state_for_reader = Arc::clone(&state);
    thread::spawn(move || {
        if let Err(err) = provider_control_reader_loop(&session_id, stream, state_for_reader) {
            eprintln!("provider control reader ended for {session_id}: {err}");
        }
    });
    Ok(())
}

fn provider_control_reader_loop(
    session_id: &str,
    mut stream: TcpStream,
    state: Arc<BrokerState>,
) -> Result<()> {
    loop {
        let line = match read_protocol_line(&mut stream, MAX_PROTOCOL_LINE_BYTES) {
            Ok(line) => line,
            Err(err) => {
                remove_provider_if_same_stream(session_id, &stream, &state)?;
                return Err(err);
            }
        };
        if line.is_empty() {
            continue;
        }
        if let Some(nonce) = line.strip_prefix("OPENED ") {
            if let Some(tx) = lock_mutex(&state.pending_open)?.remove(nonce.trim()) {
                let _ = tx.send(Ok(()));
            }
            continue;
        }
        if let Some(rest) = line.strip_prefix("FAILED ") {
            let mut parts = rest.splitn(2, ' ');
            let nonce = parts.next().unwrap_or_default().trim();
            let reason = parts
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("provider open failed");
            if let Some(tx) = lock_mutex(&state.pending_open)?.remove(nonce) {
                let _ = tx.send(Err(reason.to_string()));
            }
        }
    }
}

fn remove_provider_if_same_stream(
    session_id: &str,
    stream: &TcpStream,
    state: &BrokerState,
) -> Result<()> {
    let mut providers = lock_mutex(&state.providers)?;
    if let Some(existing) = providers.get(session_id) {
        let existing_addr = existing
            .control_writer
            .lock()
            .ok()
            .and_then(|writer| writer.peer_addr().ok());
        let closing_addr = stream.peer_addr().ok();
        if existing_addr == closing_addr {
            providers.remove(session_id);
        }
    }
    Ok(())
}

fn handle_provider_data(mut stream: TcpStream, state: Arc<BrokerState>) -> Result<()> {
    let line = read_protocol_line(&mut stream, MAX_PROTOCOL_LINE_BYTES)?;
    let (session_id, token, nonce) = parse_data_registration(&line)?;
    let provider = {
        let providers = lock_mutex(&state.providers)?;
        providers.get(&session_id).cloned()
    };
    let Some(provider) = provider else {
        stream.write_all(b"ERR unknown-session\n")?;
        return Ok(());
    };
    if provider.token != token {
        stream.write_all(b"ERR forbidden\n")?;
        return Ok(());
    }

    let pending = lock_mutex(&state.pending_data)?.remove(&nonce);
    let Some(tx) = pending else {
        stream.write_all(b"ERR no-pending-open\n")?;
        return Ok(());
    };
    stream.write_all(b"OK\n")?;
    stream.flush()?;
    tx.send(stream)
        .map_err(|_| anyhow!("pending data receiver dropped"))?;
    Ok(())
}

fn handle_worker_proxy(mut worker_stream: TcpStream, state: Arc<BrokerState>) -> Result<()> {
    let head = read_http_header(&mut worker_stream, MAX_HTTP_HEADER_BYTES)?;
    let parsed = parse_http_request_head(&head)?;
    let (session_id, token) = parse_proxy_auth(&parsed.headers).map_err(|err| {
        let _ = write_http_error(
            &mut worker_stream,
            407,
            "Proxy Authentication Required",
            "missing or invalid Proxy-Authorization",
        );
        err
    })?;

    let provider = {
        let providers = lock_mutex(&state.providers)?;
        providers.get(&session_id).cloned()
    };
    let Some(provider) = provider else {
        write_http_error(
            &mut worker_stream,
            503,
            "Service Unavailable",
            "no provider registered for requested session",
        )?;
        return Ok(());
    };
    if provider.token != token {
        write_http_error(
            &mut worker_stream,
            403,
            "Forbidden",
            "proxy credentials do not match active provider token",
        )?;
        return Ok(());
    }

    let route = parse_target_route(&parsed)?;
    let nonce = derive_nonce("open", &session_id);
    let (open_tx, open_rx) = mpsc::channel();
    let (data_tx, data_rx) = mpsc::channel();
    {
        lock_mutex(&state.pending_open)?.insert(nonce.clone(), open_tx);
        lock_mutex(&state.pending_data)?.insert(nonce.clone(), data_tx);
    }

    let open_cmd = format!("OPEN {} {} {}\n", nonce, route.host, route.port);
    {
        let mut writer = lock_mutex(&provider.control_writer)?;
        writer.write_all(open_cmd.as_bytes())?;
        writer.flush()?;
    }

    let open_status = open_rx.recv_timeout(OPEN_TIMEOUT);
    match open_status {
        Ok(Ok(())) => {}
        Ok(Err(reason)) => {
            clear_pending_nonce(&state, &nonce)?;
            write_http_error(&mut worker_stream, 502, "Bad Gateway", &reason)?;
            return Ok(());
        }
        Err(_) => {
            clear_pending_nonce(&state, &nonce)?;
            write_http_error(
                &mut worker_stream,
                504,
                "Gateway Timeout",
                "provider did not acknowledge OPEN request",
            )?;
            return Ok(());
        }
    }

    let mut provider_data_stream = match data_rx.recv_timeout(DATA_TIMEOUT) {
        Ok(stream) => stream,
        Err(_) => {
            clear_pending_nonce(&state, &nonce)?;
            write_http_error(
                &mut worker_stream,
                504,
                "Gateway Timeout",
                "provider data channel did not arrive in time",
            )?;
            return Ok(());
        }
    };

    if route.connect_tunnel {
        worker_stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")?;
        worker_stream.flush()?;
        copy_bidirectional(worker_stream, provider_data_stream)?;
        return Ok(());
    }

    let forwarded_head = build_forwarded_head(&parsed, &route);
    provider_data_stream.write_all(&forwarded_head)?;
    provider_data_stream.flush()?;
    copy_bidirectional(worker_stream, provider_data_stream)?;
    Ok(())
}

fn clear_pending_nonce(state: &BrokerState, nonce: &str) -> Result<()> {
    lock_mutex(&state.pending_open)?.remove(nonce);
    lock_mutex(&state.pending_data)?.remove(nonce);
    Ok(())
}

fn run_provider_once(broker_addr: &str, session_id: &str, token: &str) -> Result<()> {
    let mut control = TcpStream::connect(broker_addr)
        .with_context(|| format!("failed to connect provider control to broker {broker_addr}"))?;
    control.set_nodelay(true).ok();

    let registration = format!("PROVIDER {} {}\n", session_id, token);
    control.write_all(registration.as_bytes())?;
    control.flush()?;
    let ack = read_protocol_line(&mut control, MAX_PROTOCOL_LINE_BYTES)?;
    if ack.trim() != "OK" {
        bail!("broker rejected provider registration: {ack}");
    }

    loop {
        let line = read_protocol_line(&mut control, MAX_PROTOCOL_LINE_BYTES)?;
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("OPEN ") {
            let mut parts = rest.splitn(3, ' ');
            let nonce = parts
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("OPEN command missing nonce"))?;
            let host = parts
                .next()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .ok_or_else(|| anyhow!("OPEN command missing host"))?;
            let port = parts
                .next()
                .map(str::trim)
                .ok_or_else(|| anyhow!("OPEN command missing port"))?
                .parse::<u16>()
                .context("OPEN command contained invalid port")?;

            match connect_target(host, port, Duration::from_secs(10)) {
                Ok(target_stream) => {
                    match connect_provider_data_channel(broker_addr, session_id, token, nonce) {
                        Ok(data_stream) => {
                            let opened = format!("OPENED {}\n", nonce);
                            control.write_all(opened.as_bytes())?;
                            control.flush()?;
                            let _ = copy_bidirectional(target_stream, data_stream);
                        }
                        Err(err) => {
                            let failed =
                                format!("FAILED {} failed-to-open-data-channel:{err}\n", nonce);
                            control.write_all(failed.as_bytes())?;
                            control.flush()?;
                        }
                    }
                }
                Err(err) => {
                    let failed = format!("FAILED {} failed-to-connect-target:{err}\n", nonce);
                    control.write_all(failed.as_bytes())?;
                    control.flush()?;
                }
            }
        }
    }
}

fn connect_provider_data_channel(
    broker_addr: &str,
    session_id: &str,
    token: &str,
    nonce: &str,
) -> Result<TcpStream> {
    let mut data = TcpStream::connect(broker_addr).with_context(|| {
        format!("failed to connect provider data channel to broker {broker_addr}")
    })?;
    data.set_nodelay(true).ok();
    let registration = format!("DATA {} {} {}\n", session_id, token, nonce);
    data.write_all(registration.as_bytes())?;
    data.flush()?;
    let ack = read_protocol_line(&mut data, MAX_PROTOCOL_LINE_BYTES)?;
    if ack.trim() != "OK" {
        bail!("broker rejected data channel registration: {ack}");
    }
    Ok(data)
}

fn connect_target(host: &str, port: u16, timeout: Duration) -> Result<TcpStream> {
    let sanitized_host = host.trim().trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<_> = (sanitized_host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        bail!("no resolved addresses for target {sanitized_host}:{port}");
    }
    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(err) => last_err = Some(err),
        }
    }
    Err(anyhow!(
        "unable to connect to target {sanitized_host}:{port}: {}",
        last_err
            .map(|err| err.to_string())
            .unwrap_or_else(|| "unknown error".to_string())
    ))
}

fn read_protocol_line(stream: &mut TcpStream, max_bytes: usize) -> Result<String> {
    let mut out = Vec::with_capacity(128);
    let mut buf = [0u8; 1];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            return Err(anyhow!("connection closed while reading protocol line"));
        }
        out.push(buf[0]);
        if out.len() > max_bytes {
            bail!("protocol line exceeded {max_bytes} bytes");
        }
        if buf[0] == b'\n' {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&out).trim().to_string())
}

fn read_http_header(stream: &mut TcpStream, max_bytes: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(2048);
    let mut buf = [0u8; 1];
    loop {
        let n = stream.read(&mut buf)?;
        if n == 0 {
            bail!("connection closed while reading HTTP header");
        }
        out.push(buf[0]);
        if out.len() > max_bytes {
            bail!("HTTP header exceeded {max_bytes} bytes");
        }
        if out.len() >= 4 && &out[out.len() - 4..] == b"\r\n\r\n" {
            break;
        }
    }
    Ok(out)
}

fn parse_provider_registration(line: &str) -> Result<(String, String)> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or_default();
    let session = parts.next().unwrap_or_default();
    let token = parts.next().unwrap_or_default();
    if cmd != "PROVIDER" || session.is_empty() || token.is_empty() {
        bail!("invalid provider registration line");
    }
    Ok((session.to_string(), token.to_string()))
}

fn parse_data_registration(line: &str) -> Result<(String, String, String)> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or_default();
    let session = parts.next().unwrap_or_default();
    let token = parts.next().unwrap_or_default();
    let nonce = parts.next().unwrap_or_default();
    if cmd != "DATA" || session.is_empty() || token.is_empty() || nonce.is_empty() {
        bail!("invalid DATA registration line");
    }
    Ok((session.to_string(), token.to_string(), nonce.to_string()))
}

#[derive(Debug, Clone)]
struct ParsedRequest {
    method: String,
    target: String,
    version: String,
    headers: Vec<(String, String)>,
}

fn parse_http_request_head(head: &[u8]) -> Result<ParsedRequest> {
    let text = String::from_utf8(head.to_vec()).context("request head is not valid UTF-8")?;
    let mut lines = text.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("missing request line"))?
        .trim();
    let mut rl = request_line.split_whitespace();
    let method = rl.next().unwrap_or_default().to_string();
    let target = rl.next().unwrap_or_default().to_string();
    let version = rl.next().unwrap_or_default().to_string();
    if method.is_empty() || target.is_empty() || version.is_empty() {
        bail!("invalid request line");
    }

    let mut headers = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        let (name, value) = trimmed
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid header line"))?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }

    Ok(ParsedRequest {
        method,
        target,
        version,
        headers,
    })
}

fn parse_proxy_auth(headers: &[(String, String)]) -> Result<(String, String)> {
    let header = header_value(headers, "Proxy-Authorization")
        .ok_or_else(|| anyhow!("missing Proxy-Authorization header"))?;
    let encoded = header
        .strip_prefix("Basic ")
        .ok_or_else(|| anyhow!("Proxy-Authorization must use Basic scheme"))?;
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|err| anyhow!("invalid Proxy-Authorization base64: {err}"))?;
    let decoded_text =
        String::from_utf8(decoded).context("Proxy-Authorization contains non-UTF8 bytes")?;
    let (session, token) = decoded_text
        .split_once(':')
        .ok_or_else(|| anyhow!("Proxy-Authorization payload must be session:token"))?;
    if session.trim().is_empty() || token.trim().is_empty() {
        bail!("Proxy-Authorization session/token must be non-empty");
    }
    Ok((session.to_string(), token.to_string()))
}

#[derive(Debug, Clone)]
struct TargetRoute {
    host: String,
    port: u16,
    connect_tunnel: bool,
    origin_target: String,
}

fn parse_target_route(request: &ParsedRequest) -> Result<TargetRoute> {
    if request.method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(&request.target, 443)?;
        return Ok(TargetRoute {
            host,
            port,
            connect_tunnel: true,
            origin_target: request.target.clone(),
        });
    }

    if let Some(rest) = request.target.strip_prefix("http://") {
        let (host_port, path) = split_host_and_path(rest);
        let (host, port) = split_host_port(host_port, 80)?;
        return Ok(TargetRoute {
            host,
            port,
            connect_tunnel: false,
            origin_target: path,
        });
    }
    if let Some(rest) = request.target.strip_prefix("https://") {
        let (host_port, path) = split_host_and_path(rest);
        let (host, port) = split_host_port(host_port, 443)?;
        return Ok(TargetRoute {
            host,
            port,
            connect_tunnel: false,
            origin_target: path,
        });
    }

    let host_header = header_value(&request.headers, "Host")
        .ok_or_else(|| anyhow!("non-CONNECT requests require Host header"))?;
    let (host, port) = split_host_port(host_header, 80)?;
    Ok(TargetRoute {
        host,
        port,
        connect_tunnel: false,
        origin_target: request.target.clone(),
    })
}

fn build_forwarded_head(request: &ParsedRequest, route: &TargetRoute) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);
    out.extend_from_slice(
        format!(
            "{} {} {}\r\n",
            request.method, route.origin_target, request.version
        )
        .as_bytes(),
    );
    for (name, value) in &request.headers {
        if name.eq_ignore_ascii_case("Proxy-Authorization")
            || name.eq_ignore_ascii_case("Proxy-Connection")
        {
            continue;
        }
        out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn split_host_and_path(input: &str) -> (&str, String) {
    if let Some((host_port, path)) = input.split_once('/') {
        (host_port, format!("/{}", path))
    } else {
        (input, "/".to_string())
    }
}

fn split_host_port(host_port: &str, default_port: u16) -> Result<(String, u16)> {
    if host_port.is_empty() {
        bail!("empty host");
    }
    if let Some((host, port_str)) = host_port.rsplit_once(':')
        && !host.contains(']')
        && !port_str.is_empty()
        && port_str.chars().all(|ch| ch.is_ascii_digit())
    {
        let port = port_str.parse::<u16>()?;
        return Ok((host.to_string(), port));
    }
    Ok((host_port.to_string(), default_port))
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn write_http_error(stream: &mut TcpStream, code: u16, title: &str, message: &str) -> Result<()> {
    let body = format!("{title}: {message}\n");
    let response = format!(
        "HTTP/1.1 {code} {title}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()?;
    Ok(())
}

fn copy_bidirectional(mut left: TcpStream, mut right: TcpStream) -> Result<()> {
    left.set_nodelay(true).ok();
    right.set_nodelay(true).ok();
    let mut left_reader = left.try_clone()?;
    let mut right_writer = right.try_clone()?;
    let left_to_right = thread::spawn(move || -> Result<()> {
        std::io::copy(&mut left_reader, &mut right_writer)?;
        right_writer.shutdown(Shutdown::Write).ok();
        Ok(())
    });

    std::io::copy(&mut right, &mut left)?;
    left.shutdown(Shutdown::Write).ok();
    let _ = left_to_right.join();
    Ok(())
}

fn lock_mutex<T>(mutex: &Mutex<T>) -> Result<std::sync::MutexGuard<'_, T>> {
    mutex.lock().map_err(|_| anyhow!("mutex poisoned"))
}

fn derive_token(session_id: &str, broker_addr: &str, issued_at_unix: u64) -> String {
    let seed = format!(
        "{session_id}:{broker_addr}:{issued_at_unix}:{}:{}",
        std::process::id(),
        now_unix()
    );
    let digest = Sha256::digest(seed.as_bytes());
    digest[..16].iter().map(|b| format!("{b:02x}")).collect()
}

fn derive_nonce(prefix: &str, seed: &str) -> String {
    let raw = format!(
        "{prefix}:{seed}:{}:{}",
        now_unix(),
        std::thread::current().name().unwrap_or("t")
    );
    let digest = Sha256::digest(raw.as_bytes());
    let suffix: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
    format!("{prefix}-{suffix}")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proxy_auth_decodes_basic_credentials() {
        let credentials = STANDARD.encode("sess-123:tok-xyz");
        let headers = vec![(
            "Proxy-Authorization".to_string(),
            format!("Basic {credentials}"),
        )];
        let (session, token) = parse_proxy_auth(&headers).expect("valid auth header");
        assert_eq!(session, "sess-123");
        assert_eq!(token, "tok-xyz");
    }

    #[test]
    fn parse_target_route_for_connect() {
        let req = ParsedRequest {
            method: "CONNECT".to_string(),
            target: "api.openai.com:443".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![],
        };
        let route = parse_target_route(&req).expect("CONNECT route should parse");
        assert!(route.connect_tunnel);
        assert_eq!(route.host, "api.openai.com");
        assert_eq!(route.port, 443);
    }

    #[test]
    fn parse_target_route_for_absolute_http_uri() {
        let req = ParsedRequest {
            method: "GET".to_string(),
            target: "http://example.com/test?q=1".to_string(),
            version: "HTTP/1.1".to_string(),
            headers: vec![],
        };
        let route = parse_target_route(&req).expect("absolute URI route should parse");
        assert!(!route.connect_tunnel);
        assert_eq!(route.host, "example.com");
        assert_eq!(route.port, 80);
        assert_eq!(route.origin_target, "/test?q=1");
    }

    #[test]
    fn issue_ticket_generates_non_empty_token() {
        let ticket = issue_ticket("session-a", "127.0.0.1:9000", Some(1234)).expect("ticket");
        assert_eq!(ticket.mode, "proxy");
        assert_eq!(ticket.session_id, "session-a");
        assert!(!ticket.token.is_empty());
    }
}
