use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use swarm_proxy::{issue_ticket, run_broker, run_provider};

#[derive(Parser, Debug)]
#[command(name = "swarm-proxy", version, about = "Reverse proxy broker/provider for net_cap proxy mode")]
struct Cli {
    /// Emit JSON output.
    #[arg(long)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Broker {
        #[arg(long, default_value = "0.0.0.0:8787")]
        listen: String,
    },
    Provider {
        #[arg(long)]
        broker: String,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        token: String,
    },
    Ticket {
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        broker: String,
        #[arg(long)]
        expires_at_unix: Option<u64>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Broker { listen } => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "ok",
                        "message": "starting broker",
                        "listen": listen,
                    }))?
                );
            } else {
                println!("starting broker on {listen}");
            }
            run_broker(&listen)?;
        }
        Command::Provider {
            broker,
            session_id,
            token,
        } => {
            if cli.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "status": "ok",
                        "message": "starting provider",
                        "broker": broker,
                        "session_id": session_id,
                    }))?
                );
            } else {
                println!("starting provider for session {session_id} via {broker}");
            }
            run_provider(&broker, &session_id, &token)?;
        }
        Command::Ticket {
            session_id,
            broker,
            expires_at_unix,
            out,
        } => {
            let ticket = issue_ticket(&session_id, &broker, expires_at_unix)?;
            if let Some(path) = out {
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(&path, serde_json::to_vec_pretty(&ticket)?)?;
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "status": "ok",
                            "ticket_path": path,
                            "ticket": ticket
                        }))?
                    );
                } else {
                    println!("ticket written: {}", path.display());
                }
            } else if cli.json {
                println!("{}", serde_json::to_string_pretty(&ticket)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&ticket)?);
            }
        }
    }
    Ok(())
}
