use anyhow::{Result, anyhow};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

use swarm_core::{Backend, RouteMode, RunSpec, validate_schema_kind};
use swarm_state::LocalEngine;
use swarm_verify::verify_certificate_file;

#[derive(Parser, Debug)]
#[command(
    name = "swarm",
    version,
    about = "CLI-first attested branching launcher scaffold"
)]
struct Cli {
    /// Emit machine-readable JSON output.
    #[arg(long, global = true)]
    json: bool,

    /// Suppress non-essential output.
    #[arg(long, global = true)]
    quiet: bool,

    /// Increase verbosity. Repeat for more detail.
    #[arg(long, short, global = true, action = ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Init,
    Doctor,
    Config {
        #[command(subcommand)]
        command: ConfigCmd,
    },
    Run {
        #[command(subcommand)]
        command: RunCmd,
    },
    State {
        #[command(subcommand)]
        command: StateCmd,
    },
    Verify {
        #[command(subcommand)]
        command: VerifyCmd,
    },
    Backend {
        #[command(subcommand)]
        command: BackendCmd,
    },
    Schema {
        #[command(subcommand)]
        command: SchemaCmd,
    },
    Plan {
        #[command(subcommand)]
        command: PlanCmd,
    },
}

#[derive(Subcommand, Debug)]
enum ConfigCmd {
    Show,
    Set { key: String, value: String },
}

#[derive(Subcommand, Debug)]
enum RunCmd {
    Launch {
        #[arg(long)]
        node: String,
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long, value_enum)]
        backend: BackendArg,
        #[arg(long, value_enum, default_value_t = RouteModeArg::Direct)]
        route_mode: RouteModeArg,
        #[arg(long)]
        workflow_ref: Option<String>,
        #[arg(long)]
        allow_cold_start: bool,
    },
    Resume {
        #[arg(long)]
        node: String,
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long, value_enum)]
        backend: BackendArg,
        #[arg(long)]
        allow_cold_start: bool,
    },
    Fork {
        #[arg(long)]
        node: String,
        #[arg(long)]
        label: String,
    },
    Status {
        #[arg(long)]
        run_id: String,
    },
    Logs {
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        follow: bool,
    },
}

#[derive(Subcommand, Debug)]
enum StateCmd {
    Inspect {
        #[arg(long)]
        state_id: String,
    },
    Fork {
        #[arg(long)]
        state_cap: String,
    },
}

#[derive(Subcommand, Debug)]
enum VerifyCmd {
    Cert {
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        expected_artifact_hash: String,
        #[arg(long)]
        required_commit: String,
        #[arg(long)]
        attestation: Option<PathBuf>,
    },
    Proof {
        #[arg(long)]
        proof: PathBuf,
        #[arg(long)]
        public_inputs: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum BackendCmd {
    Github {
        #[command(subcommand)]
        command: GithubBackendCmd,
    },
    Local {
        #[command(subcommand)]
        command: LocalBackendCmd,
    },
}

#[derive(Subcommand, Debug)]
enum GithubBackendCmd {
    Dispatch {
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        workflow_ref: String,
    },
    Collect {
        #[arg(long)]
        run_id: String,
    },
}

#[derive(Subcommand, Debug)]
enum LocalBackendCmd {
    Execute {
        #[arg(long)]
        node: String,
        #[arg(long)]
        run_id: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SchemaCmd {
    Validate {
        #[arg(long)]
        schema: String,
        #[arg(long)]
        file: PathBuf,
    },
}

#[derive(Subcommand, Debug)]
enum PlanCmd {
    Show,
}

#[derive(Debug, Clone, ValueEnum)]
enum BackendArg {
    Local,
    Github,
    Gitlab,
}

#[derive(Debug, Clone, ValueEnum)]
enum RouteModeArg {
    Direct,
    ClientExit,
}

#[derive(Debug, Serialize)]
struct CliResult {
    status: String,
    message: String,
    data: Value,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct SwarmConfig {
    default_backend: Option<String>,
    workflow_ref: Option<String>,
    default_route_mode: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let json_output = cli.json;
    let result = execute(cli)?;
    render(result, json_output)
}

fn execute(cli: Cli) -> Result<CliResult> {
    match cli.command {
        Commands::Init => {
            let path = config_path()?;
            if !path.exists() {
                save_config(&SwarmConfig::default())?;
            }

            let engine = local_engine()?;
            let engine_root = engine.resolve_local_ref("local://");
            fs::create_dir_all(&engine_root)?;

            Ok(success(
                "initialized swarm config and local engine root",
                json!({ "config_path": path, "local_engine_root": engine_root }),
            ))
        }
        Commands::Doctor => {
            let path = config_path()?;
            let exists = path.exists();
            let cfg = load_config().unwrap_or_default();
            let engine = local_engine()?;
            let checks = json!({
                "config_exists": exists,
                "config_path": path,
                "workflow_ref_set": cfg.workflow_ref.is_some(),
                "local_engine_root": engine.resolve_local_ref("local://"),
            });
            Ok(success("doctor checks complete", checks))
        }
        Commands::Config { command } => match command {
            ConfigCmd::Show => {
                let cfg = load_config().unwrap_or_default();
                Ok(success("config loaded", serde_json::to_value(cfg)?))
            }
            ConfigCmd::Set { key, value } => {
                let mut cfg = load_config().unwrap_or_default();
                match key.as_str() {
                    "default_backend" => cfg.default_backend = Some(value),
                    "workflow_ref" => cfg.workflow_ref = Some(value),
                    "default_route_mode" => cfg.default_route_mode = Some(value),
                    _ => {
                        return Err(anyhow!(
                            "unsupported key '{key}', expected one of: default_backend, workflow_ref, default_route_mode"
                        ));
                    }
                }
                save_config(&cfg)?;
                Ok(success("config updated", serde_json::to_value(cfg)?))
            }
        },
        Commands::Run { command } => match command {
            RunCmd::Launch {
                node,
                run_id,
                backend,
                route_mode,
                workflow_ref,
                allow_cold_start,
            } => {
                let backend_core = to_backend(backend);
                let spec = RunSpec {
                    run_id: run_id.unwrap_or_else(|| format!("run-{}", sanitize(&node))),
                    node,
                    backend: backend_core.clone(),
                    route_mode: to_route_mode(route_mode),
                    workflow_ref,
                };

                if matches!(backend_core, Backend::Local) {
                    let artifacts = local_engine()?.launch(&spec, allow_cold_start)?;
                    return Ok(success(
                        "local launch completed",
                        serde_json::to_value(artifacts)?,
                    ));
                }

                Ok(success(
                    "non-local launch scaffold",
                    json!({ "run_spec": spec, "note": "GitHub/GitLab execution lands in M2/M5" }),
                ))
            }
            RunCmd::Resume {
                node,
                run_id,
                backend,
                allow_cold_start,
            } => {
                let backend_core = to_backend(backend);
                let spec = RunSpec {
                    run_id: run_id.unwrap_or_else(|| format!("resume-{}", sanitize(&node))),
                    node,
                    backend: backend_core.clone(),
                    route_mode: RouteMode::Direct,
                    workflow_ref: load_config().ok().and_then(|cfg| cfg.workflow_ref),
                };

                if matches!(backend_core, Backend::Local) {
                    let artifacts = local_engine()?.resume(&spec, allow_cold_start)?;
                    return Ok(success(
                        "local resume completed",
                        serde_json::to_value(artifacts)?,
                    ));
                }

                Ok(success(
                    "non-local resume scaffold",
                    json!({ "run_spec": spec, "note": "GitHub/GitLab execution lands in M2/M5" }),
                ))
            }
            RunCmd::Fork { node, label } => {
                let artifacts = local_engine()?.fork(&node, &label)?;
                Ok(success(
                    "local fork completed",
                    serde_json::to_value(artifacts)?,
                ))
            }
            RunCmd::Status { run_id } => {
                let result = local_engine()?.load_run_result(&run_id)?;
                Ok(success("local run status loaded", result))
            }
            RunCmd::Logs { run_id, follow } => {
                let hint = local_engine()?.logs_hint(&run_id);
                Ok(success(
                    "local log hints",
                    json!({ "follow": follow, "paths": hint }),
                ))
            }
        },
        Commands::State { command } => match command {
            StateCmd::Inspect { state_id } => {
                let inspection = local_engine()?.inspect_state(&state_id)?;
                Ok(success(
                    "state inspection complete",
                    serde_json::to_value(inspection)?,
                ))
            }
            StateCmd::Fork { state_cap } => Ok(success(
                "state fork by raw token is not implemented yet",
                json!({ "state_cap_ref": redact_secret(&state_cap) }),
            )),
        },
        Commands::Verify { command } => match command {
            VerifyCmd::Cert {
                certificate,
                expected_artifact_hash,
                required_commit,
                attestation,
            } => {
                let cert = verify_certificate_file(
                    &certificate,
                    &expected_artifact_hash,
                    &required_commit,
                )?;
                Ok(success(
                    "certificate verification passed",
                    json!({
                        "certificate_path": certificate,
                        "attestation": attestation,
                        "certificate": cert
                    }),
                ))
            }
            VerifyCmd::Proof {
                proof,
                public_inputs,
            } => Ok(success(
                "proof verification scaffold",
                json!({ "proof": proof, "public_inputs": public_inputs, "verified": false }),
            )),
        },
        Commands::Backend { command } => match command {
            BackendCmd::Github { command } => match command {
                GithubBackendCmd::Dispatch {
                    run_id,
                    workflow_ref,
                } => Ok(success(
                    "github dispatch scaffold",
                    json!({ "run_id": run_id, "workflow_ref": workflow_ref }),
                )),
                GithubBackendCmd::Collect { run_id } => Ok(success(
                    "github collect scaffold",
                    json!({ "run_id": run_id, "artifacts": ["result.json", "next_tokens.json"] }),
                )),
            },
            BackendCmd::Local { command } => match command {
                LocalBackendCmd::Execute { node, run_id } => {
                    let spec = RunSpec {
                        run_id: run_id.unwrap_or_else(|| format!("local-exec-{}", sanitize(&node))),
                        node,
                        backend: Backend::Local,
                        route_mode: RouteMode::Direct,
                        workflow_ref: Some(
                            "local/swarm-local-run.yml@local-dev-commit".to_string(),
                        ),
                    };
                    let artifacts = local_engine()?.launch(&spec, true)?;
                    Ok(success(
                        "local backend execute completed",
                        serde_json::to_value(artifacts)?,
                    ))
                }
            },
        },
        Commands::Schema { command } => match command {
            SchemaCmd::Validate { schema, file } => {
                let schema_check = validate_schema_kind(&schema);
                let file_exists = file.exists();
                let mut errors = schema_check.errors.clone();
                if !file_exists {
                    errors.push(format!("file does not exist: {}", file.display()));
                }
                let valid = schema_check.valid && file_exists;
                Ok(success(
                    if valid {
                        "schema validation passed"
                    } else {
                        "schema validation failed"
                    },
                    json!({
                        "schema": schema,
                        "file": file,
                        "valid": valid,
                        "errors": errors,
                    }),
                ))
            }
        },
        Commands::Plan { command } => match command {
            PlanCmd::Show => Ok(success(
                "planning docs",
                json!({
                    "root": "docs",
                    "files": [
                        "01-notes-synthesis.md",
                        "03-cli-spec.md",
                        "07-roadmap.md",
                        "10-implementation-backlog.md"
                    ]
                }),
            )),
        },
    }
}

fn success(message: &str, data: Value) -> CliResult {
    CliResult {
        status: "ok".to_string(),
        message: message.to_string(),
        data,
    }
}

fn render(result: CliResult, json_output: bool) -> Result<()> {
    if json_output {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("{}", result.message);
        if result.data != json!({}) {
            println!("{}", serde_json::to_string_pretty(&result.data)?);
        }
    }
    Ok(())
}

fn config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME is not set"))?;
    Ok(Path::new(&home).join(".swarm").join("config.json"))
}

fn local_engine() -> Result<LocalEngine> {
    let cwd = std::env::current_dir()?;
    Ok(LocalEngine::new(cwd.join(".swarm").join("local")))
}

fn load_config() -> Result<SwarmConfig> {
    let path = config_path()?;
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn save_config(cfg: &SwarmConfig) -> Result<()> {
    let path = config_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(cfg)?)?;
    Ok(())
}

fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>()
}

fn redact_secret(s: &str) -> String {
    if s.len() <= 8 {
        "********".to_string()
    } else {
        format!("{}...{}", &s[0..4], &s[s.len() - 4..])
    }
}

fn to_backend(value: BackendArg) -> Backend {
    match value {
        BackendArg::Local => Backend::Local,
        BackendArg::Github => Backend::Github,
        BackendArg::Gitlab => Backend::Gitlab,
    }
}

fn to_route_mode(value: RouteModeArg) -> RouteMode {
    match value {
        RouteModeArg::Direct => RouteMode::Direct,
        RouteModeArg::ClientExit => RouteMode::ClientExit,
    }
}
