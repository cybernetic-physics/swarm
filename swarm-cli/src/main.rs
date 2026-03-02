mod github_backend;
mod net_cap;
mod signer;

use anyhow::{Result, anyhow};
use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

use swarm_core::{
    Backend, CapabilityEnvelope, RouteMode, RunSpec, redact_capability_token, validate_schema_kind,
    validate_schema_value,
};
use swarm_state::LocalEngine;
use swarm_verify::{verify_certificate_file_with_policy, verify_proof_file};

const DEFAULT_AGENT_IMAGE: &str = "ghcr.io/example/swarm-agent:latest";
const DEFAULT_AGENT_STEP: &str = "echo swarm m2 dispatch";
const DEFAULT_GH_MAX_ATTEMPTS: u32 = github_backend::DEFAULT_MAX_ATTEMPTS;
const DEFAULT_GH_TIMEOUT_SECS: u64 = github_backend::DEFAULT_TIMEOUT_SECS;

const EXIT_INVALID_INPUT: i32 = 2;
const EXIT_VERIFICATION_FAILED: i32 = 3;
const EXIT_BACKEND_FAILURE: i32 = 4;
const EXIT_RESTORE_FAILURE: i32 = 5;
const EXIT_POLICY_VIOLATION: i32 = 6;

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
    Wallet {
        #[command(subcommand)]
        command: WalletCmd,
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
enum WalletCmd {
    Import {
        #[command(subcommand)]
        command: WalletImportCmd,
    },
    Address {
        #[arg(long)]
        alias: Option<String>,
    },
    Balance {
        #[arg(long)]
        alias: Option<String>,
        #[arg(long, default_value = signer::DEFAULT_BASE_SEPOLIA_RPC_URL)]
        rpc_url: String,
        #[arg(long, default_value_t = signer::DEFAULT_BASE_SEPOLIA_CHAIN_ID)]
        chain_id: u64,
    },
    Send {
        #[arg(long)]
        alias: Option<String>,
        #[arg(long, default_value = signer::DEFAULT_BASE_SEPOLIA_RPC_URL)]
        rpc_url: String,
        #[arg(long, default_value_t = signer::DEFAULT_BASE_SEPOLIA_CHAIN_ID)]
        chain_id: u64,
        #[arg(long)]
        to: String,
        #[arg(long)]
        value_wei: String,
    },
}

#[derive(Subcommand, Debug)]
enum WalletImportCmd {
    PrivateKey {
        #[arg(long)]
        alias: Option<String>,
        #[arg(long)]
        private_key: Option<String>,
        #[arg(long)]
        set_default: bool,
    },
    Mnemonic {
        #[arg(long)]
        alias: Option<String>,
        #[arg(long)]
        mnemonic: Option<String>,
        #[arg(long)]
        set_default: bool,
    },
    Keystore {
        #[arg(long)]
        alias: Option<String>,
        #[arg(long)]
        keystore: PathBuf,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        set_default: bool,
    },
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
        net_cap_ticket: Option<PathBuf>,
        #[arg(long)]
        allow_direct_fallback: bool,
        #[arg(long, default_value = "http://example.com/")]
        net_probe_url: String,
        #[arg(long)]
        workflow_ref: Option<String>,
        #[arg(long)]
        allow_cold_start: bool,
        #[arg(long)]
        agent_image: Option<String>,
        #[arg(long)]
        agent_step: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = DEFAULT_GH_MAX_ATTEMPTS)]
        max_attempts: u32,
        #[arg(long, default_value_t = DEFAULT_GH_TIMEOUT_SECS)]
        timeout_secs: u64,
    },
    Resume {
        #[arg(long)]
        node: String,
        #[arg(long)]
        run_id: Option<String>,
        #[arg(long, value_enum)]
        backend: BackendArg,
        #[arg(long, value_enum, default_value_t = RouteModeArg::Direct)]
        route_mode: RouteModeArg,
        #[arg(long)]
        net_cap_ticket: Option<PathBuf>,
        #[arg(long)]
        allow_direct_fallback: bool,
        #[arg(long, default_value = "http://example.com/")]
        net_probe_url: String,
        #[arg(long)]
        workflow_ref: Option<String>,
        #[arg(long)]
        allow_cold_start: bool,
        #[arg(long)]
        agent_image: Option<String>,
        #[arg(long)]
        agent_step: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = DEFAULT_GH_MAX_ATTEMPTS)]
        max_attempts: u32,
        #[arg(long, default_value_t = DEFAULT_GH_TIMEOUT_SECS)]
        timeout_secs: u64,
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
    Cancel {
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        gh_run_id: Option<u64>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = DEFAULT_GH_MAX_ATTEMPTS)]
        max_attempts: u32,
        #[arg(long, default_value_t = DEFAULT_GH_TIMEOUT_SECS)]
        timeout_secs: u64,
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
        #[arg(long)]
        policy_file: Option<PathBuf>,
        #[arg(long)]
        require_policy: bool,
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
        #[arg(long, value_enum, default_value_t = RouteModeArg::Direct)]
        route_mode: RouteModeArg,
        #[arg(long)]
        net_cap_ticket: Option<PathBuf>,
        #[arg(long)]
        allow_direct_fallback: bool,
        #[arg(long, default_value = "http://example.com/")]
        net_probe_url: String,
        #[arg(long)]
        allow_cold_start: bool,
        #[arg(long, default_value = DEFAULT_AGENT_IMAGE)]
        agent_image: String,
        #[arg(long, default_value = DEFAULT_AGENT_STEP)]
        agent_step: String,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = DEFAULT_GH_MAX_ATTEMPTS)]
        max_attempts: u32,
        #[arg(long, default_value_t = DEFAULT_GH_TIMEOUT_SECS)]
        timeout_secs: u64,
    },
    Collect {
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        gh_run_id: u64,
        #[arg(long)]
        workflow_ref: Option<String>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        skip_verify_cert: bool,
        #[arg(long, default_value_t = true)]
        require_policy: bool,
        #[arg(long, default_value_t = DEFAULT_GH_MAX_ATTEMPTS)]
        max_attempts: u32,
        #[arg(long, default_value_t = DEFAULT_GH_TIMEOUT_SECS)]
        timeout_secs: u64,
    },
    Cancel {
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        gh_run_id: Option<u64>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long, default_value_t = DEFAULT_GH_MAX_ATTEMPTS)]
        max_attempts: u32,
        #[arg(long, default_value_t = DEFAULT_GH_TIMEOUT_SECS)]
        timeout_secs: u64,
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
    let cli = Cli::parse();
    let json_output = cli.json;
    match execute(cli) {
        Ok(result) => {
            if let Err(err) = render(result, json_output) {
                eprintln!("error: {err}");
                std::process::exit(1);
            }
        }
        Err(err) => {
            let code = classify_exit_code(&err);
            render_error(&err, json_output, code);
            std::process::exit(code);
        }
    }
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
            let github_checks = github_backend::doctor_checks(&cwd()?, cfg.workflow_ref.as_deref());
            let checks = json!({
                "config_exists": exists,
                "config_path": path,
                "workflow_ref_set": cfg.workflow_ref.is_some(),
                "local_engine_root": engine.resolve_local_ref("local://"),
                "github": github_checks,
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
        Commands::Wallet { command } => match command {
            WalletCmd::Import { command } => match command {
                WalletImportCmd::PrivateKey {
                    alias,
                    private_key,
                    set_default,
                } => {
                    let imported = signer::import_private_key(alias, private_key, set_default)?;
                    Ok(success(
                        "wallet private key imported",
                        serde_json::to_value(imported)?,
                    ))
                }
                WalletImportCmd::Mnemonic {
                    alias,
                    mnemonic,
                    set_default,
                } => {
                    let imported = signer::import_mnemonic(alias, mnemonic, set_default)?;
                    Ok(success(
                        "wallet mnemonic imported",
                        serde_json::to_value(imported)?,
                    ))
                }
                WalletImportCmd::Keystore {
                    alias,
                    keystore,
                    password,
                    set_default,
                } => {
                    let imported =
                        signer::import_keystore(alias, keystore.as_path(), password, set_default)?;
                    Ok(success(
                        "wallet keystore imported",
                        serde_json::to_value(imported)?,
                    ))
                }
            },
            WalletCmd::Address { alias } => {
                let address = signer::wallet_address(alias)?;
                Ok(success(
                    "wallet address loaded",
                    serde_json::to_value(address)?,
                ))
            }
            WalletCmd::Balance {
                alias,
                rpc_url,
                chain_id,
            } => {
                let balance = signer::wallet_balance(alias, &rpc_url, chain_id)?;
                Ok(success(
                    "wallet balance loaded",
                    serde_json::to_value(balance)?,
                ))
            }
            WalletCmd::Send {
                alias,
                rpc_url,
                chain_id,
                to,
                value_wei,
            } => {
                let sent = signer::wallet_send(alias, &rpc_url, chain_id, &to, &value_wei)?;
                Ok(success(
                    "wallet transaction submitted",
                    serde_json::to_value(sent)?,
                ))
            }
        },
        Commands::Run { command } => match command {
            RunCmd::Launch {
                node,
                run_id,
                backend,
                route_mode,
                net_cap_ticket,
                allow_direct_fallback,
                net_probe_url,
                workflow_ref,
                allow_cold_start,
                agent_image,
                agent_step,
                dry_run,
                max_attempts,
                timeout_secs,
            } => {
                let backend_core = to_backend(backend);
                let route_mode_core = to_route_mode(route_mode);
                let net_cap = net_cap::evaluate_route_policy(
                    &route_mode_core,
                    net_cap_ticket.as_deref(),
                    allow_direct_fallback,
                    &net_probe_url,
                )?;
                let workflow_ref =
                    workflow_ref.or_else(|| load_config().ok().and_then(|c| c.workflow_ref));
                let spec = RunSpec {
                    run_id: run_id.unwrap_or_else(|| format!("run-{}", sanitize(&node))),
                    node,
                    backend: backend_core.clone(),
                    route_mode: route_mode_core,
                    workflow_ref,
                };

                if matches!(backend_core, Backend::Local) {
                    let artifacts = local_engine()?.launch(&spec, allow_cold_start)?;
                    return Ok(success(
                        "local launch completed",
                        json!({ "artifacts": artifacts, "net_cap": net_cap }),
                    ));
                }

                if matches!(backend_core, Backend::Github) {
                    let policy = gh_policy(max_attempts, timeout_secs);
                    let dispatched = github_backend::dispatch_run_with_policy(
                        &cwd()?,
                        &spec,
                        allow_cold_start,
                        agent_image.as_deref().unwrap_or(DEFAULT_AGENT_IMAGE),
                        agent_step.as_deref().unwrap_or(DEFAULT_AGENT_STEP),
                        dry_run,
                        &policy,
                    )?;
                    return Ok(success(
                        "github launch dispatch prepared",
                        json!({ "dispatch": dispatched, "net_cap": net_cap }),
                    ));
                }

                Ok(success(
                    "gitlab launch scaffold",
                    json!({
                        "run_spec": spec,
                        "net_cap": net_cap,
                        "note": "GitLab execution lands in M5"
                    }),
                ))
            }
            RunCmd::Resume {
                node,
                run_id,
                backend,
                route_mode,
                net_cap_ticket,
                allow_direct_fallback,
                net_probe_url,
                workflow_ref,
                allow_cold_start,
                agent_image,
                agent_step,
                dry_run,
                max_attempts,
                timeout_secs,
            } => {
                let backend_core = to_backend(backend);
                let route_mode_core = to_route_mode(route_mode);
                let net_cap = net_cap::evaluate_route_policy(
                    &route_mode_core,
                    net_cap_ticket.as_deref(),
                    allow_direct_fallback,
                    &net_probe_url,
                )?;
                let workflow_ref =
                    workflow_ref.or_else(|| load_config().ok().and_then(|c| c.workflow_ref));
                let spec = RunSpec {
                    run_id: run_id.unwrap_or_else(|| format!("resume-{}", sanitize(&node))),
                    node,
                    backend: backend_core.clone(),
                    route_mode: route_mode_core,
                    workflow_ref,
                };

                if matches!(backend_core, Backend::Local) {
                    let artifacts = local_engine()?.resume(&spec, allow_cold_start)?;
                    return Ok(success(
                        "local resume completed",
                        json!({ "artifacts": artifacts, "net_cap": net_cap }),
                    ));
                }

                if matches!(backend_core, Backend::Github) {
                    let policy = gh_policy(max_attempts, timeout_secs);
                    let dispatched = github_backend::dispatch_run_with_policy(
                        &cwd()?,
                        &spec,
                        allow_cold_start,
                        agent_image.as_deref().unwrap_or(DEFAULT_AGENT_IMAGE),
                        agent_step.as_deref().unwrap_or(DEFAULT_AGENT_STEP),
                        dry_run,
                        &policy,
                    )?;
                    return Ok(success(
                        "github resume dispatch prepared",
                        json!({ "dispatch": dispatched, "net_cap": net_cap }),
                    ));
                }

                Ok(success(
                    "gitlab resume scaffold",
                    json!({
                        "run_spec": spec,
                        "net_cap": net_cap,
                        "note": "GitLab execution lands in M5"
                    }),
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
                if let Ok(result) = local_engine()?.load_run_result(&run_id) {
                    return Ok(success("local run status loaded", result));
                }

                let result = github_backend::load_github_run_status(&cwd()?, &run_id)?;
                Ok(success("github run status loaded", result))
            }
            RunCmd::Logs { run_id, follow } => {
                let local_hint = local_engine()?.logs_hint(&run_id);
                let github_hint = github_backend::logs_hint(&cwd()?, &run_id);
                Ok(success(
                    "log hints",
                    json!({ "follow": follow, "local": local_hint, "github": github_hint }),
                ))
            }
            RunCmd::Cancel {
                run_id,
                gh_run_id,
                dry_run,
                max_attempts,
                timeout_secs,
            } => {
                let canceled = github_backend::cancel_run(
                    &cwd()?,
                    &run_id,
                    gh_run_id,
                    dry_run,
                    &gh_policy(max_attempts, timeout_secs),
                )?;
                Ok(success(
                    "github cancel handled",
                    serde_json::to_value(canceled)?,
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
            StateCmd::Fork { state_cap } => {
                let capability = CapabilityEnvelope::decode(&state_cap)
                    .map_err(|err| anyhow!("INVALID_STATE_CAP: {err}"))?;
                Ok(success(
                    "state fork by raw token is not implemented yet",
                    json!({
                        "state_cap": capability.redacted(),
                        "state_cap_ref": redact_capability_token(&state_cap)
                    }),
                ))
            }
        },
        Commands::Verify { command } => match command {
            VerifyCmd::Cert {
                certificate,
                expected_artifact_hash,
                required_commit,
                attestation,
                policy_file,
                require_policy,
            } => {
                let cert = verify_certificate_file_with_policy(
                    &certificate,
                    &expected_artifact_hash,
                    &required_commit,
                    policy_file.as_deref(),
                    require_policy,
                )
                .map_err(|err| anyhow!("VERIFY_CERT_FAILED: {err}"))?;
                Ok(success(
                    "certificate verification passed",
                    json!({
                        "certificate_path": certificate,
                        "attestation": attestation,
                        "policy_file": policy_file,
                        "require_policy": require_policy,
                        "certificate": cert
                    }),
                ))
            }
            VerifyCmd::Proof {
                proof,
                public_inputs,
            } => {
                let verified = verify_proof_file(&proof, &public_inputs)
                    .map_err(|err| anyhow!("VERIFY_PROOF_FAILED: {err}"))?;
                Ok(success(
                    "proof verification passed",
                    json!({ "proof": proof, "public_inputs": public_inputs, "verified": verified }),
                ))
            }
        },
        Commands::Backend { command } => match command {
            BackendCmd::Github { command } => match command {
                GithubBackendCmd::Dispatch {
                    run_id,
                    workflow_ref,
                    route_mode,
                    net_cap_ticket,
                    allow_direct_fallback,
                    net_probe_url,
                    allow_cold_start,
                    agent_image,
                    agent_step,
                    dry_run,
                    max_attempts,
                    timeout_secs,
                } => {
                    let route_mode_core = to_route_mode(route_mode);
                    let net_cap = net_cap::evaluate_route_policy(
                        &route_mode_core,
                        net_cap_ticket.as_deref(),
                        allow_direct_fallback,
                        &net_probe_url,
                    )?;
                    let spec = RunSpec {
                        run_id,
                        node: "root".to_string(),
                        backend: Backend::Github,
                        route_mode: route_mode_core,
                        workflow_ref: Some(workflow_ref),
                    };
                    let dispatched = github_backend::dispatch_run_with_policy(
                        &cwd()?,
                        &spec,
                        allow_cold_start,
                        &agent_image,
                        &agent_step,
                        dry_run,
                        &gh_policy(max_attempts, timeout_secs),
                    )?;
                    Ok(success(
                        "github dispatch handled",
                        json!({ "dispatch": dispatched, "net_cap": net_cap }),
                    ))
                }
                GithubBackendCmd::Collect {
                    run_id,
                    gh_run_id,
                    workflow_ref,
                    out_dir,
                    dry_run,
                    skip_verify_cert,
                    require_policy,
                    max_attempts,
                    timeout_secs,
                } => {
                    let collected = github_backend::collect_run_with_policy_and_verify(
                        &cwd()?,
                        &run_id,
                        gh_run_id,
                        workflow_ref.as_deref(),
                        out_dir.as_deref(),
                        dry_run,
                        &gh_policy(max_attempts, timeout_secs),
                        !skip_verify_cert,
                        require_policy,
                    )?;
                    Ok(success(
                        "github collect handled",
                        serde_json::to_value(collected)?,
                    ))
                }
                GithubBackendCmd::Cancel {
                    run_id,
                    gh_run_id,
                    dry_run,
                    max_attempts,
                    timeout_secs,
                } => {
                    let canceled = github_backend::cancel_run(
                        &cwd()?,
                        &run_id,
                        gh_run_id,
                        dry_run,
                        &gh_policy(max_attempts, timeout_secs),
                    )?;
                    Ok(success(
                        "github cancel handled",
                        serde_json::to_value(canceled)?,
                    ))
                }
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
                let mut errors = schema_check.errors.clone();
                if !file.exists() {
                    errors.push(format!("file does not exist: {}", file.display()));
                } else {
                    match fs::read_to_string(&file) {
                        Ok(contents) => match serde_json::from_str::<Value>(&contents) {
                            Ok(value) => {
                                let value_check = validate_schema_value(&schema, &value);
                                errors.extend(value_check.errors);
                            }
                            Err(err) => {
                                errors.push(format!("invalid JSON in {}: {err}", file.display()))
                            }
                        },
                        Err(err) => {
                            errors.push(format!("failed to read {}: {err}", file.display()))
                        }
                    }
                }
                let valid = schema_check.valid && errors.is_empty();
                if !valid {
                    return Err(anyhow!(
                        "SCHEMA_VALIDATE_FAILED: schema={} file={} errors={}",
                        schema,
                        file.display(),
                        errors.join(" | ")
                    ));
                }
                Ok(success(
                    "schema validation passed",
                    json!({
                        "schema": schema,
                        "file": file,
                        "valid": true,
                        "errors": [],
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
                        "10-implementation-backlog.md",
                        "12-m1-quickstart.md"
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

fn render_error(err: &anyhow::Error, json_output: bool, code: i32) {
    if json_output {
        if let Some(backend_err) = err.downcast_ref::<github_backend::GithubBackendError>() {
            let payload = json!({
                "status": "error",
                "code": code,
                "error": backend_err.info(),
                "message": err.to_string(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
            );
            return;
        }
        let payload = json!({
            "status": "error",
            "code": code,
            "message": err.to_string(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string())
        );
    } else {
        eprintln!("error: {err}");
    }
}

fn classify_exit_code(err: &anyhow::Error) -> i32 {
    if let Some(backend_err) = err.downcast_ref::<github_backend::GithubBackendError>() {
        return match backend_err.info().category.as_str() {
            "validation" => EXIT_INVALID_INPUT,
            "compatibility" => EXIT_RESTORE_FAILURE,
            "policy" => EXIT_POLICY_VIOLATION,
            "dispatch" | "collect" | "cancel" | "dependency" | "timeout" | "artifact" => {
                EXIT_BACKEND_FAILURE
            }
            _ => 1,
        };
    }

    let msg = err.to_string();
    if msg.starts_with("VERIFY_CERT_FAILED:") || msg.starts_with("VERIFY_PROOF_FAILED:") {
        EXIT_VERIFICATION_FAILED
    } else if msg.starts_with("NET_CAP_POLICY_VIOLATION:") {
        EXIT_POLICY_VIOLATION
    } else if msg.starts_with("SCHEMA_VALIDATE_FAILED:")
        || msg.starts_with("INVALID_STATE_CAP:")
        || msg.starts_with("WALLET_")
        || msg.contains("unsupported key")
    {
        EXIT_INVALID_INPUT
    } else {
        1
    }
}

fn config_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME is not set"))?;
    Ok(Path::new(&home).join(".swarm").join("config.json"))
}

fn local_engine() -> Result<LocalEngine> {
    let cwd = std::env::current_dir()?;
    Ok(LocalEngine::new(cwd.join(".swarm").join("local")))
}

fn cwd() -> Result<PathBuf> {
    Ok(std::env::current_dir()?)
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

fn gh_policy(max_attempts: u32, timeout_secs: u64) -> github_backend::GhCommandPolicy {
    github_backend::GhCommandPolicy {
        max_attempts,
        timeout_secs,
        retry_backoff_ms: 250,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn schema_validate_invalid_returns_error() {
        let tmp = TempDir::new().expect("temp dir");
        let existing_file = tmp.path().join("x.json");
        fs::write(&existing_file, "{}").expect("write fixture file");

        let cli = Cli {
            json: true,
            quiet: false,
            verbose: 0,
            command: Commands::Schema {
                command: SchemaCmd::Validate {
                    schema: "banana".to_string(),
                    file: existing_file,
                },
            },
        };

        let err = execute(cli).expect_err("invalid schema should be an error");
        assert!(err.to_string().starts_with("SCHEMA_VALIDATE_FAILED:"));
        assert_eq!(classify_exit_code(&err), EXIT_INVALID_INPUT);
    }

    #[test]
    fn net_cap_policy_violation_maps_to_policy_exit_code() {
        let err = anyhow!("NET_CAP_POLICY_VIOLATION: route policy mismatch");
        assert_eq!(classify_exit_code(&err), EXIT_POLICY_VIOLATION);
    }

    #[test]
    fn verify_proof_failure_maps_to_verification_exit_code() {
        let err = anyhow!("VERIFY_PROOF_FAILED: invalid proof");
        assert_eq!(classify_exit_code(&err), EXIT_VERIFICATION_FAILED);
    }

    #[test]
    fn wallet_errors_map_to_invalid_input_exit_code() {
        let err = anyhow!("WALLET_CHAIN_MISMATCH: expected chain id mismatch");
        assert_eq!(classify_exit_code(&err), EXIT_INVALID_INPUT);
    }

    #[test]
    fn invalid_state_cap_maps_to_invalid_input_exit_code() {
        let cli = Cli {
            json: true,
            quiet: false,
            verbose: 0,
            command: Commands::State {
                command: StateCmd::Fork {
                    state_cap: "not-a-capability-token".to_string(),
                },
            },
        };
        let err = execute(cli).expect_err("invalid state_cap should fail");
        assert!(err.to_string().starts_with("INVALID_STATE_CAP:"));
        assert_eq!(classify_exit_code(&err), EXIT_INVALID_INPUT);
    }

    #[test]
    fn schema_validate_rejects_invalid_json_payload() {
        let tmp = TempDir::new().expect("temp dir");
        let payload = tmp.path().join("bad.json");
        fs::write(&payload, "{\"run_id\":\"x\"").expect("write malformed json");

        let cli = Cli {
            json: true,
            quiet: false,
            verbose: 0,
            command: Commands::Schema {
                command: SchemaCmd::Validate {
                    schema: "result".to_string(),
                    file: payload,
                },
            },
        };

        let err = execute(cli).expect_err("malformed JSON must fail schema validation");
        assert!(err.to_string().contains("invalid JSON"));
        assert_eq!(classify_exit_code(&err), EXIT_INVALID_INPUT);
    }

    #[test]
    fn schema_validate_rejects_shape_mismatch_payload() {
        let tmp = TempDir::new().expect("temp dir");
        let payload = tmp.path().join("bad-shape.json");
        fs::write(
            &payload,
            serde_json::to_vec_pretty(&json!({
                "run_id": "run-fixture-1",
                "status": "succeeded",
                "operation": "launch",
                "node_id": "node-1",
                "parent_node_id": null,
                "state_id": "state-1",
                "restore_mode": "checkpoint",
                "bundle_ref": "local://bundle",
                "bundle_sha256": "sha256:abcd",
                "certificate_ref": "",
                "artifact_hash": "sha256:ef01"
            }))
            .expect("serialize"),
        )
        .expect("write payload");

        let cli = Cli {
            json: true,
            quiet: false,
            verbose: 0,
            command: Commands::Schema {
                command: SchemaCmd::Validate {
                    schema: "result".to_string(),
                    file: payload,
                },
            },
        };

        let err = execute(cli).expect_err("shape mismatch must fail schema validation");
        assert!(
            err.to_string()
                .contains("certificate_ref must be a non-empty string")
        );
        assert_eq!(classify_exit_code(&err), EXIT_INVALID_INPUT);
    }
}
