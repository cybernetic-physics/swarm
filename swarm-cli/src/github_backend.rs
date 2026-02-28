use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::error::Error;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use swarm_core::{RouteMode, RunSpec};
use swarm_verify::verify_certificate_file_with_policy;

pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;
pub const DEFAULT_TIMEOUT_SECS: u64 = 45;
const DEFAULT_RETRY_BACKOFF_MS: u64 = 250;

fn default_max_attempts() -> u32 {
    DEFAULT_MAX_ATTEMPTS
}

fn default_timeout_secs() -> u64 {
    DEFAULT_TIMEOUT_SECS
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GithubErrorInfo {
    pub code: String,
    pub category: String,
    pub retryable: bool,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct GithubBackendError {
    info: GithubErrorInfo,
}

impl GithubBackendError {
    pub fn validation(code: &str, message: impl Into<String>) -> Self {
        Self::new(code, "validation", false, message)
    }

    pub fn dependency(code: &str, message: impl Into<String>) -> Self {
        Self::new(code, "dependency", false, message)
    }

    pub fn dispatch(code: &str, retryable: bool, message: impl Into<String>) -> Self {
        Self::new(code, "dispatch", retryable, message)
    }

    pub fn collect(code: &str, retryable: bool, message: impl Into<String>) -> Self {
        Self::new(code, "collect", retryable, message)
    }

    pub fn cancel(code: &str, retryable: bool, message: impl Into<String>) -> Self {
        Self::new(code, "cancel", retryable, message)
    }

    pub fn artifact(code: &str, message: impl Into<String>) -> Self {
        Self::new(code, "artifact", false, message)
    }

    pub fn compatibility(code: &str, message: impl Into<String>) -> Self {
        Self::new(code, "compatibility", false, message)
    }

    pub fn timeout(code: &str, retryable: bool, message: impl Into<String>) -> Self {
        Self::new(code, "timeout", retryable, message)
    }

    fn new(code: &str, category: &str, retryable: bool, message: impl Into<String>) -> Self {
        Self {
            info: GithubErrorInfo {
                code: code.to_string(),
                category: category.to_string(),
                retryable,
                message: message.into(),
            },
        }
    }

    pub fn info(&self) -> &GithubErrorInfo {
        &self.info
    }
}

impl fmt::Display for GithubBackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}:{}] {}",
            self.info.category, self.info.code, self.info.message
        )
    }
}

impl Error for GithubBackendError {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhCommandPolicy {
    pub max_attempts: u32,
    pub timeout_secs: u64,
    pub retry_backoff_ms: u64,
}

#[derive(Debug, Clone)]
struct DispatchOptions<'a> {
    allow_cold_start: bool,
    agent_image: &'a str,
    agent_step: &'a str,
    dry_run: bool,
    policy: &'a GhCommandPolicy,
    gh_binary: &'a Path,
    dispatch_inputs: DispatchInputOverrides,
}

#[derive(Debug, Clone)]
struct CollectOptions<'a> {
    workflow_ref: Option<&'a str>,
    out_dir: Option<&'a Path>,
    dry_run: bool,
    policy: &'a GhCommandPolicy,
    gh_binary: &'a Path,
    verify_certificate: bool,
    require_policy: bool,
}

#[derive(Debug, Clone, Default)]
struct DispatchInputOverrides {
    checkpoint_in: Option<String>,
    state_cap_in: Option<String>,
    net_cap_in: Option<String>,
}

impl DispatchInputOverrides {
    fn from_env() -> Self {
        Self {
            checkpoint_in: dispatch_input_override("SWARM_CHECKPOINT_IN"),
            state_cap_in: dispatch_input_override("SWARM_STATE_CAP_IN"),
            net_cap_in: dispatch_input_override("SWARM_NET_CAP_IN"),
        }
    }
}

impl Default for GhCommandPolicy {
    fn default() -> Self {
        Self {
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            retry_backoff_ms: DEFAULT_RETRY_BACKOFF_MS,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubWorkflowRef {
    pub owner: String,
    pub repo: String,
    pub workflow_path: String,
    pub workflow_file: String,
    pub commit_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GithubRunLedger {
    pub run_id: String,
    pub workflow_ref: String,
    pub owner_repo: String,
    pub workflow_file: String,
    pub commit_sha: String,
    #[serde(default)]
    pub dispatch_ref: Option<String>,
    pub route_mode: String,
    pub fallback_policy: String,
    pub dispatched: bool,
    pub dispatch_mode: String,
    pub gh_run_id: Option<u64>,
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub canceled: bool,
    #[serde(default)]
    pub last_error: Option<GithubErrorInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DispatchResult {
    pub run_id: String,
    pub owner_repo: String,
    pub workflow_file: String,
    pub commit_sha: String,
    pub dispatched: bool,
    pub dry_run: bool,
    pub ledger_ref: String,
    pub command_preview: Vec<String>,
    pub attempts_used: u32,
    pub policy: GhCommandPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectResult {
    pub run_id: String,
    pub owner_repo: String,
    pub gh_run_id: u64,
    pub downloaded_to: String,
    pub result_ref: Option<String>,
    pub next_tokens_ref: Option<String>,
    pub restore_mode: Option<String>,
    pub compatibility_ok: bool,
    pub compatibility_reason: String,
    pub certificate_ref: Option<String>,
    pub policy_ref: Option<String>,
    pub verification_ok: bool,
    pub verification_reason: String,
    pub artifact_report: ArtifactReport,
    pub errors: Vec<GithubErrorInfo>,
    pub attempts_used: u32,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactReport {
    pub required: Vec<String>,
    pub found: Vec<String>,
    pub missing: Vec<String>,
}

impl ArtifactReport {
    fn required_defaults() -> Vec<String> {
        vec!["result.json".to_string(), "next_tokens.json".to_string()]
    }

    fn empty() -> Self {
        Self {
            required: Self::required_defaults(),
            found: vec![],
            missing: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelResult {
    pub run_id: String,
    pub owner_repo: String,
    pub gh_run_id: u64,
    pub canceled: bool,
    pub dry_run: bool,
    pub command_preview: Vec<String>,
    pub attempts_used: u32,
    pub policy: GhCommandPolicy,
}

pub fn parse_workflow_ref(workflow_ref: &str) -> Result<GithubWorkflowRef> {
    let (lhs, commit_sha) = workflow_ref.rsplit_once('@').ok_or_else(|| {
        anyhow!(GithubBackendError::validation(
            "WORKFLOW_REF_INVALID",
            "workflow_ref must contain '@<commit_sha>'",
        ))
    })?;

    if !is_hex_40(commit_sha) {
        return Err(anyhow!(GithubBackendError::validation(
            "WORKFLOW_REF_UNPINNED",
            format!("commit_sha must be a pinned 40-hex value, got '{commit_sha}'"),
        )));
    }

    let mut parts = lhs.split('/');
    let owner = parts.next().ok_or_else(|| {
        anyhow!(GithubBackendError::validation(
            "WORKFLOW_REF_INVALID",
            "workflow_ref missing owner",
        ))
    })?;
    let repo = parts.next().ok_or_else(|| {
        anyhow!(GithubBackendError::validation(
            "WORKFLOW_REF_INVALID",
            "workflow_ref missing repo",
        ))
    })?;
    if owner.trim().is_empty() || repo.trim().is_empty() {
        return Err(anyhow!(GithubBackendError::validation(
            "WORKFLOW_REF_INVALID",
            "workflow_ref owner/repo segments must be non-empty",
        )));
    }
    let workflow_path = parts.collect::<Vec<_>>().join("/");
    if workflow_path.is_empty() {
        return Err(anyhow!(GithubBackendError::validation(
            "WORKFLOW_REF_INVALID",
            "workflow_ref missing workflow path",
        )));
    }
    let workflow_file = Path::new(&workflow_path)
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| {
            anyhow!(GithubBackendError::validation(
                "WORKFLOW_REF_INVALID",
                format!("failed to parse workflow filename from '{workflow_path}'"),
            ))
        })?
        .to_string();

    Ok(GithubWorkflowRef {
        owner: owner.to_string(),
        repo: repo.to_string(),
        workflow_path,
        workflow_file,
        commit_sha: commit_sha.to_string(),
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn dispatch_run(
    cwd: &Path,
    spec: &RunSpec,
    allow_cold_start: bool,
    agent_image: &str,
    agent_step: &str,
    dry_run: bool,
) -> Result<DispatchResult> {
    dispatch_run_with_policy(
        cwd,
        spec,
        allow_cold_start,
        agent_image,
        agent_step,
        dry_run,
        &GhCommandPolicy::default(),
    )
}

pub fn dispatch_run_with_policy(
    cwd: &Path,
    spec: &RunSpec,
    allow_cold_start: bool,
    agent_image: &str,
    agent_step: &str,
    dry_run: bool,
    policy: &GhCommandPolicy,
) -> Result<DispatchResult> {
    let options = DispatchOptions {
        allow_cold_start,
        agent_image,
        agent_step,
        dry_run,
        policy,
        gh_binary: Path::new("gh"),
        dispatch_inputs: DispatchInputOverrides::from_env(),
    };
    dispatch_run_internal(cwd, spec, &options)
}

fn dispatch_run_internal(
    cwd: &Path,
    spec: &RunSpec,
    options: &DispatchOptions<'_>,
) -> Result<DispatchResult> {
    let workflow_ref_raw = spec.workflow_ref.clone().ok_or_else(|| {
        anyhow!(GithubBackendError::validation(
            "WORKFLOW_REF_REQUIRED",
            "workflow_ref is required for github backend",
        ))
    })?;
    let wf = parse_workflow_ref(&workflow_ref_raw)?;

    let owner_repo = format!("{}/{}", wf.owner, wf.repo);
    let dispatch_ref = dispatch_ref();

    let endpoint = format!(
        "repos/{owner_repo}/actions/workflows/{}/dispatches",
        wf.workflow_file
    );
    let fallback_policy = if options.allow_cold_start {
        "allow_cold_start"
    } else {
        "fail_closed"
    };

    let mut cmd = vec![
        "api".to_string(),
        "--method".to_string(),
        "POST".to_string(),
        endpoint,
        "-f".to_string(),
        format!("ref={dispatch_ref}"),
        "-f".to_string(),
        format!("inputs[request_id]={}", spec.run_id),
        "-f".to_string(),
        format!("inputs[expected_commit_sha]={}", wf.commit_sha),
        "-f".to_string(),
        "inputs[source_backend]=artifact".to_string(),
        "-f".to_string(),
        "inputs[output_backend]=artifact".to_string(),
        "-f".to_string(),
        format!("inputs[agent_image]={}", options.agent_image),
        "-f".to_string(),
        format!("inputs[agent_step]={}", options.agent_step),
    ];

    match options.dispatch_inputs.checkpoint_in.as_deref() {
        Some(value) => {
            cmd.push("-f".to_string());
            cmd.push(format!("inputs[checkpoint_in]={value}"));
        }
        None if options.allow_cold_start => {
            cmd.push("-f".to_string());
            cmd.push("inputs[checkpoint_in]=".to_string());
        }
        None => {}
    }

    if let Some(value) = options.dispatch_inputs.state_cap_in.as_deref() {
        cmd.push("-f".to_string());
        cmd.push(format!("inputs[state_cap_in]={value}"));
    }

    if let Some(value) = options.dispatch_inputs.net_cap_in.as_deref() {
        cmd.push("-f".to_string());
        cmd.push(format!("inputs[net_cap_in]={value}"));
    }

    let attempts_used = if options.dry_run {
        0
    } else {
        run_gh_command_with_policy(
            cwd,
            options.gh_binary,
            &cmd,
            options.policy,
            GhOperation::Dispatch,
        )?
    };

    let ledger = GithubRunLedger {
        run_id: spec.run_id.clone(),
        workflow_ref: workflow_ref_raw,
        owner_repo: owner_repo.clone(),
        workflow_file: wf.workflow_file.clone(),
        commit_sha: wf.commit_sha.clone(),
        dispatch_ref: Some(dispatch_ref),
        route_mode: route_mode_str(&spec.route_mode).to_string(),
        fallback_policy: fallback_policy.to_string(),
        dispatched: !options.dry_run,
        dispatch_mode: if options.dry_run {
            "dry_run".to_string()
        } else {
            "live".to_string()
        },
        gh_run_id: None,
        max_attempts: normalized_policy(options.policy).max_attempts,
        timeout_secs: normalized_policy(options.policy).timeout_secs,
        canceled: false,
        last_error: None,
    };

    let ledger_path = github_ledger_path(cwd, &spec.run_id);
    write_json(&ledger_path, &ledger)?;

    Ok(DispatchResult {
        run_id: spec.run_id.clone(),
        owner_repo,
        workflow_file: wf.workflow_file,
        commit_sha: wf.commit_sha,
        dispatched: !options.dry_run,
        dry_run: options.dry_run,
        ledger_ref: local_ref(cwd, &ledger_path),
        command_preview: with_gh_prefix(options.gh_binary, &cmd),
        attempts_used,
        policy: normalized_policy(options.policy),
    })
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn collect_run(
    cwd: &Path,
    run_id: &str,
    gh_run_id: u64,
    workflow_ref: Option<&str>,
    out_dir: Option<&Path>,
    dry_run: bool,
) -> Result<CollectResult> {
    collect_run_with_policy_and_verify(
        cwd,
        run_id,
        gh_run_id,
        workflow_ref,
        out_dir,
        dry_run,
        &GhCommandPolicy::default(),
        true,
        true,
    )
}

#[allow(dead_code)]
pub fn collect_run_with_policy(
    cwd: &Path,
    run_id: &str,
    gh_run_id: u64,
    workflow_ref: Option<&str>,
    out_dir: Option<&Path>,
    dry_run: bool,
    policy: &GhCommandPolicy,
) -> Result<CollectResult> {
    collect_run_with_policy_and_verify(
        cwd,
        run_id,
        gh_run_id,
        workflow_ref,
        out_dir,
        dry_run,
        policy,
        true,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn collect_run_with_policy_and_verify(
    cwd: &Path,
    run_id: &str,
    gh_run_id: u64,
    workflow_ref: Option<&str>,
    out_dir: Option<&Path>,
    dry_run: bool,
    policy: &GhCommandPolicy,
    verify_certificate: bool,
    require_policy: bool,
) -> Result<CollectResult> {
    let options = CollectOptions {
        workflow_ref,
        out_dir,
        dry_run,
        policy,
        gh_binary: Path::new("gh"),
        verify_certificate,
        require_policy,
    };
    collect_run_internal(cwd, run_id, gh_run_id, &options)
}

fn collect_run_internal(
    cwd: &Path,
    run_id: &str,
    gh_run_id: u64,
    options: &CollectOptions<'_>,
) -> Result<CollectResult> {
    let policy = normalized_policy(options.policy);
    let mut ledger = load_or_seed_ledger(cwd, run_id, options.workflow_ref)?;
    ledger.gh_run_id = Some(gh_run_id);
    ledger.max_attempts = policy.max_attempts;
    ledger.timeout_secs = policy.timeout_secs;
    ledger.canceled = false;
    ledger.last_error = None;

    let download_dir = options.out_dir.map(Path::to_path_buf).unwrap_or_else(|| {
        cwd.join(".swarm")
            .join("github")
            .join("collect")
            .join(run_id)
    });
    fs::create_dir_all(&download_dir)?;

    let mut result_ref = None;
    let mut next_tokens_ref = None;
    let mut restore_mode = None;
    let mut compatibility_ok = true;
    let mut compatibility_reason = "ok".to_string();
    let mut certificate_ref = None;
    let mut policy_ref = None;
    let mut verification_ok = !options.verify_certificate || options.dry_run;
    let mut verification_reason = if options.dry_run {
        "skipped in dry_run mode".to_string()
    } else if options.verify_certificate {
        "pending".to_string()
    } else {
        "disabled by collect option".to_string()
    };
    let mut expected_artifact_hash: Option<String> = None;
    let mut errors: Vec<GithubErrorInfo> = vec![];
    let mut artifact_report = ArtifactReport::empty();
    if options.verify_certificate {
        artifact_report
            .required
            .push("certificate.json".to_string());
        if options.require_policy {
            artifact_report.required.push("policy.json".to_string());
        }
    }
    let mut attempts_used = 0;

    let cmd = vec![
        "run".to_string(),
        "download".to_string(),
        gh_run_id.to_string(),
        "-R".to_string(),
        ledger.owner_repo.clone(),
        "-D".to_string(),
        download_dir.display().to_string(),
    ];

    if !options.dry_run {
        attempts_used = match run_gh_command_with_policy(
            cwd,
            options.gh_binary,
            &cmd,
            &policy,
            GhOperation::Collect,
        ) {
            Ok(attempts) => attempts,
            Err(err) => {
                ledger.last_error = backend_error_info_from_anyhow(&err);
                write_json(&github_ledger_path(cwd, run_id), &ledger)?;
                return Err(err);
            }
        };

        let result_path = find_first_file_named(&download_dir, "result.json");
        let next_tokens_path = find_first_file_named(&download_dir, "next_tokens.json");
        let mut missing = vec![];
        if result_path.is_some() {
            artifact_report.found.push("result.json".to_string());
        } else {
            missing.push("result.json".to_string());
            errors.push(
                GithubBackendError::artifact(
                    "ARTIFACT_MISSING_RESULT",
                    "required artifact result.json is missing",
                )
                .info()
                .clone(),
            );
        }
        if next_tokens_path.is_some() {
            artifact_report.found.push("next_tokens.json".to_string());
        } else {
            missing.push("next_tokens.json".to_string());
            errors.push(
                GithubBackendError::artifact(
                    "ARTIFACT_MISSING_NEXT_TOKENS",
                    "required artifact next_tokens.json is missing",
                )
                .info()
                .clone(),
            );
        }
        artifact_report.missing = missing;

        if let Some(path) = &result_path {
            let result_json: Result<Value> = read_json(path).map_err(|err| {
                anyhow!(GithubBackendError::artifact(
                    "ARTIFACT_RESULT_PARSE_FAILED",
                    format!("failed to parse result.json: {err}"),
                ))
            });
            match result_json.and_then(|value| {
                validate_result_artifact(&value)?;
                Ok(value)
            }) {
                Ok(result_json) => {
                    restore_mode = result_json
                        .get("restore_mode")
                        .and_then(Value::as_str)
                        .map(ToString::to_string);
                    if options.verify_certificate {
                        match require_string_field(
                            &result_json,
                            "artifact_hash",
                            "ARTIFACT_RESULT_SCHEMA_INVALID",
                        ) {
                            Ok(value) => expected_artifact_hash = Some(value.to_string()),
                            Err(err) => {
                                if let Some(info) = backend_error_info_from_anyhow(&err) {
                                    errors.push(info);
                                }
                            }
                        }
                    }

                    let local_run_dir = cwd.join(".swarm").join("local").join("runs").join(run_id);
                    fs::create_dir_all(&local_run_dir)?;
                    let dest = local_run_dir.join("result.json");
                    fs::copy(path, &dest)?;
                    result_ref = Some(local_ref(cwd, &dest));
                }
                Err(err) => {
                    if let Some(info) = backend_error_info_from_anyhow(&err) {
                        errors.push(info);
                    }
                }
            }
        }

        if let Some(path) = &next_tokens_path {
            let next_tokens_json: Result<Value> = read_json(path).map_err(|err| {
                anyhow!(GithubBackendError::artifact(
                    "ARTIFACT_NEXT_TOKENS_PARSE_FAILED",
                    format!("failed to parse next_tokens.json: {err}"),
                ))
            });
            match next_tokens_json.and_then(|value| {
                validate_next_tokens_artifact(&value)?;
                Ok(value)
            }) {
                Ok(_) => {
                    let local_run_dir = cwd.join(".swarm").join("local").join("runs").join(run_id);
                    fs::create_dir_all(&local_run_dir)?;
                    let dest = local_run_dir.join("next_tokens.json");
                    fs::copy(path, &dest)?;
                    next_tokens_ref = Some(local_ref(cwd, &dest));
                }
                Err(err) => {
                    if let Some(info) = backend_error_info_from_anyhow(&err) {
                        errors.push(info);
                    }
                }
            }
        }

        if let Some(mode) = restore_mode.as_deref() {
            if mode == "cold_start" && ledger.fallback_policy == "fail_closed" {
                compatibility_ok = false;
                compatibility_reason =
                    "restore_mode=cold_start violates fail_closed policy".to_string();
                errors.push(
                    GithubBackendError::compatibility(
                        "RESTORE_POLICY_VIOLATION",
                        compatibility_reason.clone(),
                    )
                    .info()
                    .clone(),
                );
            }
        }

        if options.verify_certificate {
            if errors.is_empty() {
                let certificate_path = find_first_file_named(&download_dir, "certificate.json");
                match certificate_path {
                    Some(path) => {
                        artifact_report.found.push("certificate.json".to_string());
                        let local_run_dir =
                            cwd.join(".swarm").join("local").join("runs").join(run_id);
                        fs::create_dir_all(&local_run_dir)?;

                        let cert_dest = local_run_dir.join("certificate.json");
                        fs::copy(path, &cert_dest)?;
                        certificate_ref = Some(local_ref(cwd, &cert_dest));

                        let policy_source = find_first_file_named(&download_dir, "policy.json");
                        let policy_dest = if let Some(policy_path) = policy_source {
                            artifact_report.found.push("policy.json".to_string());
                            let dest = local_run_dir.join("policy.json");
                            fs::copy(policy_path, &dest)?;
                            policy_ref = Some(local_ref(cwd, &dest));
                            Some(dest)
                        } else {
                            None
                        };

                        if options.require_policy && policy_dest.is_none() {
                            verification_ok = false;
                            verification_reason =
                                "required artifact policy.json is missing".to_string();
                            artifact_report.missing.push("policy.json".to_string());
                            errors.push(
                                GithubBackendError::artifact(
                                    "ARTIFACT_MISSING_POLICY",
                                    verification_reason.clone(),
                                )
                                .info()
                                .clone(),
                            );
                        } else if let Some(expected_hash) = expected_artifact_hash.as_deref() {
                            match verify_certificate_file_with_policy(
                                &cert_dest,
                                expected_hash,
                                &ledger.commit_sha,
                                policy_dest.as_deref(),
                                options.require_policy,
                            ) {
                                Ok(_) => {
                                    verification_ok = true;
                                    verification_reason = "ok".to_string();
                                }
                                Err(err) => {
                                    verification_ok = false;
                                    verification_reason = err.to_string();
                                    errors.push(
                                        GithubBackendError::artifact(
                                            "ARTIFACT_CERT_VERIFY_FAILED",
                                            format!("certificate verification failed: {err}"),
                                        )
                                        .info()
                                        .clone(),
                                    );
                                }
                            }
                        } else {
                            verification_ok = false;
                            verification_reason =
                                "result.json is missing artifact_hash required for verification"
                                    .to_string();
                            errors.push(
                                GithubBackendError::artifact(
                                    "ARTIFACT_RESULT_MISSING_HASH",
                                    verification_reason.clone(),
                                )
                                .info()
                                .clone(),
                            );
                        }
                    }
                    None => {
                        verification_ok = false;
                        verification_reason =
                            "required artifact certificate.json is missing".to_string();
                        artifact_report.missing.push("certificate.json".to_string());
                        errors.push(
                            GithubBackendError::artifact(
                                "ARTIFACT_MISSING_CERTIFICATE",
                                verification_reason.clone(),
                            )
                            .info()
                            .clone(),
                        );
                    }
                }
            } else {
                verification_ok = false;
                verification_reason =
                    "skipped due to earlier artifact validation failure".to_string();
            }
        }
    }

    ledger.last_error = errors.first().cloned();
    write_json(&github_ledger_path(cwd, run_id), &ledger)?;
    if let Some(first_error) = errors.first() {
        return Err(anyhow!(error_from_info(first_error)));
    }

    Ok(CollectResult {
        run_id: run_id.to_string(),
        owner_repo: ledger.owner_repo.clone(),
        gh_run_id,
        downloaded_to: download_dir.display().to_string(),
        result_ref,
        next_tokens_ref,
        restore_mode,
        compatibility_ok,
        compatibility_reason,
        certificate_ref,
        policy_ref,
        verification_ok,
        verification_reason,
        artifact_report,
        errors,
        attempts_used,
        dry_run: options.dry_run,
    })
}

pub fn cancel_run(
    cwd: &Path,
    run_id: &str,
    gh_run_id: Option<u64>,
    dry_run: bool,
    policy: &GhCommandPolicy,
) -> Result<CancelResult> {
    cancel_run_internal(cwd, run_id, gh_run_id, dry_run, policy, Path::new("gh"))
}

fn cancel_run_internal(
    cwd: &Path,
    run_id: &str,
    gh_run_id: Option<u64>,
    dry_run: bool,
    policy: &GhCommandPolicy,
    gh_binary: &Path,
) -> Result<CancelResult> {
    let policy = normalized_policy(policy);
    let mut ledger: GithubRunLedger =
        read_json(&github_ledger_path(cwd, run_id)).map_err(|err| {
            anyhow!(GithubBackendError::validation(
                "RUN_LEDGER_MISSING",
                format!("run ledger missing for run_id={run_id}: {err}"),
            ))
        })?;
    let gh_run_id = gh_run_id.or(ledger.gh_run_id).ok_or_else(|| {
        anyhow!(GithubBackendError::validation(
            "GH_RUN_ID_REQUIRED",
            "gh_run_id is required (provide --gh-run-id or collect first)",
        ))
    })?;
    ledger.gh_run_id = Some(gh_run_id);

    let cmd = vec![
        "run".to_string(),
        "cancel".to_string(),
        gh_run_id.to_string(),
        "-R".to_string(),
        ledger.owner_repo.clone(),
    ];
    let attempts_used = if dry_run {
        0
    } else {
        run_gh_command_with_policy(cwd, gh_binary, &cmd, &policy, GhOperation::Cancel)?
    };
    if !dry_run {
        ledger.canceled = true;
    }
    ledger.max_attempts = policy.max_attempts;
    ledger.timeout_secs = policy.timeout_secs;
    ledger.last_error = None;
    write_json(&github_ledger_path(cwd, run_id), &ledger)?;

    Ok(CancelResult {
        run_id: run_id.to_string(),
        owner_repo: ledger.owner_repo,
        gh_run_id,
        canceled: !dry_run,
        dry_run,
        command_preview: with_gh_prefix(gh_binary, &cmd),
        attempts_used,
        policy,
    })
}

pub fn load_github_run_status(cwd: &Path, run_id: &str) -> Result<Value> {
    let result_path = cwd
        .join(".swarm")
        .join("local")
        .join("runs")
        .join(run_id)
        .join("result.json");
    if result_path.exists() {
        return read_json(&result_path);
    }

    let ledger = read_json::<GithubRunLedger>(&github_ledger_path(cwd, run_id))?;
    Ok(json!({
        "run_id": run_id,
        "status": if ledger.canceled { "canceled" } else if ledger.dispatched { "dispatched" } else { "prepared" },
        "owner_repo": ledger.owner_repo,
        "workflow_file": ledger.workflow_file,
        "commit_sha": ledger.commit_sha,
        "gh_run_id": ledger.gh_run_id,
        "fallback_policy": ledger.fallback_policy,
        "max_attempts": ledger.max_attempts,
        "timeout_secs": ledger.timeout_secs,
        "last_error": ledger.last_error
    }))
}

pub fn logs_hint(cwd: &Path, run_id: &str) -> Value {
    json!({
        "run_id": run_id,
        "ledger_path": github_ledger_path(cwd, run_id),
        "collect_dir": cwd.join(".swarm").join("github").join("collect").join(run_id),
        "local_run_dir": cwd.join(".swarm").join("local").join("runs").join(run_id),
    })
}

pub fn doctor_checks(cwd: &Path, workflow_ref: Option<&str>) -> Value {
    let workflow_pin = match workflow_ref {
        Some(value) => match parse_workflow_ref(value) {
            Ok(parsed) => json!({
                "configured": true,
                "valid": true,
                "owner_repo": format!("{}/{}", parsed.owner, parsed.repo),
                "workflow_file": parsed.workflow_file,
            }),
            Err(err) => json!({
                "configured": true,
                "valid": false,
                "error": err.to_string(),
            }),
        },
        None => json!({
            "configured": false,
            "valid": false,
            "error": "workflow_ref is not set in config",
        }),
    };

    let gh_version = probe_gh(cwd, &["--version"]);
    let gh_auth = probe_gh(cwd, &["auth", "status", "-h", "github.com"]);

    json!({
        "gh_cli_available": gh_version.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "gh_auth_ok": gh_auth.get("ok").and_then(Value::as_bool).unwrap_or(false),
        "gh_version_probe": gh_version,
        "gh_auth_probe": gh_auth,
        "workflow_pin": workflow_pin,
        "github_ledger_dir": cwd.join(".swarm").join("github").join("runs"),
    })
}

fn load_or_seed_ledger(
    cwd: &Path,
    run_id: &str,
    workflow_ref: Option<&str>,
) -> Result<GithubRunLedger> {
    let path = github_ledger_path(cwd, run_id);
    if path.exists() {
        return read_json(&path);
    }

    let workflow_ref = workflow_ref.ok_or_else(|| {
        anyhow!(GithubBackendError::validation(
            "WORKFLOW_REF_REQUIRED",
            "workflow_ref is required when no existing ledger exists",
        ))
    })?;
    let wf = parse_workflow_ref(workflow_ref)?;
    let ledger = GithubRunLedger {
        run_id: run_id.to_string(),
        workflow_ref: workflow_ref.to_string(),
        owner_repo: format!("{}/{}", wf.owner, wf.repo),
        workflow_file: wf.workflow_file,
        commit_sha: wf.commit_sha,
        dispatch_ref: None,
        route_mode: "direct".to_string(),
        fallback_policy: "allow_cold_start".to_string(),
        dispatched: false,
        dispatch_mode: "collect_only".to_string(),
        gh_run_id: None,
        max_attempts: DEFAULT_MAX_ATTEMPTS,
        timeout_secs: DEFAULT_TIMEOUT_SECS,
        canceled: false,
        last_error: None,
    };
    write_json(&path, &ledger)?;
    Ok(ledger)
}

fn is_hex_40(value: &str) -> bool {
    value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn route_mode_str(mode: &RouteMode) -> &'static str {
    match mode {
        RouteMode::Direct => "direct",
        RouteMode::ClientExit => "client_exit",
    }
}

fn dispatch_ref() -> String {
    std::env::var("SWARM_GH_DISPATCH_REF")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "main".to_string())
}

fn dispatch_input_override(var: &str) -> Option<String> {
    normalized_dispatch_input_override(std::env::var(var).ok())
}

fn normalized_dispatch_input_override(value: Option<String>) -> Option<String> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Copy)]
enum GhOperation {
    Dispatch,
    Collect,
    Cancel,
}

impl GhOperation {
    fn code(self) -> &'static str {
        match self {
            Self::Dispatch => "GH_DISPATCH_FAILED",
            Self::Collect => "GH_COLLECT_FAILED",
            Self::Cancel => "GH_CANCEL_FAILED",
        }
    }

    fn build_error(self, retryable: bool, message: impl Into<String>) -> GithubBackendError {
        match self {
            Self::Dispatch => GithubBackendError::dispatch(self.code(), retryable, message),
            Self::Collect => GithubBackendError::collect(self.code(), retryable, message),
            Self::Cancel => GithubBackendError::cancel(self.code(), retryable, message),
        }
    }
}

fn run_gh_command_with_policy(
    cwd: &Path,
    gh_binary: &Path,
    args: &[String],
    policy: &GhCommandPolicy,
    operation: GhOperation,
) -> Result<u32> {
    let policy = normalized_policy(policy);
    let mut last_err: Option<GithubBackendError> = None;

    for attempt in 1..=policy.max_attempts {
        match run_gh_once(cwd, gh_binary, args, policy.timeout_secs, operation) {
            Ok(()) => return Ok(attempt),
            Err(err) => {
                let should_retry = err.info.retryable && attempt < policy.max_attempts;
                last_err = Some(err);
                if should_retry {
                    let sleep_ms = policy.retry_backoff_ms.saturating_mul(attempt as u64);
                    thread::sleep(Duration::from_millis(sleep_ms));
                    continue;
                }
                break;
            }
        }
    }

    let err = last_err.unwrap_or_else(|| {
        operation.build_error(false, "gh command failed without diagnostic details")
    });
    Err(anyhow!(GithubBackendError::new(
        &err.info.code,
        &err.info.category,
        err.info.retryable,
        format!(
            "{} (attempted {} time(s), timeout={}s)",
            err.info.message, policy.max_attempts, policy.timeout_secs
        ),
    )))
}

fn run_gh_once(
    cwd: &Path,
    gh_binary: &Path,
    args: &[String],
    timeout_secs: u64,
    operation: GhOperation,
) -> std::result::Result<(), GithubBackendError> {
    let mut child = Command::new(gh_binary)
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| {
            GithubBackendError::dependency(
                "GH_CLI_UNAVAILABLE",
                format!(
                    "failed to invoke `gh` ({}): {err}; ensure GitHub CLI is installed/authenticated",
                    gh_binary.display()
                ),
            )
        })?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(1));
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let output = child.wait_with_output().map_err(|err| {
                    operation.build_error(true, format!("failed to read gh command output: {err}"))
                })?;
                if status.success() {
                    return Ok(());
                }
                let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                let message = format!(
                    "gh command failed (status {status}): stderr: {stderr} stdout: {stdout}"
                );
                return Err(operation.build_error(is_retryable_failure(&stderr, &stdout), message));
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(GithubBackendError::timeout(
                        "GH_COMMAND_TIMEOUT",
                        true,
                        format!(
                            "gh command timed out after {timeout_secs}s: {} {}",
                            gh_binary.display(),
                            args.join(" ")
                        ),
                    ));
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) => {
                return Err(operation
                    .build_error(true, format!("failed while waiting for gh command: {err}")));
            }
        }
    }
}

fn is_retryable_failure(stderr: &str, stdout: &str) -> bool {
    let combined = format!("{stderr}\n{stdout}").to_lowercase();
    let retryable_signals = [
        "timed out",
        "timeout",
        "connection reset",
        "temporarily unavailable",
        "502",
        "503",
        "504",
        "rate limit",
        "secondary rate limit",
        "try again",
    ];
    retryable_signals
        .iter()
        .any(|needle| combined.contains(needle))
}

fn normalized_policy(policy: &GhCommandPolicy) -> GhCommandPolicy {
    GhCommandPolicy {
        max_attempts: policy.max_attempts.max(1),
        timeout_secs: policy.timeout_secs.max(1),
        retry_backoff_ms: policy.retry_backoff_ms.max(50),
    }
}

fn backend_error_info_from_anyhow(err: &anyhow::Error) -> Option<GithubErrorInfo> {
    err.downcast_ref::<GithubBackendError>()
        .map(|backend_err| backend_err.info().clone())
}

fn error_from_info(info: &GithubErrorInfo) -> GithubBackendError {
    GithubBackendError::new(
        &info.code,
        &info.category,
        info.retryable,
        info.message.clone(),
    )
}

fn with_gh_prefix(gh_binary: &Path, args: &[String]) -> Vec<String> {
    let mut full = vec![gh_binary.display().to_string()];
    full.extend(args.iter().map(|arg| redact_dispatch_input_arg(arg)));
    full
}

fn redact_dispatch_input_arg(arg: &str) -> String {
    const SENSITIVE_PREFIXES: [&str; 2] = ["inputs[state_cap_in]=", "inputs[net_cap_in]="];
    if SENSITIVE_PREFIXES
        .iter()
        .any(|prefix| arg.starts_with(prefix))
    {
        let key = arg.split('=').next().unwrap_or(arg);
        return format!("{key}=<redacted>");
    }

    arg.to_string()
}

fn require_string_field<'a>(value: &'a Value, field: &str, code: &str) -> Result<&'a str> {
    value.get(field).and_then(Value::as_str).ok_or_else(|| {
        anyhow!(GithubBackendError::artifact(
            code,
            format!("artifact field '{field}' must be a string"),
        ))
    })
}

fn validate_result_artifact(value: &Value) -> Result<()> {
    require_string_field(value, "run_id", "ARTIFACT_RESULT_SCHEMA_INVALID")?;
    require_string_field(value, "status", "ARTIFACT_RESULT_SCHEMA_INVALID")?;
    let restore_mode =
        require_string_field(value, "restore_mode", "ARTIFACT_RESULT_SCHEMA_INVALID")?;
    if restore_mode != "checkpoint" && restore_mode != "cold_start" {
        return Err(anyhow!(GithubBackendError::artifact(
            "ARTIFACT_RESULT_SCHEMA_INVALID",
            format!("restore_mode must be checkpoint|cold_start, got '{restore_mode}'"),
        )));
    }
    Ok(())
}

fn validate_next_tokens_artifact(value: &Value) -> Result<()> {
    require_string_field(
        value,
        "state_cap_next",
        "ARTIFACT_NEXT_TOKENS_SCHEMA_INVALID",
    )?;
    require_string_field(value, "net_cap_next", "ARTIFACT_NEXT_TOKENS_SCHEMA_INVALID")?;
    Ok(())
}

fn probe_gh(cwd: &Path, args: &[&str]) -> Value {
    match Command::new("gh")
        .args(args)
        .current_dir(cwd)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
    {
        Ok(output) => json!({
            "ok": output.status.success(),
            "status": output.status.code(),
            "stdout_bytes": output.stdout.len(),
            "stderr_bytes": output.stderr.len(),
            "output_redacted": true,
            "args": args,
        }),
        Err(err) => json!({
            "ok": false,
            "status": null,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "output_redacted": true,
            "error": err.to_string(),
            "args": args,
        }),
    }
}

fn find_first_file_named(root: &Path, filename: &str) -> Option<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = fs::read_dir(&dir).ok()?;
        for entry in entries {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(OsStr::to_str) == Some(filename) {
                return Some(path);
            }
        }
    }
    None
}

fn github_ledger_path(cwd: &Path, run_id: &str) -> PathBuf {
    cwd.join(".swarm")
        .join("github")
        .join("runs")
        .join(format!("{run_id}.json"))
}

fn local_ref(cwd: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(cwd).unwrap_or(path);
    format!("local://{}", rel.display())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value)?;
    fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::path::PathBuf;
    use swarm_core::{Backend, RouteMode, RunSpec};
    use swarm_verify::hash_certificate_bytes;
    use tempfile::TempDir;

    const CERTIFICATE_FIXTURE: &str =
        include_str!("../../fixtures/contracts/certificate.valid.json");

    fn sample_workflow_ref() -> &'static str {
        "owner/repo/.github/workflows/loom-paid-run.yml@1234567890abcdef1234567890abcdef12345678"
    }

    fn sample_spec(run_id: &str) -> RunSpec {
        RunSpec {
            run_id: run_id.to_string(),
            node: "root".to_string(),
            backend: Backend::Github,
            route_mode: RouteMode::Direct,
            workflow_ref: Some(sample_workflow_ref().to_string()),
        }
    }

    #[test]
    fn parse_valid_workflow_ref() {
        let wf = parse_workflow_ref(sample_workflow_ref()).expect("workflow ref should parse");

        assert_eq!(wf.owner, "owner");
        assert_eq!(wf.repo, "repo");
        assert_eq!(wf.workflow_file, "loom-paid-run.yml");
    }

    #[test]
    fn reject_unpinned_commit() {
        let err = parse_workflow_ref("owner/repo/.github/workflows/loom-paid-run.yml@main")
            .expect_err("unpinned commit should fail");
        assert!(err.to_string().contains("40-hex"));
    }

    #[test]
    fn reject_missing_commit_pin() {
        let err = parse_workflow_ref("owner/repo/.github/workflows/loom-paid-run.yml")
            .expect_err("workflow ref without @<sha> should fail");
        assert!(err.to_string().contains("@<commit_sha>"));
    }

    #[test]
    fn reject_missing_workflow_path() {
        let err = parse_workflow_ref("owner/repo@1234567890abcdef1234567890abcdef12345678")
            .expect_err("workflow ref without path should fail");
        assert!(err.to_string().contains("workflow path"));
    }

    #[test]
    fn dispatch_dry_run_writes_ledger() {
        let cwd = TempDir::new().expect("temp dir");
        let spec = sample_spec("dispatch-dry-run");

        let out = dispatch_run(
            cwd.path(),
            &spec,
            false,
            "ghcr.io/example/swarm-agent:test",
            "echo test",
            true,
        )
        .expect("dispatch should succeed");

        assert_eq!(out.run_id, "dispatch-dry-run");
        assert!(!out.dispatched);
        assert!(out.command_preview.contains(&"gh".to_string()));
        assert!(
            out.command_preview
                .contains(&"inputs[agent_step]=echo test".to_string())
        );

        let ledger_path = cwd
            .path()
            .join(".swarm")
            .join("github")
            .join("runs")
            .join("dispatch-dry-run.json");
        let ledger: GithubRunLedger = read_json(&ledger_path).expect("ledger json");

        assert_eq!(ledger.route_mode, "direct");
        assert_eq!(ledger.fallback_policy, "fail_closed");
        assert_eq!(ledger.dispatch_mode, "dry_run");
        assert!(!ledger.dispatched);
        assert_eq!(ledger.owner_repo, "owner/repo");
    }

    #[test]
    fn dispatch_allow_cold_start_sets_policy_and_input() {
        let cwd = TempDir::new().expect("temp dir");
        let mut spec = sample_spec("dispatch-allow-cold-start");
        spec.route_mode = RouteMode::ClientExit;

        let out = dispatch_run(
            cwd.path(),
            &spec,
            true,
            "ghcr.io/example/swarm-agent:test",
            "echo test",
            true,
        )
        .expect("dispatch should succeed");

        assert!(
            out.command_preview
                .contains(&"inputs[checkpoint_in]=".to_string())
        );

        let ledger: GithubRunLedger = read_json(
            &cwd.path()
                .join(".swarm")
                .join("github")
                .join("runs")
                .join("dispatch-allow-cold-start.json"),
        )
        .expect("ledger json");
        assert_eq!(ledger.route_mode, "client_exit");
        assert_eq!(ledger.fallback_policy, "allow_cold_start");
    }

    #[test]
    fn dispatch_override_inputs_are_included_without_empty_checkpoint() {
        let cwd = TempDir::new().expect("temp dir");
        let spec = sample_spec("dispatch-override-inputs");
        let policy = GhCommandPolicy::default();
        let options = DispatchOptions {
            allow_cold_start: true,
            agent_image: "ghcr.io/example/swarm-agent:test",
            agent_step: "echo test",
            dry_run: true,
            policy: &policy,
            gh_binary: Path::new("gh"),
            dispatch_inputs: DispatchInputOverrides {
                checkpoint_in: Some("gh-artifact://12345/state-bundle-run".to_string()),
                state_cap_in: Some("state-cap-token".to_string()),
                net_cap_in: Some("net-cap-token".to_string()),
            },
        };

        let out =
            dispatch_run_internal(cwd.path(), &spec, &options).expect("dispatch should succeed");
        assert!(
            out.command_preview.contains(
                &"inputs[checkpoint_in]=gh-artifact://12345/state-bundle-run".to_string()
            )
        );
        assert!(
            out.command_preview
                .contains(&"inputs[state_cap_in]=<redacted>".to_string())
        );
        assert!(
            out.command_preview
                .contains(&"inputs[net_cap_in]=<redacted>".to_string())
        );
        assert!(
            !out.command_preview
                .contains(&"inputs[state_cap_in]=state-cap-token".to_string())
        );
        assert!(
            !out.command_preview
                .contains(&"inputs[net_cap_in]=net-cap-token".to_string())
        );
        assert!(
            !out.command_preview
                .contains(&"inputs[checkpoint_in]=".to_string())
        );
    }

    #[test]
    fn redact_dispatch_input_arg_masks_state_and_net_tokens_only() {
        assert_eq!(
            redact_dispatch_input_arg("inputs[state_cap_in]=secret-state-token"),
            "inputs[state_cap_in]=<redacted>"
        );
        assert_eq!(
            redact_dispatch_input_arg("inputs[net_cap_in]=secret-net-token"),
            "inputs[net_cap_in]=<redacted>"
        );
        assert_eq!(
            redact_dispatch_input_arg("inputs[checkpoint_in]=gh-artifact://123/state-bundle"),
            "inputs[checkpoint_in]=gh-artifact://123/state-bundle"
        );
    }

    #[test]
    fn normalized_dispatch_input_override_trims_and_drops_empty_values() {
        assert_eq!(
            normalized_dispatch_input_override(Some("  token ".to_string())),
            Some("token".to_string())
        );
        assert_eq!(
            normalized_dispatch_input_override(Some("  ".to_string())),
            None
        );
        assert_eq!(normalized_dispatch_input_override(None), None);
    }

    #[test]
    fn dispatch_requires_workflow_ref() {
        let cwd = TempDir::new().expect("temp dir");
        let spec = RunSpec {
            run_id: "missing-workflow-ref".to_string(),
            node: "root".to_string(),
            backend: Backend::Github,
            route_mode: RouteMode::Direct,
            workflow_ref: None,
        };

        let err = dispatch_run(cwd.path(), &spec, false, "image", "step", true)
            .expect_err("dispatch without workflow_ref should fail");
        assert!(err.to_string().contains("workflow_ref is required"));
    }

    #[test]
    fn collect_dry_run_requires_workflow_ref_without_ledger() {
        let cwd = TempDir::new().expect("temp dir");
        let err = collect_run(cwd.path(), "collect-without-ledger", 42, None, None, true)
            .expect_err("collect should fail when ledger and workflow_ref are both missing");
        assert!(err.to_string().contains("workflow_ref is required"));
    }

    #[test]
    fn collect_dry_run_seeds_ledger_and_gh_run_id() {
        let cwd = TempDir::new().expect("temp dir");
        let out = collect_run(
            cwd.path(),
            "collect-seed",
            42,
            Some(sample_workflow_ref()),
            None,
            true,
        )
        .expect("collect should succeed");

        assert_eq!(out.run_id, "collect-seed");
        assert_eq!(out.owner_repo, "owner/repo");
        assert!(out.dry_run);
        assert!(
            out.downloaded_to
                .ends_with(".swarm/github/collect/collect-seed")
        );

        let ledger: GithubRunLedger = read_json(
            &cwd.path()
                .join(".swarm")
                .join("github")
                .join("runs")
                .join("collect-seed.json"),
        )
        .expect("ledger json");
        assert_eq!(ledger.dispatch_mode, "collect_only");
        assert_eq!(ledger.fallback_policy, "allow_cold_start");
        assert_eq!(ledger.gh_run_id, Some(42));
    }

    #[test]
    fn collect_dry_run_updates_existing_ledger() {
        let cwd = TempDir::new().expect("temp dir");
        let spec = sample_spec("collect-existing-ledger");
        dispatch_run(cwd.path(), &spec, false, "image", "step", true)
            .expect("dispatch should seed ledger");

        let out = collect_run(cwd.path(), "collect-existing-ledger", 99, None, None, true)
            .expect("collect should use existing ledger");
        assert_eq!(out.gh_run_id, 99);

        let ledger: GithubRunLedger = read_json(
            &cwd.path()
                .join(".swarm")
                .join("github")
                .join("runs")
                .join("collect-existing-ledger.json"),
        )
        .expect("ledger json");
        assert_eq!(ledger.fallback_policy, "fail_closed");
        assert_eq!(ledger.gh_run_id, Some(99));
    }

    #[test]
    fn load_status_uses_local_result_when_available() {
        let cwd = TempDir::new().expect("temp dir");
        let local_run_dir = cwd
            .path()
            .join(".swarm")
            .join("local")
            .join("runs")
            .join("status-local-result");
        fs::create_dir_all(&local_run_dir).expect("create local run dir");
        fs::write(
            local_run_dir.join("result.json"),
            serde_json::to_vec_pretty(&json!({
                "run_id": "status-local-result",
                "status": "succeeded",
                "restore_mode": "checkpoint"
            }))
            .expect("serialize result json"),
        )
        .expect("write result json");

        let status = load_github_run_status(cwd.path(), "status-local-result")
            .expect("status should load from local result");
        assert_eq!(
            status.get("status").and_then(Value::as_str),
            Some("succeeded")
        );
    }

    #[test]
    fn load_status_falls_back_to_prepared_ledger() {
        let cwd = TempDir::new().expect("temp dir");
        let spec = sample_spec("status-prepared");
        dispatch_run(cwd.path(), &spec, false, "image", "step", true)
            .expect("dispatch should seed ledger");

        let status = load_github_run_status(cwd.path(), "status-prepared")
            .expect("status should load from ledger");
        assert_eq!(
            status.get("status").and_then(Value::as_str),
            Some("prepared")
        );
        assert_eq!(
            status.get("fallback_policy").and_then(Value::as_str),
            Some("fail_closed")
        );
    }

    #[test]
    fn load_status_falls_back_to_dispatched_ledger() {
        let cwd = TempDir::new().expect("temp dir");
        let ledger = GithubRunLedger {
            run_id: "status-dispatched".to_string(),
            workflow_ref: sample_workflow_ref().to_string(),
            owner_repo: "owner/repo".to_string(),
            workflow_file: "loom-paid-run.yml".to_string(),
            commit_sha: "1234567890abcdef1234567890abcdef12345678".to_string(),
            dispatch_ref: Some("main".to_string()),
            route_mode: "direct".to_string(),
            fallback_policy: "fail_closed".to_string(),
            dispatched: true,
            dispatch_mode: "live".to_string(),
            gh_run_id: Some(777),
            max_attempts: 3,
            timeout_secs: 45,
            canceled: false,
            last_error: None,
        };
        write_json(
            &cwd.path()
                .join(".swarm")
                .join("github")
                .join("runs")
                .join("status-dispatched.json"),
            &ledger,
        )
        .expect("write ledger");

        let status = load_github_run_status(cwd.path(), "status-dispatched")
            .expect("status should load from ledger");
        assert_eq!(
            status.get("status").and_then(Value::as_str),
            Some("dispatched")
        );
        assert_eq!(status.get("gh_run_id").and_then(Value::as_u64), Some(777));
    }

    #[test]
    fn logs_hint_returns_expected_paths() {
        let cwd = TempDir::new().expect("temp dir");
        let hint = logs_hint(cwd.path(), "logs-run");

        assert!(
            hint.get("ledger_path")
                .and_then(Value::as_str)
                .expect("ledger_path string")
                .ends_with(".swarm/github/runs/logs-run.json")
        );
        assert!(
            hint.get("collect_dir")
                .and_then(Value::as_str)
                .expect("collect_dir string")
                .ends_with(".swarm/github/collect/logs-run")
        );
        assert!(
            hint.get("local_run_dir")
                .and_then(Value::as_str)
                .expect("local_run_dir string")
                .ends_with(".swarm/local/runs/logs-run")
        );
    }

    fn write_fake_gh_script(dir: &TempDir, script_body: &str) -> PathBuf {
        let gh_path = dir.path().join("gh");
        fs::write(&gh_path, script_body).expect("write gh script");
        let mut perms = fs::metadata(&gh_path).expect("gh metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&gh_path, perms).expect("set executable permissions");
        gh_path
    }

    fn write_collect_fixture_copy_script(dir: &TempDir, fixture_dir: &Path) -> PathBuf {
        write_fake_gh_script(
            dir,
            &format!(
                r#"#!/bin/sh
set -eu
out_dir=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-D" ]; then
    shift
    out_dir="$1"
    break
  fi
  shift
done
mkdir -p "$out_dir/artifact"
for file in result.json next_tokens.json certificate.json policy.json; do
  if [ -f "{fixture_dir}/$file" ]; then
    cp "{fixture_dir}/$file" "$out_dir/artifact/$file"
  fi
done
exit 0
"#,
                fixture_dir = fixture_dir.display()
            ),
        )
    }

    fn write_collect_fixture_artifacts(
        root: &Path,
        run_id: &str,
        commit_sha: &str,
        include_policy_file: bool,
        mismatched_artifact_hash: bool,
        override_cert_commit: Option<&str>,
    ) {
        let policy_bytes = serde_json::to_vec_pretty(&json!({
            "schema_version": "agent_swarm-policy-v1",
            "run_id": run_id,
            "route_mode": "direct"
        }))
        .expect("serialize policy fixture");
        let mut policy_bytes = policy_bytes;
        policy_bytes.push(b'\n');

        let mut cert: Value =
            serde_json::from_str(CERTIFICATE_FIXTURE).expect("parse cert fixture");
        cert["job_id"] = json!(run_id);
        cert["runtime"]["workflow_ref"] = json!(format!(
            "owner/repo/.github/workflows/loom-paid-run.yml@{}",
            override_cert_commit.unwrap_or(commit_sha)
        ));
        cert["policy"] = json!({
            "schema_version": "agent_swarm-policy-v1",
            "policy_hash": hash_certificate_bytes(&policy_bytes),
            "policy_ref": format!("artifact://swarm-live-{run_id}/policy.json"),
            "policy_generated_at": "2026-02-28T12:00:20Z"
        });
        let mut cert_bytes = serde_json::to_vec_pretty(&cert).expect("serialize cert fixture");
        cert_bytes.push(b'\n');

        let artifact_hash = if mismatched_artifact_hash {
            "sha256:deadbeef".to_string()
        } else {
            hash_certificate_bytes(&cert_bytes)
        };

        fs::write(
            root.join("result.json"),
            serde_json::to_vec_pretty(&json!({
                "run_id": run_id,
                "status": "succeeded",
                "restore_mode": "checkpoint",
                "artifact_hash": artifact_hash,
            }))
            .expect("serialize result"),
        )
        .expect("write result");
        fs::write(
            root.join("next_tokens.json"),
            serde_json::to_vec_pretty(&json!({
                "state_cap_next": "state-cap-next",
                "net_cap_next": "net-cap-next",
            }))
            .expect("serialize next tokens"),
        )
        .expect("write next tokens");
        fs::write(root.join("certificate.json"), cert_bytes).expect("write certificate");
        if include_policy_file {
            fs::write(root.join("policy.json"), policy_bytes).expect("write policy");
        }
    }

    #[test]
    fn dispatch_retries_on_transient_failure_then_succeeds() {
        let cwd = TempDir::new().expect("temp dir");
        let tools = TempDir::new().expect("tool dir");
        let gh = write_fake_gh_script(
            &tools,
            r#"#!/bin/sh
mkdir -p "$PWD/.swarm"
count_file="$PWD/.swarm/gh-attempt-count.txt"
count=0
if [ -f "$count_file" ]; then
  count=$(cat "$count_file")
fi
count=$((count+1))
echo "$count" > "$count_file"
if [ "$count" -lt 3 ]; then
  echo "503 Service Unavailable" >&2
  exit 1
fi
exit 0
"#,
        );
        let spec = sample_spec("retry-dispatch");
        let policy = GhCommandPolicy {
            max_attempts: 4,
            timeout_secs: 2,
            retry_backoff_ms: 1,
        };

        let options = DispatchOptions {
            allow_cold_start: false,
            agent_image: "image",
            agent_step: "step",
            dry_run: false,
            policy: &policy,
            gh_binary: &gh,
            dispatch_inputs: DispatchInputOverrides::default(),
        };
        let result = dispatch_run_internal(cwd.path(), &spec, &options)
            .expect("dispatch should succeed after retries");

        assert_eq!(result.attempts_used, 3);
        let count = fs::read_to_string(cwd.path().join(".swarm").join("gh-attempt-count.txt"))
            .expect("read attempt count");
        assert_eq!(count.trim(), "3");
    }

    #[test]
    fn dispatch_timeout_is_classified() {
        let cwd = TempDir::new().expect("temp dir");
        let tools = TempDir::new().expect("tool dir");
        let gh = write_fake_gh_script(
            &tools,
            r#"#!/bin/sh
sleep 2
exit 0
"#,
        );
        let args = vec![
            "api".to_string(),
            "--method".to_string(),
            "POST".to_string(),
        ];
        let policy = GhCommandPolicy {
            max_attempts: 1,
            timeout_secs: 1,
            retry_backoff_ms: 1,
        };

        let err =
            run_gh_command_with_policy(cwd.path(), &gh, &args, &policy, GhOperation::Dispatch)
                .expect_err("timeout should fail");
        let backend_err = err
            .downcast_ref::<GithubBackendError>()
            .expect("typed backend error");
        assert_eq!(backend_err.info().code, "GH_COMMAND_TIMEOUT");
        assert_eq!(backend_err.info().category, "timeout");
    }

    #[test]
    fn cancel_updates_ledger_and_uses_expected_command() {
        let cwd = TempDir::new().expect("temp dir");
        let tools = TempDir::new().expect("tool dir");
        let gh = write_fake_gh_script(
            &tools,
            r#"#!/bin/sh
mkdir -p "$PWD/.swarm"
printf "%s" "$*" > "$PWD/.swarm/cancel-args.txt"
exit 0
"#,
        );
        let spec = sample_spec("cancel-path");
        let dispatch_options = DispatchOptions {
            allow_cold_start: true,
            agent_image: "image",
            agent_step: "step",
            dry_run: true,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            dispatch_inputs: DispatchInputOverrides::default(),
        };
        dispatch_run_internal(cwd.path(), &spec, &dispatch_options).expect("seed ledger");

        let cancel = cancel_run_internal(
            cwd.path(),
            "cancel-path",
            Some(991),
            false,
            &GhCommandPolicy::default(),
            &gh,
        )
        .expect("cancel should succeed");
        assert!(cancel.canceled);
        assert_eq!(cancel.gh_run_id, 991);

        let args =
            fs::read_to_string(cwd.path().join(".swarm").join("cancel-args.txt")).expect("args");
        assert!(args.contains("run cancel 991 -R owner/repo"));

        let status = load_github_run_status(cwd.path(), "cancel-path").expect("status");
        assert_eq!(
            status.get("status").and_then(Value::as_str),
            Some("canceled")
        );
    }

    #[test]
    fn collect_fails_when_required_artifacts_missing() {
        let cwd = TempDir::new().expect("temp dir");
        let tools = TempDir::new().expect("tool dir");
        let gh = write_fake_gh_script(
            &tools,
            r#"#!/bin/sh
exit 0
"#,
        );
        let spec = sample_spec("collect-missing");
        let dispatch_options = DispatchOptions {
            allow_cold_start: false,
            agent_image: "image",
            agent_step: "step",
            dry_run: true,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            dispatch_inputs: DispatchInputOverrides::default(),
        };
        dispatch_run_internal(cwd.path(), &spec, &dispatch_options).expect("seed ledger");

        let collect_policy = GhCommandPolicy {
            max_attempts: 1,
            timeout_secs: 2,
            retry_backoff_ms: 1,
        };
        let collect_options = CollectOptions {
            workflow_ref: None,
            out_dir: None,
            dry_run: false,
            policy: &collect_policy,
            gh_binary: &gh,
            verify_certificate: false,
            require_policy: false,
        };
        let err = collect_run_internal(cwd.path(), "collect-missing", 77, &collect_options)
            .expect_err("missing artifacts should fail");
        let backend_err = err
            .downcast_ref::<GithubBackendError>()
            .expect("typed backend error");
        assert_eq!(backend_err.info().code, "ARTIFACT_MISSING_RESULT");
        assert_eq!(backend_err.info().category, "artifact");
    }

    #[test]
    fn reject_empty_owner_or_repo_segments() {
        let err = parse_workflow_ref(
            "/repo/.github/workflows/loom-paid-run.yml@1234567890abcdef1234567890abcdef12345678",
        )
        .expect_err("empty owner should fail");
        assert!(
            err.to_string()
                .contains("owner/repo segments must be non-empty")
        );

        let err = parse_workflow_ref(
            "owner//.github/workflows/loom-paid-run.yml@1234567890abcdef1234567890abcdef12345678",
        )
        .expect_err("empty repo should fail");
        assert!(
            err.to_string()
                .contains("owner/repo segments must be non-empty")
        );
    }

    #[test]
    fn collect_parse_failure_persists_last_error_and_run_id() {
        let cwd = TempDir::new().expect("temp dir");
        let tools = TempDir::new().expect("tool dir");
        let gh = write_fake_gh_script(
            &tools,
            r#"#!/bin/sh
out_dir=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-D" ]; then
    shift
    out_dir="$1"
    break
  fi
  shift
done
mkdir -p "$out_dir/artifact"
printf '{"run_id":123,"status":"succeeded","restore_mode":"checkpoint"}' > "$out_dir/artifact/result.json"
printf '{"state_cap_next":"ok","net_cap_next":"ok"}' > "$out_dir/artifact/next_tokens.json"
exit 0
"#,
        );

        let spec = sample_spec("collect-parse-failure");
        let dispatch_options = DispatchOptions {
            allow_cold_start: false,
            agent_image: "image",
            agent_step: "step",
            dry_run: true,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            dispatch_inputs: DispatchInputOverrides::default(),
        };
        dispatch_run_internal(cwd.path(), &spec, &dispatch_options).expect("seed ledger");

        let collect_policy = GhCommandPolicy {
            max_attempts: 1,
            timeout_secs: 2,
            retry_backoff_ms: 1,
        };
        let collect_options = CollectOptions {
            workflow_ref: None,
            out_dir: None,
            dry_run: false,
            policy: &collect_policy,
            gh_binary: &gh,
            verify_certificate: false,
            require_policy: false,
        };
        let err = collect_run_internal(cwd.path(), "collect-parse-failure", 321, &collect_options)
            .expect_err("invalid result schema should fail");
        let backend_err = err
            .downcast_ref::<GithubBackendError>()
            .expect("typed backend error");
        assert_eq!(backend_err.info().code, "ARTIFACT_RESULT_SCHEMA_INVALID");

        let ledger: GithubRunLedger = read_json(
            &cwd.path()
                .join(".swarm")
                .join("github")
                .join("runs")
                .join("collect-parse-failure.json"),
        )
        .expect("ledger json");
        assert_eq!(ledger.gh_run_id, Some(321));
        let last_error = ledger.last_error.expect("last error should be persisted");
        assert_eq!(last_error.code, "ARTIFACT_RESULT_SCHEMA_INVALID");
    }

    #[test]
    fn collect_verifies_certificate_and_policy_by_default() {
        let cwd = TempDir::new().expect("temp dir");
        let tools = TempDir::new().expect("tool dir");
        let fixture = TempDir::new().expect("fixture dir");

        let spec = sample_spec("collect-verify-success");
        write_collect_fixture_artifacts(
            fixture.path(),
            &spec.run_id,
            "1234567890abcdef1234567890abcdef12345678",
            true,
            false,
            None,
        );

        let gh = write_collect_fixture_copy_script(&tools, fixture.path());
        let dispatch_options = DispatchOptions {
            allow_cold_start: false,
            agent_image: "image",
            agent_step: "step",
            dry_run: true,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            dispatch_inputs: DispatchInputOverrides::default(),
        };
        dispatch_run_internal(cwd.path(), &spec, &dispatch_options).expect("seed ledger");

        let collect_options = CollectOptions {
            workflow_ref: None,
            out_dir: None,
            dry_run: false,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            verify_certificate: true,
            require_policy: true,
        };

        let out = collect_run_internal(cwd.path(), &spec.run_id, 888, &collect_options)
            .expect("collect should verify cert and policy");
        assert!(out.verification_ok);
        assert_eq!(out.verification_reason, "ok");
        assert!(out.certificate_ref.is_some());
        assert!(out.policy_ref.is_some());
        assert!(
            out.artifact_report
                .found
                .contains(&"certificate.json".to_string())
        );
        assert!(
            out.artifact_report
                .found
                .contains(&"policy.json".to_string())
        );
    }

    #[test]
    fn collect_fails_closed_on_certificate_hash_mismatch() {
        let cwd = TempDir::new().expect("temp dir");
        let tools = TempDir::new().expect("tool dir");
        let fixture = TempDir::new().expect("fixture dir");

        let spec = sample_spec("collect-verify-hash-mismatch");
        write_collect_fixture_artifacts(
            fixture.path(),
            &spec.run_id,
            "1234567890abcdef1234567890abcdef12345678",
            true,
            true,
            None,
        );

        let gh = write_collect_fixture_copy_script(&tools, fixture.path());
        let dispatch_options = DispatchOptions {
            allow_cold_start: false,
            agent_image: "image",
            agent_step: "step",
            dry_run: true,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            dispatch_inputs: DispatchInputOverrides::default(),
        };
        dispatch_run_internal(cwd.path(), &spec, &dispatch_options).expect("seed ledger");

        let collect_options = CollectOptions {
            workflow_ref: None,
            out_dir: None,
            dry_run: false,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            verify_certificate: true,
            require_policy: true,
        };
        let err = collect_run_internal(cwd.path(), &spec.run_id, 889, &collect_options)
            .expect_err("collect should fail on hash mismatch");
        let backend_err = err
            .downcast_ref::<GithubBackendError>()
            .expect("typed backend error");
        assert_eq!(backend_err.info().code, "ARTIFACT_CERT_VERIFY_FAILED");

        let ledger: GithubRunLedger = read_json(
            &cwd.path()
                .join(".swarm")
                .join("github")
                .join("runs")
                .join(format!("{}.json", spec.run_id)),
        )
        .expect("ledger json");
        assert_eq!(
            ledger.last_error.expect("persisted error").code,
            "ARTIFACT_CERT_VERIFY_FAILED"
        );
    }

    #[test]
    fn collect_fails_closed_when_policy_required_but_missing() {
        let cwd = TempDir::new().expect("temp dir");
        let tools = TempDir::new().expect("tool dir");
        let fixture = TempDir::new().expect("fixture dir");

        let spec = sample_spec("collect-verify-policy-missing");
        write_collect_fixture_artifacts(
            fixture.path(),
            &spec.run_id,
            "1234567890abcdef1234567890abcdef12345678",
            false,
            false,
            None,
        );

        let gh = write_collect_fixture_copy_script(&tools, fixture.path());
        let dispatch_options = DispatchOptions {
            allow_cold_start: false,
            agent_image: "image",
            agent_step: "step",
            dry_run: true,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            dispatch_inputs: DispatchInputOverrides::default(),
        };
        dispatch_run_internal(cwd.path(), &spec, &dispatch_options).expect("seed ledger");

        let collect_options = CollectOptions {
            workflow_ref: None,
            out_dir: None,
            dry_run: false,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            verify_certificate: true,
            require_policy: true,
        };
        let err = collect_run_internal(cwd.path(), &spec.run_id, 890, &collect_options)
            .expect_err("collect should fail when policy is required but missing");
        let backend_err = err
            .downcast_ref::<GithubBackendError>()
            .expect("typed backend error");
        assert_eq!(backend_err.info().code, "ARTIFACT_MISSING_POLICY");
    }

    #[test]
    fn collect_fails_closed_on_required_commit_mismatch() {
        let cwd = TempDir::new().expect("temp dir");
        let tools = TempDir::new().expect("tool dir");
        let fixture = TempDir::new().expect("fixture dir");

        let spec = sample_spec("collect-verify-commit-mismatch");
        write_collect_fixture_artifacts(
            fixture.path(),
            &spec.run_id,
            "1234567890abcdef1234567890abcdef12345678",
            true,
            false,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        );

        let gh = write_collect_fixture_copy_script(&tools, fixture.path());
        let dispatch_options = DispatchOptions {
            allow_cold_start: false,
            agent_image: "image",
            agent_step: "step",
            dry_run: true,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            dispatch_inputs: DispatchInputOverrides::default(),
        };
        dispatch_run_internal(cwd.path(), &spec, &dispatch_options).expect("seed ledger");

        let collect_options = CollectOptions {
            workflow_ref: None,
            out_dir: None,
            dry_run: false,
            policy: &GhCommandPolicy::default(),
            gh_binary: &gh,
            verify_certificate: true,
            require_policy: true,
        };
        let err = collect_run_internal(cwd.path(), &spec.run_id, 891, &collect_options)
            .expect_err("collect should fail on commit mismatch");
        let backend_err = err
            .downcast_ref::<GithubBackendError>()
            .expect("typed backend error");
        assert_eq!(backend_err.info().code, "ARTIFACT_CERT_VERIFY_FAILED");
    }
}
