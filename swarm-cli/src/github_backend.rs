use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use swarm_core::{RouteMode, RunSpec};

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
    pub route_mode: String,
    pub fallback_policy: String,
    pub dispatched: bool,
    pub dispatch_mode: String,
    pub gh_run_id: Option<u64>,
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
    pub dry_run: bool,
}

pub fn parse_workflow_ref(workflow_ref: &str) -> Result<GithubWorkflowRef> {
    let (lhs, commit_sha) = workflow_ref
        .rsplit_once('@')
        .ok_or_else(|| anyhow!("workflow_ref must contain '@<commit_sha>'"))?;

    if !is_hex_40(commit_sha) {
        bail!("commit_sha must be a pinned 40-hex value, got '{commit_sha}'");
    }

    let mut parts = lhs.split('/');
    let owner = parts
        .next()
        .ok_or_else(|| anyhow!("workflow_ref missing owner"))?;
    let repo = parts
        .next()
        .ok_or_else(|| anyhow!("workflow_ref missing repo"))?;
    let workflow_path = parts.collect::<Vec<_>>().join("/");
    if workflow_path.is_empty() {
        bail!("workflow_ref missing workflow path");
    }
    let workflow_file = Path::new(&workflow_path)
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| anyhow!("failed to parse workflow filename from '{workflow_path}'"))?
        .to_string();

    Ok(GithubWorkflowRef {
        owner: owner.to_string(),
        repo: repo.to_string(),
        workflow_path,
        workflow_file,
        commit_sha: commit_sha.to_string(),
    })
}

pub fn dispatch_run(
    cwd: &Path,
    spec: &RunSpec,
    allow_cold_start: bool,
    agent_image: &str,
    agent_step: &str,
    dry_run: bool,
) -> Result<DispatchResult> {
    let workflow_ref_raw = spec
        .workflow_ref
        .clone()
        .ok_or_else(|| anyhow!("workflow_ref is required for github backend"))?;
    let wf = parse_workflow_ref(&workflow_ref_raw)?;

    let owner_repo = format!("{}/{}", wf.owner, wf.repo);

    let endpoint = format!(
        "repos/{owner_repo}/actions/workflows/{}/dispatches",
        wf.workflow_file
    );
    let fallback_policy = if allow_cold_start {
        "allow_cold_start"
    } else {
        "fail_closed"
    };

    let mut cmd = vec![
        "gh".to_string(),
        "api".to_string(),
        "--method".to_string(),
        "POST".to_string(),
        endpoint,
        "-f".to_string(),
        format!("ref={}", wf.commit_sha),
        "-f".to_string(),
        format!("inputs[request_id]={}", spec.run_id),
        "-f".to_string(),
        format!("inputs[expected_commit_sha]={}", wf.commit_sha),
        "-f".to_string(),
        "inputs[source_backend]=artifact".to_string(),
        "-f".to_string(),
        "inputs[output_backend]=artifact".to_string(),
        "-f".to_string(),
        format!("inputs[agent_image]={agent_image}"),
        "-f".to_string(),
        format!("inputs[agent_step]={agent_step}"),
    ];

    if allow_cold_start {
        cmd.push("-f".to_string());
        cmd.push("inputs[checkpoint_in]=".to_string());
    }

    if !dry_run {
        run_gh_command(cwd, &cmd[1..])?;
    }

    let ledger = GithubRunLedger {
        run_id: spec.run_id.clone(),
        workflow_ref: workflow_ref_raw,
        owner_repo: owner_repo.clone(),
        workflow_file: wf.workflow_file.clone(),
        commit_sha: wf.commit_sha.clone(),
        route_mode: route_mode_str(&spec.route_mode).to_string(),
        fallback_policy: fallback_policy.to_string(),
        dispatched: !dry_run,
        dispatch_mode: if dry_run {
            "dry_run".to_string()
        } else {
            "live".to_string()
        },
        gh_run_id: None,
    };

    let ledger_path = github_ledger_path(cwd, &spec.run_id);
    write_json(&ledger_path, &ledger)?;

    Ok(DispatchResult {
        run_id: spec.run_id.clone(),
        owner_repo,
        workflow_file: wf.workflow_file,
        commit_sha: wf.commit_sha,
        dispatched: !dry_run,
        dry_run,
        ledger_ref: local_ref(cwd, &ledger_path),
        command_preview: cmd,
    })
}

pub fn collect_run(
    cwd: &Path,
    run_id: &str,
    gh_run_id: u64,
    workflow_ref: Option<&str>,
    out_dir: Option<&Path>,
    dry_run: bool,
) -> Result<CollectResult> {
    let mut ledger = load_or_seed_ledger(cwd, run_id, workflow_ref)?;
    ledger.gh_run_id = Some(gh_run_id);

    let download_dir = out_dir.map(Path::to_path_buf).unwrap_or_else(|| {
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

    let cmd = vec![
        "gh".to_string(),
        "run".to_string(),
        "download".to_string(),
        gh_run_id.to_string(),
        "-R".to_string(),
        ledger.owner_repo.clone(),
        "-D".to_string(),
        download_dir.display().to_string(),
    ];

    if !dry_run {
        run_gh_command(cwd, &cmd[1..])?;

        let result_path = find_first_file_named(&download_dir, "result.json");
        let next_tokens_path = find_first_file_named(&download_dir, "next_tokens.json");

        if let Some(path) = &result_path {
            let result_json: Value = read_json(path)?;
            restore_mode = result_json
                .get("restore_mode")
                .and_then(Value::as_str)
                .map(ToString::to_string);

            let local_run_dir = cwd.join(".swarm").join("local").join("runs").join(run_id);
            fs::create_dir_all(&local_run_dir)?;
            let dest = local_run_dir.join("result.json");
            fs::copy(path, &dest)?;
            result_ref = Some(local_ref(cwd, &dest));
        }

        if let Some(path) = &next_tokens_path {
            let local_run_dir = cwd.join(".swarm").join("local").join("runs").join(run_id);
            fs::create_dir_all(&local_run_dir)?;
            let dest = local_run_dir.join("next_tokens.json");
            fs::copy(path, &dest)?;
            next_tokens_ref = Some(local_ref(cwd, &dest));
        }

        if let Some(mode) = restore_mode.as_deref() {
            if mode == "cold_start" && ledger.fallback_policy == "fail_closed" {
                compatibility_ok = false;
                compatibility_reason =
                    "restore_mode=cold_start violates fail_closed policy".to_string();
            }
        }
    }

    write_json(&github_ledger_path(cwd, run_id), &ledger)?;

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
        dry_run,
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
        "status": if ledger.dispatched { "dispatched" } else { "prepared" },
        "owner_repo": ledger.owner_repo,
        "workflow_file": ledger.workflow_file,
        "commit_sha": ledger.commit_sha,
        "gh_run_id": ledger.gh_run_id,
        "fallback_policy": ledger.fallback_policy
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

fn load_or_seed_ledger(
    cwd: &Path,
    run_id: &str,
    workflow_ref: Option<&str>,
) -> Result<GithubRunLedger> {
    let path = github_ledger_path(cwd, run_id);
    if path.exists() {
        return read_json(&path);
    }

    let workflow_ref = workflow_ref
        .ok_or_else(|| anyhow!("workflow_ref is required when no existing ledger exists"))?;
    let wf = parse_workflow_ref(workflow_ref)?;
    let ledger = GithubRunLedger {
        run_id: run_id.to_string(),
        workflow_ref: workflow_ref.to_string(),
        owner_repo: format!("{}/{}", wf.owner, wf.repo),
        workflow_file: wf.workflow_file,
        commit_sha: wf.commit_sha,
        route_mode: "direct".to_string(),
        fallback_policy: "allow_cold_start".to_string(),
        dispatched: false,
        dispatch_mode: "collect_only".to_string(),
        gh_run_id: None,
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

fn run_gh_command(cwd: &Path, args: &[String]) -> Result<()> {
    let output = Command::new("gh")
        .args(args)
        .current_dir(cwd)
        .output()
        .with_context(
            || "failed to invoke `gh`; ensure GitHub CLI is installed and authenticated",
        )?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "gh command failed (status {}): stderr: {} stdout: {}",
            output.status,
            stderr.trim(),
            stdout.trim()
        );
    }

    Ok(())
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
    use swarm_core::{Backend, RouteMode, RunSpec};
    use tempfile::TempDir;

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
            route_mode: "direct".to_string(),
            fallback_policy: "fail_closed".to_string(),
            dispatched: true,
            dispatch_mode: "live".to_string(),
            gh_run_id: Some(777),
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
}
