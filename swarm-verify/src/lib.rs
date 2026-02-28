use anyhow::{Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;
use swarm_core::validate_schema_value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Certificate {
    #[serde(rename = "type")]
    pub kind: String,
    pub job_id: String,
    pub request_hash: String,
    pub mode: String,
    pub parent_state: ParentState,
    pub result: CertificateResult,
    pub runtime: Runtime,
    pub timestamp: String,
    pub policy: Option<PolicyBinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParentState {
    pub state_id: String,
    pub bundle_sha256: String,
    pub ratchet_step: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CertificateResult {
    pub response_sha256: String,
    pub response_locator: String,
    pub new_state: NewState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NewState {
    pub state_id: String,
    pub bundle_sha256: String,
    pub bundle_manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Runtime {
    pub workflow_ref: String,
    pub runner_class: String,
    pub started_at: String,
    pub finished_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyBinding {
    pub schema_version: String,
    pub policy_hash: String,
    pub policy_ref: String,
    pub policy_generated_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofEnvelope {
    pub schema_version: String,
    pub public_inputs_sha256: String,
    pub proof_system: String,
    pub proof_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofVerification {
    pub schema_version: String,
    pub public_inputs_sha256: String,
    pub proof_system: String,
    pub proof_ref: String,
}

fn hash_bytes_prefixed_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
}

pub fn hash_certificate_bytes(bytes: &[u8]) -> String {
    hash_bytes_prefixed_sha256(bytes)
}

pub fn verify_certificate_hash_binding(
    certificate_bytes: &[u8],
    expected_artifact_hash: &str,
) -> Result<()> {
    let actual = hash_certificate_bytes(certificate_bytes);
    if actual != expected_artifact_hash {
        return Err(anyhow!(
            "artifact hash mismatch: expected {expected_artifact_hash}, got {actual}"
        ));
    }
    Ok(())
}

pub fn extract_commit_from_workflow_ref(workflow_ref: &str) -> Result<&str> {
    let (_, commit) = workflow_ref
        .rsplit_once('@')
        .ok_or_else(|| anyhow!("workflow_ref must contain '@<commit_sha>'"))?;
    if commit.trim().is_empty() {
        bail!("workflow_ref must contain non-empty '@<commit_sha>'");
    }
    Ok(commit)
}

fn ensure_non_empty(value: &str, field: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field} must be a non-empty string");
    }
    Ok(())
}

fn ensure_sha256(value: &str, field: &str) -> Result<()> {
    if !value.starts_with("sha256:") || value.len() <= "sha256:".len() {
        bail!("{field} must be a non-empty sha256-prefixed string");
    }
    Ok(())
}

pub fn verify_certificate_semantics(certificate: &Certificate) -> Result<()> {
    if certificate.kind != "loom-agent-run-v1" {
        bail!(
            "type must equal 'loom-agent-run-v1', got '{}'",
            certificate.kind
        );
    }

    ensure_non_empty(&certificate.job_id, "job_id")?;
    ensure_sha256(&certificate.request_hash, "request_hash")?;

    match certificate.mode.as_str() {
        "prompt-run" | "state-license" => {}
        other => bail!("mode must be one of [prompt-run, state-license], got '{other}'"),
    }

    ensure_non_empty(&certificate.parent_state.state_id, "parent_state.state_id")?;
    ensure_sha256(
        &certificate.parent_state.bundle_sha256,
        "parent_state.bundle_sha256",
    )?;

    ensure_sha256(
        &certificate.result.response_sha256,
        "result.response_sha256",
    )?;
    ensure_non_empty(
        &certificate.result.response_locator,
        "result.response_locator",
    )?;
    ensure_non_empty(
        &certificate.result.new_state.state_id,
        "result.new_state.state_id",
    )?;
    ensure_sha256(
        &certificate.result.new_state.bundle_sha256,
        "result.new_state.bundle_sha256",
    )?;
    ensure_sha256(
        &certificate.result.new_state.bundle_manifest_sha256,
        "result.new_state.bundle_manifest_sha256",
    )?;

    ensure_non_empty(&certificate.runtime.workflow_ref, "runtime.workflow_ref")?;
    extract_commit_from_workflow_ref(&certificate.runtime.workflow_ref)?;
    ensure_non_empty(&certificate.runtime.runner_class, "runtime.runner_class")?;
    ensure_non_empty(&certificate.runtime.started_at, "runtime.started_at")?;
    ensure_non_empty(&certificate.runtime.finished_at, "runtime.finished_at")?;
    ensure_non_empty(&certificate.timestamp, "timestamp")?;

    if let Some(policy) = &certificate.policy {
        if policy.schema_version != "agent_swarm-policy-v1" {
            bail!(
                "policy.schema_version must equal 'agent_swarm-policy-v1', got '{}'",
                policy.schema_version
            );
        }
        ensure_sha256(&policy.policy_hash, "policy.policy_hash")?;
        ensure_non_empty(&policy.policy_ref, "policy.policy_ref")?;
    }

    Ok(())
}

pub fn verify_required_commit(certificate: &Certificate, required_commit: &str) -> Result<()> {
    ensure_non_empty(required_commit, "required_commit")?;
    let actual_commit = extract_commit_from_workflow_ref(&certificate.runtime.workflow_ref)?;
    if actual_commit != required_commit {
        return Err(anyhow!(
            "commit mismatch: required {required_commit}, got {actual_commit}"
        ));
    }
    Ok(())
}

pub fn load_certificate(path: &Path) -> Result<(Certificate, Vec<u8>)> {
    let bytes = fs::read(path)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let schema_check = validate_schema_value("certificate", &value);
    if !schema_check.valid {
        bail!(
            "certificate schema validation failed: {}",
            schema_check.errors.join(" | ")
        );
    }
    let cert: Certificate = serde_json::from_value(value)?;
    Ok((cert, bytes))
}

pub fn verify_policy_binding(
    certificate: &Certificate,
    policy_bytes: Option<&[u8]>,
    require_policy: bool,
) -> Result<()> {
    match &certificate.policy {
        Some(binding) => {
            let bytes = policy_bytes.ok_or_else(|| {
                anyhow!("certificate includes policy metadata; provide --policy-file")
            })?;
            let _: serde_json::Value = serde_json::from_slice(bytes)
                .map_err(|err| anyhow!("policy file must contain valid JSON: {err}"))?;
            let actual_hash = hash_bytes_prefixed_sha256(bytes);
            if actual_hash != binding.policy_hash {
                bail!(
                    "policy hash mismatch: certificate declares {}, actual {}",
                    binding.policy_hash,
                    actual_hash
                );
            }
            Ok(())
        }
        None => {
            if require_policy {
                bail!("policy is required but certificate has no policy section");
            }
            if policy_bytes.is_some() {
                bail!("policy file provided but certificate has no policy metadata");
            }
            Ok(())
        }
    }
}

pub fn verify_certificate_file(
    certificate_path: &Path,
    expected_artifact_hash: &str,
    required_commit: &str,
) -> Result<Certificate> {
    verify_certificate_file_with_policy(
        certificate_path,
        expected_artifact_hash,
        required_commit,
        None,
        false,
    )
}

pub fn verify_certificate_file_with_policy(
    certificate_path: &Path,
    expected_artifact_hash: &str,
    required_commit: &str,
    policy_path: Option<&Path>,
    require_policy: bool,
) -> Result<Certificate> {
    let (cert, bytes) = load_certificate(certificate_path)?;
    verify_certificate_hash_binding(&bytes, expected_artifact_hash)?;
    verify_certificate_semantics(&cert)?;
    verify_required_commit(&cert, required_commit)?;
    let policy_bytes = match policy_path {
        Some(path) => Some(fs::read(path)?),
        None => None,
    };
    verify_policy_binding(&cert, policy_bytes.as_deref(), require_policy)?;
    Ok(cert)
}

pub fn verify_proof_file(
    proof_path: &Path,
    public_inputs_path: &Path,
) -> Result<ProofVerification> {
    let proof_bytes = fs::read(proof_path)?;
    let public_inputs_bytes = fs::read(public_inputs_path)?;

    // MVP check: ensure public inputs are valid JSON before hash binding.
    let _: serde_json::Value = serde_json::from_slice(&public_inputs_bytes)?;

    let proof: ProofEnvelope = serde_json::from_slice(&proof_bytes)?;
    if proof.schema_version != "swarm-proof-envelope-v1" {
        bail!(
            "proof schema_version must equal 'swarm-proof-envelope-v1', got '{}'",
            proof.schema_version
        );
    }
    ensure_sha256(&proof.public_inputs_sha256, "public_inputs_sha256")?;
    ensure_non_empty(&proof.proof_system, "proof_system")?;
    ensure_non_empty(&proof.proof_ref, "proof_ref")?;

    let actual_public_inputs_hash = hash_bytes_prefixed_sha256(&public_inputs_bytes);
    if actual_public_inputs_hash != proof.public_inputs_sha256 {
        bail!(
            "public inputs hash mismatch: proof declares {}, actual {}",
            proof.public_inputs_sha256,
            actual_public_inputs_hash
        );
    }

    Ok(ProofVerification {
        schema_version: proof.schema_version,
        public_inputs_sha256: proof.public_inputs_sha256,
        proof_system: proof.proof_system,
        proof_ref: proof.proof_ref,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        Certificate, extract_commit_from_workflow_ref, hash_certificate_bytes,
        verify_certificate_file, verify_certificate_file_with_policy,
        verify_certificate_hash_binding, verify_certificate_semantics, verify_policy_binding,
        verify_proof_file, verify_required_commit,
    };
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    const CERTIFICATE_FIXTURE: &str =
        include_str!("../../fixtures/contracts/certificate.valid.json");

    #[test]
    fn hash_binding_succeeds_for_same_bytes() {
        let bytes = br#"{"type":"loom-agent-run-v1"}"#;
        let expected = hash_certificate_bytes(bytes);
        verify_certificate_hash_binding(bytes, &expected).expect("hash binding should pass");
    }

    #[test]
    fn hash_binding_fails_for_mismatch() {
        let bytes = br#"{"type":"loom-agent-run-v1"}"#;
        let err = verify_certificate_hash_binding(bytes, "sha256:deadbeef")
            .expect_err("hash binding should fail");
        assert!(err.to_string().contains("artifact hash mismatch"));
    }

    #[test]
    fn extract_commit_requires_separator() {
        let err = extract_commit_from_workflow_ref("owner/repo/.github/workflows/run.yml")
            .expect_err("workflow ref must contain separator");
        assert!(err.to_string().contains("workflow_ref must contain"));
    }

    #[test]
    fn verify_required_commit_rejects_mismatch() {
        let cert: Certificate = serde_json::from_str(CERTIFICATE_FIXTURE).expect("fixture parse");
        let err = verify_required_commit(&cert, "deadbeef")
            .expect_err("required commit mismatch should fail");
        assert!(err.to_string().contains("commit mismatch"));
    }

    #[test]
    fn verify_certificate_semantics_rejects_invalid_mode() {
        let mut cert: Certificate =
            serde_json::from_str(CERTIFICATE_FIXTURE).expect("fixture parse");
        cert.mode = "unsupported".to_string();
        let err = verify_certificate_semantics(&cert).expect_err("invalid mode should fail");
        assert!(err.to_string().contains("mode must be one of"));
    }

    #[test]
    fn verify_certificate_file_passes_with_frozen_fixture() {
        let tmp = TempDir::new().expect("temp dir");
        let path = tmp.path().join("certificate.json");
        fs::write(&path, CERTIFICATE_FIXTURE).expect("write fixture");
        let expected_hash = hash_certificate_bytes(CERTIFICATE_FIXTURE.as_bytes());

        let cert = verify_certificate_file(
            &path,
            &expected_hash,
            "0123456789abcdef0123456789abcdef01234567",
        )
        .expect("fixture certificate should verify");
        assert_eq!(cert.kind, "loom-agent-run-v1");
    }

    #[test]
    fn verify_certificate_file_rejects_schema_invalid_document() {
        let tmp = TempDir::new().expect("temp dir");
        let path = tmp.path().join("certificate.bad.json");
        fs::write(
            &path,
            serde_json::to_vec_pretty(&json!({
                "type": "loom-agent-run-v1",
                "job_id": "run-1"
            }))
            .expect("serialize"),
        )
        .expect("write malformed certificate");

        let expected_hash =
            hash_certificate_bytes(&fs::read(&path).expect("read malformed certificate for hash"));
        let err = verify_certificate_file(
            &path,
            &expected_hash,
            "0123456789abcdef0123456789abcdef01234567",
        )
        .expect_err("schema invalid certificate should fail");
        assert!(
            err.to_string()
                .contains("certificate schema validation failed")
        );
    }

    #[test]
    fn verify_policy_binding_passes_for_matching_policy_hash() {
        let mut cert: Certificate =
            serde_json::from_str(CERTIFICATE_FIXTURE).expect("fixture parse");
        let policy_bytes = br#"{"schema_version":"agent_swarm-policy-v1","route_mode":"direct"}"#;
        cert.policy = Some(super::PolicyBinding {
            schema_version: "agent_swarm-policy-v1".to_string(),
            policy_hash: hash_certificate_bytes(policy_bytes),
            policy_ref: "local://runs/run-1/policy.json".to_string(),
            policy_generated_at: Some("2026-02-28T12:00:20Z".to_string()),
        });

        verify_policy_binding(&cert, Some(policy_bytes), false)
            .expect("policy binding should pass");
    }

    #[test]
    fn verify_policy_binding_rejects_hash_mismatch() {
        let mut cert: Certificate =
            serde_json::from_str(CERTIFICATE_FIXTURE).expect("fixture parse");
        let policy_bytes = br#"{"schema_version":"agent_swarm-policy-v1","route_mode":"direct"}"#;
        cert.policy = Some(super::PolicyBinding {
            schema_version: "agent_swarm-policy-v1".to_string(),
            policy_hash: "sha256:deadbeef".to_string(),
            policy_ref: "local://runs/run-1/policy.json".to_string(),
            policy_generated_at: None,
        });

        let err = verify_policy_binding(&cert, Some(policy_bytes), false)
            .expect_err("policy hash mismatch should fail");
        assert!(err.to_string().contains("policy hash mismatch"));
    }

    #[test]
    fn verify_policy_binding_strict_mode_requires_policy_metadata() {
        let cert: Certificate = serde_json::from_str(CERTIFICATE_FIXTURE).expect("fixture parse");
        let err = verify_policy_binding(&cert, None, true)
            .expect_err("strict mode should require policy metadata");
        assert!(err.to_string().contains("policy is required"));
    }

    #[test]
    fn verify_policy_binding_rejects_missing_policy_file_when_metadata_present() {
        let mut cert: Certificate =
            serde_json::from_str(CERTIFICATE_FIXTURE).expect("fixture parse");
        cert.policy = Some(super::PolicyBinding {
            schema_version: "agent_swarm-policy-v1".to_string(),
            policy_hash: "sha256:abcd".to_string(),
            policy_ref: "local://runs/run-1/policy.json".to_string(),
            policy_generated_at: None,
        });

        let err = verify_policy_binding(&cert, None, false)
            .expect_err("missing policy file should fail when metadata present");
        assert!(err.to_string().contains("provide --policy-file"));
    }

    #[test]
    fn verify_certificate_file_with_policy_rejects_strict_mode_without_policy() {
        let tmp = TempDir::new().expect("temp dir");
        let cert_path = tmp.path().join("certificate.json");
        fs::write(&cert_path, CERTIFICATE_FIXTURE).expect("write fixture");
        let expected_hash = hash_certificate_bytes(CERTIFICATE_FIXTURE.as_bytes());

        let err = verify_certificate_file_with_policy(
            &cert_path,
            &expected_hash,
            "0123456789abcdef0123456789abcdef01234567",
            None,
            true,
        )
        .expect_err("strict policy mode should fail without metadata");
        assert!(err.to_string().contains("policy is required"));
    }

    #[test]
    fn verify_certificate_file_with_policy_passes_for_matching_file() {
        let tmp = TempDir::new().expect("temp dir");
        let cert_path = tmp.path().join("certificate.with-policy.json");
        let policy_path = tmp.path().join("policy.json");
        let policy_bytes = br#"{"schema_version":"agent_swarm-policy-v1","route_mode":"direct"}"#;
        fs::write(&policy_path, policy_bytes).expect("write policy fixture");

        let mut cert_value: serde_json::Value =
            serde_json::from_str(CERTIFICATE_FIXTURE).expect("fixture parse");
        cert_value["policy"] = json!({
            "schema_version": "agent_swarm-policy-v1",
            "policy_hash": hash_certificate_bytes(policy_bytes),
            "policy_ref": "local://runs/run-1/policy.json",
            "policy_generated_at": "2026-02-28T12:00:20Z"
        });
        let cert_bytes = serde_json::to_vec_pretty(&cert_value).expect("serialize cert");
        fs::write(&cert_path, &cert_bytes).expect("write cert with policy");
        let expected_hash = hash_certificate_bytes(&cert_bytes);

        let cert = verify_certificate_file_with_policy(
            &cert_path,
            &expected_hash,
            "0123456789abcdef0123456789abcdef01234567",
            Some(&policy_path),
            true,
        )
        .expect("matching policy file should verify");
        assert!(cert.policy.is_some());
    }

    #[test]
    fn verify_proof_file_passes_for_matching_public_inputs_hash() {
        let tmp = TempDir::new().expect("temp dir");
        let inputs_path = tmp.path().join("public_inputs.json");
        let proof_path = tmp.path().join("proof.json");

        let public_inputs = br#"{"job_id":"run-1","request_hash":"sha256:abcd"}"#;
        fs::write(&inputs_path, public_inputs).expect("write public inputs");
        let inputs_hash = hash_certificate_bytes(public_inputs);

        fs::write(
            &proof_path,
            serde_json::to_vec_pretty(&json!({
                "schema_version": "swarm-proof-envelope-v1",
                "public_inputs_sha256": inputs_hash,
                "proof_system": "groth16",
                "proof_ref": "local://proofs/run-1.bin"
            }))
            .expect("serialize proof"),
        )
        .expect("write proof");

        let verified =
            verify_proof_file(&proof_path, &inputs_path).expect("proof verification should pass");
        assert_eq!(verified.schema_version, "swarm-proof-envelope-v1");
    }

    #[test]
    fn verify_proof_file_rejects_hash_mismatch() {
        let tmp = TempDir::new().expect("temp dir");
        let inputs_path = tmp.path().join("public_inputs.json");
        let proof_path = tmp.path().join("proof.json");

        fs::write(&inputs_path, br#"{"job_id":"run-1"}"#).expect("write public inputs");
        fs::write(
            &proof_path,
            serde_json::to_vec_pretty(&json!({
                "schema_version": "swarm-proof-envelope-v1",
                "public_inputs_sha256": "sha256:deadbeef",
                "proof_system": "groth16",
                "proof_ref": "local://proofs/run-1.bin"
            }))
            .expect("serialize proof"),
        )
        .expect("write proof");

        let err = verify_proof_file(&proof_path, &inputs_path)
            .expect_err("hash mismatch should fail verification");
        assert!(err.to_string().contains("public inputs hash mismatch"));
    }
}
