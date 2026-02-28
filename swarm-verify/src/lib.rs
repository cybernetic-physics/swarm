use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Certificate {
    #[serde(rename = "type")]
    pub kind: String,
    pub job_id: String,
    pub request_hash: String,
    pub runtime: Runtime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Runtime {
    pub workflow_ref: String,
    pub runner_class: String,
    pub started_at: String,
    pub finished_at: String,
}

pub fn hash_certificate_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
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
    workflow_ref
        .rsplit('@')
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("workflow_ref must contain '@<commit_sha>'"))
}

pub fn verify_required_commit(certificate: &Certificate, required_commit: &str) -> Result<()> {
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
    let cert: Certificate = serde_json::from_slice(&bytes)?;
    Ok((cert, bytes))
}

pub fn verify_certificate_file(
    certificate_path: &Path,
    expected_artifact_hash: &str,
    required_commit: &str,
) -> Result<Certificate> {
    let (cert, bytes) = load_certificate(certificate_path)?;
    verify_certificate_hash_binding(&bytes, expected_artifact_hash)?;
    verify_required_commit(&cert, required_commit)?;
    Ok(cert)
}

#[cfg(test)]
mod tests {
    use super::{hash_certificate_bytes, verify_certificate_hash_binding};

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
}
