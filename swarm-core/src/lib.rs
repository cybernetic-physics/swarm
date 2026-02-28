pub mod capability;
pub mod models;

pub use capability::{
    CapabilityEnvelope, CapabilityEnvelopeRedacted, CapabilityKind, chain_key_ref,
    redact_capability_token,
};
pub use models::{
    Backend, RestoreMode, RouteMode, RunOutcome, RunSpec, RunStatus, SchemaValidationResult,
};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaContract {
    kind: &'static str,
    schema_path: &'static str,
    fixture_path: &'static str,
    schema_json: &'static str,
    fixture_json: &'static str,
}

const NODE_SCHEMA_JSON: &str = include_str!("../../schemas/node.schema.json");
const CERTIFICATE_SCHEMA_JSON: &str = include_str!("../../schemas/certificate.schema.json");
const RESULT_SCHEMA_JSON: &str = include_str!("../../schemas/result.schema.json");
const NEXT_TOKENS_SCHEMA_JSON: &str = include_str!("../../schemas/next_tokens.schema.json");

const NODE_FIXTURE_JSON: &str = include_str!("../../fixtures/contracts/node.valid.json");
const CERTIFICATE_FIXTURE_JSON: &str =
    include_str!("../../fixtures/contracts/certificate.valid.json");
const RESULT_FIXTURE_JSON: &str = include_str!("../../fixtures/contracts/result.valid.json");
const NEXT_TOKENS_FIXTURE_JSON: &str =
    include_str!("../../fixtures/contracts/next_tokens.valid.json");

fn schema_contract(kind: &str) -> Option<SchemaContract> {
    match kind {
        "node" => Some(SchemaContract {
            kind: "node",
            schema_path: "schemas/node.schema.json",
            fixture_path: "fixtures/contracts/node.valid.json",
            schema_json: NODE_SCHEMA_JSON,
            fixture_json: NODE_FIXTURE_JSON,
        }),
        "certificate" => Some(SchemaContract {
            kind: "certificate",
            schema_path: "schemas/certificate.schema.json",
            fixture_path: "fixtures/contracts/certificate.valid.json",
            schema_json: CERTIFICATE_SCHEMA_JSON,
            fixture_json: CERTIFICATE_FIXTURE_JSON,
        }),
        "result" => Some(SchemaContract {
            kind: "result",
            schema_path: "schemas/result.schema.json",
            fixture_path: "fixtures/contracts/result.valid.json",
            schema_json: RESULT_SCHEMA_JSON,
            fixture_json: RESULT_FIXTURE_JSON,
        }),
        "next_tokens" => Some(SchemaContract {
            kind: "next_tokens",
            schema_path: "schemas/next_tokens.schema.json",
            fixture_path: "fixtures/contracts/next_tokens.valid.json",
            schema_json: NEXT_TOKENS_SCHEMA_JSON,
            fixture_json: NEXT_TOKENS_FIXTURE_JSON,
        }),
        _ => None,
    }
}

fn known_kinds() -> &'static [&'static str] {
    &["node", "certificate", "result", "next_tokens"]
}

pub fn validate_schema_kind(schema: &str) -> SchemaValidationResult {
    let Some(contract) = schema_contract(schema) else {
        return SchemaValidationResult {
            schema: schema.to_string(),
            valid: false,
            errors: vec![format!(
                "unknown schema '{schema}', expected one of: {}",
                known_kinds().join(", ")
            )],
        };
    };

    let mut errors = Vec::new();
    if serde_json::from_str::<Value>(contract.schema_json).is_err() {
        errors.push(format!(
            "invalid contract schema JSON in {}",
            contract.schema_path
        ));
    }

    match serde_json::from_str::<Value>(contract.fixture_json) {
        Ok(value) => {
            let fixture_errors = validate_contract_value(schema, &value);
            errors.extend(
                fixture_errors
                    .into_iter()
                    .map(|err| format!("fixture invalid in {}: {err}", contract.fixture_path)),
            );
        }
        Err(_) => errors.push(format!("invalid fixture JSON in {}", contract.fixture_path)),
    }

    SchemaValidationResult {
        schema: schema.to_string(),
        valid: errors.is_empty(),
        errors,
    }
}

pub fn validate_schema_value(schema: &str, value: &Value) -> SchemaValidationResult {
    let mut base = validate_schema_kind(schema);
    if !base.valid {
        return base;
    }
    let errors = validate_contract_value(schema, value);
    base.valid = errors.is_empty();
    base.errors = errors;
    base
}

fn validate_contract_value(schema: &str, value: &Value) -> Vec<String> {
    match schema {
        "node" => validate_node(value),
        "certificate" => validate_certificate(value),
        "result" => validate_result(value),
        "next_tokens" => validate_next_tokens(value),
        _ => vec![format!("unsupported schema '{schema}'")],
    }
}

fn validate_node(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(obj) = value.as_object() else {
        return vec!["node must be a JSON object".to_string()];
    };

    require_eq_str(
        obj.get("schema_version"),
        "agent_swarm-node-v1",
        "schema_version",
        &mut errors,
    );
    require_non_empty_string(obj.get("node_id"), "node_id", &mut errors);
    require_nullable_string(obj.get("parent_node_id"), "parent_node_id", &mut errors);
    require_non_empty_string(obj.get("created_at"), "created_at", &mut errors);

    let Some(workspace) = require_object(obj.get("workspace"), "workspace", &mut errors) else {
        return errors;
    };
    require_enum_string(
        workspace.get("mode"),
        &["snapshot", "delta"],
        "workspace.mode",
        &mut errors,
    );
    require_prefixed_hash(
        workspace.get("artifact_hash"),
        "workspace.artifact_hash",
        &mut errors,
    );
    require_non_empty_string(
        workspace.get("artifact_ref"),
        "workspace.artifact_ref",
        &mut errors,
    );

    let Some(state_db) = require_object(obj.get("state_db"), "state_db", &mut errors) else {
        return errors;
    };
    require_prefixed_hash(
        state_db.get("snapshot_hash"),
        "state_db.snapshot_hash",
        &mut errors,
    );
    require_non_empty_string(
        state_db.get("snapshot_ref"),
        "state_db.snapshot_ref",
        &mut errors,
    );
    require_non_empty_string(state_db.get("state_id"), "state_db.state_id", &mut errors);
    require_u64(
        state_db.get("ratchet_step"),
        "state_db.ratchet_step",
        &mut errors,
    );

    if let Some(engine) = require_object(state_db.get("engine"), "state_db.engine", &mut errors) {
        require_eq_str(
            engine.get("kind"),
            "sqlite-serialized",
            "state_db.engine.kind",
            &mut errors,
        );
        require_eq_str(
            engine.get("schema_version"),
            "loom-state-v1",
            "state_db.engine.schema_version",
            &mut errors,
        );
    }

    if let Some(runtime) = require_object(obj.get("runtime"), "runtime", &mut errors) {
        require_bool(
            runtime.get("checkpoint_supported"),
            "runtime.checkpoint_supported",
            &mut errors,
        );
        if let Some(restore_compat) = require_object(
            runtime.get("restore_compat"),
            "runtime.restore_compat",
            &mut errors,
        ) {
            require_non_empty_string(
                restore_compat.get("substrate"),
                "runtime.restore_compat.substrate",
                &mut errors,
            );
        }
    }

    if let Some(network) = require_object(obj.get("network"), "network", &mut errors) {
        require_enum_string(
            network.get("route_mode"),
            &["direct", "client_exit"],
            "network.route_mode",
            &mut errors,
        );
        if let Some(token) = require_object(network.get("token"), "network.token", &mut errors) {
            require_non_empty_string(
                token.get("token_ref"),
                "network.token.token_ref",
                &mut errors,
            );
            require_u64(
                token.get("ratchet_step"),
                "network.token.ratchet_step",
                &mut errors,
            );
        }
    }

    match obj.get("tags") {
        Some(Value::Array(values)) => {
            for (idx, value) in values.iter().enumerate() {
                if !value.is_string() {
                    errors.push(format!("tags[{idx}] must be a string"));
                }
            }
        }
        _ => errors.push("tags must be an array of strings".to_string()),
    }

    errors
}

fn validate_certificate(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(obj) = value.as_object() else {
        return vec!["certificate must be a JSON object".to_string()];
    };

    require_eq_str(obj.get("type"), "loom-agent-run-v1", "type", &mut errors);
    require_non_empty_string(obj.get("job_id"), "job_id", &mut errors);
    require_prefixed_hash(obj.get("request_hash"), "request_hash", &mut errors);
    require_enum_string(
        obj.get("mode"),
        &["prompt-run", "state-license"],
        "mode",
        &mut errors,
    );
    require_non_empty_string(obj.get("timestamp"), "timestamp", &mut errors);

    if let Some(parent_state) = require_object(obj.get("parent_state"), "parent_state", &mut errors)
    {
        require_non_empty_string(
            parent_state.get("state_id"),
            "parent_state.state_id",
            &mut errors,
        );
        require_prefixed_hash(
            parent_state.get("bundle_sha256"),
            "parent_state.bundle_sha256",
            &mut errors,
        );
        require_u64(
            parent_state.get("ratchet_step"),
            "parent_state.ratchet_step",
            &mut errors,
        );
    }

    if let Some(result) = require_object(obj.get("result"), "result", &mut errors) {
        require_prefixed_hash(
            result.get("response_sha256"),
            "result.response_sha256",
            &mut errors,
        );
        require_non_empty_string(
            result.get("response_locator"),
            "result.response_locator",
            &mut errors,
        );
        if let Some(new_state) =
            require_object(result.get("new_state"), "result.new_state", &mut errors)
        {
            require_non_empty_string(
                new_state.get("state_id"),
                "result.new_state.state_id",
                &mut errors,
            );
            require_prefixed_hash(
                new_state.get("bundle_sha256"),
                "result.new_state.bundle_sha256",
                &mut errors,
            );
            require_prefixed_hash(
                new_state.get("bundle_manifest_sha256"),
                "result.new_state.bundle_manifest_sha256",
                &mut errors,
            );
        }
    }

    if let Some(runtime) = require_object(obj.get("runtime"), "runtime", &mut errors) {
        require_non_empty_string(
            runtime.get("workflow_ref"),
            "runtime.workflow_ref",
            &mut errors,
        );
        require_non_empty_string(
            runtime.get("runner_class"),
            "runtime.runner_class",
            &mut errors,
        );
        require_non_empty_string(runtime.get("started_at"), "runtime.started_at", &mut errors);
        require_non_empty_string(
            runtime.get("finished_at"),
            "runtime.finished_at",
            &mut errors,
        );
    }

    if let Some(policy_value) = obj.get("policy") {
        if let Some(policy) = require_object(Some(policy_value), "policy", &mut errors) {
            require_eq_str(
                policy.get("schema_version"),
                "agent_swarm-policy-v1",
                "policy.schema_version",
                &mut errors,
            );
            require_prefixed_hash(policy.get("policy_hash"), "policy.policy_hash", &mut errors);
            require_non_empty_string(policy.get("policy_ref"), "policy.policy_ref", &mut errors);
        }
    }

    errors
}

fn validate_result(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(obj) = value.as_object() else {
        return vec!["result must be a JSON object".to_string()];
    };

    require_non_empty_string(obj.get("run_id"), "run_id", &mut errors);
    require_non_empty_string(obj.get("status"), "status", &mut errors);
    require_non_empty_string(obj.get("operation"), "operation", &mut errors);
    require_non_empty_string(obj.get("node_id"), "node_id", &mut errors);
    require_nullable_string(obj.get("parent_node_id"), "parent_node_id", &mut errors);
    require_non_empty_string(obj.get("state_id"), "state_id", &mut errors);
    require_enum_string(
        obj.get("restore_mode"),
        &["checkpoint", "cold_start"],
        "restore_mode",
        &mut errors,
    );
    require_non_empty_string(obj.get("bundle_ref"), "bundle_ref", &mut errors);
    require_prefixed_hash(obj.get("bundle_sha256"), "bundle_sha256", &mut errors);
    require_non_empty_string(obj.get("certificate_ref"), "certificate_ref", &mut errors);
    require_prefixed_hash(obj.get("artifact_hash"), "artifact_hash", &mut errors);

    errors
}

fn validate_next_tokens(value: &Value) -> Vec<String> {
    let mut errors = Vec::new();
    let Some(obj) = value.as_object() else {
        return vec!["next_tokens must be a JSON object".to_string()];
    };

    require_non_empty_string(obj.get("state_cap_next"), "state_cap_next", &mut errors);
    require_non_empty_string(obj.get("net_cap_next"), "net_cap_next", &mut errors);
    require_non_empty_string(obj.get("state_id_next"), "state_id_next", &mut errors);
    require_u64(obj.get("ratchet_step"), "ratchet_step", &mut errors);

    errors
}

fn require_object<'a>(
    value: Option<&'a Value>,
    field: &str,
    errors: &mut Vec<String>,
) -> Option<&'a serde_json::Map<String, Value>> {
    match value {
        Some(Value::Object(obj)) => Some(obj),
        _ => {
            errors.push(format!("{field} must be an object"));
            None
        }
    }
}

fn require_non_empty_string(value: Option<&Value>, field: &str, errors: &mut Vec<String>) {
    match value {
        Some(Value::String(s)) if !s.trim().is_empty() => {}
        _ => errors.push(format!("{field} must be a non-empty string")),
    }
}

fn require_nullable_string(value: Option<&Value>, field: &str, errors: &mut Vec<String>) {
    match value {
        Some(Value::String(_)) | Some(Value::Null) => {}
        _ => errors.push(format!("{field} must be a string or null")),
    }
}

fn require_u64(value: Option<&Value>, field: &str, errors: &mut Vec<String>) {
    match value.and_then(Value::as_u64) {
        Some(_) => {}
        None => errors.push(format!("{field} must be an unsigned integer")),
    }
}

fn require_bool(value: Option<&Value>, field: &str, errors: &mut Vec<String>) {
    match value.and_then(Value::as_bool) {
        Some(_) => {}
        None => errors.push(format!("{field} must be a boolean")),
    }
}

fn require_eq_str(value: Option<&Value>, expected: &str, field: &str, errors: &mut Vec<String>) {
    match value.and_then(Value::as_str) {
        Some(actual) if actual == expected => {}
        Some(actual) => errors.push(format!("{field} must equal '{expected}', got '{actual}'")),
        None => errors.push(format!("{field} must be a string")),
    }
}

fn require_enum_string(
    value: Option<&Value>,
    allowed: &[&str],
    field: &str,
    errors: &mut Vec<String>,
) {
    match value.and_then(Value::as_str) {
        Some(actual) if allowed.contains(&actual) => {}
        Some(actual) => errors.push(format!(
            "{field} must be one of [{}], got '{actual}'",
            allowed.join(", ")
        )),
        None => errors.push(format!("{field} must be a string")),
    }
}

fn require_prefixed_hash(value: Option<&Value>, field: &str, errors: &mut Vec<String>) {
    match value.and_then(Value::as_str) {
        Some(s) if s.starts_with("sha256:") && s.len() > "sha256:".len() => {}
        Some(s) => errors.push(format!(
            "{field} must be a non-empty sha256-prefixed string, got '{s}'"
        )),
        None => errors.push(format!("{field} must be a string")),
    }
}

#[cfg(test)]
mod tests {
    use super::{known_kinds, validate_schema_kind, validate_schema_value};
    use serde_json::json;

    #[test]
    fn validates_known_schema() {
        let res = validate_schema_kind("certificate");
        assert!(res.valid);
        assert!(res.errors.is_empty());
    }

    #[test]
    fn rejects_unknown_schema() {
        let res = validate_schema_kind("banana");
        assert!(!res.valid);
        assert_eq!(res.errors.len(), 1);
    }

    #[test]
    fn validates_all_frozen_contracts() {
        for kind in known_kinds() {
            let res = validate_schema_kind(kind);
            assert!(res.valid, "{kind} errors: {:?}", res.errors);
        }
    }

    #[test]
    fn validates_valid_result_instance() {
        let value = json!({
            "run_id": "run-1",
            "status": "succeeded",
            "operation": "launch",
            "node_id": "node-abc",
            "parent_node_id": "node-root",
            "state_id": "state-1",
            "restore_mode": "checkpoint",
            "bundle_ref": "local://bundles/node-abc.tar",
            "bundle_sha256": "sha256:abcd",
            "certificate_ref": "local://runs/run-1/certificate.json",
            "artifact_hash": "sha256:ef01"
        });
        let res = validate_schema_value("result", &value);
        assert!(res.valid, "errors: {:?}", res.errors);
    }

    #[test]
    fn rejects_invalid_next_tokens_instance() {
        let value = json!({
            "state_cap_next": "",
            "net_cap_next": "abc",
            "state_id_next": "state-2",
            "ratchet_step": "not-a-number"
        });
        let res = validate_schema_value("next_tokens", &value);
        assert!(!res.valid);
        assert!(!res.errors.is_empty());
    }

    #[test]
    fn rejects_invalid_certificate_policy_block() {
        let value = json!({
            "type": "loom-agent-run-v1",
            "job_id": "run-1",
            "request_hash": "sha256:abcd",
            "mode": "prompt-run",
            "parent_state": {
                "state_id": "state-parent",
                "bundle_sha256": "sha256:parent",
                "ratchet_step": 1
            },
            "result": {
                "response_sha256": "sha256:resp",
                "response_locator": "local://runs/run-1/result.json",
                "new_state": {
                    "state_id": "state-child",
                    "bundle_sha256": "sha256:child",
                    "bundle_manifest_sha256": "sha256:manifest"
                }
            },
            "runtime": {
                "workflow_ref": "owner/repo/.github/workflows/run.yml@0123456789abcdef0123456789abcdef01234567",
                "runner_class": "github-hosted",
                "started_at": "2026-02-28T12:00:10Z",
                "finished_at": "2026-02-28T12:00:20Z"
            },
            "timestamp": "2026-02-28T12:00:20Z",
            "policy": {
                "schema_version": "wrong-policy-schema",
                "policy_hash": "sha256:",
                "policy_ref": ""
            }
        });

        let res = validate_schema_value("certificate", &value);
        assert!(!res.valid);
        assert!(
            res.errors
                .iter()
                .any(|err| err.contains("policy.schema_version"))
        );
        assert!(
            res.errors
                .iter()
                .any(|err| err.contains("policy.policy_hash"))
        );
        assert!(
            res.errors
                .iter()
                .any(|err| err.contains("policy.policy_ref"))
        );
    }
}
