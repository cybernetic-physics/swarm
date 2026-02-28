use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Backend {
    Local,
    Github,
    Gitlab,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteMode {
    Direct,
    ClientExit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RestoreMode {
    Checkpoint,
    ColdStart,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunSpec {
    pub run_id: String,
    pub node: String,
    pub backend: Backend,
    pub route_mode: RouteMode,
    pub workflow_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunOutcome {
    pub run_id: String,
    pub status: RunStatus,
    pub restore_mode: RestoreMode,
    pub certificate_ref: Option<String>,
    pub artifact_hash: Option<String>,
    pub next_state_id: Option<String>,
    pub next_state_cap_ref: Option<String>,
    pub next_net_cap_ref: Option<String>,
    pub errors: Vec<String>,
}

impl RunOutcome {
    pub fn queued(run_id: String) -> Self {
        Self {
            run_id,
            status: RunStatus::Queued,
            restore_mode: RestoreMode::Checkpoint,
            certificate_ref: None,
            artifact_hash: None,
            next_state_id: None,
            next_state_cap_ref: None,
            next_net_cap_ref: None,
            errors: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SchemaValidationResult {
    pub schema: String,
    pub valid: bool,
    pub errors: Vec<String>,
}
