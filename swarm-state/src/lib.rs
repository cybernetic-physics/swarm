use anyhow::{Context, Result, anyhow, bail};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use swarm_core::{
    Backend, CapabilityEnvelope, CapabilityKind, RestoreMode, RouteMode, RunOutcome, RunSpec,
    RunStatus, chain_key_ref,
};
use tar::{Builder, Header};
use tempfile::NamedTempFile;

const INDEX_SCHEMA_VERSION: &str = "swarm-local-index-v1";
const NODE_SCHEMA_VERSION: &str = "agent_swarm-node-v1";
const STATE_ENGINE_SCHEMA_VERSION: &str = "loom-state-v1";

#[derive(Debug, Clone)]
pub struct LocalEngine {
    root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalRunArtifacts {
    pub run_id: String,
    pub node_id: String,
    pub parent_node_id: Option<String>,
    pub state_id: String,
    pub bundle_ref: String,
    pub certificate_ref: String,
    pub result_ref: String,
    pub next_tokens_ref: String,
    pub artifact_hash: String,
    pub outcome: RunOutcome,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalForkArtifacts {
    pub node_id: String,
    pub parent_node_id: String,
    pub state_id: String,
    pub bundle_ref: String,
    pub state_cap_next: String,
    pub net_cap_next: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateInspection {
    pub state_id: String,
    pub snapshot_hash: String,
    pub snapshot_ref: String,
    pub parent_state_id: Option<String>,
    pub plaintext_size_bytes: u64,
    pub event_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct EngineIndex {
    schema_version: String,
    next_sequence: u64,
    aliases: BTreeMap<String, String>,
}

impl Default for EngineIndex {
    fn default() -> Self {
        Self {
            schema_version: INDEX_SCHEMA_VERSION.to_string(),
            next_sequence: 1,
            aliases: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    pub schema_version: String,
    pub node_id: String,
    pub parent_node_id: Option<String>,
    pub created_at: String,
    pub workspace: WorkspaceBlock,
    pub state_db: StateDbBlock,
    pub runtime: RuntimeBlock,
    pub network: NetworkBlock,
    pub tags: Vec<String>,

    // Local-only secret fields for M1 scaffold.
    pub state_cap_token: String,
    pub net_cap_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceBlock {
    pub mode: String,
    pub artifact_hash: String,
    pub artifact_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDbBlock {
    pub snapshot_hash: String,
    pub snapshot_ref: String,
    pub ratchet_step: u64,
    pub state_id: String,
    pub engine: EngineBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineBlock {
    pub kind: String,
    pub schema_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeBlock {
    pub checkpoint_supported: bool,
    pub checkpoint_hash: Option<String>,
    pub checkpoint_ref: Option<String>,
    pub restore_compat: RestoreCompatBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreCompatBlock {
    pub substrate: String,
    pub image_digest: Option<String>,
    pub kernel: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBlock {
    pub route_mode: RouteMode,
    pub token: NetworkTokenBlock,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTokenBlock {
    pub token_ref: String,
    pub ratchet_step: u64,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateSnapshotMeta {
    state_id: String,
    parent_state_id: Option<String>,
    snapshot_hash: String,
    snapshot_ref: String,
    plaintext_size_bytes: u64,
}

type CapabilityToken = CapabilityEnvelope;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundleManifest {
    schema_version: String,
    node_id: String,
    state_id: String,
    snapshot_hash: String,
    snapshot_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BundleMeta {
    bundle_ref: String,
    bundle_hash: String,
}

#[derive(Debug, Clone, Copy)]
enum OperationKind {
    Launch,
    Resume,
}

impl OperationKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Launch => "launch",
            Self::Resume => "resume",
        }
    }
}

impl LocalEngine {
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    pub fn launch(&self, spec: &RunSpec, allow_cold_start: bool) -> Result<LocalRunArtifacts> {
        self.transition(spec, OperationKind::Launch, allow_cold_start)
    }

    pub fn resume(&self, spec: &RunSpec, allow_cold_start: bool) -> Result<LocalRunArtifacts> {
        self.transition(spec, OperationKind::Resume, allow_cold_start)
    }

    pub fn fork(&self, parent_node_ref: &str, label: &str) -> Result<LocalForkArtifacts> {
        let mut index = self.ensure_initialized()?;
        let parent_node = self.resolve_node(&index, parent_node_ref)?;

        let parent_state_cap = CapabilityToken::decode(&parent_node.state_cap_token)?;
        let parent_net_cap = CapabilityToken::decode(&parent_node.net_cap_token)?;

        let next_state_cap = derive_child_token(
            &parent_state_cap,
            &format!("fork:{label}"),
            &parent_state_cap.state_id,
        );
        let next_net_cap = derive_child_token(
            &parent_net_cap,
            &format!("fork:{label}"),
            &parent_state_cap.state_id,
        );

        let state_meta = self.read_state_meta(&parent_state_cap.state_id)?;

        let seq = self.take_sequence(&mut index);
        let node_id = self.make_node_id(
            &parent_node.node_id,
            "fork",
            &format!("{label}:{}", next_state_cap.ratchet_step),
            &next_state_cap.state_id,
        );

        let child = NodeRecord {
            schema_version: NODE_SCHEMA_VERSION.to_string(),
            node_id: node_id.clone(),
            parent_node_id: Some(parent_node.node_id.clone()),
            created_at: logical_time(seq),
            workspace: WorkspaceBlock {
                mode: "snapshot".to_string(),
                artifact_hash: prefixed_sha256(b""),
                artifact_ref: "local://workspace/empty".to_string(),
            },
            state_db: StateDbBlock {
                snapshot_hash: state_meta.snapshot_hash.clone(),
                snapshot_ref: state_meta.snapshot_ref.clone(),
                ratchet_step: next_state_cap.ratchet_step,
                state_id: next_state_cap.state_id.clone(),
                engine: EngineBlock {
                    kind: "sqlite-serialized".to_string(),
                    schema_version: STATE_ENGINE_SCHEMA_VERSION.to_string(),
                },
            },
            runtime: RuntimeBlock {
                checkpoint_supported: false,
                checkpoint_hash: None,
                checkpoint_ref: None,
                restore_compat: RestoreCompatBlock {
                    substrate: "local".to_string(),
                    image_digest: None,
                    kernel: None,
                },
            },
            network: NetworkBlock {
                route_mode: parent_node.network.route_mode.clone(),
                token: NetworkTokenBlock {
                    token_ref: format!(
                        "secret://net_cap/{}",
                        chain_key_ref(&next_net_cap.chain_key)
                    ),
                    ratchet_step: next_net_cap.ratchet_step,
                    expires_at: None,
                },
            },
            tags: vec!["fork".to_string(), format!("branch:{label}")],
            state_cap_token: next_state_cap.encode()?,
            net_cap_token: next_net_cap.encode()?,
        };

        self.write_node(&child)?;
        index
            .aliases
            .insert(format!("branch:{label}"), child.node_id.clone());
        self.write_index(&index)?;

        let bundle = self.build_bundle(&child)?;

        Ok(LocalForkArtifacts {
            node_id: child.node_id,
            parent_node_id: parent_node.node_id,
            state_id: child.state_db.state_id,
            bundle_ref: bundle.bundle_ref,
            state_cap_next: child.state_cap_token,
            net_cap_next: child.net_cap_token,
        })
    }

    pub fn load_run_result(&self, run_id: &str) -> Result<Value> {
        let result_path = self.runs_dir().join(run_id).join("result.json");
        if !result_path.exists() {
            bail!("run result not found: {}", result_path.display());
        }
        read_json(&result_path)
    }

    pub fn logs_hint(&self, run_id: &str) -> Value {
        json!({
            "run_id": run_id,
            "result_path": self.runs_dir().join(run_id).join("result.json"),
            "certificate_path": self.runs_dir().join(run_id).join("certificate.json"),
            "next_tokens_path": self.runs_dir().join(run_id).join("next_tokens.json")
        })
    }

    pub fn inspect_state(&self, state_id: &str) -> Result<StateInspection> {
        self.ensure_initialized()?;
        let meta = self.read_state_meta(state_id)?;
        let event_count = self.try_count_events(state_id).ok();

        Ok(StateInspection {
            state_id: meta.state_id,
            snapshot_hash: meta.snapshot_hash,
            snapshot_ref: meta.snapshot_ref,
            parent_state_id: meta.parent_state_id,
            plaintext_size_bytes: meta.plaintext_size_bytes,
            event_count,
        })
    }

    pub fn extract_bundle(&self, bundle_path: &Path, destination: &Path) -> Result<()> {
        fs::create_dir_all(destination)?;
        let file = File::open(bundle_path)?;
        let mut archive = tar::Archive::new(file);
        archive.unpack(destination)?;
        Ok(())
    }

    pub fn resolve_local_ref(&self, local_ref: &str) -> PathBuf {
        let rel = local_ref.strip_prefix("local://").unwrap_or(local_ref);
        self.root.join(rel)
    }

    fn transition(
        &self,
        spec: &RunSpec,
        operation: OperationKind,
        allow_cold_start: bool,
    ) -> Result<LocalRunArtifacts> {
        let mut index = self.ensure_initialized()?;
        let parent_node = self.resolve_node(&index, &spec.node)?;

        let run_id = self.unique_run_id(&spec.run_id, &mut index);

        let mut spec = spec.clone();
        spec.run_id = run_id.clone();

        let parent_state_cap = CapabilityToken::decode(&parent_node.state_cap_token)?;
        let parent_net_cap = CapabilityToken::decode(&parent_node.net_cap_token)?;

        let parent_plain = self.load_plain_snapshot(&parent_state_cap)?;
        let next_plain =
            self.apply_sql_event(&parent_plain, &spec, operation, &parent_node.node_id)?;

        let next_state_id = state_id_from_plaintext(&next_plain);
        let next_state_cap = derive_child_token(
            &parent_state_cap,
            &format!("{}:{}", operation.as_str(), spec.run_id),
            &next_state_id,
        );
        let next_net_cap = derive_child_token(
            &parent_net_cap,
            &format!("{}:{}", operation.as_str(), spec.run_id),
            &next_state_id,
        );

        let state_meta = self.write_encrypted_snapshot(
            &next_state_cap,
            &next_plain,
            Some(parent_state_cap.state_id.clone()),
        )?;

        let seq = self.take_sequence(&mut index);
        let node_id = self.make_node_id(
            &parent_node.node_id,
            operation.as_str(),
            &spec.run_id,
            &next_state_id,
        );

        let child = NodeRecord {
            schema_version: NODE_SCHEMA_VERSION.to_string(),
            node_id: node_id.clone(),
            parent_node_id: Some(parent_node.node_id.clone()),
            created_at: logical_time(seq),
            workspace: WorkspaceBlock {
                mode: "snapshot".to_string(),
                artifact_hash: prefixed_sha256(b""),
                artifact_ref: "local://workspace/empty".to_string(),
            },
            state_db: StateDbBlock {
                snapshot_hash: state_meta.snapshot_hash.clone(),
                snapshot_ref: state_meta.snapshot_ref.clone(),
                ratchet_step: next_state_cap.ratchet_step,
                state_id: state_meta.state_id.clone(),
                engine: EngineBlock {
                    kind: "sqlite-serialized".to_string(),
                    schema_version: STATE_ENGINE_SCHEMA_VERSION.to_string(),
                },
            },
            runtime: RuntimeBlock {
                checkpoint_supported: false,
                checkpoint_hash: None,
                checkpoint_ref: None,
                restore_compat: RestoreCompatBlock {
                    substrate: "local".to_string(),
                    image_digest: None,
                    kernel: None,
                },
            },
            network: NetworkBlock {
                route_mode: spec.route_mode.clone(),
                token: NetworkTokenBlock {
                    token_ref: format!(
                        "secret://net_cap/{}",
                        chain_key_ref(&next_net_cap.chain_key)
                    ),
                    ratchet_step: next_net_cap.ratchet_step,
                    expires_at: None,
                },
            },
            tags: vec![operation.as_str().to_string()],
            state_cap_token: next_state_cap.encode()?,
            net_cap_token: next_net_cap.encode()?,
        };

        let bundle = self.build_bundle(&child)?;

        let artifact = self.write_run_artifacts(
            &spec,
            operation,
            &parent_node,
            &child,
            &bundle,
            &next_state_cap,
            &next_net_cap,
            allow_cold_start,
        )?;

        self.write_node(&child)?;
        index
            .aliases
            .insert(format!("run:{}", spec.run_id), child.node_id.clone());
        self.write_index(&index)?;

        Ok(artifact)
    }

    fn ensure_initialized(&self) -> Result<EngineIndex> {
        self.ensure_layout()?;

        let mut index = if self.index_path().exists() {
            read_json(&self.index_path())?
        } else {
            EngineIndex::default()
        };

        if !index.aliases.contains_key("root") {
            let root = self.create_root_node(&mut index)?;
            index.aliases.insert("root".to_string(), root.node_id);
        }

        self.write_index(&index)?;
        Ok(index)
    }

    fn create_root_node(&self, index: &mut EngineIndex) -> Result<NodeRecord> {
        let root_plain = self.create_initial_snapshot()?;
        let root_state_id = state_id_from_plaintext(&root_plain);

        let root_state_cap = CapabilityToken {
            version: 1,
            kind: CapabilityKind::StateCap,
            state_id: root_state_id.clone(),
            ratchet_step: 0,
            chain_key: sha256_hex(b"root-state-chain-key"),
        };
        let root_net_cap = CapabilityToken {
            version: 1,
            kind: CapabilityKind::NetCap,
            state_id: root_state_id.clone(),
            ratchet_step: 0,
            chain_key: sha256_hex(b"root-net-chain-key"),
        };

        let state_meta = self.write_encrypted_snapshot(&root_state_cap, &root_plain, None)?;

        let seq = self.take_sequence(index);
        let node_id = format!("node-root-{}", &root_state_id[6..18]);

        let node = NodeRecord {
            schema_version: NODE_SCHEMA_VERSION.to_string(),
            node_id,
            parent_node_id: None,
            created_at: logical_time(seq),
            workspace: WorkspaceBlock {
                mode: "snapshot".to_string(),
                artifact_hash: prefixed_sha256(b""),
                artifact_ref: "local://workspace/empty".to_string(),
            },
            state_db: StateDbBlock {
                snapshot_hash: state_meta.snapshot_hash,
                snapshot_ref: state_meta.snapshot_ref,
                ratchet_step: 0,
                state_id: root_state_id,
                engine: EngineBlock {
                    kind: "sqlite-serialized".to_string(),
                    schema_version: STATE_ENGINE_SCHEMA_VERSION.to_string(),
                },
            },
            runtime: RuntimeBlock {
                checkpoint_supported: false,
                checkpoint_hash: None,
                checkpoint_ref: None,
                restore_compat: RestoreCompatBlock {
                    substrate: "local".to_string(),
                    image_digest: None,
                    kernel: None,
                },
            },
            network: NetworkBlock {
                route_mode: RouteMode::Direct,
                token: NetworkTokenBlock {
                    token_ref: format!(
                        "secret://net_cap/{}",
                        chain_key_ref(&root_net_cap.chain_key)
                    ),
                    ratchet_step: 0,
                    expires_at: None,
                },
            },
            tags: vec!["root".to_string()],
            state_cap_token: root_state_cap.encode()?,
            net_cap_token: root_net_cap.encode()?,
        };

        self.write_node(&node)?;
        Ok(node)
    }

    fn create_initial_snapshot(&self) -> Result<Vec<u8>> {
        let temp = NamedTempFile::new_in(self.tmp_dir())?;
        let conn = Connection::open(temp.path())?;
        ensure_schema(&conn)?;
        conn.execute(
            "INSERT OR REPLACE INTO kv(key, value) VALUES('engine_version', 'swarm-state-v1')",
            [],
        )?;
        conn.execute(
            "INSERT OR REPLACE INTO kv(key, value) VALUES('root_initialized', 'true')",
            [],
        )?;
        conn.execute_batch("VACUUM;")?;
        drop(conn);
        Ok(fs::read(temp.path())?)
    }

    fn apply_sql_event(
        &self,
        parent_plain: &[u8],
        spec: &RunSpec,
        operation: OperationKind,
        parent_node_id: &str,
    ) -> Result<Vec<u8>> {
        let temp = NamedTempFile::new_in(self.tmp_dir())?;
        fs::write(temp.path(), parent_plain)?;

        let conn = Connection::open(temp.path())?;
        ensure_schema(&conn)?;

        let detail = json!({
            "operation": operation.as_str(),
            "requested_node": spec.node,
            "run_id": spec.run_id,
        })
        .to_string();

        conn.execute(
            "INSERT INTO events(event_type, run_id, node_id, backend, route_mode, detail) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                operation.as_str(),
                spec.run_id,
                parent_node_id,
                backend_as_str(&spec.backend),
                route_mode_as_str(&spec.route_mode),
                detail,
            ],
        )?;
        conn.execute_batch("VACUUM;")?;
        drop(conn);

        Ok(fs::read(temp.path())?)
    }

    fn write_encrypted_snapshot(
        &self,
        token: &CapabilityToken,
        plaintext: &[u8],
        parent_state_id: Option<String>,
    ) -> Result<StateSnapshotMeta> {
        let encrypted = encrypt_snapshot(plaintext, token)?;
        let snapshot_hash = prefixed_sha256(&encrypted);

        let snapshot_path = self
            .states_dir()
            .join(format!("{}.sqlite.enc", token.state_id));
        write_bytes_atomic(&snapshot_path, &encrypted)?;

        let meta = StateSnapshotMeta {
            state_id: token.state_id.clone(),
            parent_state_id,
            snapshot_hash,
            snapshot_ref: self.local_ref(&snapshot_path),
            plaintext_size_bytes: plaintext.len() as u64,
        };

        write_json(
            &self
                .states_dir()
                .join(format!("{}.meta.json", token.state_id)),
            &meta,
        )?;

        Ok(meta)
    }

    fn load_plain_snapshot(&self, token: &CapabilityToken) -> Result<Vec<u8>> {
        let snapshot_path = self
            .states_dir()
            .join(format!("{}.sqlite.enc", token.state_id));
        let encrypted = fs::read(&snapshot_path).with_context(|| {
            format!(
                "snapshot payload missing for state_id {} at {}",
                token.state_id,
                snapshot_path.display()
            )
        })?;
        decrypt_snapshot(&encrypted, token)
    }

    fn build_bundle(&self, node: &NodeRecord) -> Result<BundleMeta> {
        let snapshot_path = self.resolve_local_ref(&node.state_db.snapshot_ref);
        let snapshot_bytes = fs::read(&snapshot_path)?;

        let manifest = BundleManifest {
            schema_version: "swarm-branch-bundle-v1".to_string(),
            node_id: node.node_id.clone(),
            state_id: node.state_db.state_id.clone(),
            snapshot_hash: node.state_db.snapshot_hash.clone(),
            snapshot_ref: node.state_db.snapshot_ref.clone(),
        };

        let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
        let node_bytes = serde_json::to_vec_pretty(node)?;

        let bundle_path = self.bundles_dir().join(format!("{}.tar", node.node_id));
        write_deterministic_tar(
            &bundle_path,
            vec![
                ("manifest.json", manifest_bytes),
                ("node.json", node_bytes),
                ("state/state.snapshot.enc", snapshot_bytes),
            ],
        )?;

        let bundle_hash = prefixed_sha256(&fs::read(&bundle_path)?);
        Ok(BundleMeta {
            bundle_ref: self.local_ref(&bundle_path),
            bundle_hash,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn write_run_artifacts(
        &self,
        spec: &RunSpec,
        operation: OperationKind,
        parent_node: &NodeRecord,
        child_node: &NodeRecord,
        bundle: &BundleMeta,
        next_state_cap: &CapabilityToken,
        next_net_cap: &CapabilityToken,
        allow_cold_start: bool,
    ) -> Result<LocalRunArtifacts> {
        self.fail_if_requested("write_run_artifacts_precommit")?;

        let run_dir = self.runs_dir().join(&spec.run_id);
        fs::create_dir_all(&run_dir)?;

        let request_hash = prefixed_sha256(
            format!(
                "{}::{}::{}::{}",
                operation.as_str(),
                spec.run_id,
                parent_node.node_id,
                child_node.node_id
            )
            .as_bytes(),
        );

        let workflow_ref = spec
            .workflow_ref
            .clone()
            .unwrap_or_else(|| "local/swarm-local-run.yml@local-dev-commit".to_string());

        let certificate = json!({
            "type": "loom-agent-run-v1",
            "job_id": spec.run_id,
            "request_hash": request_hash,
            "mode": "prompt-run",
            "parent_state": {
                "state_id": parent_node.state_db.state_id,
                "bundle_sha256": bundle.bundle_hash,
                "ratchet_step": parent_node.state_db.ratchet_step,
            },
            "result": {
                "response_sha256": prefixed_sha256(format!("{}::{}", operation.as_str(), spec.run_id).as_bytes()),
                "response_locator": self.local_ref(&run_dir.join("result.json")),
                "new_state": {
                    "state_id": child_node.state_db.state_id,
                    "bundle_sha256": bundle.bundle_hash,
                    "bundle_manifest_sha256": prefixed_sha256(b"manifest-v1")
                }
            },
            "runtime": {
                "workflow_ref": workflow_ref,
                "runner_class": "local",
                "started_at": logical_time(child_node.state_db.ratchet_step),
                "finished_at": logical_time(child_node.state_db.ratchet_step),
            },
            "timestamp": logical_time(child_node.state_db.ratchet_step),
        });

        let certificate_path = run_dir.join("certificate.json");
        let certificate_bytes = serde_json::to_vec_pretty(&certificate)?;
        write_bytes_atomic(&certificate_path, &certificate_bytes)?;
        let artifact_hash = prefixed_sha256(&certificate_bytes);

        let restore_mode = if allow_cold_start {
            RestoreMode::ColdStart
        } else {
            RestoreMode::Checkpoint
        };

        let result_path = run_dir.join("result.json");
        let result_json = json!({
            "run_id": spec.run_id,
            "status": "succeeded",
            "operation": operation.as_str(),
            "node_id": child_node.node_id,
            "parent_node_id": child_node.parent_node_id,
            "state_id": child_node.state_db.state_id,
            "restore_mode": match restore_mode {
                RestoreMode::Checkpoint => "checkpoint",
                RestoreMode::ColdStart => "cold_start",
            },
            "bundle_ref": bundle.bundle_ref,
            "bundle_sha256": bundle.bundle_hash,
            "certificate_ref": self.local_ref(&certificate_path),
            "artifact_hash": artifact_hash,
        });
        write_bytes_atomic(&result_path, &serde_json::to_vec_pretty(&result_json)?)?;

        let next_tokens_path = run_dir.join("next_tokens.json");
        let next_tokens_json = json!({
            "state_cap_next": next_state_cap.encode()?,
            "net_cap_next": next_net_cap.encode()?,
            "state_id_next": child_node.state_db.state_id,
            "ratchet_step": child_node.state_db.ratchet_step,
        });
        write_bytes_atomic(
            &next_tokens_path,
            &serde_json::to_vec_pretty(&next_tokens_json)?,
        )?;

        let outcome = RunOutcome {
            run_id: spec.run_id.clone(),
            status: RunStatus::Succeeded,
            restore_mode,
            certificate_ref: Some(self.local_ref(&certificate_path)),
            artifact_hash: Some(artifact_hash.clone()),
            next_state_id: Some(child_node.state_db.state_id.clone()),
            next_state_cap_ref: Some(format!(
                "local://runs/{}/next_tokens.json#state_cap_next",
                spec.run_id
            )),
            next_net_cap_ref: Some(format!(
                "local://runs/{}/next_tokens.json#net_cap_next",
                spec.run_id
            )),
            errors: vec![],
        };

        Ok(LocalRunArtifacts {
            run_id: spec.run_id.clone(),
            node_id: child_node.node_id.clone(),
            parent_node_id: child_node.parent_node_id.clone(),
            state_id: child_node.state_db.state_id.clone(),
            bundle_ref: bundle.bundle_ref.clone(),
            certificate_ref: self.local_ref(&certificate_path),
            result_ref: self.local_ref(&result_path),
            next_tokens_ref: self.local_ref(&next_tokens_path),
            artifact_hash,
            outcome,
        })
    }

    fn unique_run_id(&self, requested: &str, index: &mut EngineIndex) -> String {
        let mut candidate = requested.to_string();
        while self.runs_dir().join(&candidate).exists() {
            let seq = self.take_sequence(index);
            candidate = format!("{}-{seq}", requested);
        }
        candidate
    }

    fn try_count_events(&self, state_id: &str) -> Result<u64> {
        let node = self.find_node_by_state_id(state_id)?;
        let token = CapabilityToken::decode(&node.state_cap_token)?;
        let plain = self.load_plain_snapshot(&token)?;

        let temp = NamedTempFile::new_in(self.tmp_dir())?;
        fs::write(temp.path(), plain)?;
        let conn = Connection::open(temp.path())?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    fn find_node_by_state_id(&self, state_id: &str) -> Result<NodeRecord> {
        for entry in fs::read_dir(self.nodes_dir())? {
            let entry = entry?;
            if !entry.path().is_file() {
                continue;
            }
            let node: NodeRecord = read_json(&entry.path())?;
            if node.state_db.state_id == state_id {
                return Ok(node);
            }
        }

        bail!("no node found for state_id '{state_id}'")
    }

    fn read_state_meta(&self, state_id: &str) -> Result<StateSnapshotMeta> {
        read_json(&self.states_dir().join(format!("{}.meta.json", state_id)))
    }

    fn resolve_node(&self, index: &EngineIndex, node_ref: &str) -> Result<NodeRecord> {
        let node_id = index
            .aliases
            .get(node_ref)
            .cloned()
            .unwrap_or_else(|| node_ref.to_string());

        self.load_node(&node_id).with_context(|| {
            format!(
                "unknown node ref '{node_ref}' (resolved node_id '{node_id}'). known aliases: {}",
                index.aliases.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })
    }

    fn load_node(&self, node_id: &str) -> Result<NodeRecord> {
        read_json(&self.nodes_dir().join(format!("{node_id}.json")))
    }

    fn write_node(&self, node: &NodeRecord) -> Result<()> {
        write_json(
            &self.nodes_dir().join(format!("{}.json", node.node_id)),
            node,
        )
    }

    fn take_sequence(&self, index: &mut EngineIndex) -> u64 {
        let seq = index.next_sequence;
        index.next_sequence = index.next_sequence.saturating_add(1);
        seq
    }

    fn make_node_id(
        &self,
        parent_node_id: &str,
        operation: &str,
        marker: &str,
        state_id: &str,
    ) -> String {
        let hex =
            sha256_hex(format!("{parent_node_id}::{operation}::{marker}::{state_id}").as_bytes());
        format!("node-{}", &hex[..24])
    }

    fn ensure_layout(&self) -> Result<()> {
        fs::create_dir_all(&self.root)?;
        fs::create_dir_all(self.nodes_dir())?;
        fs::create_dir_all(self.states_dir())?;
        fs::create_dir_all(self.bundles_dir())?;
        fs::create_dir_all(self.runs_dir())?;
        fs::create_dir_all(self.tmp_dir())?;
        Ok(())
    }

    fn write_index(&self, index: &EngineIndex) -> Result<()> {
        write_json(&self.index_path(), index)
    }

    fn fail_if_requested(&self, failpoint: &str) -> Result<()> {
        let marker = self.root.join("failpoints").join(failpoint);
        if marker.exists() {
            bail!("injected failure: {failpoint}");
        }
        Ok(())
    }

    fn local_ref(&self, path: &Path) -> String {
        let rel = path.strip_prefix(&self.root).unwrap_or(path);
        format!("local://{}", rel.display())
    }

    fn index_path(&self) -> PathBuf {
        self.root.join("index.json")
    }

    fn nodes_dir(&self) -> PathBuf {
        self.root.join("nodes")
    }

    fn states_dir(&self) -> PathBuf {
        self.root.join("states")
    }

    fn bundles_dir(&self) -> PathBuf {
        self.root.join("bundles")
    }

    fn runs_dir(&self) -> PathBuf {
        self.root.join("runs")
    }

    fn tmp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS kv (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            run_id TEXT NOT NULL,
            node_id TEXT NOT NULL,
            backend TEXT NOT NULL,
            route_mode TEXT NOT NULL,
            detail TEXT NOT NULL
        );
    ",
    )?;
    Ok(())
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
    write_bytes_atomic(path, &bytes)?;
    Ok(())
}

fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("path has no parent for atomic write: {}", path.display()))?;
    fs::create_dir_all(parent)?;
    let mut temp = NamedTempFile::new_in(parent)?;
    temp.write_all(bytes)?;
    temp.flush()?;
    temp.persist(path)
        .map_err(|err| anyhow!("failed to persist {}: {}", path.display(), err))?;
    Ok(())
}

fn write_deterministic_tar(path: &Path, mut files: Vec<(&str, Vec<u8>)>) -> Result<()> {
    files.sort_by(|a, b| a.0.cmp(b.0));

    let file = File::create(path)?;
    let mut builder = Builder::new(file);

    for (name, bytes) in files {
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        builder.append_data(&mut header, name, Cursor::new(bytes))?;
    }

    builder.finish()?;
    Ok(())
}

fn state_id_from_plaintext(plain: &[u8]) -> String {
    format!("state-{}", sha256_hex(plain))
}

fn prefixed_sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    hex::encode(digest)
}

fn logical_time(sequence: u64) -> String {
    let sec = sequence % 60;
    let min = (sequence / 60) % 60;
    let hour = (sequence / 3600) % 24;
    format!("1970-01-01T{hour:02}:{min:02}:{sec:02}Z")
}

fn derive_child_token(
    parent: &CapabilityToken,
    context: &str,
    next_state_id: &str,
) -> CapabilityToken {
    let next_chain_key = sha256_hex(format!("{}::{context}", parent.chain_key).as_bytes());

    CapabilityToken {
        version: parent.version,
        kind: parent.kind.clone(),
        state_id: next_state_id.to_string(),
        ratchet_step: parent.ratchet_step + 1,
        chain_key: next_chain_key,
    }
}

fn encrypt_snapshot(plaintext: &[u8], token: &CapabilityToken) -> Result<Vec<u8>> {
    let key_bytes = derive_key_bytes(&token.chain_key);
    let nonce_bytes = derive_nonce_bytes(&token.state_id, token.ratchet_step);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| anyhow!("snapshot encryption failed"))
}

fn decrypt_snapshot(ciphertext: &[u8], token: &CapabilityToken) -> Result<Vec<u8>> {
    let key_bytes = derive_key_bytes(&token.chain_key);
    let nonce_bytes = derive_nonce_bytes(&token.state_id, token.ratchet_step);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("snapshot decryption failed"))
}

fn derive_key_bytes(chain_key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"swarm-state-key-v1");
    hasher.update(chain_key.as_bytes());
    let digest = hasher.finalize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&digest[..32]);
    out
}

fn derive_nonce_bytes(state_id: &str, ratchet_step: u64) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(b"swarm-state-nonce-v1");
    hasher.update(state_id.as_bytes());
    hasher.update(ratchet_step.to_le_bytes());
    let digest = hasher.finalize();

    let mut out = [0u8; 12];
    out.copy_from_slice(&digest[..12]);
    out
}

fn backend_as_str(backend: &Backend) -> &'static str {
    match backend {
        Backend::Local => "local",
        Backend::Github => "github",
        Backend::Gitlab => "gitlab",
    }
}

fn route_mode_as_str(route_mode: &RouteMode) -> &'static str {
    match route_mode {
        RouteMode::Direct => "direct",
        RouteMode::ClientExit => "client_exit",
    }
}

#[cfg(test)]
mod tests {
    use super::{LocalEngine, LocalRunArtifacts, prefixed_sha256};
    use serde_json::Value;
    use std::fs;
    use std::path::Path;
    use swarm_core::{Backend, CapabilityEnvelope, RouteMode, RunSpec, validate_schema_value};
    use tempfile::TempDir;

    #[derive(Debug, Clone)]
    struct ArtifactBytes {
        bundle: Vec<u8>,
        result: Vec<u8>,
        next_tokens: Vec<u8>,
        certificate: Vec<u8>,
    }

    fn run_spec(run_id: &str, node: &str) -> RunSpec {
        RunSpec {
            run_id: run_id.to_string(),
            node: node.to_string(),
            backend: Backend::Local,
            route_mode: RouteMode::Direct,
            workflow_ref: Some("local/swarm-local-run.yml@local-dev-commit".to_string()),
        }
    }

    fn read_json(path: &Path) -> Value {
        let bytes = fs::read(path).expect("json bytes");
        serde_json::from_slice(&bytes).expect("json parse")
    }

    fn capture_artifact_bytes(
        engine: &LocalEngine,
        artifacts: &LocalRunArtifacts,
    ) -> ArtifactBytes {
        ArtifactBytes {
            bundle: fs::read(engine.resolve_local_ref(&artifacts.bundle_ref))
                .expect("bundle bytes"),
            result: fs::read(engine.resolve_local_ref(&artifacts.result_ref))
                .expect("result bytes"),
            next_tokens: fs::read(engine.resolve_local_ref(&artifacts.next_tokens_ref))
                .expect("next_tokens bytes"),
            certificate: fs::read(engine.resolve_local_ref(&artifacts.certificate_ref))
                .expect("certificate bytes"),
        }
    }

    fn assert_run_artifact_contracts(
        engine: &LocalEngine,
        artifacts: &LocalRunArtifacts,
    ) -> (CapabilityEnvelope, CapabilityEnvelope) {
        let result_path = engine.resolve_local_ref(&artifacts.result_ref);
        let next_tokens_path = engine.resolve_local_ref(&artifacts.next_tokens_ref);
        let certificate_path = engine.resolve_local_ref(&artifacts.certificate_ref);
        let bundle_path = engine.resolve_local_ref(&artifacts.bundle_ref);

        let result_value = read_json(&result_path);
        let result_check = validate_schema_value("result", &result_value);
        assert!(
            result_check.valid,
            "result schema errors: {:?}",
            result_check.errors
        );

        let next_tokens_value = read_json(&next_tokens_path);
        let next_tokens_check = validate_schema_value("next_tokens", &next_tokens_value);
        assert!(
            next_tokens_check.valid,
            "next_tokens schema errors: {:?}",
            next_tokens_check.errors
        );

        let certificate_value = read_json(&certificate_path);
        let certificate_check = validate_schema_value("certificate", &certificate_value);
        assert!(
            certificate_check.valid,
            "certificate schema errors: {:?}",
            certificate_check.errors
        );

        let bundle_bytes = fs::read(&bundle_path).expect("bundle bytes for hash validation");
        let bundle_sha = result_value
            .get("bundle_sha256")
            .and_then(Value::as_str)
            .expect("result bundle_sha256");
        assert_eq!(bundle_sha, prefixed_sha256(&bundle_bytes));

        let artifact_hash = result_value
            .get("artifact_hash")
            .and_then(Value::as_str)
            .expect("result artifact_hash");
        assert_eq!(artifact_hash, artifacts.artifact_hash);

        let state_cap_token = next_tokens_value
            .get("state_cap_next")
            .and_then(Value::as_str)
            .expect("state_cap_next");
        let net_cap_token = next_tokens_value
            .get("net_cap_next")
            .and_then(Value::as_str)
            .expect("net_cap_next");
        let state_id_next = next_tokens_value
            .get("state_id_next")
            .and_then(Value::as_str)
            .expect("state_id_next");
        let ratchet_step = next_tokens_value
            .get("ratchet_step")
            .and_then(Value::as_u64)
            .expect("ratchet_step");

        let state_cap = CapabilityEnvelope::decode(state_cap_token).expect("decode state_cap");
        let net_cap = CapabilityEnvelope::decode(net_cap_token).expect("decode net_cap");

        assert_eq!(state_cap.state_id, state_id_next);
        assert_eq!(state_cap.ratchet_step, ratchet_step);
        assert_eq!(net_cap.state_id, state_cap.state_id);
        assert_eq!(net_cap.ratchet_step, state_cap.ratchet_step);

        (state_cap, net_cap)
    }

    #[test]
    fn launch_resume_and_inspect_state() {
        let temp = TempDir::new().expect("tempdir should be created");
        let engine = LocalEngine::new(temp.path().join(".swarm/local"));

        let launched = engine
            .launch(&run_spec("run-a", "root"), true)
            .expect("launch should succeed");

        let resumed = engine
            .resume(&run_spec("run-b", &launched.node_id), true)
            .expect("resume should succeed");

        assert_ne!(launched.state_id, resumed.state_id);

        let inspected = engine
            .inspect_state(&resumed.state_id)
            .expect("state inspect should succeed");

        assert!(inspected.event_count.unwrap_or(0) >= 2);
    }

    #[test]
    fn fork_reuses_parent_state_with_new_tokens() {
        let temp = TempDir::new().expect("tempdir should be created");
        let engine = LocalEngine::new(temp.path().join(".swarm/local"));

        let launched = engine
            .launch(&run_spec("run-a", "root"), true)
            .expect("launch should succeed");

        let forked = engine
            .fork(&launched.node_id, "experiment")
            .expect("fork should succeed");

        assert_eq!(forked.parent_node_id, launched.node_id);
        assert_eq!(forked.state_id, launched.state_id);
        assert_ne!(forked.node_id, forked.parent_node_id);
    }

    #[test]
    fn deterministic_bundle_roundtrip_extracts_expected_files() {
        let temp = TempDir::new().expect("tempdir should be created");
        let engine = LocalEngine::new(temp.path().join(".swarm/local"));

        let launched = engine
            .launch(&run_spec("run-a", "root"), true)
            .expect("launch should succeed");

        let bundle_path = engine.resolve_local_ref(&launched.bundle_ref);
        let extract_dir = temp.path().join("bundle_extract");
        engine
            .extract_bundle(&bundle_path, &extract_dir)
            .expect("bundle extract should succeed");

        assert!(extract_dir.join("manifest.json").exists());
        assert!(extract_dir.join("node.json").exists());
        assert!(extract_dir.join("state/state.snapshot.enc").exists());
    }

    #[test]
    fn deterministic_launch_artifacts_are_byte_stable_across_engines() {
        let temp_a = TempDir::new().expect("tempdir a");
        let temp_b = TempDir::new().expect("tempdir b");
        let engine_a = LocalEngine::new(temp_a.path().join(".swarm/local"));
        let engine_b = LocalEngine::new(temp_b.path().join(".swarm/local"));

        let run_a = engine_a
            .launch(&run_spec("run-conformance-launch", "root"), false)
            .expect("engine a launch");
        let run_b = engine_b
            .launch(&run_spec("run-conformance-launch", "root"), false)
            .expect("engine b launch");

        let bytes_a = capture_artifact_bytes(&engine_a, &run_a);
        let bytes_b = capture_artifact_bytes(&engine_b, &run_b);

        assert_eq!(bytes_a.bundle, bytes_b.bundle);
        assert_eq!(bytes_a.result, bytes_b.result);
        assert_eq!(bytes_a.next_tokens, bytes_b.next_tokens);
        assert_eq!(bytes_a.certificate, bytes_b.certificate);

        let (state_cap_a, net_cap_a) = assert_run_artifact_contracts(&engine_a, &run_a);
        let (state_cap_b, net_cap_b) = assert_run_artifact_contracts(&engine_b, &run_b);
        assert_eq!(state_cap_a, state_cap_b);
        assert_eq!(net_cap_a, net_cap_b);
    }

    #[test]
    fn deterministic_resume_artifacts_are_byte_stable_and_ratchet() {
        let temp_a = TempDir::new().expect("tempdir a");
        let temp_b = TempDir::new().expect("tempdir b");
        let engine_a = LocalEngine::new(temp_a.path().join(".swarm/local"));
        let engine_b = LocalEngine::new(temp_b.path().join(".swarm/local"));

        let launch_a = engine_a
            .launch(&run_spec("run-conformance-base", "root"), false)
            .expect("engine a launch");
        let launch_b = engine_b
            .launch(&run_spec("run-conformance-base", "root"), false)
            .expect("engine b launch");

        let resume_a = engine_a
            .resume(
                &run_spec("run-conformance-resume", &launch_a.node_id),
                false,
            )
            .expect("engine a resume");
        let resume_b = engine_b
            .resume(
                &run_spec("run-conformance-resume", &launch_b.node_id),
                false,
            )
            .expect("engine b resume");

        let resume_bytes_a = capture_artifact_bytes(&engine_a, &resume_a);
        let resume_bytes_b = capture_artifact_bytes(&engine_b, &resume_b);
        assert_eq!(resume_bytes_a.bundle, resume_bytes_b.bundle);
        assert_eq!(resume_bytes_a.result, resume_bytes_b.result);
        assert_eq!(resume_bytes_a.next_tokens, resume_bytes_b.next_tokens);
        assert_eq!(resume_bytes_a.certificate, resume_bytes_b.certificate);

        let (launch_state_cap_a, launch_net_cap_a) =
            assert_run_artifact_contracts(&engine_a, &launch_a);
        let (launch_state_cap_b, launch_net_cap_b) =
            assert_run_artifact_contracts(&engine_b, &launch_b);
        assert_eq!(launch_state_cap_a, launch_state_cap_b);
        assert_eq!(launch_net_cap_a, launch_net_cap_b);

        let (resume_state_cap_a, resume_net_cap_a) =
            assert_run_artifact_contracts(&engine_a, &resume_a);
        let (resume_state_cap_b, resume_net_cap_b) =
            assert_run_artifact_contracts(&engine_b, &resume_b);
        assert_eq!(resume_state_cap_a, resume_state_cap_b);
        assert_eq!(resume_net_cap_a, resume_net_cap_b);

        assert_eq!(
            resume_state_cap_a.ratchet_step,
            launch_state_cap_a.ratchet_step + 1
        );
        assert_eq!(
            resume_net_cap_a.ratchet_step,
            launch_net_cap_a.ratchet_step + 1
        );
        assert_ne!(resume_state_cap_a.state_id, launch_state_cap_a.state_id);
        assert_ne!(resume_net_cap_a.state_id, launch_net_cap_a.state_id);
    }

    #[test]
    fn launch_failure_during_artifact_write_does_not_commit_rotated_alias() {
        let temp = TempDir::new().expect("tempdir should be created");
        let engine = LocalEngine::new(temp.path().join(".swarm/local"));

        let marker = temp
            .path()
            .join(".swarm/local/failpoints/write_run_artifacts_precommit");
        fs::create_dir_all(marker.parent().expect("failpoint dir")).expect("create failpoint dir");
        fs::write(&marker, b"1").expect("write failpoint marker");

        let err = engine
            .launch(&run_spec("run-fail-atomicity", "root"), false)
            .expect_err("launch should fail with injected failpoint");
        assert!(
            err.to_string()
                .contains("injected failure: write_run_artifacts_precommit"),
            "unexpected error: {err}"
        );

        let index_path = temp.path().join(".swarm/local/index.json");
        let index = read_json(&index_path);
        let aliases = index
            .get("aliases")
            .and_then(Value::as_object)
            .expect("aliases object");
        assert!(!aliases.contains_key("run:run-fail-atomicity"));

        let nodes_dir = temp.path().join(".swarm/local/nodes");
        let node_count = fs::read_dir(&nodes_dir)
            .expect("nodes dir")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
            .count();
        assert_eq!(node_count, 1, "only root node should be committed");

        fs::remove_file(&marker).expect("remove failpoint marker");

        let recovered = engine
            .launch(&run_spec("run-fail-atomicity", "root"), false)
            .expect("launch should recover once failpoint is removed");
        assert_eq!(recovered.run_id, "run-fail-atomicity");

        let index_after = read_json(&index_path);
        let aliases_after = index_after
            .get("aliases")
            .and_then(Value::as_object)
            .expect("aliases object after recovery");
        let alias_node = aliases_after
            .get("run:run-fail-atomicity")
            .and_then(Value::as_str)
            .expect("run alias should be present after recovery");
        assert_eq!(alias_node, recovered.node_id);
    }
}
