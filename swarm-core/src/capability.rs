use anyhow::{Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CAPABILITY_VERSION_V1: u8 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    StateCap,
    NetCap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityEnvelope {
    pub version: u8,
    pub kind: CapabilityKind,
    pub state_id: String,
    pub ratchet_step: u64,
    pub chain_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityEnvelopeRedacted {
    pub version: u8,
    pub kind: CapabilityKind,
    pub state_id: String,
    pub ratchet_step: u64,
    pub chain_key_ref: String,
}

impl CapabilityEnvelope {
    pub fn validate(&self) -> Result<()> {
        if self.version != CAPABILITY_VERSION_V1 {
            bail!(
                "capability version must equal {}, got {}",
                CAPABILITY_VERSION_V1,
                self.version
            );
        }
        if self.state_id.trim().is_empty() {
            bail!("state_id must be a non-empty string");
        }
        if self.chain_key.trim().is_empty() {
            bail!("chain_key must be a non-empty string");
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self)?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(encoded: &str) -> Result<Self> {
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|err| anyhow!("invalid capability token encoding: {err}"))?;
        let envelope: Self = serde_json::from_slice(&bytes)
            .map_err(|err| anyhow!("invalid capability token payload: {err}"))?;
        envelope.validate()?;
        Ok(envelope)
    }

    pub fn redacted(&self) -> CapabilityEnvelopeRedacted {
        CapabilityEnvelopeRedacted {
            version: self.version,
            kind: self.kind.clone(),
            state_id: self.state_id.clone(),
            ratchet_step: self.ratchet_step,
            chain_key_ref: chain_key_ref(&self.chain_key),
        }
    }
}

pub fn chain_key_ref(chain_key: &str) -> String {
    let digest = Sha256::digest(chain_key.as_bytes());
    format!("ck:{}", &hex::encode(digest)[..12])
}

pub fn redact_capability_token(token: &str) -> String {
    match CapabilityEnvelope::decode(token) {
        Ok(envelope) => {
            let redacted = envelope.redacted();
            format!(
                "{}:{}:{}:{}",
                redacted.version,
                kind_as_str(&redacted.kind),
                redacted.state_id,
                redacted.chain_key_ref
            )
        }
        Err(_) => {
            if token.len() <= 8 {
                "cap:********".to_string()
            } else {
                format!("cap:{}...{}", &token[..4], &token[token.len() - 4..])
            }
        }
    }
}

fn kind_as_str(kind: &CapabilityKind) -> &'static str {
    match kind {
        CapabilityKind::StateCap => "state_cap",
        CapabilityKind::NetCap => "net_cap",
    }
}

#[cfg(test)]
mod tests {
    use super::{CapabilityEnvelope, CapabilityKind, redact_capability_token};

    fn sample_capability() -> CapabilityEnvelope {
        CapabilityEnvelope {
            version: 1,
            kind: CapabilityKind::StateCap,
            state_id: "state-123".to_string(),
            ratchet_step: 42,
            chain_key: "deadbeefcafebabe".to_string(),
        }
    }

    #[test]
    fn roundtrip_encode_decode_preserves_values() {
        let cap = sample_capability();
        let encoded = cap.encode().expect("encode");
        let decoded = CapabilityEnvelope::decode(&encoded).expect("decode");
        assert_eq!(decoded, cap);
    }

    #[test]
    fn redacted_summary_does_not_expose_chain_key() {
        let cap = sample_capability();
        let redacted = cap.redacted();
        assert_ne!(redacted.chain_key_ref, cap.chain_key);
        assert!(redacted.chain_key_ref.starts_with("ck:"));
    }

    #[test]
    fn redact_capability_token_masks_invalid_payload() {
        let redacted = redact_capability_token("bad-token");
        assert!(redacted.starts_with("cap:"));
    }
}
