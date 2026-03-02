use alloy::network::{EthereumWallet, TransactionBuilder};
use alloy::primitives::{Address, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy_signer_local::{MnemonicBuilder, PrivateKeySigner, coins_bip39::English};
use anyhow::{Context, Result, anyhow, bail};
use keyring::Entry;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use tempfile::NamedTempFile;
use tokio::runtime::Builder as RuntimeBuilder;

pub const DEFAULT_BASE_SEPOLIA_CHAIN_ID: u64 = 84_532;
pub const DEFAULT_BASE_SEPOLIA_RPC_URL: &str = "https://sepolia.base.org";

const DEFAULT_SIGNER_ALIAS: &str = "default";
const KEYRING_SERVICE: &str = "swarm-cli.wallet";
const KEYRING_ACCOUNT_PREFIX: &str = "signer.";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignerBackendKind {
    PrivateKey,
    Mnemonic,
    Keystore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSignerRecord {
    pub alias: String,
    pub backend: SignerBackendKind,
    pub address: String,
    pub keyring_account: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SignerRegistry {
    #[serde(default)]
    pub default_alias: Option<String>,
    #[serde(default)]
    pub signers: Vec<StoredSignerRecord>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletImportResult {
    pub alias: String,
    pub backend: SignerBackendKind,
    pub address: String,
    pub keyring_account: String,
    pub default_alias: String,
    pub replaced_existing: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletAddressResult {
    pub alias: String,
    pub backend: SignerBackendKind,
    pub address: String,
    pub keyring_account: String,
    pub default_alias: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletBalanceResult {
    pub alias: String,
    pub address: String,
    pub rpc_url: String,
    pub expected_chain_id: u64,
    pub chain_id: u64,
    pub balance_wei: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WalletSendResult {
    pub alias: String,
    pub from: String,
    pub to: String,
    pub value_wei: String,
    pub rpc_url: String,
    pub chain_id: u64,
    pub tx_hash: String,
}

struct LoadedSigner {
    alias: String,
    backend: SignerBackendKind,
    keyring_account: String,
    address: Address,
    signer: PrivateKeySigner,
    default_alias: String,
}

pub fn import_private_key(
    alias: Option<String>,
    private_key: Option<String>,
    set_default: bool,
) -> Result<WalletImportResult> {
    let alias = normalize_alias(alias);
    let private_key = secret_from_opt_or_prompt(private_key, "Private key (hex): ")?;
    let signer = signer_from_private_key(&private_key)?;
    upsert_signer(
        alias,
        SignerBackendKind::PrivateKey,
        signer.address(),
        private_key,
        set_default,
    )
}

pub fn import_mnemonic(
    alias: Option<String>,
    mnemonic: Option<String>,
    set_default: bool,
) -> Result<WalletImportResult> {
    let alias = normalize_alias(alias);
    let mnemonic = secret_from_opt_or_prompt(mnemonic, "Mnemonic phrase: ")?;
    let signer = signer_from_mnemonic(&mnemonic)?;
    upsert_signer(
        alias,
        SignerBackendKind::Mnemonic,
        signer.address(),
        mnemonic,
        set_default,
    )
}

pub fn import_keystore(
    alias: Option<String>,
    keystore_path: &Path,
    password: Option<String>,
    set_default: bool,
) -> Result<WalletImportResult> {
    let alias = normalize_alias(alias);
    let keystore_json = SecretString::new(
        fs::read_to_string(keystore_path)
            .with_context(|| format!("failed reading keystore {}", keystore_path.display()))?
            .into(),
    );
    let password = secret_from_opt_or_prompt(password, "Keystore password: ")?;
    let signer = signer_from_keystore_json(&keystore_json, &password)?;
    upsert_signer(
        alias,
        SignerBackendKind::Keystore,
        signer.address(),
        keystore_json,
        set_default,
    )
}

pub fn wallet_address(alias: Option<String>) -> Result<WalletAddressResult> {
    let loaded = load_signer(alias)?;
    Ok(WalletAddressResult {
        alias: loaded.alias,
        backend: loaded.backend,
        address: format!("{:#x}", loaded.address),
        keyring_account: loaded.keyring_account,
        default_alias: loaded.default_alias,
    })
}

pub fn wallet_balance(
    alias: Option<String>,
    rpc_url: &str,
    expected_chain_id: u64,
) -> Result<WalletBalanceResult> {
    let loaded = load_signer(alias)?;
    let address = loaded.address;
    let (chain_id, balance) = run_async(async move {
        let provider = ProviderBuilder::new().on_http(rpc_url.parse()?);
        let chain_id = provider.get_chain_id().await?;
        let balance = provider.get_balance(address).await?;
        Ok::<(u64, U256), anyhow::Error>((chain_id, balance))
    })?;
    if chain_id != expected_chain_id {
        bail!(
            "WALLET_CHAIN_MISMATCH: expected chain_id={}, rpc returned chain_id={}",
            expected_chain_id,
            chain_id
        );
    }
    Ok(WalletBalanceResult {
        alias: loaded.alias,
        address: format!("{:#x}", loaded.address),
        rpc_url: rpc_url.to_string(),
        expected_chain_id,
        chain_id,
        balance_wei: balance.to_string(),
    })
}

pub fn wallet_send(
    alias: Option<String>,
    rpc_url: &str,
    expected_chain_id: u64,
    to: &str,
    value_wei: &str,
) -> Result<WalletSendResult> {
    let loaded = load_signer(alias)?;
    let to = parse_address(to)?;
    let value = parse_wei(value_wei)?;
    let from = loaded.address;
    let signer = loaded.signer;
    let rpc_url_owned = rpc_url.to_string();
    let (chain_id, tx_hash) = run_async(async move {
        let wallet = EthereumWallet::new(signer);
        let provider = ProviderBuilder::new()
            .wallet(wallet)
            .on_http(rpc_url_owned.parse()?);
        let chain_id = provider.get_chain_id().await?;
        let tx = TransactionRequest::default().with_to(to).with_value(value);
        let pending = provider.send_transaction(tx).await?;
        let tx_hash = *pending.tx_hash();
        Ok::<(u64, TxHash), anyhow::Error>((chain_id, tx_hash))
    })?;
    if chain_id != expected_chain_id {
        bail!(
            "WALLET_CHAIN_MISMATCH: expected chain_id={}, rpc returned chain_id={}",
            expected_chain_id,
            chain_id
        );
    }
    Ok(WalletSendResult {
        alias: loaded.alias,
        from: format!("{:#x}", from),
        to: format!("{:#x}", to),
        value_wei: value.to_string(),
        rpc_url: rpc_url.to_string(),
        chain_id,
        tx_hash: format!("{tx_hash:#x}"),
    })
}

fn run_async<T>(fut: impl std::future::Future<Output = Result<T>>) -> Result<T> {
    let runtime = RuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .context("failed creating async runtime")?;
    runtime.block_on(fut)
}

fn upsert_signer(
    alias: String,
    backend: SignerBackendKind,
    address: Address,
    secret: SecretString,
    set_default: bool,
) -> Result<WalletImportResult> {
    let mut registry = load_registry()?;
    let keyring_account = keyring_account_for_alias(&alias);
    let replaced_existing = registry.signers.iter().any(|signer| signer.alias == alias);
    let record = StoredSignerRecord {
        alias: alias.clone(),
        backend: backend.clone(),
        address: format!("{:#x}", address),
        keyring_account: keyring_account.clone(),
    };
    registry.signers.retain(|signer| signer.alias != alias);
    registry.signers.push(record);

    if set_default || registry.default_alias.is_none() {
        registry.default_alias = Some(alias.clone());
    }
    let default_alias = registry
        .default_alias
        .clone()
        .unwrap_or_else(|| alias.clone());

    store_secret(&keyring_account, &secret)?;
    save_registry(&registry)?;

    Ok(WalletImportResult {
        alias,
        backend,
        address: format!("{:#x}", address),
        keyring_account,
        default_alias,
        replaced_existing,
    })
}

fn load_signer(alias: Option<String>) -> Result<LoadedSigner> {
    let registry = load_registry()?;
    let alias = alias.unwrap_or_else(|| {
        registry
            .default_alias
            .clone()
            .unwrap_or_else(|| DEFAULT_SIGNER_ALIAS.to_string())
    });

    let record = registry
        .signers
        .iter()
        .find(|signer| signer.alias == alias)
        .cloned()
        .ok_or_else(|| anyhow!("WALLET_SIGNER_NOT_FOUND: alias '{}' is not imported", alias))?;
    let default_alias = registry.default_alias.unwrap_or(alias.clone());

    let secret = load_secret(&record.keyring_account)?;
    let signer = match record.backend {
        SignerBackendKind::PrivateKey => signer_from_private_key(&secret)?,
        SignerBackendKind::Mnemonic => signer_from_mnemonic(&secret)?,
        SignerBackendKind::Keystore => {
            let password = secret_from_opt_or_prompt(None, "Keystore password: ")?;
            signer_from_keystore_json(&secret, &password)?
        }
    };
    let derived = signer.address();
    let expected = parse_address(&record.address)?;
    if derived != expected {
        bail!(
            "WALLET_ADDRESS_MISMATCH: stored address={} derived address={:#x}",
            record.address,
            derived
        );
    }

    Ok(LoadedSigner {
        alias: record.alias,
        backend: record.backend,
        keyring_account: record.keyring_account,
        address: derived,
        signer,
        default_alias,
    })
}

fn parse_address(value: &str) -> Result<Address> {
    Address::from_str(value).map_err(|err| anyhow!("invalid EVM address '{}': {err}", value))
}

fn parse_wei(value_wei: &str) -> Result<U256> {
    U256::from_str(value_wei).map_err(|err| anyhow!("invalid --value-wei '{}': {err}", value_wei))
}

fn signer_from_private_key(private_key: &SecretString) -> Result<PrivateKeySigner> {
    PrivateKeySigner::from_str(private_key.expose_secret())
        .map_err(|err| anyhow!("invalid private key: {err}"))
}

fn signer_from_mnemonic(mnemonic: &SecretString) -> Result<PrivateKeySigner> {
    MnemonicBuilder::<English>::default()
        .phrase(mnemonic.expose_secret())
        .build()
        .map_err(|err| anyhow!("invalid mnemonic: {err}"))
}

fn signer_from_keystore_json(
    keystore_json: &SecretString,
    password: &SecretString,
) -> Result<PrivateKeySigner> {
    let mut tmp =
        NamedTempFile::new().context("failed creating temporary file for keystore decrypt")?;
    tmp.write_all(keystore_json.expose_secret().as_bytes())
        .context("failed writing temporary keystore JSON")?;
    PrivateKeySigner::decrypt_keystore(tmp.path(), password.expose_secret())
        .map_err(|err| anyhow!("failed decrypting keystore JSON: {err}"))
}

fn normalize_alias(alias: Option<String>) -> String {
    match alias {
        Some(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => DEFAULT_SIGNER_ALIAS.to_string(),
    }
}

fn keyring_account_for_alias(alias: &str) -> String {
    format!("{KEYRING_ACCOUNT_PREFIX}{alias}")
}

fn load_registry() -> Result<SignerRegistry> {
    let path = registry_path()?;
    if !path.exists() {
        return Ok(SignerRegistry::default());
    }
    let bytes = fs::read(&path).with_context(|| format!("failed reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("invalid JSON in {}", path.display()))
}

fn save_registry(registry: &SignerRegistry) -> Result<()> {
    let path = registry_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    fs::write(&path, serde_json::to_vec_pretty(registry)?)
        .with_context(|| format!("failed writing {}", path.display()))?;
    Ok(())
}

fn registry_path() -> Result<PathBuf> {
    let home = std::env::var("HOME").map_err(|_| anyhow!("HOME is not set"))?;
    Ok(Path::new(&home).join(".swarm").join("wallet_signers.json"))
}

fn keyring_entry(keyring_account: &str) -> Result<Entry> {
    Entry::new(KEYRING_SERVICE, keyring_account)
        .map_err(|err| anyhow!("keyring init failed for '{}': {err}", keyring_account))
}

fn store_secret(keyring_account: &str, secret: &SecretString) -> Result<()> {
    keyring_entry(keyring_account)?
        .set_password(secret.expose_secret())
        .map_err(|err| {
            anyhow!(
                "failed writing keychain secret '{}': {err}",
                keyring_account
            )
        })
}

fn load_secret(keyring_account: &str) -> Result<SecretString> {
    let secret = keyring_entry(keyring_account)?
        .get_password()
        .map_err(|err| {
            anyhow!(
                "failed reading keychain secret '{}': {err}",
                keyring_account
            )
        })?;
    Ok(SecretString::new(secret.into()))
}

fn secret_from_opt_or_prompt(value: Option<String>, prompt: &str) -> Result<SecretString> {
    let raw = match value {
        Some(text) => text,
        None => rpassword::prompt_password(prompt).context("failed reading hidden prompt input")?,
    };
    if raw.trim().is_empty() {
        bail!("input cannot be empty");
    }
    Ok(SecretString::new(raw.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_alias_falls_back_to_default() {
        assert_eq!(normalize_alias(None), DEFAULT_SIGNER_ALIAS);
        assert_eq!(normalize_alias(Some("".to_string())), DEFAULT_SIGNER_ALIAS);
    }

    #[test]
    fn keyring_account_prefix_is_stable() {
        assert_eq!(
            keyring_account_for_alias("buyer"),
            "signer.buyer".to_string()
        );
    }

    #[test]
    fn parse_wei_rejects_non_numeric_values() {
        let err = parse_wei("1.23").expect_err("non-integer wei must fail");
        assert!(err.to_string().contains("invalid --value-wei"));
    }
}
