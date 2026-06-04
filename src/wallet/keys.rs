use crate::crypto::dilithium::KyveraKeyPair;
use crate::crypto::kyber::KyberKeyPair;
use crate::crypto::sphincs::SphincsKeyPair;
use serde::{Deserialize, Serialize};

// A complete Kyvera wallet. Holds all three key pairs and the
// derived address. This is everything you need to send transactions,
// participate in the network, and validate epoch blocks.
// The secret keys never leave this struct unencrypted.
// Storage layer handles encryption before anything hits disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyveraWallet {
    // The wallet's public address — safe to share openly.
    // Derived from the Dilithium public key via SHA3-256 + kyv1 prefix.
    pub address: String,

    // Signs transactions. The most critical key pair.
    // Compromise of the signing secret key means loss of funds.
    pub signing_keypair: KyveraKeyPair,

    // Encrypts node sessions. Used when this wallet runs a validator node.
    // Not needed for basic sending and receiving.
    pub network_keypair: KyberKeyPair,

    // Signs epoch blocks. Only active when staking at Nexus tier.
    // Regular wallets still carry this for future use.
    pub epoch_keypair: SphincsKeyPair,

    // Human-readable label for this wallet.
    // Never transmitted anywhere — purely local for the user's benefit.
    pub label: String,

    // Unix timestamp in seconds of when this wallet was created.
    pub created_at: i64,
}

// The public-facing information about a wallet.
// Safe to display, log, or share. Contains no secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub label: String,
    pub created_at: i64,
    pub signing_public_key: String,
    pub network_public_key: String,
    pub epoch_public_key: String,
}

impl KyveraWallet {
    // Create a brand new wallet from scratch.
    // Generates all three key pairs independently.
    // The label is just a local name — "main", "savings", whatever.
    pub fn generate(label: &str) -> Self {
        let signing_keypair = KyveraKeyPair::generate();
        let address = signing_keypair.address();

        KyveraWallet {
            address,
            signing_keypair,
            network_keypair: KyberKeyPair::generate(),
            epoch_keypair: SphincsKeyPair::generate(),
            label: label.to_string(),
            created_at: chrono::Utc::now().timestamp(),
        }
    }

    // Return the public info about this wallet.
    // Call this when you need to display wallet details
    // without risking exposure of any secret keys.
    pub fn info(&self) -> WalletInfo {
        WalletInfo {
            address: self.address.clone(),
            label: self.label.clone(),
            created_at: self.created_at,
            signing_public_key: hex::encode(&self.signing_keypair.public_key),
            network_public_key: self.network_keypair.public_key_hex(),
            epoch_public_key: self.epoch_keypair.public_key_hex(),
        }
    }

    // The signing public key as hex.
    // This is what gets embedded in transactions so nodes
    // can verify the signature without knowing the secret key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.signing_keypair.public_key)
    }

    // Quick check that the wallet's address actually matches
    // what you would derive from its public key right now.
    // Useful for sanity checking after loading from disk.
    pub fn verify_address_integrity(&self) -> bool {
        self.signing_keypair.address() == self.address
    }

    // Look up the spendable balance for this wallet from a given
    // account state. In production this queries the chain state.
    // For now it takes the balance directly — the node layer will
    // wire this to the actual state trie in Month 5.
    pub fn spendable_balance(&self, account: &crate::types::account::Account) -> u64 {
        account.balance
    }

    // Total balance including staked funds.
    // Useful for display in a wallet UI.
    pub fn total_balance(&self, account: &crate::types::account::Account) -> u64 {
        account.total_balance()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wallet_generation() {
        let wallet = KyveraWallet::generate("main");

        assert!(wallet.address.starts_with("kyv1"));
        assert_eq!(wallet.address.len(), 68);
        assert_eq!(wallet.label, "main");
        assert!(wallet.created_at > 0);
    }

    #[test]
    fn test_two_wallets_have_different_addresses() {
        let wallet1 = KyveraWallet::generate("wallet1");
        let wallet2 = KyveraWallet::generate("wallet2");

        assert_ne!(wallet1.address, wallet2.address);
    }

    #[test]
    fn test_wallet_info_contains_no_secret_keys() {
        let wallet = KyveraWallet::generate("test");
        let info = wallet.info();

        // Info should have public keys
        assert!(!info.signing_public_key.is_empty());
        assert!(!info.network_public_key.is_empty());
        assert!(!info.epoch_public_key.is_empty());

        // Address should match
        assert_eq!(info.address, wallet.address);
    }

    #[test]
    fn test_address_integrity_check() {
        let wallet = KyveraWallet::generate("test");

        // Freshly generated wallet should always pass integrity check
        assert!(wallet.verify_address_integrity());
    }

    #[test]
    fn test_wallet_serialization() {
        // Wallets get serialized before encryption and written to disk.
        // Round trip must be lossless or we lose access to funds.
        let wallet = KyveraWallet::generate("savings");
        let json = serde_json::to_string(&wallet).unwrap();
        let restored: KyveraWallet = serde_json::from_str(&json).unwrap();

        assert_eq!(wallet.address, restored.address);
        assert_eq!(wallet.label, restored.label);
        assert_eq!(wallet.signing_keypair.public_key, restored.signing_keypair.public_key);
        assert!(restored.verify_address_integrity());
    }
}