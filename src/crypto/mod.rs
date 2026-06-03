pub mod dilithium;
pub mod kyber;
pub mod sphincs;

use crate::crypto::dilithium::{KyveraKeyPair, KyveraSignature};
use crate::crypto::kyber::{KyberKeyPair, KyberEncapsulation};
use crate::crypto::sphincs::{SphincsKeyPair, SphincsSignature};
use sha3::{Digest, Sha3_256};
use hex;

// Everything a Kyvera node or wallet needs from the crypto layer
// goes through this module. Rather than importing Dilithium, Kyber,
// and SPHINCS+ separately everywhere, callers use this unified interface.
// Makes it easier to swap implementations later if NIST ever updates
// the standards, and keeps the rest of the codebase clean.

// A complete cryptographic identity for a Kyvera wallet.
// Holds all three key pairs — one for signing transactions,
// one for network session encryption, one for epoch block finality.
// In practice the wallet stores these securely on disk and loads
// them on startup. The secret keys never leave the local machine.
#[derive(Debug, Clone)]
pub struct KyveraIdentity {
    pub signing_keypair: KyveraKeyPair,
    pub network_keypair: KyberKeyPair,
    pub epoch_keypair: SphincsKeyPair,
    pub address: String,
}

// The nonce ties a signature to a specific transaction context.
// A valid nonce proves the transaction is fresh and has never
// been submitted before. Prevents replay attacks at the signature
// level before the transaction even reaches the mempool.
#[derive(Debug, Clone)]
pub struct TransactionNonce {
    // The sender's current on-chain account nonce
    pub account_nonce: u64,

    // Millisecond timestamp of when the transaction was created
    pub timestamp_ms: i64,

    // SHA3-256 hash of the current chain state root
    // Binds the signature to a specific point in chain history
    pub chain_state_hash: String,
}

impl KyveraIdentity {
    // Create a complete cryptographic identity from scratch.
    // Called once when a new wallet is created.
    // All three key pairs are generated fresh and independently.
    pub fn generate() -> Self {
        let signing_keypair = KyveraKeyPair::generate();
        let address = signing_keypair.address();
        KyveraIdentity {
            signing_keypair,
            network_keypair: KyberKeyPair::generate(),
            epoch_keypair: SphincsKeyPair::generate(),
            address,
        }
    }

    // Sign a transaction payload with the full quantum-resistant nonce.
    // The message that actually gets signed is not just the transaction —
    // it is the transaction combined with the nonce fields. This binds
    // the signature to this specific account, this specific moment,
    // and this specific point in chain history simultaneously.
    // An attacker cannot reuse this signature in any other context.
    pub fn sign_transaction(
        &self,
        transaction_bytes: &[u8],
        nonce: &TransactionNonce,
    ) -> Result<KyveraSignature, String> {
        let bound_message = bind_message_to_nonce(transaction_bytes, nonce);
        self.signing_keypair.sign(&bound_message)
    }

    // Sign an epoch block header with SPHINCS+.
    // Only called by validators when they produce or countersign
    // an epoch block. Regular wallets never need this.
    pub fn sign_epoch_block(&self, header_bytes: &[u8]) -> Result<SphincsSignature, String> {
        self.epoch_keypair.sign(header_bytes)
    }

    // Establish an encrypted session with a peer node.
    // Takes the peer's Kyber public key and returns the ciphertext
    // to send them plus the shared secret to encrypt the session with.
    pub fn initiate_session(
        peer_public_key_hex: &str,
    ) -> Result<KyberEncapsulation, String> {
        KyberKeyPair::encapsulate(peer_public_key_hex)
    }

    // Accept an incoming encrypted session from a peer.
    // Takes the ciphertext they sent and returns the shared secret.
    // Both sides now have the same secret without ever transmitting it.
    pub fn accept_session(&self, ciphertext_hex: &str) -> Result<Vec<u8>, String> {
        self.network_keypair.decapsulate(ciphertext_hex)
    }
}

impl TransactionNonce {
    pub fn new(account_nonce: u64, chain_state_hash: String) -> Self {
        TransactionNonce {
            account_nonce,
            timestamp_ms: chrono::Utc::now().timestamp_millis(),
            chain_state_hash,
        }
    }
}

// Bind a transaction payload to its nonce before signing.
// This is what makes signatures non-replayable on Kyvera.
// The signed bytes include the account nonce, the timestamp,
// and the chain state hash — any of these changing invalidates
// the signature entirely. An old signature cannot be reused
// in a new block, a new account state, or a different context.
pub fn bind_message_to_nonce(message: &[u8], nonce: &TransactionNonce) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(message);
    hasher.update(nonce.account_nonce.to_le_bytes());
    hasher.update(nonce.timestamp_ms.to_le_bytes());
    hasher.update(nonce.chain_state_hash.as_bytes());
    hasher.finalize().to_vec()
}

// Verify a transaction signature against its nonce.
// Called by nodes when they receive a transaction.
// Reconstructs the exact bytes that were signed and checks
// the signature against them. If the nonce fields have changed
// at all since signing, verification fails.
pub fn verify_transaction_signature(
    transaction_bytes: &[u8],
    nonce: &TransactionNonce,
    signature_hex: &str,
    public_key_hex: &str,
) -> bool {
    let bound_message = bind_message_to_nonce(transaction_bytes, nonce);
    let signature = match KyveraSignature::from_hex(signature_hex) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    signature.verify(&bound_message, public_key_hex)
}

// Verify an epoch block SPHINCS+ signature.
// Both the Dilithium and SPHINCS+ signatures must be valid
// for an epoch block to be accepted. This function handles
// the SPHINCS+ side of that check.
pub fn verify_epoch_block_signature(
    header_bytes: &[u8],
    signature_hex: &str,
    public_key_hex: &str,
) -> bool {
    let signature = match SphincsSignature::from_hex(signature_hex) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    signature.verify(header_bytes, public_key_hex)
}

// Compute a SHA3-256 hash of any byte slice.
// Used throughout the protocol for block hashing, merkle trees,
// address derivation, and anywhere else a hash is needed.
// Keeping it centralised here means one place to update if
// we ever need to change the hash function.
pub fn sha3_256(input: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = KyveraIdentity::generate();

        assert!(identity.address.starts_with("kyv1"));
        assert_eq!(identity.address.len(), 68);
    }

    #[test]
    fn test_two_identities_are_unique() {
        let id1 = KyveraIdentity::generate();
        let id2 = KyveraIdentity::generate();

        assert_ne!(id1.address, id2.address);
    }

    #[test]
    fn test_sign_and_verify_transaction() {
        let identity = KyveraIdentity::generate();
        let tx_bytes = b"send 10 KYV to kyv1abc";
        let nonce = TransactionNonce::new(
            0,
            "abc123chain_state_hash".to_string(),
        );

        let signature = identity.sign_transaction(tx_bytes, &nonce).unwrap();

        // Verify using the standalone function the way a node would
        assert!(verify_transaction_signature(
            tx_bytes,
            &nonce,
            &signature.to_hex(),
            &identity.signing_keypair.public_key_hex(),
        ));
    }

    #[test]
    fn test_replayed_transaction_fails() {
        let identity = KyveraIdentity::generate();
        let tx_bytes = b"send 10 KYV to kyv1abc";

        let nonce_original = TransactionNonce::new(
            0,
            "state_hash_at_block_100".to_string(),
        );

        let signature = identity.sign_transaction(tx_bytes, &nonce_original).unwrap();

        // Attacker tries to replay the same transaction with a different
        // chain state — the signature must not verify
        let nonce_replayed = TransactionNonce::new(
            0,
            "state_hash_at_block_200".to_string(),
        );

        assert!(!verify_transaction_signature(
            tx_bytes,
            &nonce_replayed,
            &signature.to_hex(),
            &identity.signing_keypair.public_key_hex(),
        ));
    }

    #[test]
    fn test_sign_and_verify_epoch_block() {
        let identity = KyveraIdentity::generate();
        let header_bytes = b"epoch_block_290000_header";

        let signature = identity.sign_epoch_block(header_bytes).unwrap();

        assert!(verify_epoch_block_signature(
            header_bytes,
            &signature.to_hex(),
            &identity.epoch_keypair.public_key_hex(),
        ));
    }

    #[test]
    fn test_session_establishment() {
        let _node_a = KyveraIdentity::generate();
        let node_b = KyveraIdentity::generate();

        // Node A initiates a session using Node B's public key
        let encapsulation = KyveraIdentity::initiate_session(
            &node_b.network_keypair.public_key_hex()
        ).unwrap();

        // Node B accepts and recovers the shared secret
        let secret_b = node_b
            .accept_session(&encapsulation.ciphertext_hex())
            .unwrap();

        // Both nodes must have arrived at the same secret
        assert_eq!(encapsulation.shared_secret, secret_b);
    }

    #[test]
    fn test_sha3_256_is_deterministic() {
        let input = b"kyvera block header";

        let hash1 = sha3_256(input);
        let hash2 = sha3_256(input);

        assert_eq!(hash1, hash2);
        // SHA3-256 output is always 32 bytes = 64 hex chars
        assert_eq!(hash1.len(), 64);
    }
}