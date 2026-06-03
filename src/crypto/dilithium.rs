use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};
use sha3::{Digest, Sha3_256};
use hex;

// Wraps a Dilithium3 key pair.
// Dilithium3 gives us 128-bit post-quantum security — the same
// security level NIST recommends for long-term data protection.
// We use Dilithium3 specifically because it hits the sweet spot
// between signature size and security. Dilithium2 is faster but
// weaker. Dilithium5 is stronger but the signatures get heavy.
#[derive(Debug, Clone)]
pub struct KyveraKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

// A signed transaction or message ready to broadcast.
// Keeping the signature separate from the message is deliberate —
// nodes verify signatures without needing to re-parse the payload.
#[derive(Debug, Clone)]
pub struct KyveraSignature {
    pub signature_bytes: Vec<u8>,
}

impl KyveraKeyPair {
    // Generate a fresh Dilithium3 key pair.
    // Every new Kyvera wallet calls this exactly once.
    // The secret key never leaves the wallet. Ever.
    pub fn generate() -> Self {
        let (pk, sk) = dilithium3::keypair();
        KyveraKeyPair {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    // Derive a wallet address from the public key.
    // We hash the public key with SHA3-256 and take the full 32 bytes
    // encoded as hex with a "kyv1" prefix for human readability.
    // The prefix makes Kyvera addresses instantly recognisable and
    // prevents accidentally sending to an address from another chain.
    pub fn address(&self) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(&self.public_key);
        let hash = hasher.finalize();
        format!("kyv1{}", hex::encode(hash))
    }

    // Sign a message with this key pair.
    // In practice the message is always a serialized transaction.
    // Returns the detached signature bytes — we store the signature
    // separately from the message rather than prepending it.
    pub fn sign(&self, message: &[u8]) -> Result<KyveraSignature, String> {
        let sk = dilithium3::SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| format!("Failed to load secret key: {}", e))?;

        let sig = dilithium3::detached_sign(message, &sk);

        Ok(KyveraSignature {
            signature_bytes: sig.as_bytes().to_vec(),
        })
    }

    // Return just the public key as a hex string.
    // This is what gets stored in transactions and broadcast to the network.
    // Nodes use this to verify signatures without ever seeing the secret key.
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }
}

impl KyveraSignature {
    // Verify a detached signature against a message and public key.
    // Called by every node that receives a transaction before
    // it gets anywhere near the mempool.
    // Returns true only if the signature is valid.
    // Any error — wrong key, tampered message, bad bytes — returns false.
    // We intentionally swallow the error detail here. Callers don't need
    // to know why verification failed, just that it did.
    pub fn verify(&self, message: &[u8], public_key_hex: &str) -> bool {
        let pk_bytes = match hex::decode(public_key_hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let pk = match dilithium3::PublicKey::from_bytes(&pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match dilithium3::DetachedSignature::from_bytes(&self.signature_bytes) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
    }

    // Encode the signature as hex for storage and transmission.
    // Dilithium3 signatures are 3,293 bytes — significantly larger
    // than ECDSA's 64 bytes. This is the tradeoff for quantum resistance.
    // The dual-block architecture exists partly to absorb this overhead.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.signature_bytes)
    }

    // Reconstruct a signature from a hex string pulled from storage or
    // received over the network.
    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| format!("Failed to decode signature hex: {}", e))?;
        Ok(KyveraSignature { signature_bytes: bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KyveraKeyPair::generate();

        // Dilithium3 public key is 1952 bytes
        assert_eq!(keypair.public_key.len(), 1952);

        // Dilithium3 secret key is 4000 bytes
        assert_eq!(keypair.secret_key.len(), 4032);
    }

    #[test]
    fn test_address_derivation() {
        let keypair = KyveraKeyPair::generate();
        let address = keypair.address();

        // Every Kyvera address starts with kyv1
        assert!(address.starts_with("kyv1"));

        // kyv1 prefix + 64 hex chars from SHA3-256
        assert_eq!(address.len(), 68);
    }

    #[test]
    fn test_two_keypairs_produce_different_addresses() {
        let keypair1 = KyveraKeyPair::generate();
        let keypair2 = KyveraKeyPair::generate();

        // Sanity check — two different wallets should never share an address
        assert_ne!(keypair1.address(), keypair2.address());
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = KyveraKeyPair::generate();
        let message = b"send 10 KYV to kyv1abc";

        let signature = keypair.sign(message).unwrap();

        // Valid signature should verify cleanly
        assert!(signature.verify(message, &keypair.public_key_hex()));
    }

    #[test]
    fn test_tampered_message_fails_verification() {
        let keypair = KyveraKeyPair::generate();
        let message = b"send 10 KYV to kyv1abc";
        let tampered = b"send 999 KYV to kyv1abc";

        let signature = keypair.sign(message).unwrap();

        // Tampered message must not verify — this is the whole point
        assert!(!signature.verify(tampered, &keypair.public_key_hex()));
    }

    #[test]
    fn test_wrong_key_fails_verification() {
        let keypair1 = KyveraKeyPair::generate();
        let keypair2 = KyveraKeyPair::generate();
        let message = b"send 10 KYV to kyv1abc";

        let signature = keypair1.sign(message).unwrap();

        // Signature from keypair1 must not verify against keypair2's public key
        assert!(!signature.verify(message, &keypair2.public_key_hex()));
    }

    #[test]
    fn test_signature_hex_round_trip() {
        let keypair = KyveraKeyPair::generate();
        let message = b"test transaction payload";

        let signature = keypair.sign(message).unwrap();
        let hex = signature.to_hex();

        // Reconstruct from hex and verify it still works
        let reconstructed = KyveraSignature::from_hex(&hex).unwrap();
        assert!(reconstructed.verify(message, &keypair.public_key_hex()));

        // Dilithium3 signature is 3309 bytes = 6618 hex chars
        assert_eq!(hex.len(), 6618);
    }
}