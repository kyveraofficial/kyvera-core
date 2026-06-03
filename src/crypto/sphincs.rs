use pqcrypto_sphincsplus::sphincssha2128fsimple;
use pqcrypto_traits::sign::{PublicKey, SecretKey, DetachedSignature};
use serde::{Deserialize, Serialize};
use hex;

// SPHINCS+ is the backup layer on top of Dilithium.
// It is only used on epoch blocks, not every transaction.
// The reason it exists at all is defense-in-depth — if someone
// ever breaks the math behind lattice-based cryptography and
// Dilithium falls, SPHINCS+ is still standing because it relies
// entirely on hash functions, not lattice problems.
// Hash functions are the most battle-tested primitive in cryptography.
// Breaking SHA2 would break the entire internet, not just Kyvera.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SphincsKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SphincsSignature {
    pub signature_bytes: Vec<u8>,
}

impl SphincsKeyPair {
    // Generate a SPHINCS+ key pair for epoch block signing.
    // In practice each validator holds one of these alongside
    // their Dilithium key pair. Epoch blocks get signed by both.
    pub fn generate() -> Self {
        let (pk, sk) = sphincssha2128fsimple::keypair();
        SphincsKeyPair {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    // Sign an epoch block header with SPHINCS+.
    // The message here is always a serialized epoch block header.
    // We sign the header not the full block — same reason as Dilithium,
    // nodes can verify finality without downloading every transaction.
    pub fn sign(&self, message: &[u8]) -> Result<SphincsSignature, String> {
        let sk = sphincssha2128fsimple::SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| format!("Failed to load SPHINCS+ secret key: {}", e))?;

        let sig = sphincssha2128fsimple::detached_sign(message, &sk);

        Ok(SphincsSignature {
            signature_bytes: sig.as_bytes().to_vec(),
        })
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }
}

impl SphincsSignature {
    // Verify a SPHINCS+ signature on an epoch block header.
    // Called by every node when they receive an epoch block.
    // An epoch block with an invalid SPHINCS+ signature is rejected
    // regardless of whether the Dilithium signature is valid.
    // Both must pass. That is the defense-in-depth guarantee.
    pub fn verify(&self, message: &[u8], public_key_hex: &str) -> bool {
        let pk_bytes = match hex::decode(public_key_hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        let pk = match sphincssha2128fsimple::PublicKey::from_bytes(&pk_bytes) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        let sig = match sphincssha2128fsimple::DetachedSignature::from_bytes(
            &self.signature_bytes
        ) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        sphincssha2128fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.signature_bytes)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| format!("Failed to decode SPHINCS+ signature hex: {}", e))?;
        Ok(SphincsSignature { signature_bytes: bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = SphincsKeyPair::generate();

        // SPHINCS+-SHA2-128f public key is 32 bytes
        assert_eq!(keypair.public_key.len(), 32);

        // SPHINCS+-SHA2-128f secret key is 64 bytes
        assert_eq!(keypair.secret_key.len(), 64);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = SphincsKeyPair::generate();
        let epoch_block_header = b"epoch_block_header_bytes_placeholder";

        let signature = keypair.sign(epoch_block_header).unwrap();

        assert!(signature.verify(epoch_block_header, &keypair.public_key_hex()));
    }

    #[test]
    fn test_tampered_message_fails() {
        let keypair = SphincsKeyPair::generate();
        let original = b"epoch block 290000";
        let tampered = b"epoch block 290001";

        let signature = keypair.sign(original).unwrap();

        assert!(!signature.verify(tampered, &keypair.public_key_hex()));
    }

    #[test]
    fn test_wrong_key_fails() {
        let keypair1 = SphincsKeyPair::generate();
        let keypair2 = SphincsKeyPair::generate();
        let message = b"epoch block header";

        let signature = keypair1.sign(message).unwrap();

        assert!(!signature.verify(message, &keypair2.public_key_hex()));
    }

    #[test]
    fn test_hex_round_trip() {
        let keypair = SphincsKeyPair::generate();
        let message = b"epoch block header";

        let signature = keypair.sign(message).unwrap();
        let hex = signature.to_hex();
        let reconstructed = SphincsSignature::from_hex(&hex).unwrap();

        assert!(reconstructed.verify(message, &keypair.public_key_hex()));
    }
}