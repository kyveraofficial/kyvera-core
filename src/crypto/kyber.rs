use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{PublicKey, SecretKey, Ciphertext, SharedSecret};
use serde::{Deserialize, Serialize};
use hex;

// Kyber768 handles encrypted key exchange between Kyvera nodes.
// Every time two nodes connect they use this to establish a shared
// secret that encrypts their entire session. Even if someone records
// the traffic today and a quantum computer exists tomorrow, they
// still cannot decrypt it. That's the guarantee Kyber gives us.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyberKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

// The result of a key encapsulation.
// The sender gets the shared secret and sends the ciphertext to the peer.
// The peer decapsulates the ciphertext with their secret key to get
// the same shared secret. Neither side ever transmits the secret itself.
#[derive(Debug, Clone)]
pub struct KyberEncapsulation {
    pub ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

impl KyberKeyPair {
    // Generate a fresh Kyber768 key pair for this node.
    // Each node generates one of these at startup and uses it
    // for all incoming connection handshakes.
    pub fn generate() -> Self {
        let (pk, sk) = kyber768::keypair();
        KyberKeyPair {
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        }
    }

    // Encapsulate a shared secret using the recipient's public key.
    // Called by the node initiating the connection.
    // Returns the ciphertext to send and the shared secret to use
    // for encrypting the session. The secret never leaves this machine.
    pub fn encapsulate(public_key_hex: &str) -> Result<KyberEncapsulation, String> {
        let pk_bytes = hex::decode(public_key_hex)
            .map_err(|e| format!("Failed to decode public key: {}", e))?;

        let pk = kyber768::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("Invalid Kyber public key: {}", e))?;

        let (shared_secret, ciphertext) = kyber768::encapsulate(&pk);

        Ok(KyberEncapsulation {
            ciphertext: ciphertext.as_bytes().to_vec(),
            shared_secret: shared_secret.as_bytes().to_vec(),
        })
    }

    // Decapsulate a ciphertext received from a connecting peer.
    // Called by the node receiving the connection.
    // Returns the same shared secret the sender derived, without
    // either side ever transmitting the secret over the wire.
    pub fn decapsulate(&self, ciphertext_hex: &str) -> Result<Vec<u8>, String> {
        let sk = kyber768::SecretKey::from_bytes(&self.secret_key)
            .map_err(|e| format!("Failed to load secret key: {}", e))?;

        let ct_bytes = hex::decode(ciphertext_hex)
            .map_err(|e| format!("Failed to decode ciphertext: {}", e))?;

        let ct = kyber768::Ciphertext::from_bytes(&ct_bytes)
            .map_err(|e| format!("Invalid ciphertext: {}", e))?;

        let shared_secret = kyber768::decapsulate(&ct, &sk);

        Ok(shared_secret.as_bytes().to_vec())
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }
}

impl KyberEncapsulation {
    pub fn ciphertext_hex(&self) -> String {
        hex::encode(&self.ciphertext)
    }

    pub fn shared_secret_hex(&self) -> String {
        hex::encode(&self.shared_secret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KyberKeyPair::generate();

        // Kyber768 public key is 1184 bytes
        assert_eq!(keypair.public_key.len(), 1184);

        // Kyber768 secret key is 2400 bytes
        assert_eq!(keypair.secret_key.len(), 2400);
    }

    #[test]
    fn test_encapsulate_and_decapsulate() {
        let keypair = KyberKeyPair::generate();

        // Sender encapsulates using the recipient's public key
        let encapsulation = KyberKeyPair::encapsulate(&keypair.public_key_hex()).unwrap();

        // Recipient decapsulates using their secret key
        let recovered_secret = keypair
            .decapsulate(&encapsulation.ciphertext_hex())
            .unwrap();

        // Both sides must arrive at the same shared secret
        // This is the entire point of a key encapsulation mechanism
        assert_eq!(encapsulation.shared_secret, recovered_secret);
    }

    #[test]
    fn test_shared_secret_is_32_bytes() {
        let keypair = KyberKeyPair::generate();
        let encapsulation = KyberKeyPair::encapsulate(&keypair.public_key_hex()).unwrap();

        // Kyber768 shared secret is always 32 bytes
        // This becomes the symmetric encryption key for the session
        assert_eq!(encapsulation.shared_secret.len(), 32);
    }

    #[test]
    fn test_wrong_key_cannot_decapsulate() {
        let keypair1 = KyberKeyPair::generate();
        let keypair2 = KyberKeyPair::generate();

        // Encapsulate for keypair1
        let encapsulation = KyberKeyPair::encapsulate(&keypair1.public_key_hex()).unwrap();

        // keypair2 tries to decapsulate — it will get a different secret
        // Kyber doesn't error on wrong key, it just produces garbage
        // which means the session will fail to establish. That's correct behaviour.
        let wrong_secret = keypair2
            .decapsulate(&encapsulation.ciphertext_hex())
            .unwrap();

        assert_ne!(encapsulation.shared_secret, wrong_secret);
    }

    #[test]
    fn test_two_sessions_produce_different_secrets() {
        let keypair = KyberKeyPair::generate();

        let session1 = KyberKeyPair::encapsulate(&keypair.public_key_hex()).unwrap();
        let session2 = KyberKeyPair::encapsulate(&keypair.public_key_hex()).unwrap();

        // Every session gets a fresh secret even with the same key pair
        // Reusing session keys is a classic cryptographic mistake
        assert_ne!(session1.shared_secret, session2.shared_secret);
    }
}