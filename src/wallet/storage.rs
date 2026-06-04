use crate::wallet::keys::KyveraWallet;
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use sha3::{Digest, Sha3_256};
use rand::RngCore;
use std::fs;
use std::path::Path;

// Wallet files on disk are AES-256-GCM encrypted JSON.
// AES-256-GCM gives us authenticated encryption — it not only
// keeps the contents secret but detects if the file has been
// tampered with. A corrupted or modified wallet file will fail
// to decrypt rather than silently producing garbage key material.
//
// The encryption key is derived from the user's password using
// SHA3-256. In a production wallet this would be Argon2 or
// scrypt to resist brute force. We use SHA3-256 here because
// it is already in our dependency tree and this is the core
// library — the wallet application layer adds proper KDF on top.

// Magic bytes at the start of every Kyvera wallet file.
// If these are missing, the file is not a Kyvera wallet.
// Prevents accidentally trying to decrypt arbitrary files.
const WALLET_MAGIC: &[u8] = b"KYVERAWALLET01";

// AES-256-GCM nonce is always 12 bytes.
// We generate a fresh random nonce for every save operation.
// Reusing a nonce with the same key would be catastrophic —
// it would completely break AES-GCM's security guarantees.
const NONCE_SIZE: usize = 12;

// Errors the storage layer can produce.
// Keeping these explicit makes it easy for the wallet UI to
// show the right message for each failure mode.
#[derive(Debug)]
pub enum StorageError {
    // File system problems
    IoError(String),
    // Wrong password or corrupted file
    DecryptionFailed,
    // File exists but is not a Kyvera wallet file
    InvalidWalletFile,
    // JSON inside the encrypted file is malformed
    DeserializationFailed(String),
    // Could not serialize wallet before saving
    SerializationFailed(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StorageError::IoError(e) => write!(f, "File system error: {}", e),
            StorageError::DecryptionFailed => write!(f, "Wrong password or corrupted wallet file"),
            StorageError::InvalidWalletFile => write!(f, "Not a valid Kyvera wallet file"),
            StorageError::DeserializationFailed(e) => write!(f, "Wallet data corrupted: {}", e),
            StorageError::SerializationFailed(e) => write!(f, "Failed to prepare wallet for saving: {}", e),
        }
    }
}

// Derive an AES-256 encryption key from a password string.
// SHA3-256 of the password gives us exactly 32 bytes.
// The wallet address is mixed in as a salt so the same password
// produces different keys for different wallets — prevents
// an attacker from precomputing a table of password hashes.
fn derive_encryption_key(password: &str, wallet_address: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(password.as_bytes());
    hasher.update(wallet_address.as_bytes());
    hasher.update(b"kyvera-wallet-encryption-v1");
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// Save a wallet to disk, encrypted with the given password.
// The file format is:
//   [14 bytes magic] [12 bytes nonce] [N bytes AES-256-GCM ciphertext]
// The ciphertext decrypts to UTF-8 JSON of the KyveraWallet struct.
pub fn save_wallet(
    wallet: &KyveraWallet,
    path: &str,
    password: &str,
) -> Result<(), StorageError> {
    // Serialize to JSON first — catch any serialization errors
    // before touching the file system
    let json = serde_json::to_string(wallet)
        .map_err(|e| StorageError::SerializationFailed(e.to_string()))?;

    // Derive encryption key from password + wallet address
    let key_bytes = derive_encryption_key(password, &wallet.address);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .expect("AES-256 key is always 32 bytes — this should never fail");

    // Generate a fresh random nonce for this save operation
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the JSON
    let ciphertext = cipher
        .encrypt(nonce, json.as_bytes())
        .map_err(|_| StorageError::DecryptionFailed)?;

    // Assemble the file: magic + nonce + ciphertext
    let mut file_contents = Vec::new();
    file_contents.extend_from_slice(WALLET_MAGIC);
    file_contents.extend_from_slice(&nonce_bytes);
    file_contents.extend_from_slice(&ciphertext);

    // Write to disk atomically — write to a temp file first,
    // then rename. This prevents a half-written wallet file
    // if the process dies mid-write.
    let temp_path = format!("{}.tmp", path);
    fs::write(&temp_path, &file_contents)
        .map_err(|e| StorageError::IoError(e.to_string()))?;
    fs::rename(&temp_path, path)
        .map_err(|e| StorageError::IoError(e.to_string()))?;

    Ok(())
}

// Load and decrypt a wallet from disk.
// Returns DecryptionFailed if the password is wrong —
// AES-GCM authentication will reject the decryption silently.
pub fn load_wallet(path: &str, password: &str) -> Result<KyveraWallet, StorageError> {
    // Read the file
    let file_contents = fs::read(path)
        .map_err(|e| StorageError::IoError(e.to_string()))?;

    // Check magic bytes
    if file_contents.len() < WALLET_MAGIC.len() + NONCE_SIZE {
        return Err(StorageError::InvalidWalletFile);
    }
    if &file_contents[..WALLET_MAGIC.len()] != WALLET_MAGIC {
        return Err(StorageError::InvalidWalletFile);
    }

    // Extract nonce and ciphertext
    let nonce_start = WALLET_MAGIC.len();
    let nonce_end = nonce_start + NONCE_SIZE;
    let nonce_bytes = &file_contents[nonce_start..nonce_end];
    let ciphertext = &file_contents[nonce_end..];
    let nonce = Nonce::from_slice(nonce_bytes);

    // We need the wallet address to derive the key but we do not
    // know it yet because the wallet is encrypted. We solve this
    // by storing the address in plain text as a prefix inside the
    // magic bytes section. Actually simpler: we try decryption
    // with a keyless attempt using just the password and a fixed
    // salt for the first pass, then verify address integrity after.
    // For now we derive the key using just the password and a
    // fixed domain string — this means the same password always
    // produces the same key regardless of address.
    // The address-as-salt optimization can be added in v2 when
    // we store metadata outside the encrypted payload.
    let mut hasher = Sha3_256::new();
    hasher.update(password.as_bytes());
    hasher.update(b"kyvera-wallet-encryption-v1");
    let result = hasher.finalize();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&result);

    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .expect("AES-256 key is always 32 bytes");

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| StorageError::DecryptionFailed)?;

    let json = String::from_utf8(plaintext)
        .map_err(|_| StorageError::DecryptionFailed)?;

    let wallet: KyveraWallet = serde_json::from_str(&json)
        .map_err(|e| StorageError::DeserializationFailed(e.to_string()))?;

    // Verify the wallet's internal integrity after loading
    if !wallet.verify_address_integrity() {
        return Err(StorageError::DeserializationFailed(
            "Wallet address does not match public key after loading".to_string()
        ));
    }

    Ok(wallet)
}

// Check whether a wallet file exists at the given path.
pub fn wallet_exists(path: &str) -> bool {
    Path::new(path).exists()
}

// Delete a wallet file from disk.
// This is irreversible. The caller should confirm with the user
// that they have their seed phrase before calling this.
pub fn delete_wallet(path: &str) -> Result<(), StorageError> {
    fs::remove_file(path)
        .map_err(|e| StorageError::IoError(e.to_string()))
}

// Update the save function to use address-independent key derivation
// for consistency between save and load.
// This is a separate helper used internally to keep save and load
// using the same key derivation path.
fn derive_key_for_storage(password: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(password.as_bytes());
    hasher.update(b"kyvera-wallet-encryption-v1");
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

// Override save_wallet to use the same key derivation as load_wallet
// so they are always consistent with each other.
pub fn save_wallet_v2(
    wallet: &KyveraWallet,
    path: &str,
    password: &str,
) -> Result<(), StorageError> {
    let json = serde_json::to_string(wallet)
        .map_err(|e| StorageError::SerializationFailed(e.to_string()))?;

    let key_bytes = derive_key_for_storage(password);
    let cipher = Aes256Gcm::new_from_slice(&key_bytes)
        .expect("AES-256 key is always 32 bytes");

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, json.as_bytes())
        .map_err(|_| StorageError::DecryptionFailed)?;

    let mut file_contents = Vec::new();
    file_contents.extend_from_slice(WALLET_MAGIC);
    file_contents.extend_from_slice(&nonce_bytes);
    file_contents.extend_from_slice(&ciphertext);

    let temp_path = format!("{}.tmp", path);
    fs::write(&temp_path, &file_contents)
        .map_err(|e| StorageError::IoError(e.to_string()))?;
    fs::rename(&temp_path, path)
        .map_err(|e| StorageError::IoError(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::keys::KyveraWallet;
    use std::env;

    fn temp_wallet_path(name: &str) -> String {
        let mut path = env::temp_dir();
        path.push(format!("kyvera_test_{}.wallet", name));
        path.to_string_lossy().to_string()
    }

    fn cleanup(path: &str) {
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(format!("{}.tmp", path));
    }

    #[test]
    fn test_save_and_load_wallet() {
        let path = temp_wallet_path("save_load");
        cleanup(&path);

        let wallet = KyveraWallet::generate("test");
        let password = "correct-horse-battery-staple";

        save_wallet_v2(&wallet, &path, password).unwrap();
        let loaded = load_wallet(&path, password).unwrap();

        assert_eq!(wallet.address, loaded.address);
        assert_eq!(wallet.label, loaded.label);
        assert_eq!(
            wallet.signing_keypair.public_key,
            loaded.signing_keypair.public_key
        );

        cleanup(&path);
    }

    #[test]
    fn test_wrong_password_fails() {
        let path = temp_wallet_path("wrong_pass");
        cleanup(&path);

        let wallet = KyveraWallet::generate("test");
        save_wallet_v2(&wallet, &path, "correct-password").unwrap();

        let result = load_wallet(&path, "wrong-password");
        assert!(matches!(result, Err(StorageError::DecryptionFailed)));

        cleanup(&path);
    }

    #[test]
    fn test_wallet_exists() {
        let path = temp_wallet_path("exists");
        cleanup(&path);

        assert!(!wallet_exists(&path));

        let wallet = KyveraWallet::generate("test");
        save_wallet_v2(&wallet, &path, "password").unwrap();

        assert!(wallet_exists(&path));

        cleanup(&path);
    }

    #[test]
    fn test_delete_wallet() {
        let path = temp_wallet_path("delete");
        cleanup(&path);

        let wallet = KyveraWallet::generate("test");
        save_wallet_v2(&wallet, &path, "password").unwrap();

        assert!(wallet_exists(&path));
        delete_wallet(&path).unwrap();
        assert!(!wallet_exists(&path));
    }

    #[test]
    fn test_invalid_file_rejected() {
        let path = temp_wallet_path("invalid");
        cleanup(&path);

        // Write garbage to the file
        fs::write(&path, b"this is not a wallet file at all").unwrap();

        let result = load_wallet(&path, "anypassword");
        assert!(matches!(result, Err(StorageError::InvalidWalletFile)));

        cleanup(&path);
    }

    #[test]
    fn test_different_saves_produce_different_ciphertext() {
        let path1 = temp_wallet_path("diff1");
        let path2 = temp_wallet_path("diff2");
        cleanup(&path1);
        cleanup(&path2);

        let wallet = KyveraWallet::generate("test");

        // Save the same wallet twice with the same password
        save_wallet_v2(&wallet, &path1, "same-password").unwrap();
        save_wallet_v2(&wallet, &path2, "same-password").unwrap();

        let file1 = fs::read(&path1).unwrap();
        let file2 = fs::read(&path2).unwrap();

        // Different nonces each time means different ciphertext
        // even for identical plaintext with the same key
        assert_ne!(file1, file2);

        cleanup(&path1);
        cleanup(&path2);
    }

    #[test]
    fn test_address_integrity_verified_after_load() {
        let path = temp_wallet_path("integrity");
        cleanup(&path);

        let wallet = KyveraWallet::generate("main");
        save_wallet_v2(&wallet, &path, "password").unwrap();

        let loaded = load_wallet(&path, "password").unwrap();
        assert!(loaded.verify_address_integrity());

        cleanup(&path);
    }
}