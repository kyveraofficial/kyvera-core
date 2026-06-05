use sha3::{Digest, Sha3_256};
use hex;

// Everything that gets hashed on Kyvera goes through this module.
// Centralising it here means one place to update if we ever need
// to change the hash function, and one place to audit.
// We use SHA3-256 (Keccak) throughout — it is quantum resistant
// in the sense that Grover's algorithm only halves its effective
// security from 256 bits to 128 bits, which remains computationally
// infeasible for any foreseeable hardware.

// Hash a block header to produce the block's canonical identifier.
// This is what miners are grinding a nonce against.
// The input is a serialized block header — all fields concatenated
// in a deterministic order so every node computes the same hash
// for the same header regardless of platform or architecture.
pub fn hash_block_header(
    index: u64,
    timestamp: i64,
    previous_hash: &str,
    merkle_root: &str,
    nonce: u64,
    difficulty: u32,
    is_epoch_block: bool,
    epoch_index: u64,
    state_root: &str,
) -> String {
    let mut input = String::new();
    input.push_str(&index.to_string());
    input.push_str(&timestamp.to_string());
    input.push_str(previous_hash);
    input.push_str(merkle_root);
    input.push_str(&nonce.to_string());
    input.push_str(&difficulty.to_string());
    input.push_str(&(is_epoch_block as u8).to_string());
    input.push_str(&epoch_index.to_string());
    input.push_str(state_root);

    sha3_256_hex(input.as_bytes())
}

// Hash a transaction to produce its canonical identifier.
// The transaction hash is computed from all fields except
// the hash field itself — that would be circular.
pub fn hash_transaction(
    sender: &str,
    receiver: &str,
    amount: u64,
    fee: u64,
    nonce: u64,
    timestamp: i64,
    transaction_type: &str,
    data: &[u8],
    signature: &str,
) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(sender.as_bytes());
    hasher.update(receiver.as_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(fee.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.update(timestamp.to_le_bytes());
    hasher.update(transaction_type.as_bytes());
    hasher.update(data);
    hasher.update(signature.as_bytes());
    hex::encode(hasher.finalize())
}

// The core SHA3-256 function used everywhere.
// Returns lowercase hex string of the 32-byte digest.
pub fn sha3_256_hex(input: &[u8]) -> String {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

// Double SHA3-256 — hash the hash.
// Used for extra security in certain contexts like
// the genesis block commitment.
pub fn double_sha3_256(input: &[u8]) -> String {
    let first = sha3_256_hex(input);
    sha3_256_hex(first.as_bytes())
}

// Check if a hash meets the required difficulty target.
// Difficulty is expressed as the number of leading zero bits
// required in the hash. This is how proof of work works —
// miners grind until they find a nonce that produces a hash
// with enough leading zeros.
//
// difficulty 1  = 1 leading zero nibble  (easy)
// difficulty 4  = 4 leading zero nibbles (moderate)
// difficulty 8  = 8 leading zero nibbles (hard)
pub fn meets_difficulty(hash: &str, difficulty: u32) -> bool {
    let required_zeros = difficulty as usize;
    if hash.len() < required_zeros {
        return false;
    }
    hash.chars()
        .take(required_zeros)
        .all(|c| c == '0')
}

// Count the number of leading zero nibbles in a hash.
// Used by the difficulty adjustment algorithm to measure
// how hard recent blocks were to mine.
pub fn count_leading_zeros(hash: &str) -> u32 {
    hash.chars()
        .take_while(|&c| c == '0')
        .count() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_is_deterministic() {
        let input = b"kyvera genesis block";
        let hash1 = sha3_256_hex(input);
        let hash2 = sha3_256_hex(input);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sha3_256_produces_64_char_hex() {
        let hash = sha3_256_hex(b"test");
        // SHA3-256 is 32 bytes = 64 hex characters
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_different_inputs_produce_different_hashes() {
        let hash1 = sha3_256_hex(b"kyvera block 1");
        let hash2 = sha3_256_hex(b"kyvera block 2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_double_sha3_differs_from_single() {
        let input = b"kyvera";
        let single = sha3_256_hex(input);
        let double = double_sha3_256(input);
        // Double hash should differ from single hash
        assert_ne!(single, double);
        // Both should be valid 64-char hex strings
        assert_eq!(double.len(), 64);
    }

    #[test]
    fn test_block_header_hash_is_deterministic() {
        let hash1 = hash_block_header(
            0,
            1234567890,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "merkle_root_placeholder",
            42,
            4,
            true,
            0,
            "",
        );
        let hash2 = hash_block_header(
            0,
            1234567890,
            "0000000000000000000000000000000000000000000000000000000000000000",
            "merkle_root_placeholder",
            42,
            4,
            true,
            0,
            "",
        );
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64);
    }

    #[test]
    fn test_changing_nonce_changes_hash() {
        let hash1 = hash_block_header(
            0, 1234567890, "prev", "merkle", 0, 4, false, 0, ""
        );
        let hash2 = hash_block_header(
            0, 1234567890, "prev", "merkle", 1, 4, false, 0, ""
        );
        // Even a nonce change of 1 should produce a completely different hash
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_meets_difficulty_zero_is_always_true() {
        // Any hash meets difficulty 0
        let hash = sha3_256_hex(b"anything");
        assert!(meets_difficulty(&hash, 0));
    }

    #[test]
    fn test_meets_difficulty_checks_leading_zeros() {
        assert!(meets_difficulty("0000abcd", 4));
        assert!(meets_difficulty("000abcde", 3));
        assert!(!meets_difficulty("000abcde", 4));
        assert!(!meets_difficulty("abcdef00", 1));
    }

    #[test]
    fn test_count_leading_zeros() {
        assert_eq!(count_leading_zeros("0000abcd"), 4);
        assert_eq!(count_leading_zeros("000abcde"), 3);
        assert_eq!(count_leading_zeros("abcdef00"), 0);
        assert_eq!(count_leading_zeros("00000000"), 8);
    }

    #[test]
    fn test_transaction_hash_is_deterministic() {
        let hash1 = hash_transaction(
            "kyv1sender", "kyv1receiver",
            1_000_000_000, 1_000_000,
            0, 1234567890,
            "Transfer", b"", "signature"
        );
        let hash2 = hash_transaction(
            "kyv1sender", "kyv1receiver",
            1_000_000_000, 1_000_000,
            0, 1234567890,
            "Transfer", b"", "signature"
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_changing_amount_changes_transaction_hash() {
        let hash1 = hash_transaction(
            "kyv1sender", "kyv1receiver",
            1_000_000_000, 1_000_000,
            0, 1234567890, "Transfer", b"", "sig"
        );
        let hash2 = hash_transaction(
            "kyv1sender", "kyv1receiver",
            2_000_000_000, 1_000_000,
            0, 1234567890, "Transfer", b"", "sig"
        );
        assert_ne!(hash1, hash2);
    }
}