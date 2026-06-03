use bip39::{Mnemonic, Language};
use sha3::{Digest, Sha3_256};

// Seed phrases give users a human-readable backup of their wallet.
// Instead of telling someone to write down 4,000 bytes of secret key,
// they write down 24 words. Those 24 words deterministically reproduce
// the exact same key material every time. Lose your device, restore
// your wallet anywhere with just the words.
//
// We use the BIP39 standard because it is the most widely understood
// and tested seed phrase format in the entire crypto ecosystem.
// Every hardware wallet, every major software wallet understands it.

// How many words in a Kyvera seed phrase.
// 24 words gives 256 bits of entropy — the same security level
// as the Dilithium keys it protects. Using fewer words would be
// the weakest link in the chain.
pub const SEED_WORD_COUNT: usize = 24;

// Generate a fresh 24-word BIP39 seed phrase.
// Each call produces a completely different phrase.
// The user must write this down and store it somewhere safe.
// There is no recovery if it is lost.
pub fn generate_seed_phrase() -> String {
    // bip39 v2 generates from raw entropy rather than a word count directly.
    // 32 bytes of entropy = 256 bits = 24 words. That is what we want.
    let mut entropy = [0u8; 32];
    rand::Rng::fill(&mut rand::thread_rng(), &mut entropy);
    let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
        .expect("Failed to generate mnemonic — this should never happen");
    mnemonic.to_string()
}

// Derive a deterministic seed from a phrase.
// Same phrase always produces the same seed bytes.
// This seed is what we use to reconstruct the wallet key pairs.
// The passphrase is an optional extra password on top of the words.
// Empty string means no passphrase — valid and common.
pub fn seed_from_phrase(phrase: &str, passphrase: &str) -> Result<Vec<u8>, String> {
    let mnemonic = Mnemonic::parse_in(Language::English, phrase)
        .map_err(|e| format!("Invalid seed phrase: {}", e))?;

    // BIP39 standard derivation — phrase + optional passphrase -> 64 bytes
    let seed = mnemonic.to_seed(passphrase);
    Ok(seed.to_vec())
}

// Validate that a seed phrase is well-formed.
// Checks word count, that all words are in the BIP39 wordlist,
// and that the checksum at the end is valid.
// Call this before accepting user input anywhere.
pub fn validate_seed_phrase(phrase: &str) -> bool {
    Mnemonic::parse_in(Language::English, phrase).is_ok()
}

// Derive a deterministic private key seed for a specific purpose
// from the master seed. We use domain separation so the signing key,
// network key, and epoch key all derive from different parts of the
// same master seed without any of them leaking information about the others.
//
// domain should be one of:
//   "kyvera-signing"  — for the Dilithium transaction signing key
//   "kyvera-network"  — for the Kyber network encryption key
//   "kyvera-epoch"    — for the SPHINCS+ epoch block signing key
pub fn derive_key_seed(master_seed: &[u8], domain: &str) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    hasher.update(master_seed);
    hasher.update(domain.as_bytes());
    hasher.finalize().to_vec()
}

// Display-safe version of a seed phrase for confirmation screens.
// Numbers each word so users can verify them one at a time.
// "1. abandon  2. ability  3. able ..."
pub fn format_seed_phrase_for_display(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .enumerate()
        .map(|(i, word)| format!("{}. {}", i + 1, word))
        .collect::<Vec<String>>()
        .join("  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_phrase_generates_24_words() {
        let phrase = generate_seed_phrase();
        let word_count = phrase.split_whitespace().count();
        assert_eq!(word_count, SEED_WORD_COUNT);
    }

    #[test]
    fn test_two_phrases_are_different() {
        let phrase1 = generate_seed_phrase();
        let phrase2 = generate_seed_phrase();
        // If these were ever equal we have a serious randomness problem
        assert_ne!(phrase1, phrase2);
    }

    #[test]
    fn test_valid_phrase_passes_validation() {
        let phrase = generate_seed_phrase();
        assert!(validate_seed_phrase(&phrase));
    }

    #[test]
    fn test_garbage_fails_validation() {
        assert!(!validate_seed_phrase("this is not a valid seed phrase at all"));
        assert!(!validate_seed_phrase(""));
        assert!(!validate_seed_phrase("abandon abandon abandon"));
    }

    #[test]
    fn test_same_phrase_produces_same_seed() {
        let phrase = generate_seed_phrase();
        let seed1 = seed_from_phrase(&phrase, "").unwrap();
        let seed2 = seed_from_phrase(&phrase, "").unwrap();
        // Deterministic — same phrase must always give same seed
        assert_eq!(seed1, seed2);
    }

    #[test]
    fn test_different_passphrases_produce_different_seeds() {
        let phrase = generate_seed_phrase();
        let seed_no_pass = seed_from_phrase(&phrase, "").unwrap();
        let seed_with_pass = seed_from_phrase(&phrase, "my-extra-password").unwrap();
        // Same phrase, different passphrase = completely different seed
        // This is intentional — passphrase is a second factor
        assert_ne!(seed_no_pass, seed_with_pass);
    }

    #[test]
    fn test_seed_is_64_bytes() {
        let phrase = generate_seed_phrase();
        let seed = seed_from_phrase(&phrase, "").unwrap();
        // BIP39 always produces 64 bytes
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_domain_separation_produces_different_keys() {
        let phrase = generate_seed_phrase();
        let master = seed_from_phrase(&phrase, "").unwrap();

        let signing_seed = derive_key_seed(&master, "kyvera-signing");
        let network_seed = derive_key_seed(&master, "kyvera-network");
        let epoch_seed   = derive_key_seed(&master, "kyvera-epoch");

        // All three must be different — that is the point of domain separation
        assert_ne!(signing_seed, network_seed);
        assert_ne!(signing_seed, epoch_seed);
        assert_ne!(network_seed, epoch_seed);
    }

    #[test]
    fn test_format_seed_phrase_for_display() {
        let phrase = generate_seed_phrase();
        let formatted = format_seed_phrase_for_display(&phrase);

        // Should start with "1."
        assert!(formatted.starts_with("1."));
        // Should contain "24." for the last word
        assert!(formatted.contains("24."));
    }

    #[test]
    fn test_invalid_phrase_returns_error() {
        let result = seed_from_phrase("not a valid phrase at all really", "");
        assert!(result.is_err());
    }
}