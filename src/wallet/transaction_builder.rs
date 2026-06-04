use crate::types::transaction::{Transaction, TransactionType};
use crate::wallet::keys::KyveraWallet;
use crate::crypto::{TransactionNonce, bind_message_to_nonce, sha3_256};

// Builds and signs transactions from a wallet.
// This is the layer between the wallet and the network.
// The wallet holds keys. The builder uses those keys to create
// properly formed, signed transactions ready to broadcast.
// Nothing leaves this module unsigned.

#[derive(Debug)]
pub enum BuilderError {
    // Wallet cannot cover amount plus fee
    InsufficientBalance { available: u64, required: u64 },
    // Signing failed — should be extremely rare
    SigningFailed(String),
    // Invalid recipient address format
    InvalidAddress(String),
    // Amount is zero — pointless transaction
    ZeroAmount,
}

impl std::fmt::Display for BuilderError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BuilderError::InsufficientBalance { available, required } =>
                write!(f, "Insufficient balance: have {} KYV units, need {}", available, required),
            BuilderError::SigningFailed(e) =>
                write!(f, "Transaction signing failed: {}", e),
            BuilderError::InvalidAddress(a) =>
                write!(f, "Invalid address format: {}", a),
            BuilderError::ZeroAmount =>
                write!(f, "Transaction amount cannot be zero"),
        }
    }
}

// Validate that an address looks like a Kyvera address.
// kyv1 prefix followed by exactly 64 hex characters.
// This is a format check only — it does not verify the address
// exists on chain or has ever received funds.
pub fn validate_address(address: &str) -> bool {
    if !address.starts_with("kyv1") {
        return false;
    }
    let hex_part = &address[4..];
    if hex_part.len() != 64 {
        return false;
    }
    hex_part.chars().all(|c| c.is_ascii_hexdigit())
}

// Build and sign a KYV transfer transaction.
// Takes the sender's wallet, recipient address, amount, fee,
// and the current chain state hash for replay protection.
// Returns a fully signed Transaction ready to broadcast.
pub fn build_transfer(
    wallet: &KyveraWallet,
    recipient: &str,
    amount: u64,
    fee: u64,
    account_nonce: u64,
    chain_state_hash: &str,
) -> Result<Transaction, BuilderError> {
    // Basic sanity checks before touching any crypto
    if amount == 0 {
        return Err(BuilderError::ZeroAmount);
    }
    if !validate_address(recipient) {
        return Err(BuilderError::InvalidAddress(recipient.to_string()));
    }

    // Build the unsigned transaction first
    let mut tx = Transaction::new(
        wallet.address.clone(),
        recipient.to_string(),
        amount,
        fee,
        account_nonce,
        TransactionType::Transfer,
        vec![],
    );

    // Serialize the transaction payload for signing.
    // We sign the JSON of the transaction without the signature
    // and hash fields — those get filled in after signing.
    let tx_payload = serde_json::to_vec(&tx)
        .map_err(|e| BuilderError::SigningFailed(e.to_string()))?;

    // Build the nonce that binds this signature to this specific
    // account state and chain height
    let nonce = TransactionNonce::new(
        account_nonce,
        chain_state_hash.to_string(),
    );

    // Sign with Dilithium3
    let signature = wallet.signing_keypair
        .sign(&bind_message_to_nonce(&tx_payload, &nonce))
        .map_err(|e| BuilderError::SigningFailed(e))?;

    // Fill in the signature and compute the transaction hash
    tx.signature = signature.to_hex();
    tx.hash = compute_transaction_hash(&tx);

    Ok(tx)
}

// Build and sign a stake lock transaction.
// Locks KYV into the staking contract to become a validator.
// The amount determines which tier the account qualifies for.
pub fn build_stake_lock(
    wallet: &KyveraWallet,
    amount: u64,
    fee: u64,
    account_nonce: u64,
    chain_state_hash: &str,
) -> Result<Transaction, BuilderError> {
    if amount == 0 {
        return Err(BuilderError::ZeroAmount);
    }

    // Stake lock targets the staking contract address
    // In production this will be the genesis-deployed contract address
    // For now we use a well-known placeholder
    let staking_contract = "kyv1000000000000000000000000000000000000000000000000000000000000stake";

    let mut tx = Transaction::new(
        wallet.address.clone(),
        staking_contract.to_string(),
        amount,
        fee,
        account_nonce,
        TransactionType::StakeLock,
        vec![],
    );

    let tx_payload = serde_json::to_vec(&tx)
        .map_err(|e| BuilderError::SigningFailed(e.to_string()))?;

    let nonce = TransactionNonce::new(account_nonce, chain_state_hash.to_string());
    let signature = wallet.signing_keypair
        .sign(&bind_message_to_nonce(&tx_payload, &nonce))
        .map_err(|e| BuilderError::SigningFailed(e))?;

    tx.signature = signature.to_hex();
    tx.hash = compute_transaction_hash(&tx);

    Ok(tx)
}

// Build and sign a stake unlock transaction.
// Begins the unbonding period to withdraw staked KYV.
pub fn build_stake_unlock(
    wallet: &KyveraWallet,
    amount: u64,
    fee: u64,
    account_nonce: u64,
    chain_state_hash: &str,
) -> Result<Transaction, BuilderError> {
    if amount == 0 {
        return Err(BuilderError::ZeroAmount);
    }

    let staking_contract = "kyv1000000000000000000000000000000000000000000000000000000000000stake";

    let mut tx = Transaction::new(
        wallet.address.clone(),
        staking_contract.to_string(),
        amount,
        fee,
        account_nonce,
        TransactionType::StakeUnlock,
        vec![],
    );

    let tx_payload = serde_json::to_vec(&tx)
        .map_err(|e| BuilderError::SigningFailed(e.to_string()))?;

    let nonce = TransactionNonce::new(account_nonce, chain_state_hash.to_string());
    let signature = wallet.signing_keypair
        .sign(&bind_message_to_nonce(&tx_payload, &nonce))
        .map_err(|e| BuilderError::SigningFailed(e))?;

    tx.signature = signature.to_hex();
    tx.hash = compute_transaction_hash(&tx);

    Ok(tx)
}

// Compute the canonical hash of a transaction.
// This is what gets stored in the blockchain and referenced
// by wallets and explorers. Computed from the full transaction
// contents including the signature.
pub fn compute_transaction_hash(tx: &Transaction) -> String {
    let payload = format!(
        "{}{}{}{}{}{}",
        tx.sender,
        tx.receiver,
        tx.amount,
        tx.fee,
        tx.nonce,
        tx.signature,
    );
    sha3_256(payload.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::keys::KyveraWallet;

    fn mock_chain_state() -> String {
        "a".repeat(64)
    }

    #[test]
    fn test_valid_address_passes_validation() {
        // A proper kyv1 address with 64 hex chars
        let valid = format!("kyv1{}", "a".repeat(64));
        assert!(validate_address(&valid));
    }

    #[test]
    fn test_invalid_addresses_rejected() {
        // Wrong prefix
        assert!(!validate_address(&format!("eth0{}", "a".repeat(64))));
        // Too short
        assert!(!validate_address(&format!("kyv1{}", "a".repeat(32))));
        // Too long
        assert!(!validate_address(&format!("kyv1{}", "a".repeat(65))));
        // Non-hex characters
        assert!(!validate_address(&format!("kyv1{}", "z".repeat(64))));
        // Empty
        assert!(!validate_address(""));
    }

    #[test]
    fn test_build_transfer_produces_signed_transaction() {
        let wallet = KyveraWallet::generate("test");
        let recipient = format!("kyv1{}", "b".repeat(64));

        let tx = build_transfer(
            &wallet,
            &recipient,
            // 10 KYV
            10_000_000_000,
            // 0.001 KYV fee
            1_000_000,
            0,
            &mock_chain_state(),
        ).unwrap();

        // Transaction must be signed after building
        assert!(!tx.hash.is_empty());
        assert!(!tx.signature.is_empty());
        assert_eq!(tx.sender, wallet.address);
        assert_eq!(tx.receiver, recipient);
        assert_eq!(tx.amount, 10_000_000_000);
        assert_eq!(tx.nonce, 0);
    }

    #[test]
    fn test_zero_amount_rejected() {
        let wallet = KyveraWallet::generate("test");
        let recipient = format!("kyv1{}", "b".repeat(64));

        let result = build_transfer(
            &wallet, &recipient, 0, 1_000_000, 0, &mock_chain_state()
        );

        assert!(matches!(result, Err(BuilderError::ZeroAmount)));
    }

    #[test]
    fn test_invalid_recipient_rejected() {
        let wallet = KyveraWallet::generate("test");

        let result = build_transfer(
            &wallet, "not-an-address", 1_000_000, 1_000_000, 0, &mock_chain_state()
        );

        assert!(matches!(result, Err(BuilderError::InvalidAddress(_))));
    }

    #[test]
    fn test_different_nonces_produce_different_hashes() {
        let wallet = KyveraWallet::generate("test");
        let recipient = format!("kyv1{}", "b".repeat(64));

        let tx1 = build_transfer(
            &wallet, &recipient, 1_000_000_000, 1_000_000, 0, &mock_chain_state()
        ).unwrap();

        let tx2 = build_transfer(
            &wallet, &recipient, 1_000_000_000, 1_000_000, 1, &mock_chain_state()
        ).unwrap();

        // Different nonces mean different signatures mean different hashes
        assert_ne!(tx1.hash, tx2.hash);
        assert_ne!(tx1.signature, tx2.signature);
    }

    #[test]
    fn test_build_stake_lock() {
        let wallet = KyveraWallet::generate("test");

        // 500 KYV — enough for Igniter tier
        let tx = build_stake_lock(
            &wallet, 500_000_000_000, 1_000_000, 0, &mock_chain_state()
        ).unwrap();

        assert!(!tx.hash.is_empty());
        assert!(!tx.signature.is_empty());
        assert_eq!(tx.transaction_type, TransactionType::StakeLock);
        assert_eq!(tx.amount, 500_000_000_000);
    }

    #[test]
    fn test_build_stake_unlock() {
        let wallet = KyveraWallet::generate("test");

        let tx = build_stake_unlock(
            &wallet, 500_000_000_000, 1_000_000, 1, &mock_chain_state()
        ).unwrap();

        assert!(!tx.hash.is_empty());
        assert_eq!(tx.transaction_type, TransactionType::StakeUnlock);
    }

    #[test]
    fn test_transaction_hash_is_deterministic() {
        let wallet = KyveraWallet::generate("test");
        let recipient = format!("kyv1{}", "c".repeat(64));

        let tx = build_transfer(
            &wallet, &recipient, 1_000_000_000, 1_000_000, 0, &mock_chain_state()
        ).unwrap();

        // Recomputing the hash from the same transaction should
        // always produce the same result
        let recomputed = compute_transaction_hash(&tx);
        assert_eq!(tx.hash, recomputed);
    }
}