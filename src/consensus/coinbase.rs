use crate::chain::mining::calculate_block_reward;
use crate::storage::db::KyveraDb;
use crate::storage::account_store::credit_account;
use crate::types::transaction::{Transaction, TransactionType};
use crate::chain::hash::sha3_256_hex;

// A coinbase transaction is the special transaction that pays
// the miner their block reward. Unlike regular transactions it
// has no sender — it creates new KYV from the emission schedule.
// Every epoch block contains exactly one coinbase transaction.
// Micro blocks do not carry coinbase transactions — only epoch blocks
// distribute mining rewards.

// The sentinel address used as the sender in coinbase transactions.
// Nodes treat any transaction from this address as a coinbase.
// The all-zeros sender can never sign a real transaction because
// no private key produces this address.
pub const COINBASE_SENDER: &str =
    "kyv10000000000000000000000000000000000000000000000000000coinbase0";

// Build a coinbase transaction for an epoch block.
// The amount is the block reward at the given epoch height.
// Coinbase transactions are signed with the genesis coinbase key
// which is a well-known null signature — nodes recognise them
// by their sender address rather than verifying a signature.
pub fn build_coinbase(
    miner_address: &str,
    epoch_block_height: u64,
    block_hash: &str,
) -> Transaction {
    let reward = calculate_block_reward(epoch_block_height);

    // The nonce for coinbase transactions is the epoch block height.
    // This ensures each coinbase is unique and cannot be replayed.
    let mut tx = Transaction::new(
        COINBASE_SENDER.to_string(),
        miner_address.to_string(),
        reward,
        0, // Coinbase transactions carry no fee
        epoch_block_height,
        TransactionType::Transfer,
        vec![],
    );

    // Coinbase hash is derived from the block hash and epoch height
    // so it is deterministic and verifiable by any node.
    let hash_input = format!("coinbase:{}:{}", block_hash, epoch_block_height);
    tx.hash = sha3_256_hex(hash_input.as_bytes());

    // Coinbase signature is a well-known constant — not a real signature.
    // Nodes skip signature verification for transactions from COINBASE_SENDER.
    tx.signature = "coinbase".to_string();

    tx
}

// Apply a coinbase transaction to the account state.
// Credits the miner with the block reward.
// Also handles the fee split from all transactions in the block —
// 40% of collected fees goes to the epoch block producer.
pub fn apply_coinbase(
    db: &KyveraDb,
    coinbase: &Transaction,
    validator_fee_share: u64,
) -> Result<(), String> {
    // Verify this is actually a coinbase transaction
    if coinbase.sender != COINBASE_SENDER {
        return Err("Not a coinbase transaction".to_string());
    }

    // Credit the miner with the block reward
    if coinbase.amount > 0 {
        credit_account(db, &coinbase.receiver, coinbase.amount)?;
    }

    // Credit the miner with their share of transaction fees
    if validator_fee_share > 0 {
        credit_account(db, &coinbase.receiver, validator_fee_share)?;
    }

    Ok(())
}

// Calculate the total fee reward for the epoch block producer.
// This is 40% of all fees collected in micro blocks since
// the last epoch block. The other 60% is split between burn
// (50%) and treasury (10%) — handled at the state trie level.
pub fn calculate_validator_fee_share(total_fees_collected: u64) -> u64 {
    // 40% of total fees goes to the epoch block producer
    total_fees_collected * 40 / 100
}

// Verify that a coinbase transaction is valid for a given epoch block.
// Checks the reward amount matches the emission schedule and that
// the hash is correctly derived from the block hash.
pub fn verify_coinbase(
    coinbase: &Transaction,
    epoch_block_height: u64,
    block_hash: &str,
) -> bool {
    // Must come from the coinbase sentinel address
    if coinbase.sender != COINBASE_SENDER {
        return false;
    }

    // Amount must match the emission schedule exactly
    let expected_reward = calculate_block_reward(epoch_block_height);
    if coinbase.amount != expected_reward {
        return false;
    }

    // Nonce must equal the epoch block height
    if coinbase.nonce != epoch_block_height {
        return false;
    }

    // Hash must be correctly derived
    let hash_input = format!("coinbase:{}:{}", block_hash, epoch_block_height);
    let expected_hash = sha3_256_hex(hash_input.as_bytes());
    if coinbase.hash != expected_hash {
        return false;
    }

    true
}

// Calculate how many KYV have been minted through mining
// up to and including the given epoch block height.
// Used by the supply integrity verification system.
pub fn calculate_mined_supply(epoch_block_height: u64) -> u64 {
    let mut total: u64 = 0;
    let mut height = 0u64;

    while height <= epoch_block_height {
        total = total.saturating_add(calculate_block_reward(height));
        height += 1;
    }

    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::KyveraDb;
    use crate::storage::account_store::get_balance;
    use crate::chain::mining::{HALVING_INTERVAL, KYV_UNITS, GENESIS_BLOCK_REWARD};

    const TEST_MINER: &str =
        "kyv1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn test_build_coinbase_genesis_reward() {
        let coinbase = build_coinbase(TEST_MINER, 0, &"a".repeat(64));

        assert_eq!(coinbase.sender, COINBASE_SENDER);
        assert_eq!(coinbase.receiver, TEST_MINER);
        assert_eq!(coinbase.amount, GENESIS_BLOCK_REWARD);
        assert_eq!(coinbase.fee, 0);
        assert_eq!(coinbase.nonce, 0);
        assert!(!coinbase.hash.is_empty());
    }

    #[test]
    fn test_coinbase_hash_is_deterministic() {
        let block_hash = "b".repeat(64);
        let cb1 = build_coinbase(TEST_MINER, 1, &block_hash);
        let cb2 = build_coinbase(TEST_MINER, 1, &block_hash);
        assert_eq!(cb1.hash, cb2.hash);
    }

    #[test]
    fn test_different_epochs_produce_different_hashes() {
        let block_hash = "c".repeat(64);
        let cb1 = build_coinbase(TEST_MINER, 0, &block_hash);
        let cb2 = build_coinbase(TEST_MINER, 1, &block_hash);
        assert_ne!(cb1.hash, cb2.hash);
    }

    #[test]
    fn test_coinbase_reward_halves_correctly() {
        let cb_epoch0 = build_coinbase(TEST_MINER, 0, &"a".repeat(64));
        let cb_epoch1 = build_coinbase(TEST_MINER, HALVING_INTERVAL, &"b".repeat(64));

        assert_eq!(cb_epoch0.amount, 50 * KYV_UNITS);
        assert_eq!(cb_epoch1.amount, 25 * KYV_UNITS);
    }

    #[test]
    fn test_verify_coinbase_valid() {
        let block_hash = "d".repeat(64);
        let coinbase = build_coinbase(TEST_MINER, 5, &block_hash);
        assert!(verify_coinbase(&coinbase, 5, &block_hash));
    }

    #[test]
    fn test_verify_coinbase_wrong_reward_fails() {
        let block_hash = "e".repeat(64);
        let mut coinbase = build_coinbase(TEST_MINER, 0, &block_hash);
        // Tamper with the reward amount
        coinbase.amount = 999_999_999_999;
        assert!(!verify_coinbase(&coinbase, 0, &block_hash));
    }

    #[test]
    fn test_verify_coinbase_wrong_height_fails() {
        let block_hash = "f".repeat(64);
        let coinbase = build_coinbase(TEST_MINER, 0, &block_hash);
        // Verify against wrong epoch height
        assert!(!verify_coinbase(&coinbase, 1, &block_hash));
    }

    #[test]
    fn test_apply_coinbase_credits_miner() {
        let db = KyveraDb::open_temp().unwrap();
        let block_hash = "g".repeat(64);
        let coinbase = build_coinbase(TEST_MINER, 0, &block_hash);

        apply_coinbase(&db, &coinbase, 0).unwrap();

        let balance = get_balance(&db, TEST_MINER).unwrap();
        assert_eq!(balance, GENESIS_BLOCK_REWARD);
    }

    #[test]
    fn test_apply_coinbase_with_fee_share() {
        let db = KyveraDb::open_temp().unwrap();
        let block_hash = "h".repeat(64);
        let coinbase = build_coinbase(TEST_MINER, 0, &block_hash);
        let fee_share = 5_000_000;

        apply_coinbase(&db, &coinbase, fee_share).unwrap();

        let balance = get_balance(&db, TEST_MINER).unwrap();
        assert_eq!(balance, GENESIS_BLOCK_REWARD + fee_share);
    }

    #[test]
    fn test_apply_non_coinbase_fails() {
        let db = KyveraDb::open_temp().unwrap();
        let mut coinbase = build_coinbase(TEST_MINER, 0, &"i".repeat(64));
        // Make it look like a regular transaction
        coinbase.sender = TEST_MINER.to_string();

        let result = apply_coinbase(&db, &coinbase, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_validator_fee_share_is_40_percent() {
        let total_fees = 100_000_000;
        let share = calculate_validator_fee_share(total_fees);
        assert_eq!(share, 40_000_000);
    }

    #[test]
    fn test_mined_supply_at_genesis() {
        // At epoch 0 only one block reward has been issued
        let supply = calculate_mined_supply(0);
        assert_eq!(supply, GENESIS_BLOCK_REWARD);
    }

    #[test]
    fn test_mined_supply_never_exceeds_mining_allocation() {
        use crate::consensus::genesis::MINING_ALLOCATION;
        // Simulate running through thousands of epochs
        let supply = calculate_mined_supply(HALVING_INTERVAL * 10);
        assert!(supply <= MINING_ALLOCATION,
            "Mined supply {} exceeds mining allocation {}",
            supply, MINING_ALLOCATION
        );
    }
}