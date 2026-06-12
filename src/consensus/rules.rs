use crate::chain::block_producer::ChainTip;
use crate::chain::hash::hash_block_header;
use crate::chain::hash::meets_difficulty;
use crate::chain::mining::calculate_block_reward;
use crate::chain::merkle::compute_merkle_root;
use crate::consensus::coinbase::{verify_coinbase, COINBASE_SENDER};
use crate::storage::db::KyveraDb;
use crate::storage::account_store::get_account;
use crate::types::block::Block;
use crate::types::transaction::{Transaction, TransactionType};
use chrono::Utc;

// The complete Proof of Kinesis consensus rule set.
// Every block received from the network passes through these rules.
// A block that fails any rule is rejected and not relayed.
// These rules are deterministic — every honest node reaches
// the same accept/reject decision for every block independently.

// Maximum allowed clock skew between a block timestamp and
// the receiving node's local time. 2 minutes is standard.
const MAX_CLOCK_SKEW_MS: i64 = 120_000;

// Minimum time between blocks of the same type.
// Prevents spam blocks and enforces the target block intervals.
const MIN_MICRO_BLOCK_INTERVAL_MS: i64 = 500;
const MIN_EPOCH_BLOCK_INTERVAL_MS: i64 = 60_000;

// Maximum number of transactions in a single micro block.
// Keeps blocks from growing too large during congestion.
const MAX_TRANSACTIONS_PER_MICRO_BLOCK: usize = 1_000;

// Maximum number of micro block hashes in an epoch block.
const MAX_MICRO_BLOCKS_PER_EPOCH: usize = 10_000;

// The result of a consensus rule check.
#[derive(Debug)]
pub enum RuleViolation {
    // Block structure violations
    InvalidHeight { expected: u64, got: u64 },
    InvalidPreviousHash { expected: String, got: String },
    InvalidHash,
    InsufficientProofOfWork { required: u32, hash: String },
    InvalidTimestamp { reason: String },
    InvalidMerkleRoot,
    BlockTooLarge { max: usize, got: usize },

    // Transaction violations
    InvalidCoinbase { reason: String },
    DuplicateTransaction { hash: String },
    InvalidTransactionNonce { expected: u64, got: u64 },
    InsufficientBalance { address: String, required: u64, available: u64 },
    MissingCoinbase,
    UnexpectedCoinbase,

    // Epoch block specific
    InvalidEpochIndex { expected: u64, got: u64 },
    InvalidBlockReward { expected: u64, got: u64 },
    InvalidStateRoot,
}

impl std::fmt::Display for RuleViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            RuleViolation::InvalidHeight { expected, got } =>
                write!(f, "Invalid height: expected {} got {}", expected, got),
            RuleViolation::InvalidPreviousHash { expected, got } =>
                write!(f, "Invalid previous hash: expected {}... got {}...",
                    &expected[..8], &got[..8]),
            RuleViolation::InvalidHash =>
                write!(f, "Block hash does not match header contents"),
            RuleViolation::InsufficientProofOfWork { required, hash } =>
                write!(f, "Hash {} does not meet difficulty {}", &hash[..16], required),
            RuleViolation::InvalidTimestamp { reason } =>
                write!(f, "Invalid timestamp: {}", reason),
            RuleViolation::InvalidMerkleRoot =>
                write!(f, "Merkle root does not match transaction list"),
            RuleViolation::BlockTooLarge { max, got } =>
                write!(f, "Block has {} transactions, maximum is {}", got, max),
            RuleViolation::InvalidCoinbase { reason } =>
                write!(f, "Invalid coinbase: {}", reason),
            RuleViolation::DuplicateTransaction { hash } =>
                write!(f, "Duplicate transaction: {}", &hash[..16]),
            RuleViolation::InvalidTransactionNonce { expected, got } =>
                write!(f, "Invalid nonce: expected {} got {}", expected, got),
            RuleViolation::InsufficientBalance { address, required, available } =>
                write!(f, "Insufficient balance at {}: need {} have {}",
                    &address[..12], required, available),
            RuleViolation::MissingCoinbase =>
                write!(f, "Epoch block is missing a coinbase transaction"),
            RuleViolation::UnexpectedCoinbase =>
                write!(f, "Micro block contains a coinbase transaction"),
            RuleViolation::InvalidEpochIndex { expected, got } =>
                write!(f, "Invalid epoch index: expected {} got {}", expected, got),
            RuleViolation::InvalidBlockReward { expected, got } =>
                write!(f, "Invalid block reward: expected {} got {}", expected, got),
            RuleViolation::InvalidStateRoot =>
                write!(f, "State root does not match computed state"),
        }
    }
}

// Validate a complete block against the full PoK consensus rules.
// Returns Ok(()) if the block is valid.
// Returns Err with the first rule violation found if invalid.
// Checks are ordered from cheapest to most expensive — we fail fast
// on structural issues before doing expensive signature or state checks.
pub fn validate_block_rules(
    block: &Block,
    transactions: &[Transaction],
    chain_tip: &ChainTip,
    db: &KyveraDb,
) -> Result<(), RuleViolation> {
    // The genesis block (height 0) is validated separately — it has
    // no prior chain tip to compare against, so the normal
    // height/epoch/coinbase rules do not apply to it.
    if block.header.index == 0 {
        check_previous_hash_genesis(block)?;
        check_proof_of_work(block)?;
        check_block_hash(block)?;
        check_merkle_root(block, transactions)?;
        return Ok(());
    }

    // 1. Structural checks — cheapest, done first
    check_height(block, chain_tip)?;
    check_previous_hash(block, chain_tip)?;
    check_block_size(block, transactions)?;
    check_timestamp(block, chain_tip)?;

    // 2. Proof of work
    check_proof_of_work(block)?;
    check_block_hash(block)?;

    // 3. Merkle root
    check_merkle_root(block, transactions)?;

    // 4. Epoch-specific checks
    if block.header.is_epoch_block {
        check_epoch_index(block, chain_tip)?;
        check_block_reward(block)?;
        check_coinbase(block, transactions)?;
    } else {
        check_no_coinbase(transactions)?;
    }

    // 5. Transaction-level checks
    check_transactions(transactions, db)?;

    Ok(())
}

fn check_height(block: &Block, tip: &ChainTip) -> Result<(), RuleViolation> {
    let expected = tip.height + 1;
    if block.header.index != expected {
        return Err(RuleViolation::InvalidHeight {
            expected,
            got: block.header.index,
        });
    }
    Ok(())
}

fn check_previous_hash(block: &Block, tip: &ChainTip) -> Result<(), RuleViolation> {
    if block.header.previous_hash != tip.hash {
        return Err(RuleViolation::InvalidPreviousHash {
            expected: tip.hash.clone(),
            got: block.header.previous_hash.clone(),
        });
    }
    Ok(())
}

fn check_previous_hash_genesis(block: &Block) -> Result<(), RuleViolation> {
    let zero_hash = "0".repeat(64);
    if block.header.previous_hash != zero_hash {
        return Err(RuleViolation::InvalidPreviousHash {
            expected: zero_hash,
            got: block.header.previous_hash.clone(),
        });
    }
    Ok(())
}

fn check_block_size(block: &Block, transactions: &[Transaction]) -> Result<(), RuleViolation> {
    if block.header.is_epoch_block {
        if block.transaction_hashes.len() > MAX_MICRO_BLOCKS_PER_EPOCH {
            return Err(RuleViolation::BlockTooLarge {
                max: MAX_MICRO_BLOCKS_PER_EPOCH,
                got: block.transaction_hashes.len(),
            });
        }
    } else {
        if transactions.len() > MAX_TRANSACTIONS_PER_MICRO_BLOCK {
            return Err(RuleViolation::BlockTooLarge {
                max: MAX_TRANSACTIONS_PER_MICRO_BLOCK,
                got: transactions.len(),
            });
        }
    }
    Ok(())
}

fn check_timestamp(block: &Block, tip: &ChainTip) -> Result<(), RuleViolation> {
    let now_ms = Utc::now().timestamp_millis();

    // Block must not be in the future beyond allowed clock skew
    if block.header.timestamp > now_ms + MAX_CLOCK_SKEW_MS {
        return Err(RuleViolation::InvalidTimestamp {
            reason: format!(
                "Block timestamp {} is {}ms in the future",
                block.header.timestamp,
                block.header.timestamp - now_ms
            ),
        });
    }

    // Block must be after the previous block
    if block.header.timestamp <= tip.timestamp && tip.timestamp > 0 {
        return Err(RuleViolation::InvalidTimestamp {
            reason: format!(
                "Block timestamp {} is not after previous block timestamp {}",
                block.header.timestamp, tip.timestamp
            ),
        });
    }

    // Enforce minimum interval between blocks of same type
    if tip.timestamp > 0 {
        let elapsed = block.header.timestamp - tip.timestamp;
        let min_interval = if block.header.is_epoch_block {
            MIN_EPOCH_BLOCK_INTERVAL_MS
        } else {
            MIN_MICRO_BLOCK_INTERVAL_MS
        };

        if elapsed < min_interval {
            return Err(RuleViolation::InvalidTimestamp {
                reason: format!(
                    "Only {}ms since last block, minimum is {}ms",
                    elapsed, min_interval
                ),
            });
        }
    }

    Ok(())
}

fn check_proof_of_work(block: &Block) -> Result<(), RuleViolation> {
    if !meets_difficulty(&block.hash, block.header.difficulty) {
        return Err(RuleViolation::InsufficientProofOfWork {
            required: block.header.difficulty,
            hash: block.hash.clone(),
        });
    }
    Ok(())
}

fn check_block_hash(block: &Block) -> Result<(), RuleViolation> {
    let recomputed = hash_block_header(
        block.header.index,
        block.header.timestamp,
        &block.header.previous_hash,
        &block.header.merkle_root,
        block.header.nonce,
        block.header.difficulty,
        block.header.is_epoch_block,
        block.header.epoch_index,
        &block.header.state_root,
    );

    if recomputed != block.hash {
        return Err(RuleViolation::InvalidHash);
    }

    Ok(())
}

fn check_merkle_root(block: &Block, transactions: &[Transaction]) -> Result<(), RuleViolation> {
    let tx_hashes: Vec<String> = transactions.iter().map(|tx| tx.hash.clone()).collect();
    let computed = compute_merkle_root(&tx_hashes);

    if computed != block.header.merkle_root {
        return Err(RuleViolation::InvalidMerkleRoot);
    }

    Ok(())
}

fn check_epoch_index(block: &Block, tip: &ChainTip) -> Result<(), RuleViolation> {
    let expected = tip.epoch_index + 1;
    if block.header.epoch_index != expected {
        return Err(RuleViolation::InvalidEpochIndex {
            expected,
            got: block.header.epoch_index,
        });
    }
    Ok(())
}

fn check_block_reward(block: &Block) -> Result<(), RuleViolation> {
    let expected = calculate_block_reward(block.header.epoch_index);
    if block.block_reward != expected {
        return Err(RuleViolation::InvalidBlockReward {
            expected,
            got: block.block_reward,
        });
    }
    Ok(())
}

fn check_coinbase(block: &Block, transactions: &[Transaction]) -> Result<(), RuleViolation> {
    // Epoch blocks must have exactly one coinbase transaction
    // and it must be the first transaction
    let coinbase = transactions.first().ok_or(RuleViolation::MissingCoinbase)?;

    if coinbase.sender != COINBASE_SENDER {
        return Err(RuleViolation::MissingCoinbase);
    }

    if !verify_coinbase(coinbase, block.header.epoch_index, &block.hash) {
        return Err(RuleViolation::InvalidCoinbase {
            reason: "Coinbase hash, amount, or nonce is incorrect".to_string(),
        });
    }

    Ok(())
}

fn check_no_coinbase(transactions: &[Transaction]) -> Result<(), RuleViolation> {
    for tx in transactions {
        if tx.sender == COINBASE_SENDER {
            return Err(RuleViolation::UnexpectedCoinbase);
        }
    }
    Ok(())
}

fn check_transactions(
    transactions: &[Transaction],
    db: &KyveraDb,
) -> Result<(), RuleViolation> {
    let mut seen_hashes = std::collections::HashSet::new();

    for tx in transactions {
        // Skip coinbase — already validated
        if tx.sender == COINBASE_SENDER {
            continue;
        }

        // No duplicate transactions in the same block
        if !seen_hashes.insert(tx.hash.clone()) {
            return Err(RuleViolation::DuplicateTransaction {
                hash: tx.hash.clone(),
            });
        }

        // Validate sender can afford the transaction
        if let Some(account) = get_account(db, &tx.sender)
            .map_err(|_| RuleViolation::InsufficientBalance {
                address: tx.sender.clone(),
                required: 0,
                available: 0,
            })? {
            let required = match tx.transaction_type {
                TransactionType::Transfer => {
                    tx.amount.saturating_add(tx.fee)
                }
                TransactionType::StakeLock => {
                    tx.amount.saturating_add(tx.fee)
                }
                TransactionType::StakeUnlock => tx.fee,
                TransactionType::ContractDeploy |
                TransactionType::ContractCall => tx.fee,
            };

            if account.balance < required {
                return Err(RuleViolation::InsufficientBalance {
                    address: tx.sender.clone(),
                    required,
                    available: account.balance,
                });
            }

            // Nonce must match exactly
            if account.nonce != tx.nonce {
                return Err(RuleViolation::InvalidTransactionNonce {
                    expected: account.nonce,
                    got: tx.nonce,
                });
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::block_producer::{produce_genesis_block, ChainTip};
    use crate::consensus::coinbase::build_coinbase;
    use crate::storage::db::KyveraDb;
    use crate::storage::account_store::credit_account;

    const MINER: &str =
        "kyv1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn test_valid_genesis_passes_all_rules() {
        let db = KyveraDb::open_temp().unwrap();
        let genesis = produce_genesis_block(MINER).unwrap();
        let tip = ChainTip::genesis();

        // Genesis has no transactions — empty slice is valid
        let result = validate_block_rules(&genesis, &[], &tip, &db);
        assert!(result.is_ok(), "Genesis block should pass all rules: {:?}", result);
    }

    #[test]
    fn test_wrong_height_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let mut genesis = produce_genesis_block(MINER).unwrap();
        let tip = ChainTip::genesis();

        // Claim height 5 when chain tip is at 0
        genesis.header.index = 5;

        let result = validate_block_rules(&genesis, &[], &tip, &db);
        assert!(matches!(result, Err(RuleViolation::InvalidHeight { .. })));
    }

    #[test]
    fn test_wrong_previous_hash_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let mut genesis = produce_genesis_block(MINER).unwrap();
        let tip = ChainTip::genesis();

        genesis.header.previous_hash = "1".repeat(64);

        let result = validate_block_rules(&genesis, &[], &tip, &db);
        assert!(matches!(result, Err(RuleViolation::InvalidPreviousHash { .. })));
    }

    #[test]
    fn test_insufficient_pow_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let mut genesis = produce_genesis_block(MINER).unwrap();
        let tip = ChainTip::genesis();

        // Claim difficulty 20 which the hash almost certainly does not meet
        genesis.header.difficulty = 20;

        let result = validate_block_rules(&genesis, &[], &tip, &db);
        assert!(matches!(result,
            Err(RuleViolation::InsufficientProofOfWork { .. }) |
            Err(RuleViolation::InvalidHash)
        ));
    }

    #[test]
    fn test_duplicate_transactions_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = format!("kyv1{}", hex::encode([1u8; 32]));
        let receiver = format!("kyv1{}", hex::encode([2u8; 32]));

        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let mut tx = crate::types::transaction::Transaction::new(
            sender.clone(), receiver.clone(),
            1_000_000_000, 1_000_000, 0,
            TransactionType::Transfer, vec![],
        );
        tx.hash = format!("{:064}", 1);
        tx.signature = "sig".to_string();

        // Same transaction twice in the same block
        let transactions = vec![tx.clone(), tx.clone()];

        let result = check_transactions(&transactions, &db);
        assert!(matches!(result, Err(RuleViolation::DuplicateTransaction { .. })));
    }

    #[test]
    fn test_insufficient_balance_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = format!("kyv1{}", hex::encode([3u8; 32]));
        let receiver = format!("kyv1{}", hex::encode([4u8; 32]));

        // Only 1 KYV but trying to send 100 KYV
        credit_account(&db, &sender, 1_000_000_000).unwrap();

        let mut tx = crate::types::transaction::Transaction::new(
            sender.clone(), receiver.clone(),
            100_000_000_000, 1_000_000, 0,
            TransactionType::Transfer, vec![],
        );
        tx.hash = format!("{:064}", 2);
        tx.signature = "sig".to_string();

        let result = check_transactions(&[tx], &db);
        assert!(matches!(result, Err(RuleViolation::InsufficientBalance { .. })));
    }

    #[test]
    fn test_wrong_nonce_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = format!("kyv1{}", hex::encode([5u8; 32]));
        let receiver = format!("kyv1{}", hex::encode([6u8; 32]));

        credit_account(&db, &sender, 100_000_000_000).unwrap();

        // Account nonce is 0 but tx claims nonce 5
        let mut tx = crate::types::transaction::Transaction::new(
            sender.clone(), receiver.clone(),
            1_000_000_000, 1_000_000, 5,
            TransactionType::Transfer, vec![],
        );
        tx.hash = format!("{:064}", 3);
        tx.signature = "sig".to_string();

        let result = check_transactions(&[tx], &db);
        assert!(matches!(result, Err(RuleViolation::InvalidTransactionNonce { .. })));
    }

    #[test]
    fn test_micro_block_with_coinbase_rejected() {
        let coinbase = build_coinbase(MINER, 0, &"a".repeat(64));
        let result = check_no_coinbase(&[coinbase]);
        assert!(matches!(result, Err(RuleViolation::UnexpectedCoinbase)));
    }

    #[test]
    fn test_epoch_block_missing_coinbase_rejected() {
        let _db = KyveraDb::open_temp().unwrap();
        let genesis = produce_genesis_block(MINER).unwrap();
        let _tip = ChainTip::genesis();

        // Epoch block with no transactions at all — missing coinbase
        let result = check_coinbase(&genesis, &[]);
        assert!(matches!(result, Err(RuleViolation::MissingCoinbase)));
    }
}