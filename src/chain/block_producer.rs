use crate::chain::hash::hash_block_header;
use crate::chain::merkle::compute_merkle_root;
use crate::chain::mining::{
    mine_block, calculate_block_reward, verify_proof_of_work,
    GENESIS_BLOCK_REWARD,
};
use crate::types::block::{Block, BlockHeader};
use crate::types::transaction::Transaction;
use chrono::Utc;

// The block producer ties together hashing, merkle trees, and mining
// to produce actual Kyvera blocks. There are two block types:
//
// Micro blocks — produced every 2-3 seconds by whoever is mining.
// They contain transactions and use a lightweight signature.
// Finality is probabilistic until the next epoch block confirms them.
//
// Epoch blocks — produced every 10 minutes. They are finality
// checkpoints that commit to all micro blocks since the last epoch.
// The halving counter tracks epoch blocks, not micro blocks.
// Full Dilithium + SPHINCS+ signatures go on epoch blocks.

// Tracks the current tip of the chain — the most recent valid block.
// Every node maintains one of these and updates it as new blocks arrive.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainTip {
    // Hash of the most recent block
    pub hash: String,
    // Height of the most recent block
    pub height: u64,
    // Timestamp of the most recent block
    pub timestamp: i64,
    // Current mining difficulty
    pub difficulty: u32,
    // Most recent epoch block index
    pub epoch_index: u64,
    // Total chain work — sum of difficulties of all blocks
    // Used for fork selection: longest chain by work, not height
    pub total_work: u64,
}

// Errors the block producer can surface
#[derive(Debug)]
pub enum BlockError {
    // Block's previous hash does not match chain tip
    InvalidPreviousHash { expected: String, got: String },
    // Block hash does not meet claimed difficulty
    InsufficientProofOfWork,
    // Block timestamp is too far in the past or future
    InvalidTimestamp,
    // Merkle root does not match the transaction list
    InvalidMerkleRoot,
    // Block height is not sequential
    InvalidHeight,
    // Mining failed to find a solution within attempt limit
    MiningFailed,
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BlockError::InvalidPreviousHash { expected, got } =>
                write!(f, "Previous hash mismatch: expected {}, got {}", &expected[..8], &got[..8]),
            BlockError::InsufficientProofOfWork =>
                write!(f, "Block hash does not meet difficulty target"),
            BlockError::InvalidTimestamp =>
                write!(f, "Block timestamp is outside acceptable range"),
            BlockError::InvalidMerkleRoot =>
                write!(f, "Merkle root does not match transaction list"),
            BlockError::InvalidHeight =>
                write!(f, "Block height is not sequential"),
            BlockError::MiningFailed =>
                write!(f, "Mining did not find a solution within the attempt limit"),
        }
    }
}

impl ChainTip {
    // The genesis chain tip — what every node starts with before
    // the first block arrives.
    pub fn genesis() -> Self {
        ChainTip {
            hash: "0".repeat(64),
            height: 0,
            timestamp: 0,
            difficulty: 1,
            epoch_index: 0,
            total_work: 0,
        }
    }

    // Update the chain tip after a new block is accepted.
    pub fn advance(&mut self, block: &Block) {
        self.hash = block.hash.clone();
        self.height = block.header.index;
        self.timestamp = block.header.timestamp;
        self.difficulty = block.header.difficulty;
        if block.header.is_epoch_block {
            self.epoch_index = block.header.epoch_index;
        }
        self.total_work += block.header.difficulty as u64;
    }
}

// Produce and mine the genesis block.
// Block zero. The beginning of Kyvera Continuum.
// No previous hash — we use 64 zeros as the genesis sentinel.
// The genesis block is always an epoch block at epoch index 0.
pub fn produce_genesis_block(miner_address: &str) -> Result<Block, BlockError> {
    let mut header = BlockHeader::new(
        0,
        "0".repeat(64),
        // Empty block — no transactions at genesis
        compute_merkle_root(&[]),
        // Genesis starts at difficulty 1 — easy enough to mine quickly
        // The network adjusts from here as miners join
        1,
        true,
        0,
    );

    // Mine the genesis block
    let mined = mine_block(&header, u64::MAX)
        .ok_or(BlockError::MiningFailed)?;

    header.nonce = mined.nonce;

    let mut block = Block::new(
        header,
        vec![],
        miner_address.to_string(),
        GENESIS_BLOCK_REWARD,
    );

    block.hash = mined.hash;
    Ok(block)
}

// Produce and mine a micro block from a list of pending transactions.
// Micro blocks are the fast layer — every 2-3 seconds.
// They do not carry Dilithium signatures at this layer.
// The epoch block that follows will commit to them with full signatures.
pub fn produce_micro_block(
    transactions: &[Transaction],
    chain_tip: &ChainTip,
    miner_address: &str,
    max_attempts: u64,
) -> Result<Block, BlockError> {
    let tx_hashes: Vec<String> = transactions
        .iter()
        .map(|tx| tx.hash.clone())
        .collect();

    let merkle_root = compute_merkle_root(&tx_hashes);

    let mut header = BlockHeader::new(
        chain_tip.height + 1,
        chain_tip.hash.clone(),
        merkle_root,
        chain_tip.difficulty,
        false,
        chain_tip.epoch_index,
    );

    let mined = mine_block(&header, max_attempts)
        .ok_or(BlockError::MiningFailed)?;

    header.nonce = mined.nonce;

    let mut block = Block::new(
        header,
        tx_hashes,
        miner_address.to_string(),
        // Micro blocks do not carry the block reward
        // Only epoch blocks distribute mining rewards
        0,
    );

    block.hash = mined.hash;
    Ok(block)
}

// Produce and mine an epoch block.
// Epoch blocks are the security layer — every 10 minutes.
// They commit to all micro blocks since the last epoch block,
// carry the full block reward, and increment the epoch counter.
// The halving schedule counts epoch blocks.
pub fn produce_epoch_block(
    micro_block_hashes: &[String],
    chain_tip: &ChainTip,
    miner_address: &str,
    state_root: &str,
    max_attempts: u64,
) -> Result<Block, BlockError> {
    let next_epoch_index = chain_tip.epoch_index + 1;

    // Calculate the reward for this epoch block
    let reward = calculate_block_reward(next_epoch_index);

    // The merkle root of an epoch block commits to the hashes
    // of all micro blocks since the last epoch, not transactions.
    // This is what makes the dual-block architecture work —
    // epoch blocks summarise micro blocks rather than transactions.
    let merkle_root = compute_merkle_root(micro_block_hashes);

    let mut header = BlockHeader::new(
        chain_tip.height + 1,
        chain_tip.hash.clone(),
        merkle_root,
        chain_tip.difficulty,
        true,
        next_epoch_index,
    );

    // State root gets committed on epoch blocks
    header.state_root = state_root.to_string();

    let mined = mine_block(&header, max_attempts)
        .ok_or(BlockError::MiningFailed)?;

    header.nonce = mined.nonce;

    let mut block = Block::new(
        header,
        micro_block_hashes.to_vec(),
        miner_address.to_string(),
        reward,
    );

    block.hash = mined.hash;
    Ok(block)
}

// Validate an incoming block before accepting it into the chain.
// Every node runs this on every block it receives.
// A block that fails any check is rejected and not relayed.
pub fn validate_block(
    block: &Block,
    chain_tip: &ChainTip,
    transactions: &[Transaction],
) -> Result<(), BlockError> {
    // 1. Height must be sequential
    if block.header.index != chain_tip.height + 1 {
        return Err(BlockError::InvalidHeight);
    }

    // 2. Previous hash must match chain tip
    if block.header.previous_hash != chain_tip.hash {
        return Err(BlockError::InvalidPreviousHash {
            expected: chain_tip.hash.clone(),
            got: block.header.previous_hash.clone(),
        });
    }

    // 3. Proof of work must meet difficulty
    if !verify_proof_of_work(&block.hash, block.header.difficulty) {
        return Err(BlockError::InsufficientProofOfWork);
    }

    // 4. Timestamp must be after the previous block and not too far in future
    let now = Utc::now().timestamp_millis();
    if block.header.timestamp < chain_tip.timestamp {
        return Err(BlockError::InvalidTimestamp);
    }
    // Allow 2 minutes (120,000 ms) clock skew
    if block.header.timestamp > now + 120_000 {
        return Err(BlockError::InvalidTimestamp);
    }

    // 5. Merkle root must match transaction list
    let tx_hashes: Vec<String> = transactions
        .iter()
        .map(|tx| tx.hash.clone())
        .collect();
    let expected_merkle = compute_merkle_root(&tx_hashes);
    if block.header.merkle_root != expected_merkle {
        return Err(BlockError::InvalidMerkleRoot);
    }

    // 6. Verify the block hash is actually correct
    let recomputed_hash = hash_block_header(
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
    if recomputed_hash != block.hash {
        return Err(BlockError::InsufficientProofOfWork);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MINER: &str = "kyv1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn test_genesis_block_production() {
        let block = produce_genesis_block(TEST_MINER).unwrap();

        assert_eq!(block.header.index, 0);
        assert_eq!(block.header.previous_hash, "0".repeat(64));
        assert!(block.header.is_epoch_block);
        assert_eq!(block.header.epoch_index, 0);
        assert_eq!(block.block_reward, GENESIS_BLOCK_REWARD);
        assert!(!block.hash.is_empty());
        assert!(verify_proof_of_work(&block.hash, block.header.difficulty));

        println!("\n  ══════════════════════════════════════════");
        println!("  KYVERA CONTINUUM — GENESIS BLOCK MINED");
        println!("  ══════════════════════════════════════════");
        println!("  Block:    #{}", block.header.index);
        println!("  Hash:     {}", block.hash);
        println!("  Nonce:    {}", block.header.nonce);
        println!("  Reward:   {} KYV", block.block_reward / 1_000_000_000);
        println!("  Miner:    {}", block.producer_address);
        println!("  ══════════════════════════════════════════\n");
    }

    #[test]
    fn test_chain_tip_starts_at_genesis() {
        let tip = ChainTip::genesis();
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, "0".repeat(64));
        assert_eq!(tip.epoch_index, 0);
        assert_eq!(tip.total_work, 0);
    }

    #[test]
    fn test_chain_tip_advances_after_block() {
        let block = produce_genesis_block(TEST_MINER).unwrap();
        let mut tip = ChainTip::genesis();
        tip.advance(&block);

        assert_eq!(tip.hash, block.hash);
        assert_eq!(tip.height, 0);
        assert_eq!(tip.epoch_index, 0);
        assert!(tip.total_work > 0);
    }

    #[test]
    fn test_micro_block_production() {
        // First mine genesis to get a real chain tip
        let genesis = produce_genesis_block(TEST_MINER).unwrap();
        let mut tip = ChainTip::genesis();
        tip.advance(&genesis);

        // Produce a micro block on top of genesis
        let micro = produce_micro_block(
            &[],
            &tip,
            TEST_MINER,
            u64::MAX,
        ).unwrap();

        assert_eq!(micro.header.index, 1);
        assert_eq!(micro.header.previous_hash, genesis.hash);
        assert!(!micro.header.is_epoch_block);
        assert_eq!(micro.block_reward, 0);
        assert!(verify_proof_of_work(&micro.hash, micro.header.difficulty));
    }

    #[test]
    fn test_epoch_block_production() {
        let genesis = produce_genesis_block(TEST_MINER).unwrap();
        let mut tip = ChainTip::genesis();
        tip.advance(&genesis);

        // Produce an epoch block referencing the genesis as a micro block
        let epoch = produce_epoch_block(
            &[genesis.hash.clone()],
            &tip,
            TEST_MINER,
            "state_root_placeholder",
            u64::MAX,
        ).unwrap();

        assert_eq!(epoch.header.index, 1);
        assert!(epoch.header.is_epoch_block);
        assert_eq!(epoch.header.epoch_index, 1);
        // Epoch 1 reward is still 50 KYV — first halving is at epoch 290,000
        assert_eq!(epoch.block_reward, GENESIS_BLOCK_REWARD);
        assert!(verify_proof_of_work(&epoch.hash, epoch.header.difficulty));
    }

    #[test]
    fn test_block_validation_passes_for_valid_block() {
        let genesis = produce_genesis_block(TEST_MINER).unwrap();
        let mut tip = ChainTip::genesis();
        tip.advance(&genesis);

        let micro = produce_micro_block(
            &[],
            &tip,
            TEST_MINER,
            u64::MAX,
        ).unwrap();

        let result = validate_block(&micro, &tip, &[]);
        assert!(result.is_ok(), "Valid block should pass validation");
    }

    #[test]
    fn test_validation_rejects_wrong_previous_hash() {
        let genesis = produce_genesis_block(TEST_MINER).unwrap();
        let mut tip = ChainTip::genesis();
        tip.advance(&genesis);

        let mut micro = produce_micro_block(
            &[], &tip, TEST_MINER, u64::MAX
        ).unwrap();

        // Tamper with the previous hash
        micro.header.previous_hash = "1".repeat(64);

        let result = validate_block(&micro, &tip, &[]);
        assert!(matches!(result, Err(BlockError::InvalidPreviousHash { .. })));
    }

    #[test]
    fn test_validation_rejects_insufficient_pow() {
        let genesis = produce_genesis_block(TEST_MINER).unwrap();
        let mut tip = ChainTip::genesis();
        tip.advance(&genesis);

        let mut micro = produce_micro_block(
            &[], &tip, TEST_MINER, u64::MAX
        ).unwrap();

        // Claim a higher difficulty than the hash actually meets
        micro.header.difficulty = 20;

        let result = validate_block(&micro, &tip, &[]);
        assert!(matches!(result, Err(BlockError::InsufficientProofOfWork)));
    }

    #[test]
    fn test_epoch_counter_increments_correctly() {
        let genesis = produce_genesis_block(TEST_MINER).unwrap();
        let mut tip = ChainTip::genesis();
        tip.advance(&genesis);

        // First epoch block should have epoch_index = 1
        let epoch1 = produce_epoch_block(
            &[genesis.hash.clone()],
            &tip,
            TEST_MINER,
            "state_root_1",
            u64::MAX,
        ).unwrap();

        assert_eq!(epoch1.header.epoch_index, 1);
        tip.advance(&epoch1);

        // Second epoch block should have epoch_index = 2
        let epoch2 = produce_epoch_block(
            &[epoch1.hash.clone()],
            &tip,
            TEST_MINER,
            "state_root_2",
            u64::MAX,
        ).unwrap();

        assert_eq!(epoch2.header.epoch_index, 2);
    }

    #[test]
    fn test_halving_reflected_in_epoch_rewards() {
        // Verify the reward at epoch 290,000 is half of genesis
        let reward_before = calculate_block_reward(289_999);
        let reward_after  = calculate_block_reward(290_000);
        assert_eq!(reward_before, GENESIS_BLOCK_REWARD);
        assert_eq!(reward_after,  GENESIS_BLOCK_REWARD / 2);
    }
}