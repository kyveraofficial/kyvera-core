use serde::{Deserialize, Serialize};
use chrono::Utc;

// The header is separated from the block body deliberately.
// When nodes are syncing they download headers first to verify
// the chain before pulling full transaction data. Keeps sync fast.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockHeader {
    // Height in the chain. Genesis is 0.
    pub index: u64,

    // Millisecond precision matters here. Two nodes producing
    // blocks at the same second need to be distinguishable.
    pub timestamp: i64,

    // This is what makes it a chain. If you change any block,
    // every hash after it breaks. That's the whole point.
    pub previous_hash: String,

    // We don't store transactions directly in the header.
    // The merkle root lets anyone verify a transaction is in
    // the block without downloading every transaction in it.
    pub merkle_root: String,

    // Miners grind this number until the block hash meets difficulty.
    // Starts at 0, increments until we find a valid hash.
    pub nonce: u64,

    // Number of leading zeros required in the block hash.
    // Adjusts automatically based on how fast blocks are coming in.
    pub difficulty: u32,

    // Kyvera runs two block types. Micro blocks are fast (2-3s) and
    // handle transactions. Epoch blocks are every 10 minutes and
    // provide cryptographic finality. This flag tells you which one.
    pub is_epoch_block: bool,

    // Only increments on epoch blocks. Everything that matters on
    // a schedule — halvings, validator rewards, governance — counts
    // epoch blocks, not micro blocks. Don't confuse the two.
    pub epoch_index: u64,

    // Fingerprint of the entire account state at this point in time.
    // Only written on epoch blocks. Empty on micro blocks because
    // state isn't finalised until the next epoch checkpoint.
    pub state_root: String,
}

// A full block. The header plus the list of what's inside it,
// plus the producer's details and the hash once mining is done.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Block {
    pub header: BlockHeader,

    // We store hashes here, not full transactions. Full transaction
    // data lives in the database keyed by hash. This keeps blocks
    // lean and lets us look up transactions independently.
    pub transaction_hashes: Vec<String>,

    // Computed after mining. Empty until the miner finds a valid nonce.
    pub hash: String,

    // Epoch blocks carry a full Dilithium signature here.
    // Micro blocks use a lighter internal scheme. The validation
    // logic checks is_epoch_block to know which to verify against.
    pub validator_signature: String,

    // Whoever mined or validated this block. Gets the block reward
    // plus a cut of the transaction fees inside.
    pub producer_address: String,

    // Denominated in the smallest KYV unit (10^-9).
    // So 50 KYV at genesis = 50_000_000_000 here.
    // Zero on micro blocks. Only epoch blocks carry the reward.
    pub block_reward: u64,
}

impl BlockHeader {
    pub fn new(
        index: u64,
        previous_hash: String,
        merkle_root: String,
        difficulty: u32,
        is_epoch_block: bool,
        epoch_index: u64,
    ) -> Self {
        BlockHeader {
            index,
            timestamp: Utc::now().timestamp_millis(),
            previous_hash,
            merkle_root,
            // Miner starts grinding from zero
            nonce: 0,
            difficulty,
            is_epoch_block,
            epoch_index,
            // State root gets filled in after execution, not at construction
            state_root: String::new(),
        }
    }
}

impl Block {
    // Hash and signature are empty until mining finishes.
    // Don't try to validate a block that was just constructed —
    // it won't pass. Call this, mine it, then set the hash.
    pub fn new(
        header: BlockHeader,
        transaction_hashes: Vec<String>,
        producer_address: String,
        block_reward: u64,
    ) -> Self {
        Block {
            header,
            transaction_hashes,
            hash: String::new(),
            validator_signature: String::new(),
            producer_address,
            block_reward,
        }
    }

    pub fn is_epoch_block(&self) -> bool {
        self.header.is_epoch_block
    }

    pub fn height(&self) -> u64 {
        self.header.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_header_creation() {
        let header = BlockHeader::new(
            0,
            // Genesis block has no parent. Convention is 64 zeros.
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            "merkle_root_placeholder".to_string(),
            4,
            true,
            0,
        );

        assert_eq!(header.index, 0);
        assert_eq!(header.nonce, 0);
        assert_eq!(header.difficulty, 4);
        assert!(header.is_epoch_block);
        assert_eq!(header.epoch_index, 0);
        assert!(header.timestamp > 0);
    }

    #[test]
    fn test_block_creation() {
        let header = BlockHeader::new(
            0,
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            "merkle_root_placeholder".to_string(),
            4,
            true,
            0,
        );

        let block = Block::new(
            header,
            vec!["tx_hash_1".to_string(), "tx_hash_2".to_string()],
            "miner_address_placeholder".to_string(),
            // 50 KYV in smallest units
            50_000_000_000,
        );

        assert_eq!(block.height(), 0);
        assert!(block.is_epoch_block());
        assert_eq!(block.transaction_hashes.len(), 2);
        assert_eq!(block.block_reward, 50_000_000_000);
        // Hash should be empty until mining runs
        assert!(block.hash.is_empty());
    }

    #[test]
    fn test_block_serialization() {
        // Make sure blocks survive a round trip through JSON.
        // This matters because blocks get written to disk and sent
        // over the network constantly.
        let header = BlockHeader::new(
            1,
            "prev_hash".to_string(),
            "merkle".to_string(),
            4,
            false,
            0,
        );

        let block = Block::new(
            header,
            vec![],
            "producer".to_string(),
            0,
        );

        let json = serde_json::to_string(&block).unwrap();
        let decoded: Block = serde_json::from_str(&json).unwrap();

        assert_eq!(block, decoded);
        assert_eq!(decoded.header.index, 1);
        assert!(!decoded.header.is_epoch_block);
    }
}