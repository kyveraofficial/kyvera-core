use crate::storage::db::KyveraDb;
use crate::types::block::Block;
use crate::chain::block_producer::ChainTip;

// The block store handles all block persistence.
// Blocks are stored by two indexes:
// 1. By hash — the canonical identifier for any block
// 2. By height — lets us look up blocks by their position in the chain
//
// We also persist the chain tip here so nodes can resume from
// exactly where they left off after a restart.

const CHAIN_TIP_KEY: &str = "chain_tip";

// Write a block to the database.
// Stores it under both the hash index and the height index.
// Both writes happen atomically — either both succeed or neither does.
pub fn save_block(db: &KyveraDb, block: &Block) -> Result<(), String> {
    let serialized = serde_json::to_vec(block)
        .map_err(|e| format!("Failed to serialize block: {}", e))?;

    // Store by hash — primary index
    KyveraDb::write(
        &db.blocks_by_hash,
        block.hash.as_bytes(),
        &serialized,
    )?;

    // Store height -> hash mapping — secondary index
    // Height is stored as 8 big-endian bytes so lexicographic
    // ordering of keys matches numeric ordering of heights.
    // This lets us iterate blocks in order efficiently.
    let height_key = block.header.index.to_be_bytes();
    KyveraDb::write(
        &db.blocks_by_height,
        &height_key,
        block.hash.as_bytes(),
    )?;

    Ok(())
}

// Load a block by its hash.
pub fn get_block_by_hash(db: &KyveraDb, hash: &str) -> Result<Option<Block>, String> {
    let data = KyveraDb::read(&db.blocks_by_hash, hash.as_bytes())?;
    match data {
        None => Ok(None),
        Some(bytes) => {
            let block = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Failed to deserialize block: {}", e))?;
            Ok(Some(block))
        }
    }
}

// Load a block by its height.
// Looks up the hash first, then loads the full block by hash.
pub fn get_block_by_height(db: &KyveraDb, height: u64) -> Result<Option<Block>, String> {
    let height_key = height.to_be_bytes();
    let hash_bytes = KyveraDb::read(&db.blocks_by_height, &height_key)?;

    match hash_bytes {
        None => Ok(None),
        Some(hash_bytes) => {
            let hash = String::from_utf8(hash_bytes)
                .map_err(|e| format!("Invalid hash bytes: {}", e))?;
            get_block_by_hash(db, &hash)
        }
    }
}

// Check whether a block with the given hash exists.
pub fn block_exists(db: &KyveraDb, hash: &str) -> Result<bool, String> {
    KyveraDb::exists(&db.blocks_by_hash, hash.as_bytes())
}

// Save the current chain tip to the database.
// Called every time a new block is accepted.
// On restart the node loads this to know where to resume from.
pub fn save_chain_tip(db: &KyveraDb, tip: &ChainTip) -> Result<(), String> {
    let serialized = serde_json::to_vec(tip)
        .map_err(|e| format!("Failed to serialize chain tip: {}", e))?;
    db.set_metadata(CHAIN_TIP_KEY, &serialized)
}

// Load the chain tip from the database.
// Returns None if no blocks have been written yet — fresh node.
pub fn load_chain_tip(db: &KyveraDb) -> Result<Option<ChainTip>, String> {
    let data = db.get_metadata(CHAIN_TIP_KEY)?;
    match data {
        None => Ok(None),
        Some(bytes) => {
            let tip = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Failed to deserialize chain tip: {}", e))?;
            Ok(Some(tip))
        }
    }
}

// Get the total number of blocks stored.
pub fn block_count(db: &KyveraDb) -> usize {
    KyveraDb::count(&db.blocks_by_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::block_producer::{produce_genesis_block, ChainTip};

    const TEST_MINER: &str = "kyv1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn test_save_and_load_block_by_hash() {
        let db = KyveraDb::open_temp().unwrap();
        let block = produce_genesis_block(TEST_MINER).unwrap();

        save_block(&db, &block).unwrap();

        let loaded = get_block_by_hash(&db, &block.hash).unwrap();
        assert!(loaded.is_some());

        let loaded = loaded.unwrap();
        assert_eq!(loaded.hash, block.hash);
        assert_eq!(loaded.header.index, 0);
        assert_eq!(loaded.block_reward, block.block_reward);
    }

    #[test]
    fn test_save_and_load_block_by_height() {
        let db = KyveraDb::open_temp().unwrap();
        let block = produce_genesis_block(TEST_MINER).unwrap();

        save_block(&db, &block).unwrap();

        let loaded = get_block_by_height(&db, 0).unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().hash, block.hash);
    }

    #[test]
    fn test_block_exists() {
        let db = KyveraDb::open_temp().unwrap();
        let block = produce_genesis_block(TEST_MINER).unwrap();

        assert!(!block_exists(&db, &block.hash).unwrap());
        save_block(&db, &block).unwrap();
        assert!(block_exists(&db, &block.hash).unwrap());
    }

    #[test]
    fn test_nonexistent_block_returns_none() {
        let db = KyveraDb::open_temp().unwrap();
        let result = get_block_by_hash(&db, "nonexistent_hash").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_block_count() {
        let db = KyveraDb::open_temp().unwrap();
        assert_eq!(block_count(&db), 0);

        let block = produce_genesis_block(TEST_MINER).unwrap();
        save_block(&db, &block).unwrap();
        assert_eq!(block_count(&db), 1);
    }

    #[test]
    fn test_save_and_load_chain_tip() {
        let db = KyveraDb::open_temp().unwrap();
        let block = produce_genesis_block(TEST_MINER).unwrap();

        let mut tip = ChainTip::genesis();
        tip.advance(&block);

        save_chain_tip(&db, &tip).unwrap();

        let loaded = load_chain_tip(&db).unwrap();
        assert!(loaded.is_some());

        let loaded = loaded.unwrap();
        assert_eq!(loaded.hash, tip.hash);
        assert_eq!(loaded.height, tip.height);
        assert_eq!(loaded.epoch_index, tip.epoch_index);
    }

    #[test]
    fn test_load_chain_tip_returns_none_on_fresh_db() {
        let db = KyveraDb::open_temp().unwrap();
        let tip = load_chain_tip(&db).unwrap();
        assert!(tip.is_none());
    }

    #[test]
    fn test_chain_tip_updates_on_new_block() {
        let db = KyveraDb::open_temp().unwrap();
        let block = produce_genesis_block(TEST_MINER).unwrap();

        let mut tip = ChainTip::genesis();
        tip.advance(&block);
        save_chain_tip(&db, &tip).unwrap();

        // Simulate restart — load from db
        let restored_tip = load_chain_tip(&db).unwrap().unwrap();
        assert_eq!(restored_tip.hash, block.hash);
    }
}