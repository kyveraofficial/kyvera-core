use crate::chain::block_producer::produce_genesis_block;
use crate::chain::mining::GENESIS_BLOCK_REWARD;
use crate::storage::db::KyveraDb;
use crate::storage::block_store::{save_block, save_chain_tip};
use crate::storage::account_store::credit_account;
use crate::chain::block_producer::ChainTip;

// Genesis block configuration.
// Every value here is a protocol constant — hardcoded, not configurable.
// These are the values that define Kyvera Continuum from block zero.
// Changing any of these would require a hard fork and a new genesis block.

// Total supply of KYV in smallest units (1 KYV = 1,000,000,000 units)
pub const TOTAL_SUPPLY: u64 = 1_500_000_000_000_000_000;

// Genesis allocations as fractions of total supply
// Mining: 60% — released over time through PoK mining
pub const MINING_ALLOCATION: u64 = 900_000_000_000_000_000;

// Ecosystem fund: 15% — developer grants, partnerships, growth
pub const ECOSYSTEM_ALLOCATION: u64 = 225_000_000_000_000_000;

// Founder reserve: 10% — vested on-chain over 36 months
pub const FOUNDER_ALLOCATION: u64 = 150_000_000_000_000_000;

// Community and airdrop: 10% — early adopters, testnet participants
pub const COMMUNITY_ALLOCATION: u64 = 150_000_000_000_000_000;

// Reserve treasury: 5% — exchange listings, emergency liquidity
pub const TREASURY_ALLOCATION: u64 = 75_000_000_000_000_000;

// Well-known genesis addresses — labeled on the block explorer.
// On mainnet these will be real addresses derived from the
// respective key ceremonies. These are placeholder values
// for the testnet genesis.
pub const ECOSYSTEM_ADDRESS: &str =
    "kyv10000000000000000000000000000000000000000000000000ecosystem00";
pub const FOUNDER_ADDRESS: &str =
    "kyv10000000000000000000000000000000000000000000000000000founder00";
pub const COMMUNITY_ADDRESS: &str =
    "kyv100000000000000000000000000000000000000000000000000community00";
pub const TREASURY_ADDRESS: &str =
    "kyv10000000000000000000000000000000000000000000000000000treasury00";

// The genesis miner address — whoever mines the first block
// receives the genesis block reward as a coinbase transaction.
// On mainnet this is the founder address.
pub const GENESIS_MINER: &str = FOUNDER_ADDRESS;

// Initialize the chain from the genesis block.
// Called exactly once — when a new node starts with no existing chain data.
// Produces the genesis block, applies all genesis allocations to the
// account state, saves everything to the database, and returns the
// initial chain tip.
//
// If the database already contains a chain tip this function
// returns an error — you cannot re-initialize an existing chain.
pub fn initialize_chain(db: &KyveraDb) -> Result<ChainTip, String> {
    // Safety check — do not overwrite an existing chain
    if let Some(tip) = crate::storage::block_store::load_chain_tip(db)? {
        return Err(format!(
            "Chain already initialized at height {}. \
             Cannot re-initialize without wiping the database.",
            tip.height
        ));
    }

    // Mine the genesis block
    let genesis = produce_genesis_block(GENESIS_MINER)
        .map_err(|e| format!("Failed to produce genesis block: {}", e))?;

    // Apply genesis allocations to account state
    // These amounts are hardcoded and verified against the total supply
    apply_genesis_allocations(db)?;

    // Credit the genesis miner with the block reward
    credit_account(db, GENESIS_MINER, GENESIS_BLOCK_REWARD)?;

    // Save the genesis block
    save_block(db, &genesis)?;

    // Compute and save the initial state root
    let state_root = crate::storage::state_trie::compute_state_root(db)?;
    crate::storage::state_trie::save_state_root(db, &state_root)?;

    // Build and save the initial chain tip
    let mut tip = ChainTip::genesis();
    tip.advance(&genesis);
    save_chain_tip(db, &tip)?;

    println!("  Kyvera Continuum initialized.");
    println!("  Genesis block: {}", genesis.hash);
    println!("  State root:    {}", state_root);

    Ok(tip)
}

// Apply all non-mining genesis allocations to the account state.
// The mining allocation is NOT credited here — it is distributed
// over time through block rewards as miners produce epoch blocks.
fn apply_genesis_allocations(db: &KyveraDb) -> Result<(), String> {
    credit_account(db, ECOSYSTEM_ADDRESS, ECOSYSTEM_ALLOCATION)?;
    credit_account(db, FOUNDER_ADDRESS,   FOUNDER_ALLOCATION)?;
    credit_account(db, COMMUNITY_ADDRESS, COMMUNITY_ALLOCATION)?;
    credit_account(db, TREASURY_ADDRESS,  TREASURY_ALLOCATION)?;

    // Verify total non-mining allocation matches spec
    let expected = ECOSYSTEM_ALLOCATION
        + FOUNDER_ALLOCATION
        + COMMUNITY_ALLOCATION
        + TREASURY_ALLOCATION;

    let expected_with_mining = expected + MINING_ALLOCATION;

    if expected_with_mining != TOTAL_SUPPLY {
        return Err(format!(
            "Genesis allocation error: allocations sum to {} but total supply is {}",
            expected_with_mining, TOTAL_SUPPLY
        ));
    }

    Ok(())
}

// Verify that the genesis block in the database matches what we expect.
// Called on node startup to detect any database corruption or
// tampering with the genesis block.
pub fn verify_genesis_integrity(db: &KyveraDb) -> Result<bool, String> {
    let genesis = crate::storage::block_store::get_block_by_height(db, 0)?;

    match genesis {
        None => Ok(false),
        Some(block) => {
            // Genesis block must be an epoch block at height 0
            if block.header.index != 0 || !block.header.is_epoch_block {
                return Ok(false);
            }
            // Previous hash must be 64 zeros
            if block.header.previous_hash != "0".repeat(64) {
                return Ok(false);
            }
            // Producer must be the genesis miner
            if block.producer_address != GENESIS_MINER {
                return Ok(false);
            }
            Ok(true)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::KyveraDb;
    use crate::storage::account_store::get_balance;

    #[test]
    fn test_genesis_allocations_sum_to_total_supply() {
        let sum = MINING_ALLOCATION
            + ECOSYSTEM_ALLOCATION
            + FOUNDER_ALLOCATION
            + COMMUNITY_ALLOCATION
            + TREASURY_ALLOCATION;

        assert_eq!(sum, TOTAL_SUPPLY,
            "Genesis allocations must sum to exactly 1.5B KYV units");
    }

    #[test]
    fn test_initialize_chain() {
        let db = KyveraDb::open_temp().unwrap();
        let tip = initialize_chain(&db).unwrap();

        assert_eq!(tip.height, 0);
        assert!(!tip.hash.is_empty());
        assert_eq!(tip.epoch_index, 0);
    }

    #[test]
    fn test_cannot_initialize_twice() {
        let db = KyveraDb::open_temp().unwrap();
        initialize_chain(&db).unwrap();

        let result = initialize_chain(&db);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already initialized"));
    }

    #[test]
    fn test_genesis_allocations_applied_correctly() {
        let db = KyveraDb::open_temp().unwrap();
        initialize_chain(&db).unwrap();

        assert_eq!(
            get_balance(&db, ECOSYSTEM_ADDRESS).unwrap(),
            ECOSYSTEM_ALLOCATION
        );
        assert_eq!(
            get_balance(&db, COMMUNITY_ADDRESS).unwrap(),
            COMMUNITY_ALLOCATION
        );
        assert_eq!(
            get_balance(&db, TREASURY_ADDRESS).unwrap(),
            TREASURY_ALLOCATION
        );
    }

    #[test]
    fn test_founder_gets_genesis_block_reward() {
        let db = KyveraDb::open_temp().unwrap();
        initialize_chain(&db).unwrap();

        // Founder gets their allocation PLUS the genesis block reward
        let founder_balance = get_balance(&db, FOUNDER_ADDRESS).unwrap();
        assert_eq!(
            founder_balance,
            FOUNDER_ALLOCATION + GENESIS_BLOCK_REWARD
        );
    }

    #[test]
    fn test_genesis_block_saved_to_database() {
        let db = KyveraDb::open_temp().unwrap();
        initialize_chain(&db).unwrap();

        let genesis = crate::storage::block_store::get_block_by_height(&db, 0)
            .unwrap()
            .unwrap();

        assert_eq!(genesis.header.index, 0);
        assert!(genesis.header.is_epoch_block);
        assert_eq!(genesis.producer_address, GENESIS_MINER);
    }

    #[test]
    fn test_state_root_committed_at_genesis() {
        let db = KyveraDb::open_temp().unwrap();
        initialize_chain(&db).unwrap();

        let root = crate::storage::state_trie::load_state_root(&db)
            .unwrap();
        assert!(root.is_some());
        assert_eq!(root.unwrap().len(), 64);
    }

    #[test]
    fn test_verify_genesis_integrity() {
        let db = KyveraDb::open_temp().unwrap();
        initialize_chain(&db).unwrap();

        assert!(verify_genesis_integrity(&db).unwrap());
    }

    #[test]
    fn test_verify_genesis_integrity_fails_on_empty_db() {
        let db = KyveraDb::open_temp().unwrap();
        assert!(!verify_genesis_integrity(&db).unwrap());
    }
}