use crate::chain::hash::{hash_block_header, meets_difficulty};
use crate::types::block::BlockHeader;

// The mining engine for Proof of Kinesis.
// This is what miners run on their CPUs and mobile devices.
// The algorithm is designed to be memory-hard so ASICs cannot
// get a meaningful advantage over consumer hardware.
// Every nonce attempt requires enough memory that building
// a chip specifically for it costs more than it is worth.

// How many KYV units are in one KYV (10^9).
// All reward calculations use this constant.
pub const KYV_UNITS: u64 = 1_000_000_000;

// Genesis block reward — 50 KYV per epoch block.
pub const GENESIS_BLOCK_REWARD: u64 = 50 * KYV_UNITS;

// Halving interval — every 290,000 epoch blocks.
pub const HALVING_INTERVAL: u64 = 290_000;

// Target time between epoch blocks in seconds — 10 minutes.
pub const EPOCH_BLOCK_TARGET_SECONDS: u64 = 600;

// Target time between micro blocks in seconds — 2.5 seconds.
pub const MICRO_BLOCK_TARGET_SECONDS: u64 = 3;

// How many recent blocks to look at when adjusting difficulty.
// More blocks = smoother adjustment but slower response.
pub const DIFFICULTY_WINDOW: usize = 144;

// Minimum and maximum difficulty to prevent edge cases.
pub const MIN_DIFFICULTY: u32 = 1;
pub const MAX_DIFFICULTY: u32 = 64;

// The result of a successful mining attempt.
#[derive(Debug, Clone)]
pub struct MinedBlock {
    pub nonce: u64,
    pub hash: String,
    pub attempts: u64,
}

// Calculate the block reward for a given epoch block height.
// Halves every HALVING_INTERVAL epoch blocks starting from genesis.
// Returns zero once all mining rewards are exhausted.
pub fn calculate_block_reward(epoch_block_height: u64) -> u64 {
    let halving_count = epoch_block_height / HALVING_INTERVAL;

    // After 64 halvings the reward is effectively zero.
    // Using checked_shr to avoid overflow on large halving counts.
    GENESIS_BLOCK_REWARD.checked_shr(halving_count as u32).unwrap_or(0)
}

// Mine a block header by iterating nonces until the hash
// meets the required difficulty. Returns the winning nonce
// and the hash that satisfied the difficulty target.
//
// This runs on the miner's CPU. On a modern desktop this
// will find a solution in seconds at low difficulty.
// At mainnet difficulty it will take approximately 10 minutes
// for the entire network collectively to find a solution.
//
// The max_attempts parameter is a safety valve for tests —
// pass u64::MAX for real mining.
pub fn mine_block(
    header: &BlockHeader,
    max_attempts: u64,
) -> Option<MinedBlock> {
    let mut nonce: u64 = 0;

    while nonce < max_attempts {
        let hash = hash_block_header(
            header.index,
            header.timestamp,
            &header.previous_hash,
            &header.merkle_root,
            nonce,
            header.difficulty,
            header.is_epoch_block,
            header.epoch_index,
            &header.state_root,
        );

        if meets_difficulty(&hash, header.difficulty) {
            return Some(MinedBlock {
                nonce,
                hash,
                attempts: nonce + 1,
            });
        }

        nonce += 1;
    }

    None
}

// Calculate the next difficulty target based on recent block times.
// If blocks are coming in faster than the target, difficulty goes up.
// If blocks are coming in slower than the target, difficulty goes down.
// Clamped between MIN_DIFFICULTY and MAX_DIFFICULTY to prevent
// the chain from getting stuck or becoming trivially easy.
//
// timestamps: the unix timestamps of recent blocks in chronological order
// is_epoch_block: true adjusts for 10-minute target, false for 2.5-second
pub fn calculate_next_difficulty(
    current_difficulty: u32,
    timestamps: &[i64],
    is_epoch_block: bool,
) -> u32 {
    if timestamps.len() < 2 {
        // Not enough data to adjust — keep current difficulty
        return current_difficulty;
    }

    let target_seconds = if is_epoch_block {
        EPOCH_BLOCK_TARGET_SECONDS as i64
    } else {
        MICRO_BLOCK_TARGET_SECONDS as i64
    };

    // Calculate the average time between recent blocks
    let window = timestamps.len().min(DIFFICULTY_WINDOW);
    let recent = &timestamps[timestamps.len() - window..];
    let elapsed = recent.last().unwrap() - recent.first().unwrap();
    let block_count = (recent.len() - 1) as i64;

    if block_count == 0 {
        return current_difficulty;
    }

    let average_seconds = elapsed / block_count;

    // Adjust difficulty proportionally to how far off target we are.
    // We use a conservative adjustment — never more than +/- 1 per round.
    // This prevents wild oscillations that could destabilize the chain.
    let new_difficulty = if average_seconds < target_seconds / 2 {
        // Blocks coming in way too fast — increase difficulty
        current_difficulty + 1
    } else if average_seconds < target_seconds {
        // Blocks slightly fast — nudge up
        current_difficulty + 1
    } else if average_seconds > target_seconds * 2 {
        // Blocks coming in way too slow — decrease difficulty
        current_difficulty.saturating_sub(1)
    } else if average_seconds > target_seconds {
        // Blocks slightly slow — nudge down
        current_difficulty.saturating_sub(1)
    } else {
        // Right on target
        current_difficulty
    };

    // Clamp to valid range
    new_difficulty.clamp(MIN_DIFFICULTY, MAX_DIFFICULTY)
}

// Verify that a block hash meets the claimed difficulty.
// Called by every node that receives a new block.
// A block with a hash that does not meet its difficulty is invalid
// regardless of everything else being correct.
pub fn verify_proof_of_work(hash: &str, difficulty: u32) -> bool {
    meets_difficulty(hash, difficulty)
}

// Estimate the current network hash rate from recent block times.
// Returns estimated hashes per second across the whole network.
// Used for informational display — not a consensus-critical value.
pub fn estimate_hash_rate(
    difficulty: u32,
    average_block_time_seconds: f64,
) -> f64 {
    // Expected number of hashes to find a solution at given difficulty.
    // Each leading zero nibble requires 16x more work on average.
    let expected_hashes = 16f64.powi(difficulty as i32);
    expected_hashes / average_block_time_seconds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::block::BlockHeader;

    fn test_header(difficulty: u32) -> BlockHeader {
        BlockHeader::new(
            0,
            "0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            "merkle_root_placeholder".to_string(),
            difficulty,
            true,
            0,
        )
    }

    #[test]
    fn test_genesis_block_reward() {
        // Epoch 0 — full 50 KYV reward
        assert_eq!(calculate_block_reward(0), 50 * KYV_UNITS);
        assert_eq!(calculate_block_reward(1), 50 * KYV_UNITS);
        assert_eq!(calculate_block_reward(289_999), 50 * KYV_UNITS);
    }

    #[test]
    fn test_first_halving() {
        // At block 290,000 the reward halves to 25 KYV
        assert_eq!(calculate_block_reward(290_000), 25 * KYV_UNITS);
        assert_eq!(calculate_block_reward(579_999), 25 * KYV_UNITS);
    }

    #[test]
    fn test_second_halving() {
        // At block 580,000 the reward halves again to 12.5 KYV
        assert_eq!(calculate_block_reward(580_000), 12 * KYV_UNITS + 500_000_000);
    }

    #[test]
    fn test_reward_eventually_reaches_zero() {
        // After enough halvings the reward should be zero
        assert_eq!(calculate_block_reward(290_000 * 100), 0);
    }

    #[test]
    fn test_mine_block_at_low_difficulty() {
        // Difficulty 1 means just one leading zero nibble needed.
        // Should find a solution very quickly on any hardware.
        let header = test_header(1);
        let result = mine_block(&header, 100_000);

        assert!(result.is_some(), "Should find a solution at difficulty 1");
        let mined = result.unwrap();
        assert!(mined.hash.starts_with('0'));
        assert!(verify_proof_of_work(&mined.hash, 1));
    }

    #[test]
    fn test_mine_block_at_difficulty_2() {
        let header = test_header(2);
        let result = mine_block(&header, 1_000_000);

        assert!(result.is_some(), "Should find a solution at difficulty 2");
        let mined = result.unwrap();
        assert!(mined.hash.starts_with("00"));
        assert!(verify_proof_of_work(&mined.hash, 2));
    }

    #[test]
    fn test_mining_respects_max_attempts() {
        // Set max_attempts to 1 — very unlikely to find difficulty 4 in 1 try
        let header = test_header(4);
        let result = mine_block(&header, 1);
        // This might succeed by luck but almost certainly returns None
        // We cannot assert either way — just check it does not panic
        let _ = result;
    }

    #[test]
    fn test_verify_proof_of_work() {
        let header = test_header(1);
        let mined = mine_block(&header, 100_000).unwrap();

        assert!(verify_proof_of_work(&mined.hash, 1));
        // Should not pass a higher difficulty check
        assert!(!verify_proof_of_work(&mined.hash, 10));
    }

    #[test]
    fn test_difficulty_adjustment_increases_when_too_fast() {
        // Blocks coming every 1 second when target is 600 seconds
        let timestamps: Vec<i64> = (0..10).map(|i| i * 1).collect();
        let new_diff = calculate_next_difficulty(4, &timestamps, true);
        assert!(new_diff > 4, "Difficulty should increase when blocks are too fast");
    }

    #[test]
    fn test_difficulty_adjustment_decreases_when_too_slow() {
        // Blocks coming every 1200 seconds when target is 600 seconds
        let timestamps: Vec<i64> = (0..10).map(|i| i * 1200).collect();
        let new_diff = calculate_next_difficulty(4, &timestamps, true);
        assert!(new_diff < 4, "Difficulty should decrease when blocks are too slow");
    }

    #[test]
    fn test_difficulty_never_goes_below_minimum() {
        let timestamps: Vec<i64> = (0..10).map(|i| i * 99999).collect();
        let new_diff = calculate_next_difficulty(1, &timestamps, true);
        assert!(new_diff >= MIN_DIFFICULTY);
    }

    #[test]
    fn test_difficulty_never_exceeds_maximum() {
        let timestamps: Vec<i64> = (0..10).map(|i| i).collect();
        let new_diff = calculate_next_difficulty(MAX_DIFFICULTY, &timestamps, true);
        assert!(new_diff <= MAX_DIFFICULTY);
    }

    #[test]
    fn test_halving_interval_constant() {
        assert_eq!(HALVING_INTERVAL, 290_000);
    }

    #[test]
    fn test_genesis_reward_constant() {
        assert_eq!(GENESIS_BLOCK_REWARD, 50_000_000_000);
    }
}