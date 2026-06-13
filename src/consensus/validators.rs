use crate::storage::db::KyveraDb;
use crate::storage::account_store::{get_account, save_account, get_validators, credit_account};
use crate::consensus::coinbase::{apply_coinbase, calculate_validator_fee_share};
use crate::consensus::genesis::TREASURY_ADDRESS;
use crate::types::account::Account;
use crate::types::transaction::Transaction;

// This module is where Proof of Kinesis becomes genuinely "two-layer".
//
// Layer 1 — Mining: whoever mines the epoch block gets the block reward
// via the coinbase transaction. This is pure proof-of-work.
//
// Layer 2 — Staking: every active validator, regardless of whether they
// mined this particular block, receives a share of the transaction fees
// collected since the last epoch block. Their share is weighted by how
// much KYV they have staked AND their validator tier bonus.
//
// A miner who is also staked benefits from both layers. A staker who
// never mines still earns from layer 2 continuously. This is what
// ties mining and staking together into one consensus mechanism
// instead of two separate systems bolted together.

// Slash percentages, expressed in basis points (1 bps = 0.01%).
// Minor slashing — missed epoch participation, late signatures.
pub const MINOR_SLASH_BPS: u64 = 100;   // 1%

// Major slashing — double signing, invalid block signatures,
// provable malicious behaviour.
pub const MAJOR_SLASH_BPS: u64 = 1000;  // 10%

// Get the current active validator set.
// An account is an active validator if its staked balance meets
// at least the Igniter tier threshold (500 KYV).
pub fn get_active_validator_set(db: &KyveraDb) -> Result<Vec<Account>, String> {
    get_validators(db)
}

// Calculate a validator's reward weight.
// Weight = staked balance + tier bonus.
// A Nexus validator with 25,000 KYV staked has a weight of
// 25,000 + 35% of 25,000 = 33,750. This weight determines what
// share of the fee pool they receive relative to other validators.
//
// An account with no validator tier (validator_tier == None) has
// a bonus of zero — weight equals staked balance only.
pub fn calculate_validator_weight(account: &Account) -> u64 {
    let bonus_bps = account.validator_tier
    .as_ref()
    .map(|tier| tier.reward_bonus_bps())
    .unwrap_or(0);
    let bonus = account.staked_balance.saturating_mul(bonus_bps) / 10_000;
    account.staked_balance.saturating_add(bonus)
}

// Distribute the validator fee share among all active validators.
// Each validator receives a portion proportional to their weight
// relative to the total weight of all active validators.
// Returns the total amount actually distributed.
//
// If there are no active validators, the fee share is not lost —
// the caller should redirect it to the treasury in that case.
pub fn distribute_validator_rewards(
    db: &KyveraDb,
    total_share: u64,
) -> Result<u64, String> {
    if total_share == 0 {
        return Ok(0);
    }

    let validators = get_active_validator_set(db)?;
    if validators.is_empty() {
        return Ok(0);
    }

    let weights: Vec<(String, u64)> = validators
        .iter()
        .map(|v| (v.address.clone(), calculate_validator_weight(v)))
        .collect();

    let total_weight: u128 = weights.iter().map(|(_, w)| *w as u128).sum();
    if total_weight == 0 {
        return Ok(0);
    }

    let mut distributed: u64 = 0;

    for (address, weight) in &weights {
        // u128 intermediate math avoids overflow when multiplying
        // large reward pools by large weights before dividing.
        let share = (total_share as u128 * *weight as u128 / total_weight) as u64;
        if share > 0 {
            credit_account(db, address, share)?;
            distributed = distributed.saturating_add(share);
        }
    }

    Ok(distributed)
}

// Apply the complete two-layer reward for an epoch block.
//
// Step 1 (Mining layer): the coinbase transaction credits the
// epoch block miner with the block reward.
//
// Step 2 (Staking layer): the validator fee share — 40% of all
// fees collected since the last epoch block — is distributed
// across every active validator proportional to their weight.
// This happens independently of who mined the block.
//
// If no validators exist yet (very early chain life before anyone
// has staked), the validator fee share is redirected to the treasury
// rather than disappearing.
pub fn apply_epoch_rewards(
    db: &KyveraDb,
    coinbase: &Transaction,
    total_fees_collected: u64,
) -> Result<(), String> {
    // Layer 1 — mining reward to the block producer.
    // No fee share is bundled into the coinbase itself —
    // fee distribution to validators happens separately in Layer 2,
    // which the miner also benefits from if they are staked.
    apply_coinbase(db, coinbase, 0)?;

    // Layer 2 — staking reward distributed across the validator set.
    let validator_share = calculate_validator_fee_share(total_fees_collected);
    let distributed = distribute_validator_rewards(db, validator_share)?;

    // Anything not distributed (no active validators yet) goes to treasury
    // rather than being permanently lost.
    let leftover = validator_share.saturating_sub(distributed);
    if leftover > 0 {
        credit_account(db, TREASURY_ADDRESS, leftover)?;
    }

    Ok(())
}

// Slash a validator's staked balance by the given basis points.
// The slashed amount is sent to the treasury — not burned, not
// redistributed to other validators, to avoid creating a perverse
// incentive for validators to falsely accuse each other.
//
// Returns the amount slashed. Returns an error if the address
// has no account or is not currently staked.
pub fn slash_validator(
    db: &KyveraDb,
    address: &str,
    slash_bps: u64,
) -> Result<u64, String> {
    let mut account = get_account(db, address)?
        .ok_or_else(|| format!("No account found for {}", address))?;

    if account.staked_balance == 0 {
        return Err(format!("{} has no staked balance to slash", address));
    }

    let slash_amount = account.staked_balance.saturating_mul(slash_bps) / 10_000;

    if slash_amount == 0 {
        return Ok(0);
    }

    account.staked_balance -= slash_amount;
    // Re-evaluate validator tier — a large slash can demote
    // a validator out of their current tier entirely.
    account.update_validator_tier();
    save_account(db, &account)?;

    credit_account(db, TREASURY_ADDRESS, slash_amount)?;

    Ok(slash_amount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::KyveraDb;
    use crate::storage::account_store::{credit_account, lock_stake, get_balance, get_account};
    use crate::consensus::coinbase::build_coinbase;
    use crate::types::account::ValidatorTier;

    fn addr(n: u8) -> String {
        format!("kyv1{}", hex::encode([n; 32]))
    }

    const MINER: &str =
        "kyv1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn test_igniter_has_no_bonus_weight() {
        let mut account = Account::new(addr(1));
        account.staked_balance = 500_000_000_000; // 500 KYV
        account.update_validator_tier();

        assert_eq!(account.validator_tier, Some(ValidatorTier::Igniter));
        // No bonus — weight equals staked balance exactly
        assert_eq!(calculate_validator_weight(&account), 500_000_000_000);
    }

    #[test]
    fn test_kinetic_weight_includes_15_percent_bonus() {
        let mut account = Account::new(addr(2));
        account.staked_balance = 5_000_000_000_000; // 5,000 KYV
        account.update_validator_tier();

        assert_eq!(account.validator_tier, Some(ValidatorTier::Kinetic));

        let weight = calculate_validator_weight(&account);
        // 5,000 + 15% = 5,750 KYV equivalent
        assert_eq!(weight, 5_750_000_000_000);
    }

    #[test]
    fn test_nexus_weight_includes_35_percent_bonus() {
        let mut account = Account::new(addr(3));
        account.staked_balance = 25_000_000_000_000; // 25,000 KYV
        account.update_validator_tier();

        assert_eq!(account.validator_tier, Some(ValidatorTier::Nexus));

        let weight = calculate_validator_weight(&account);
        // 25,000 + 35% = 33,750 KYV equivalent
        assert_eq!(weight, 33_750_000_000_000);
    }

    #[test]
    fn test_unstaked_account_has_no_bonus_weight() {
        // An account with zero stake and no tier should have
        // weight 0 — and must not panic on the Option unwrap.
        let account = Account::new(addr(99));
        assert_eq!(account.validator_tier, None);
        assert_eq!(calculate_validator_weight(&account), 0);
    }

    #[test]
    fn test_distribute_rewards_with_no_validators_returns_zero() {
        let db = KyveraDb::open_temp().unwrap();
        let distributed = distribute_validator_rewards(&db, 1_000_000_000).unwrap();
        assert_eq!(distributed, 0);
    }

    #[test]
    fn test_distribute_rewards_single_validator_gets_everything() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(1);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 500_000_000_000).unwrap(); // Igniter

        let total_share = 1_000_000_000; // 1 KYV
        let distributed = distribute_validator_rewards(&db, total_share).unwrap();

        assert_eq!(distributed, total_share);
        let balance = get_balance(&db, &validator).unwrap();
        // Started with 1000 KYV, staked 500, kept 500, plus the reward
        assert_eq!(balance, 500_000_000_000 + total_share);
    }

    #[test]
    fn test_distribute_rewards_proportional_by_tier() {
        let db = KyveraDb::open_temp().unwrap();
        let igniter = addr(1);
        let nexus = addr(2);

        // Igniter: 500 KYV staked, weight = 500
        credit_account(&db, &igniter, 1_000_000_000_000).unwrap();
        lock_stake(&db, &igniter, 500_000_000_000).unwrap();

        // Nexus: 25,000 KYV staked, weight = 33,750
        credit_account(&db, &nexus, 30_000_000_000_000).unwrap();
        lock_stake(&db, &nexus, 25_000_000_000_000).unwrap();

        let total_share = 1_000_000_000_000; // 1000 KYV
        distribute_validator_rewards(&db, total_share).unwrap();

        let igniter_balance = get_balance(&db, &igniter).unwrap();
        let nexus_balance = get_balance(&db, &nexus).unwrap();

        // Igniter pre-reward balance: 500 KYV remaining
        // Nexus pre-reward balance: 5,000 KYV remaining
        let igniter_reward = igniter_balance - 500_000_000_000;
        let nexus_reward = nexus_balance - 5_000_000_000_000;

        // Total weight = 500 + 33,750 = 34,250
        // Igniter share = 1000 * 500/34250 ≈ 14.59 KYV
        // Nexus share   = 1000 * 33750/34250 ≈ 985.4 KYV
        // Nexus should receive vastly more despite both being "active"
        assert!(nexus_reward > igniter_reward * 50);

        // Total distributed should be very close to total_share
        let total_distributed = igniter_reward + nexus_reward;
        assert!(total_distributed <= total_share);
        assert!(total_distributed > total_share - 1000); // rounding tolerance
    }

    #[test]
    fn test_apply_epoch_rewards_full_cycle() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(5);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 500_000_000_000).unwrap();

        let block_hash = "a".repeat(64);
        let coinbase = build_coinbase(MINER, 0, &block_hash);

        let total_fees = 100_000_000; // 0.1 KYV in fees collected

        apply_epoch_rewards(&db, &coinbase, total_fees).unwrap();

        // Miner gets the block reward via mining layer
        let miner_balance = get_balance(&db, MINER).unwrap();
        assert!(miner_balance > 0);

        // Validator gets their share of the fee pool via staking layer
        let validator_balance = get_balance(&db, &validator).unwrap();
        assert!(validator_balance > 500_000_000_000);
    }

    #[test]
    fn test_apply_epoch_rewards_no_validators_sends_share_to_treasury() {
        let db = KyveraDb::open_temp().unwrap();

        let block_hash = "b".repeat(64);
        let coinbase = build_coinbase(MINER, 0, &block_hash);
        let total_fees = 100_000_000;

        apply_epoch_rewards(&db, &coinbase, total_fees).unwrap();

        let validator_share = calculate_validator_fee_share(total_fees);
        let treasury_balance = get_balance(&db, TREASURY_ADDRESS).unwrap();

        assert_eq!(treasury_balance, validator_share);
    }

    #[test]
    fn test_minor_slash_reduces_stake() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(6);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 1_000_000_000_000).unwrap(); // 1000 KYV

        let slashed = slash_validator(&db, &validator, MINOR_SLASH_BPS).unwrap();

        // 1% of 1000 KYV = 10 KYV
        assert_eq!(slashed, 10_000_000_000);

        let account = get_account(&db, &validator).unwrap().unwrap();
        assert_eq!(account.staked_balance, 990_000_000_000);
    }

    #[test]
    fn test_major_slash_can_demote_tier() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(7);

        // Exactly at Igniter minimum — 500 KYV
        credit_account(&db, &validator, 500_000_000_000).unwrap();
        lock_stake(&db, &validator, 500_000_000_000).unwrap();

        let account = get_account(&db, &validator).unwrap().unwrap();
        assert_eq!(account.validator_tier, Some(ValidatorTier::Igniter));

        // 10% slash drops them below the Igniter threshold
        slash_validator(&db, &validator, MAJOR_SLASH_BPS).unwrap();

        let account = get_account(&db, &validator).unwrap().unwrap();
        assert_eq!(account.staked_balance, 450_000_000_000);
        assert_eq!(account.validator_tier, None);
        assert!(!account.is_validator());
    }

    #[test]
    fn test_slashed_funds_go_to_treasury() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(8);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 1_000_000_000_000).unwrap();

        slash_validator(&db, &validator, MAJOR_SLASH_BPS).unwrap();

        let treasury_balance = get_balance(&db, TREASURY_ADDRESS).unwrap();
        assert_eq!(treasury_balance, 100_000_000_000); // 10% of 1000 KYV
    }

    #[test]
    fn test_slash_on_unstaked_account_fails() {
        let db = KyveraDb::open_temp().unwrap();
        let account_addr = addr(9);
        credit_account(&db, &account_addr, 1_000_000_000).unwrap();

        let result = slash_validator(&db, &account_addr, MINOR_SLASH_BPS);
        assert!(result.is_err());
    }

    #[test]
    fn test_full_cycle_mining_to_igniter_tier() {
        let db = KyveraDb::open_temp().unwrap();
        let miner = addr(10);

        // Simulate mining several epoch blocks worth of rewards
        // until the miner has enough to reach Igniter tier (500 KYV)
        let mut total_mined: u64 = 0;
        for epoch in 0..15u64 {
            let coinbase = build_coinbase(&miner, epoch, &format!("{:064}", epoch));
            apply_coinbase(&db, &coinbase, 0).unwrap();
            total_mined += coinbase.amount;
        }

        // 15 epochs at 50 KYV each = 750 KYV — comfortably past Igniter
        assert!(total_mined >= 500_000_000_000);

        let balance = get_balance(&db, &miner).unwrap();
        assert_eq!(balance, total_mined);

        // Now stake enough to become an Igniter validator
        lock_stake(&db, &miner, 500_000_000_000).unwrap();

        let account = get_account(&db, &miner).unwrap().unwrap();
        assert_eq!(account.validator_tier, Some(ValidatorTier::Igniter));
        assert!(account.is_validator());
    }
}