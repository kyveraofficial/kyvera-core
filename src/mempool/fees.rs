use crate::types::transaction::{Transaction, TransactionType};

// Kyvera fee system.
//
// All fees on Kyvera are denominated in KYV units (1 KYV = 1,000,000,000 units).
// Every transaction pays a base fee determined by its type.
// The base fee is a protocol floor — wallets can pay more (fee bumping)
// to get faster inclusion during congestion, but never less than the floor.
//
// When a transaction is included in a micro block, the fee is collected.
// At the next epoch block, collected fees are split:
//   50% permanently burned      — deflationary pressure
//   40% to epoch block producer — validator income from staking layer
//   10% to treasury contract    — ecosystem development fund
//
// The 40% validator share is further distributed across ALL active
// validators proportional to their weight (handled in consensus/validators.rs).

// Base fees in KYV units per transaction type.
// These are the protocol minimums — the absolute floor below which
// a transaction will not be relayed by any honest node.

// Plain KYV transfer between two addresses.
pub const FEE_TRANSFER: u64 = 1_000_000;             // 0.001 KYV

// Calling a function on an existing deployed smart contract.
pub const FEE_CONTRACT_CALL: u64 = 5_000_000;        // 0.005 KYV

// Deploying a new smart contract to the chain.
pub const FEE_CONTRACT_DEPLOY: u64 = 100_000_000;    // 0.1 KYV

// Any DeFi-related interaction (DEX swap, lending, liquidity).
// Higher than a plain call because DeFi operations read more state.
pub const FEE_DEFI: u64 = 10_000_000;               // 0.01 KYV

// Registering a new validator or updating registration.
pub const FEE_VALIDATOR_REGISTRATION: u64 = 1_000_000_000; // 1 KYV

// Locking KYV into the staking contract.
pub const FEE_STAKE_LOCK: u64 = 1_000_000;           // 0.001 KYV

// Initiating an unstake request.
pub const FEE_STAKE_UNLOCK: u64 = 1_000_000;         // 0.001 KYV

// Fee split fractions in basis points (10,000 bps = 100%).
pub const BURN_SHARE_BPS: u64 = 5_000;               // 50%
pub const VALIDATOR_SHARE_BPS: u64 = 4_000;          // 40%
pub const TREASURY_SHARE_BPS: u64 = 1_000;           // 10%

// Returns the minimum required fee for a given transaction type.
// Wallets should call this when building transactions to know
// the minimum fee to attach.
pub fn minimum_fee(tx_type: &TransactionType) -> u64 {
    match tx_type {
        TransactionType::Transfer      => FEE_TRANSFER,
        TransactionType::ContractCall  => FEE_CONTRACT_CALL,
        TransactionType::ContractDeploy => FEE_CONTRACT_DEPLOY,
        TransactionType::StakeLock     => FEE_STAKE_LOCK,
        TransactionType::StakeUnlock   => FEE_STAKE_UNLOCK,
    }
}

// Check whether a transaction's attached fee meets the minimum.
pub fn fee_is_sufficient(tx: &Transaction) -> bool {
    tx.fee >= minimum_fee(&tx.transaction_type)
}

// Calculate how much of a fee is burned.
// This amount is permanently removed from total supply.
// The burn happens at the epoch block level after accumulation.
pub fn calculate_burn_amount(fee: u64) -> u64 {
    fee * BURN_SHARE_BPS / 10_000
}

// Calculate the validator pool share from a fee.
// This amount is distributed across active validators at
// the next epoch block proportional to their weight.
pub fn calculate_validator_amount(fee: u64) -> u64 {
    fee * VALIDATOR_SHARE_BPS / 10_000
}

// Calculate the treasury share from a fee.
// Credited to the treasury contract address.
pub fn calculate_treasury_amount(fee: u64) -> u64 {
    fee * TREASURY_SHARE_BPS / 10_000
}

// Calculate the complete split for a given fee.
// Returns (burn, validator_pool, treasury).
// The three values will always sum to the original fee minus
// any rounding dust (which stays as burn to be conservative).
pub fn calculate_fee_split(fee: u64) -> (u64, u64, u64) {
    let burn      = calculate_burn_amount(fee);
    let validator = calculate_validator_amount(fee);
    let treasury  = calculate_treasury_amount(fee);

    // Any rounding dust goes to burn to avoid creating KYV from nothing
    let dust = fee.saturating_sub(burn).saturating_sub(validator).saturating_sub(treasury);

    (burn + dust, validator, treasury)
}

// Calculate dynamic base fee based on recent block utilization.
// When blocks are consistently full, the base fee rises.
// When blocks are consistently empty, the base fee falls back.
// This is a simplified version of EIP-1559 style base fee adjustment.
//
// avg_utilization: 0.0 to 1.0 representing average block fullness
// current_base_multiplier: current multiplier applied to all base fees (starts at 1.0)
// Returns the new multiplier for the next epoch.
pub fn adjust_base_fee_multiplier(
    avg_utilization: f64,
    current_multiplier: f64,
) -> f64 {
    // Target utilization is 50% — blocks should be half full on average.
    // Above target: fees rise. Below target: fees fall.
    // Maximum adjustment is 12.5% per epoch in either direction.
    const TARGET_UTILIZATION: f64 = 0.5;
    const MAX_CHANGE_PER_EPOCH: f64 = 0.125;
    const MIN_MULTIPLIER: f64 = 1.0;
    const MAX_MULTIPLIER: f64 = 100.0;

    let delta = (avg_utilization - TARGET_UTILIZATION) * 2.0 * MAX_CHANGE_PER_EPOCH;
    let new_multiplier = current_multiplier * (1.0 + delta);
    new_multiplier.clamp(MIN_MULTIPLIER, MAX_MULTIPLIER)
}

// Apply the dynamic multiplier to get the actual minimum fee.
pub fn effective_minimum_fee(tx_type: &TransactionType, multiplier: f64) -> u64 {
    let base = minimum_fee(tx_type);
    (base as f64 * multiplier) as u64
}

// Total fees collected in a list of transactions.
// Used to know how much to split at epoch block time.
pub fn total_fees(transactions: &[Transaction]) -> u64 {
    transactions.iter().map(|tx| tx.fee).sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::transaction::{Transaction, TransactionType};

    fn make_tx(fee: u64, tx_type: TransactionType) -> Transaction {
        let mut tx = Transaction::new(
            format!("kyv1{}", "a".repeat(64)),
            format!("kyv1{}", "b".repeat(64)),
            1_000_000_000, fee, 0,
            tx_type, vec![],
        );
        tx.hash = format!("{:064}", fee);
        tx.signature = "sig".to_string();
        tx
    }

    #[test]
    fn test_minimum_fees_are_correct() {
        assert_eq!(minimum_fee(&TransactionType::Transfer),       FEE_TRANSFER);
        assert_eq!(minimum_fee(&TransactionType::ContractCall),   FEE_CONTRACT_CALL);
        assert_eq!(minimum_fee(&TransactionType::ContractDeploy), FEE_CONTRACT_DEPLOY);
        assert_eq!(minimum_fee(&TransactionType::StakeLock),      FEE_STAKE_LOCK);
        assert_eq!(minimum_fee(&TransactionType::StakeUnlock),    FEE_STAKE_UNLOCK);
    }

    #[test]
    fn test_fee_is_sufficient() {
        let tx = make_tx(FEE_TRANSFER, TransactionType::Transfer);
        assert!(fee_is_sufficient(&tx));
    }

    #[test]
    fn test_fee_below_minimum_fails() {
        let tx = make_tx(FEE_TRANSFER - 1, TransactionType::Transfer);
        assert!(!fee_is_sufficient(&tx));
    }

    #[test]
    fn test_fee_split_sums_to_total() {
        let fee = 10_000_000;
        let (burn, validator, treasury) = calculate_fee_split(fee);
        assert_eq!(burn + validator + treasury, fee);
    }

    #[test]
    fn test_fee_split_proportions() {
        let fee = 10_000_000; // 10 KYV units
        let (burn, validator, treasury) = calculate_fee_split(fee);

        // 50% burn
        assert_eq!(burn, 5_000_000);
        // 40% validator
        assert_eq!(validator, 4_000_000);
        // 10% treasury
        assert_eq!(treasury, 1_000_000);
    }

    #[test]
    fn test_fee_split_no_dust_at_clean_numbers() {
        let fee = 1_000_000;
        let (burn, validator, treasury) = calculate_fee_split(fee);
        assert_eq!(burn + validator + treasury, fee,
            "Split must sum to exactly the original fee");
    }

    #[test]
    fn test_burn_is_largest_share() {
        let fee = 9_999_999; // Odd number to test dust handling
        let (burn, validator, treasury) = calculate_fee_split(fee);
        assert!(burn >= validator);
        assert!(burn >= treasury);
        assert_eq!(burn + validator + treasury, fee);
    }

    #[test]
    fn test_base_fee_rises_when_blocks_are_full() {
        let new_mult = adjust_base_fee_multiplier(0.9, 1.0);
        assert!(new_mult > 1.0, "Fee should rise when blocks are 90% full");
    }

    #[test]
    fn test_base_fee_falls_when_blocks_are_empty() {
        let new_mult = adjust_base_fee_multiplier(0.1, 2.0);
        assert!(new_mult < 2.0, "Fee should fall when blocks are 10% full");
    }

    #[test]
    fn test_base_fee_stable_at_target_utilization() {
        let new_mult = adjust_base_fee_multiplier(0.5, 1.5);
        // At exactly 50% utilization the multiplier should not change
        assert!((new_mult - 1.5).abs() < 0.001);
    }

    #[test]
    fn test_multiplier_never_goes_below_one() {
        let new_mult = adjust_base_fee_multiplier(0.0, 1.0);
        assert!(new_mult >= 1.0);
    }

    #[test]
    fn test_multiplier_capped_at_maximum() {
        let new_mult = adjust_base_fee_multiplier(1.0, 100.0);
        assert!(new_mult <= 100.0);
    }

    #[test]
    fn test_effective_minimum_fee_scales_with_multiplier() {
        let base = minimum_fee(&TransactionType::Transfer);
        let doubled = effective_minimum_fee(&TransactionType::Transfer, 2.0);
        assert_eq!(doubled, base * 2);
    }

    #[test]
    fn test_total_fees_sums_correctly() {
        let txs = vec![
            make_tx(1_000_000, TransactionType::Transfer),
            make_tx(5_000_000, TransactionType::ContractCall),
            make_tx(10_000_000, TransactionType::ContractDeploy),
        ];
        assert_eq!(total_fees(&txs), 16_000_000);
    }

    #[test]
    fn test_zero_fee_split_is_all_zeros() {
        let (burn, validator, treasury) = calculate_fee_split(0);
        assert_eq!(burn, 0);
        assert_eq!(validator, 0);
        assert_eq!(treasury, 0);
    }
}