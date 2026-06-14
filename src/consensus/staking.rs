use crate::storage::db::KyveraDb;
use crate::storage::account_store::{get_account, save_account, credit_account};

// Stake unlock timelock.
//
// Without this, a validator could misbehave, get caught, and instantly
// withdraw their stake before slashing could be applied. The unbonding
// period closes that gap: when a validator requests an unstake, their
// staked balance is removed immediately (so it stops counting toward
// validator weight and tier), but the funds do not return to their
// spendable balance until UNBONDING_PERIOD_EPOCHS epoch blocks later.
//
// This is deliberately additive — it does not change the existing
// instant unlock_stake/apply_stake_unlock path used by state_trie.
// Consensus-level processing should call request_unstake instead of
// the instant path, and process_matured_unstakes at every epoch block.

// Number of epoch blocks a withdrawal must wait before funds return
// to the spendable balance. At ~10 minutes per epoch block this is
// roughly 100 minutes.
pub const UNBONDING_PERIOD_EPOCHS: u64 = 10;

// A single pending withdrawal. An address can have multiple of these
// outstanding at once if they request unstakes at different times.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingUnstake {
    pub address: String,
    pub amount: u64,
    pub request_epoch: u64,
    pub unlock_epoch: u64,
}

const PENDING_UNSTAKE_PREFIX: &str = "pending_unstake:";

// Begin unbonding `amount` KYV for `address`.
// Immediately removes the amount from staked_balance and recalculates
// the validator tier — a validator who unstakes below their tier
// threshold is demoted right away, even though they have not received
// the funds yet. Returns the created pending withdrawal record.
pub fn request_unstake(
    db: &KyveraDb,
    address: &str,
    amount: u64,
    current_epoch: u64,
) -> Result<PendingUnstake, String> {
    let mut account = get_account(db, address)?
        .ok_or_else(|| format!("No account found for {}", address))?;

    if account.staked_balance < amount {
        return Err(format!(
            "Insufficient staked balance: has {} needs {}",
            account.staked_balance, amount
        ));
    }

    account.staked_balance -= amount;
    account.update_validator_tier();
    save_account(db, &account)?;

    let unlock_epoch = current_epoch + UNBONDING_PERIOD_EPOCHS;

    let pending = PendingUnstake {
        address: address.to_string(),
        amount,
        request_epoch: current_epoch,
        unlock_epoch,
    };

    save_pending_unstake(db, &pending)?;

    Ok(pending)
}

fn save_pending_unstake(db: &KyveraDb, pending: &PendingUnstake) -> Result<(), String> {
    let serialized = serde_json::to_vec(pending)
        .map_err(|e| format!("Failed to serialize pending unstake: {}", e))?;

    // Key sorts by unlock epoch first so a future "process all matured"
    // scan could stop early once it reaches unmatured entries.
    let key = format!(
        "{}{:020}:{}:{:020}",
        PENDING_UNSTAKE_PREFIX, pending.unlock_epoch, pending.address, pending.request_epoch
    );

    db.set_metadata(&key, &serialized)
}

// Get all pending withdrawals for an address, matured or not.
pub fn get_pending_unstakes(db: &KyveraDb, address: &str) -> Result<Vec<PendingUnstake>, String> {
    let mut results = Vec::new();

    for item in db.metadata.scan_prefix(PENDING_UNSTAKE_PREFIX.as_bytes()) {
        let (_, value) = item.map_err(|e| format!("Scan error: {}", e))?;
        let pending: PendingUnstake = serde_json::from_slice(&value)
            .map_err(|e| format!("Deserialize error: {}", e))?;
        if pending.address == address {
            results.push(pending);
        }
    }

    Ok(results)
}

// Process every pending withdrawal that has reached its unlock epoch.
// Credits the spendable balance and removes the pending entry.
// Called once per epoch block during consensus processing.
// Returns the total amount released across all addresses.
pub fn process_matured_unstakes(db: &KyveraDb, current_epoch: u64) -> Result<u64, String> {
    let mut total_processed: u64 = 0;
    let mut keys_to_remove = Vec::new();

    for item in db.metadata.scan_prefix(PENDING_UNSTAKE_PREFIX.as_bytes()) {
        let (key, value) = item.map_err(|e| format!("Scan error: {}", e))?;
        let pending: PendingUnstake = serde_json::from_slice(&value)
            .map_err(|e| format!("Deserialize error: {}", e))?;

        if pending.unlock_epoch <= current_epoch {
            credit_account(db, &pending.address, pending.amount)?;
            total_processed = total_processed.saturating_add(pending.amount);
            keys_to_remove.push(key.to_vec());
        }
    }

    for key in keys_to_remove {
        db.metadata.remove(&key)
            .map_err(|e| format!("Failed to remove pending unstake entry: {}", e))?;
    }

    Ok(total_processed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::KyveraDb;
    use crate::storage::account_store::{credit_account, lock_stake, get_account};

    fn addr(n: u8) -> String {
        format!("kyv1{}", hex::encode([n; 32]))
    }

    #[test]
    fn test_request_unstake_removes_staked_balance_immediately() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(1);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 500_000_000_000).unwrap();

        request_unstake(&db, &validator, 500_000_000_000, 0).unwrap();

        let account = get_account(&db, &validator).unwrap().unwrap();
        assert_eq!(account.staked_balance, 0);
        // Funds not yet returned to spendable balance
        assert_eq!(account.balance, 500_000_000_000);
    }

    #[test]
    fn test_unstake_demotes_validator_immediately() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(2);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 500_000_000_000).unwrap();
        assert!(get_account(&db, &validator).unwrap().unwrap().is_validator());

        request_unstake(&db, &validator, 500_000_000_000, 0).unwrap();

        let account = get_account(&db, &validator).unwrap().unwrap();
        assert!(!account.is_validator());
    }

    #[test]
    fn test_unlock_epoch_is_request_plus_unbonding_period() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(3);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 500_000_000_000).unwrap();

        let pending = request_unstake(&db, &validator, 500_000_000_000, 5).unwrap();

        assert_eq!(pending.request_epoch, 5);
        assert_eq!(pending.unlock_epoch, 5 + UNBONDING_PERIOD_EPOCHS);
    }

    #[test]
    fn test_funds_not_released_before_unlock_epoch() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(4);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 500_000_000_000).unwrap();
        request_unstake(&db, &validator, 500_000_000_000, 0).unwrap();

        let processed = process_matured_unstakes(&db, UNBONDING_PERIOD_EPOCHS - 1).unwrap();
        assert_eq!(processed, 0);

        let account = get_account(&db, &validator).unwrap().unwrap();
        assert_eq!(account.balance, 500_000_000_000);
    }

    #[test]
    fn test_funds_released_at_unlock_epoch() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(5);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 500_000_000_000).unwrap();
        request_unstake(&db, &validator, 500_000_000_000, 0).unwrap();

        let processed = process_matured_unstakes(&db, UNBONDING_PERIOD_EPOCHS).unwrap();
        assert_eq!(processed, 500_000_000_000);

        let account = get_account(&db, &validator).unwrap().unwrap();
        assert_eq!(account.balance, 1_000_000_000_000);
    }

    #[test]
    fn test_processing_removes_pending_entry() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(6);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 500_000_000_000).unwrap();
        request_unstake(&db, &validator, 500_000_000_000, 0).unwrap();

        process_matured_unstakes(&db, UNBONDING_PERIOD_EPOCHS).unwrap();

        let pending = get_pending_unstakes(&db, &validator).unwrap();
        assert!(pending.is_empty());

        let processed_again = process_matured_unstakes(&db, UNBONDING_PERIOD_EPOCHS).unwrap();
        assert_eq!(processed_again, 0);
    }

    #[test]
    fn test_insufficient_staked_balance_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(7);

        credit_account(&db, &validator, 1_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 100_000_000_000).unwrap();

        let result = request_unstake(&db, &validator, 500_000_000_000, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_pending_unstakes_tracked_separately() {
        let db = KyveraDb::open_temp().unwrap();
        let validator = addr(8);

        credit_account(&db, &validator, 2_000_000_000_000).unwrap();
        lock_stake(&db, &validator, 1_000_000_000_000).unwrap();

        request_unstake(&db, &validator, 400_000_000_000, 0).unwrap();
        request_unstake(&db, &validator, 600_000_000_000, 2).unwrap();

        let pending = get_pending_unstakes(&db, &validator).unwrap();
        assert_eq!(pending.len(), 2);
    }
}