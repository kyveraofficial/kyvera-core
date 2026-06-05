use crate::storage::db::KyveraDb;
use crate::types::account::Account;

// The account store manages all wallet and contract account state.
// Every address on Kyvera has exactly one account entry here.
// This is what gets queried when someone checks a balance,
// when the mempool validates that a sender can afford a transaction,
// and when the block producer applies state changes after mining.

// Save or update an account in the database.
// If the account already exists it gets overwritten with the new state.
// Called every time a transaction affects an account's balance or nonce.
pub fn save_account(db: &KyveraDb, account: &Account) -> Result<(), String> {
    let serialized = serde_json::to_vec(account)
        .map_err(|e| format!("Failed to serialize account: {}", e))?;

    KyveraDb::write(
        &db.accounts,
        account.address.as_bytes(),
        &serialized,
    )
}

// Load an account by address.
// Returns None if the address has never appeared on chain.
// A None result means zero balance — accounts only get created
// when they first receive funds.
pub fn get_account(db: &KyveraDb, address: &str) -> Result<Option<Account>, String> {
    let data = KyveraDb::read(&db.accounts, address.as_bytes())?;
    match data {
        None => Ok(None),
        Some(bytes) => {
            let account = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Failed to deserialize account: {}", e))?;
            Ok(Some(account))
        }
    }
}

// Get an account or create a default zero-balance account if it
// does not exist yet. Used when processing incoming transactions
// to ensure the receiver always has an account record.
pub fn get_or_create_account(db: &KyveraDb, address: &str) -> Result<Account, String> {
    match get_account(db, address)? {
        Some(account) => Ok(account),
        None => Ok(Account::new(address.to_string())),
    }
}

// Get the spendable balance for an address.
// Returns 0 if the address has never received funds.
// This is the real balance lookup that the wallet CLI will call
// once the RPC layer is wired up in Month 15.
pub fn get_balance(db: &KyveraDb, address: &str) -> Result<u64, String> {
    Ok(get_account(db, address)?
        .map(|a| a.balance)
        .unwrap_or(0))
}

// Get the staked balance for an address.
pub fn get_staked_balance(db: &KyveraDb, address: &str) -> Result<u64, String> {
    Ok(get_account(db, address)?
        .map(|a| a.staked_balance)
        .unwrap_or(0))
}

// Credit an account — add to its spendable balance.
// Creates the account if it does not exist.
// Called when processing incoming transfers and block rewards.
pub fn credit_account(db: &KyveraDb, address: &str, amount: u64) -> Result<(), String> {
    let mut account = get_or_create_account(db, address)?;
    account.balance = account.balance
        .checked_add(amount)
        .ok_or("Balance overflow — this should never happen")?;
    save_account(db, &account)
}

// Debit an account — subtract from its spendable balance.
// Returns an error if the account cannot afford the debit.
// Called when processing outgoing transfers and fee payments.
pub fn debit_account(db: &KyveraDb, address: &str, amount: u64) -> Result<(), String> {
    let mut account = get_or_create_account(db, address)?;
    if account.balance < amount {
        return Err(format!(
            "Insufficient balance: {} has {} but needs {}",
            address, account.balance, amount
        ));
    }
    account.balance -= amount;
    save_account(db, &account)
}

// Increment an account's nonce after it sends a transaction.
// The nonce must match exactly for the next transaction to be valid.
// This is what prevents replay attacks at the account state level.
pub fn increment_nonce(db: &KyveraDb, address: &str) -> Result<(), String> {
    let mut account = get_or_create_account(db, address)?;
    account.nonce += 1;
    save_account(db, &account)
}

// Get the current nonce for an address.
// The wallet uses this to know what nonce to put in the next transaction.
pub fn get_nonce(db: &KyveraDb, address: &str) -> Result<u64, String> {
    Ok(get_account(db, address)?
        .map(|a| a.nonce)
        .unwrap_or(0))
}

// Lock KYV into the staking contract.
// Moves funds from spendable balance to staked balance.
// Updates the validator tier based on new staked amount.
pub fn lock_stake(db: &KyveraDb, address: &str, amount: u64) -> Result<(), String> {
    let mut account = get_or_create_account(db, address)?;

    if account.balance < amount {
        return Err(format!(
            "Insufficient balance to stake: has {} needs {}",
            account.balance, amount
        ));
    }

    account.balance -= amount;
    account.staked_balance = account.staked_balance
        .checked_add(amount)
        .ok_or("Staked balance overflow")?;

    // Recalculate validator tier based on new staked amount
    account.update_validator_tier();

    save_account(db, &account)
}

// Unlock staked KYV back to spendable balance.
// In production this would have an unbonding period.
// The unbonding timelock logic lives in the consensus layer.
pub fn unlock_stake(db: &KyveraDb, address: &str, amount: u64) -> Result<(), String> {
    let mut account = get_or_create_account(db, address)?;

    if account.staked_balance < amount {
        return Err(format!(
            "Insufficient staked balance: has {} needs {}",
            account.staked_balance, amount
        ));
    }

    account.staked_balance -= amount;
    account.balance = account.balance
        .checked_add(amount)
        .ok_or("Balance overflow during unstake")?;

    // Recalculate tier — may drop a tier if below minimum
    account.update_validator_tier();

    save_account(db, &account)
}

// Get all active validators from the account store.
// Returns a list of accounts that currently hold a validator tier.
// Used by the consensus layer to determine the active validator set.
pub fn get_validators(db: &KyveraDb) -> Result<Vec<Account>, String> {
    let mut validators = Vec::new();

    // Iterate all accounts and collect those with a validator tier
    for result in db.accounts.iter() {
        let (_, value) = result
            .map_err(|e| format!("Database iteration error: {}", e))?;
        let account: Account = serde_json::from_slice(&value)
            .map_err(|e| format!("Failed to deserialize account: {}", e))?;
        if account.is_validator() {
            validators.push(account);
        }
    }

    Ok(validators)
}

// Get the total number of accounts in the database.
pub fn account_count(db: &KyveraDb) -> usize {
    KyveraDb::count(&db.accounts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::KyveraDb;

    fn test_address(n: u8) -> String {
        format!("kyv1{}", hex::encode([n; 32]))
    }

    #[test]
    fn test_get_balance_returns_zero_for_unknown_address() {
        let db = KyveraDb::open_temp().unwrap();
        let balance = get_balance(&db, &test_address(1)).unwrap();
        assert_eq!(balance, 0);
    }

    #[test]
    fn test_credit_and_get_balance() {
        let db = KyveraDb::open_temp().unwrap();
        let addr = test_address(1);

        credit_account(&db, &addr, 50_000_000_000).unwrap();

        let balance = get_balance(&db, &addr).unwrap();
        assert_eq!(balance, 50_000_000_000);
    }

    #[test]
    fn test_debit_reduces_balance() {
        let db = KyveraDb::open_temp().unwrap();
        let addr = test_address(1);

        credit_account(&db, &addr, 50_000_000_000).unwrap();
        debit_account(&db, &addr, 10_000_000_000).unwrap();

        assert_eq!(get_balance(&db, &addr).unwrap(), 40_000_000_000);
    }

    #[test]
    fn test_debit_insufficient_balance_fails() {
        let db = KyveraDb::open_temp().unwrap();
        let addr = test_address(1);

        credit_account(&db, &addr, 5_000_000_000).unwrap();

        let result = debit_account(&db, &addr, 10_000_000_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_starts_at_zero() {
        let db = KyveraDb::open_temp().unwrap();
        assert_eq!(get_nonce(&db, &test_address(1)).unwrap(), 0);
    }

    #[test]
    fn test_nonce_increments() {
        let db = KyveraDb::open_temp().unwrap();
        let addr = test_address(1);

        credit_account(&db, &addr, 1_000_000_000).unwrap();
        increment_nonce(&db, &addr).unwrap();
        increment_nonce(&db, &addr).unwrap();

        assert_eq!(get_nonce(&db, &addr).unwrap(), 2);
    }

    #[test]
    fn test_stake_lock_moves_balance() {
        let db = KyveraDb::open_temp().unwrap();
        let addr = test_address(1);

        // Give the account enough to reach Igniter tier
        credit_account(&db, &addr, 1_000_000_000_000).unwrap();
        lock_stake(&db, &addr, 500_000_000_000).unwrap();

        let account = get_account(&db, &addr).unwrap().unwrap();
        assert_eq!(account.balance, 500_000_000_000);
        assert_eq!(account.staked_balance, 500_000_000_000);
        // Should now be an Igniter validator
        assert!(account.is_validator());
    }

    #[test]
    fn test_stake_unlock_moves_balance_back() {
        let db = KyveraDb::open_temp().unwrap();
        let addr = test_address(1);

        credit_account(&db, &addr, 1_000_000_000_000).unwrap();
        lock_stake(&db, &addr, 500_000_000_000).unwrap();
        unlock_stake(&db, &addr, 500_000_000_000).unwrap();

        let account = get_account(&db, &addr).unwrap().unwrap();
        assert_eq!(account.balance, 1_000_000_000_000);
        assert_eq!(account.staked_balance, 0);
        // Below minimum stake — no longer a validator
        assert!(!account.is_validator());
    }

    #[test]
    fn test_get_validators() {
        let db = KyveraDb::open_temp().unwrap();

        let addr1 = test_address(1);
        let addr2 = test_address(2);
        let addr3 = test_address(3);

        // addr1 stakes enough for Igniter
        credit_account(&db, &addr1, 1_000_000_000_000).unwrap();
        lock_stake(&db, &addr1, 500_000_000_000).unwrap();

        // addr2 stakes enough for Kinetic
        credit_account(&db, &addr2, 10_000_000_000_000).unwrap();
        lock_stake(&db, &addr2, 5_000_000_000_000).unwrap();

        // addr3 does not stake
        credit_account(&db, &addr3, 1_000_000_000_000).unwrap();

        let validators = get_validators(&db).unwrap();
        assert_eq!(validators.len(), 2);
    }

    #[test]
    fn test_account_count() {
        let db = KyveraDb::open_temp().unwrap();
        assert_eq!(account_count(&db), 0);

        credit_account(&db, &test_address(1), 1_000_000_000).unwrap();
        credit_account(&db, &test_address(2), 1_000_000_000).unwrap();

        assert_eq!(account_count(&db), 2);
    }
}