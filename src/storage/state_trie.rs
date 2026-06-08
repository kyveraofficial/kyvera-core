use crate::storage::db::KyveraDb;
use crate::storage::account_store::{get_account, save_account};
use crate::types::account::Account;
use crate::types::transaction::{Transaction, TransactionType};
use crate::chain::hash::sha3_256_hex;

// The state trie tracks the complete account state of the chain.
// Every epoch block commits to a state root — a single hash that
// represents the state of every account at that point in time.
// If two nodes have the same state root they have identical account state.
// If they differ, something went wrong and we need to figure out who is right.
//
// We implement a simplified Patricia-Merkle trie using our sled database.
// The full Ethereum-style MPT is complex to implement correctly —
// our version gives us state root commitments and rollback capability
// which is what the protocol needs right now. A full MPT is a Month 13+
// optimization once the chain is otherwise complete.

// Key for the current state root in metadata
const STATE_ROOT_KEY: &str = "state_root";

// Key for the state snapshot stack (used for rollback)
const SNAPSHOT_COUNT_KEY: &str = "snapshot_count";

// A snapshot of account state at a specific block height.
// Stored before applying a block so we can roll back if needed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StateSnapshot {
    pub block_height: u64,
    pub state_root: String,
    // The set of addresses modified in this block
    // and their state BEFORE the block was applied.
    // On rollback we restore these exact values.
    pub modified_accounts: Vec<(String, Option<Account>)>,
}

// Compute the state root from all current account balances.
// The state root is a hash that commits to the entire account state.
// We hash all accounts sorted by address so the result is deterministic
// regardless of insertion order.
pub fn compute_state_root(db: &KyveraDb) -> Result<String, String> {
    let mut account_hashes: Vec<String> = Vec::new();

    for result in db.accounts.iter() {
        let (key, value) = result
            .map_err(|e| format!("State trie iteration error: {}", e))?;

        let address = String::from_utf8(key.to_vec())
            .map_err(|e| format!("Invalid address key: {}", e))?;

        // Hash the address + serialized account state together
        let account: Account = serde_json::from_slice(&value)
            .map_err(|e| format!("Failed to deserialize account: {}", e))?;

        let account_json = serde_json::to_string(&account)
            .map_err(|e| format!("Failed to serialize account: {}", e))?;

        let combined = format!("{}{}", address, account_json);
        account_hashes.push(sha3_256_hex(combined.as_bytes()));
    }

    if account_hashes.is_empty() {
        return Ok(sha3_256_hex(b"kyvera-empty-state"));
    }

    // Sort for determinism — same accounts always produce same root
    account_hashes.sort();

    // Hash all account hashes together into a single root
    let combined = account_hashes.join("");
    Ok(sha3_256_hex(combined.as_bytes()))
}

// Save the current state root to the database.
// Called at the end of each epoch block.
pub fn save_state_root(db: &KyveraDb, root: &str) -> Result<(), String> {
    db.set_metadata(STATE_ROOT_KEY, root.as_bytes())
}

// Load the most recently committed state root.
pub fn load_state_root(db: &KyveraDb) -> Result<Option<String>, String> {
    let data = db.get_metadata(STATE_ROOT_KEY)?;
    match data {
        None => Ok(None),
        Some(bytes) => Ok(Some(
            String::from_utf8(bytes)
                .map_err(|e| format!("Invalid state root bytes: {}", e))?
        )),
    }
}

// Take a snapshot of all accounts that will be modified by a block.
// Call this BEFORE applying the block so we can roll back if needed.
pub fn take_snapshot(
    db: &KyveraDb,
    block_height: u64,
    affected_addresses: &[String],
) -> Result<StateSnapshot, String> {
    let current_root = load_state_root(db)?
        .unwrap_or_else(|| sha3_256_hex(b"kyvera-empty-state"));

    let mut modified_accounts = Vec::new();

    for address in affected_addresses {
        let account = get_account(db, address)?;
        modified_accounts.push((address.clone(), account));
    }

    Ok(StateSnapshot {
        block_height,
        state_root: current_root,
        modified_accounts,
    })
}

// Save a snapshot to the database.
pub fn save_snapshot(db: &KyveraDb, snapshot: &StateSnapshot) -> Result<(), String> {
    let serialized = serde_json::to_vec(snapshot)
        .map_err(|e| format!("Failed to serialize snapshot: {}", e))?;

    let count = get_snapshot_count(db)?;
    let key = format!("snapshot:{:020}", count);
    db.set_metadata(&key, &serialized)?;
    db.set_metadata(SNAPSHOT_COUNT_KEY, count.to_string().as_bytes())?;
    Ok(())
}

// Roll back the state to a previous snapshot.
// Restores all accounts to their pre-block state.
// Used when a block is found to be invalid after partial application
// or during chain reorganization.
pub fn rollback_to_snapshot(db: &KyveraDb, snapshot: &StateSnapshot) -> Result<(), String> {
    for (address, pre_state) in &snapshot.modified_accounts {
        match pre_state {
            Some(account) => {
                // Restore the account to its pre-block state
                save_account(db, account)?;
            }
            None => {
                // Account did not exist before this block — delete it
                KyveraDb::delete(&db.accounts, address.as_bytes())?;
            }
        }
    }

    // Restore the state root
    save_state_root(db, &snapshot.state_root)?;

    Ok(())
}

// Apply a transaction to the state trie.
// Updates sender and receiver account balances and increments nonce.
// Returns an error if the sender cannot afford the transaction.
// This is the core state transition function.
pub fn apply_transaction(
    db: &KyveraDb,
    tx: &Transaction,
) -> Result<(), String> {
    match tx.transaction_type {
        TransactionType::Transfer => apply_transfer(db, tx),
        TransactionType::StakeLock => apply_stake_lock(db, tx),
        TransactionType::StakeUnlock => apply_stake_unlock(db, tx),
        TransactionType::ContractDeploy | TransactionType::ContractCall => {
            // Contract execution state changes are handled by the RISC Zero
            // execution layer in Month 13. For now we just debit the fee.
            apply_fee_only(db, tx)
        }
    }
}

fn apply_transfer(db: &KyveraDb, tx: &Transaction) -> Result<(), String> {
    // Load sender — must exist and have sufficient balance
    let mut sender = crate::storage::account_store::get_or_create_account(
        db, &tx.sender
    )?;

    let total_cost = tx.amount.checked_add(tx.fee)
        .ok_or("Transaction cost overflow")?;

    if sender.balance < total_cost {
        return Err(format!(
            "Insufficient balance: {} has {} but needs {}",
            tx.sender, sender.balance, total_cost
        ));
    }

    if sender.nonce != tx.nonce {
        return Err(format!(
            "Nonce mismatch: expected {} got {}",
            sender.nonce, tx.nonce
        ));
    }

    // Debit sender
    sender.balance -= total_cost;
    sender.nonce += 1;
    save_account(db, &sender)?;

    // Credit receiver
    let mut receiver = crate::storage::account_store::get_or_create_account(
        db, &tx.receiver
    )?;
    receiver.balance = receiver.balance.checked_add(tx.amount)
        .ok_or("Receiver balance overflow")?;
    save_account(db, &receiver)?;

    // Apply fee distribution (50% burn is handled at supply level,
    // 40% to validator is handled at block reward time,
    // 10% to treasury — we credit treasury address here)
    apply_fee_split(db, tx.fee)?;

    Ok(())
}

fn apply_stake_lock(db: &KyveraDb, tx: &Transaction) -> Result<(), String> {
    let mut account = crate::storage::account_store::get_or_create_account(
        db, &tx.sender
    )?;

    let total_cost = tx.amount.checked_add(tx.fee)
        .ok_or("Stake cost overflow")?;

    if account.balance < total_cost {
        return Err(format!(
            "Insufficient balance to stake: has {} needs {}",
            account.balance, total_cost
        ));
    }

    if account.nonce != tx.nonce {
        return Err(format!("Nonce mismatch: expected {} got {}", account.nonce, tx.nonce));
    }

    account.balance -= total_cost;
    account.staked_balance = account.staked_balance
        .checked_add(tx.amount)
        .ok_or("Staked balance overflow")?;
    account.nonce += 1;
    account.update_validator_tier();
    save_account(db, &account)?;

    apply_fee_split(db, tx.fee)?;
    Ok(())
}

fn apply_stake_unlock(db: &KyveraDb, tx: &Transaction) -> Result<(), String> {
    let mut account = crate::storage::account_store::get_or_create_account(
        db, &tx.sender
    )?;

    if account.staked_balance < tx.amount {
        return Err(format!(
            "Insufficient staked balance: has {} needs {}",
            account.staked_balance, tx.amount
        ));
    }

    if account.balance < tx.fee {
        return Err(format!("Insufficient balance for fee: has {} needs {}", account.balance, tx.fee));
    }

    if account.nonce != tx.nonce {
        return Err(format!("Nonce mismatch: expected {} got {}", account.nonce, tx.nonce));
    }

    account.staked_balance -= tx.amount;
    account.balance = account.balance
        .checked_add(tx.amount)
        .ok_or("Balance overflow during unstake")?;
    account.balance -= tx.fee;
    account.nonce += 1;
    account.update_validator_tier();
    save_account(db, &account)?;

    apply_fee_split(db, tx.fee)?;
    Ok(())
}

fn apply_fee_only(db: &KyveraDb, tx: &Transaction) -> Result<(), String> {
    let mut sender = crate::storage::account_store::get_or_create_account(
        db, &tx.sender
    )?;

    if sender.balance < tx.fee {
        return Err(format!("Insufficient balance for fee"));
    }

    if sender.nonce != tx.nonce {
        return Err(format!("Nonce mismatch: expected {} got {}", sender.nonce, tx.nonce));
    }

    sender.balance -= tx.fee;
    sender.nonce += 1;
    save_account(db, &sender)?;

    apply_fee_split(db, tx.fee)?;
    Ok(())
}

// Split fee: 10% goes to treasury, 50% is burned (removed from supply),
// 40% is distributed to validators at epoch reward time.
// Here we just credit the treasury — burn and validator portions
// are accounted for at epoch block production.
fn apply_fee_split(db: &KyveraDb, fee: u64) -> Result<(), String> {
    let treasury_share = fee / 10;
    if treasury_share > 0 {
        crate::storage::account_store::credit_account(
            db,
            // Genesis-defined treasury address
            "kyv10000000000000000000000000000000000000000000000000000treasury00",
            treasury_share,
        )?;
    }
    Ok(())
}

fn get_snapshot_count(db: &KyveraDb) -> Result<u64, String> {
    match db.get_metadata(SNAPSHOT_COUNT_KEY)? {
        None => Ok(0),
        Some(bytes) => {
            let s = String::from_utf8(bytes)
                .map_err(|e| format!("Invalid snapshot count: {}", e))?;
            s.parse::<u64>()
                .map_err(|e| format!("Invalid snapshot count format: {}", e))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::KyveraDb;
    use crate::storage::account_store::credit_account;
    use crate::types::transaction::{Transaction, TransactionType};

    fn addr(n: u8) -> String {
        format!("kyv1{}", hex::encode([n; 32]))
    }

    fn make_transfer(sender: &str, receiver: &str, amount: u64, fee: u64, nonce: u64) -> Transaction {
        let mut tx = Transaction::new(
            sender.to_string(),
            receiver.to_string(),
            amount,
            fee,
            nonce,
            TransactionType::Transfer,
            vec![],
        );
        tx.hash = format!("{:064}", nonce + 1);
        tx.signature = "sig".to_string();
        tx
    }

    #[test]
    fn test_empty_state_has_known_root() {
        let db = KyveraDb::open_temp().unwrap();
        let root = compute_state_root(&db).unwrap();
        assert_eq!(root.len(), 64);
        // Empty state has a deterministic root
        let root2 = compute_state_root(&db).unwrap();
        assert_eq!(root, root2);
    }

    #[test]
    fn test_state_root_changes_when_account_changes() {
        let db = KyveraDb::open_temp().unwrap();
        let root_before = compute_state_root(&db).unwrap();

        credit_account(&db, &addr(1), 1_000_000_000).unwrap();

        let root_after = compute_state_root(&db).unwrap();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn test_save_and_load_state_root() {
        let db = KyveraDb::open_temp().unwrap();
        let root = compute_state_root(&db).unwrap();
        save_state_root(&db, &root).unwrap();

        let loaded = load_state_root(&db).unwrap();
        assert_eq!(loaded, Some(root));
    }

    #[test]
    fn test_apply_transfer() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        let receiver = addr(2);

        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let tx = make_transfer(&sender, &receiver, 10_000_000_000, 1_000_000, 0);
        apply_transaction(&db, &tx).unwrap();

        let sender_balance = crate::storage::account_store::get_balance(&db, &sender).unwrap();
        let receiver_balance = crate::storage::account_store::get_balance(&db, &receiver).unwrap();

        assert_eq!(sender_balance, 100_000_000_000 - 10_000_000_000 - 1_000_000);
        assert_eq!(receiver_balance, 10_000_000_000);
    }

    #[test]
    fn test_transfer_increments_nonce() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);

        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let tx = make_transfer(&sender, &addr(2), 1_000_000_000, 1_000_000, 0);
        apply_transaction(&db, &tx).unwrap();

        let nonce = crate::storage::account_store::get_nonce(&db, &sender).unwrap();
        assert_eq!(nonce, 1);
    }

    #[test]
    fn test_transfer_insufficient_balance_fails() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);

        credit_account(&db, &sender, 1_000_000).unwrap();

        let tx = make_transfer(&sender, &addr(2), 10_000_000_000, 1_000_000, 0);
        let result = apply_transaction(&db, &tx);
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer_wrong_nonce_fails() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);

        credit_account(&db, &sender, 100_000_000_000).unwrap();

        // Nonce should be 0 but we submit nonce 1
        let tx = make_transfer(&sender, &addr(2), 1_000_000_000, 1_000_000, 1);
        let result = apply_transaction(&db, &tx);
        assert!(result.is_err());
    }

    #[test]
    fn test_snapshot_and_rollback() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        let receiver = addr(2);

        credit_account(&db, &sender, 100_000_000_000).unwrap();
        let root_before = compute_state_root(&db).unwrap();

        // Take a snapshot before the transaction
        let snapshot = take_snapshot(&db, 1, &[sender.clone(), receiver.clone()]).unwrap();

        // Apply a transaction
        let tx = make_transfer(&sender, &receiver, 10_000_000_000, 1_000_000, 0);
        apply_transaction(&db, &tx).unwrap();

        // State should have changed
        let root_after = compute_state_root(&db).unwrap();
        assert_ne!(root_before, root_after);

        // Roll back
        rollback_to_snapshot(&db, &snapshot).unwrap();

        // State should be restored
        let sender_balance = crate::storage::account_store::get_balance(&db, &sender).unwrap();
        assert_eq!(sender_balance, 100_000_000_000);

        let receiver_balance = crate::storage::account_store::get_balance(&db, &receiver).unwrap();
        assert_eq!(receiver_balance, 0);
    }

    #[test]
    fn test_same_state_produces_same_root() {
        let db1 = KyveraDb::open_temp().unwrap();
        let db2 = KyveraDb::open_temp().unwrap();

        // Apply same transactions in same order to both databases
        for i in 1..=3u8 {
            credit_account(&db1, &addr(i), 1_000_000_000u64 * i as u64).unwrap();
            credit_account(&db2, &addr(i), 1_000_000_000u64 * i as u64).unwrap();
        }

        let root1 = compute_state_root(&db1).unwrap();
        let root2 = compute_state_root(&db2).unwrap();

        // Two nodes with identical state must have identical roots
        assert_eq!(root1, root2);
    }
}