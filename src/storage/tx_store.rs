use crate::storage::db::KyveraDb;
use crate::types::transaction::Transaction;

// The transaction store handles all transaction persistence.
// Transactions are stored by hash — the canonical identifier.
// We also maintain a secondary index mapping sender address
// to their transaction hashes so wallet history lookups are fast
// without scanning the entire transaction database.

// Key prefix for the sender index.
// Stored as "sender:<address>:<nonce>" -> tx_hash
// The nonce in the key ensures ordering and uniqueness.
const SENDER_PREFIX: &str = "sender:";

// Save a transaction to the database.
// Stores it by hash and updates the sender index.
pub fn save_transaction(db: &KyveraDb, tx: &Transaction) -> Result<(), String> {
    if tx.hash.is_empty() {
        return Err("Cannot save transaction with empty hash".to_string());
    }

    let serialized = serde_json::to_vec(tx)
        .map_err(|e| format!("Failed to serialize transaction: {}", e))?;

    // Primary index: hash -> transaction
    KyveraDb::write(
        &db.transactions,
        tx.hash.as_bytes(),
        &serialized,
    )?;

    // Secondary index: sender:address:nonce -> hash
    // The nonce is zero-padded to 20 digits so lexicographic
    // ordering matches numeric ordering — lets us scan a
    // sender's transactions in nonce order efficiently.
    let sender_key = format!("{}{}:{:020}", SENDER_PREFIX, tx.sender, tx.nonce);
    KyveraDb::write(
        &db.transactions,
        sender_key.as_bytes(),
        tx.hash.as_bytes(),
    )?;

    Ok(())
}

// Load a transaction by its hash.
pub fn get_transaction(db: &KyveraDb, hash: &str) -> Result<Option<Transaction>, String> {
    let data = KyveraDb::read(&db.transactions, hash.as_bytes())?;
    match data {
        None => Ok(None),
        Some(bytes) => {
            let tx = serde_json::from_slice(&bytes)
                .map_err(|e| format!("Failed to deserialize transaction: {}", e))?;
            Ok(Some(tx))
        }
    }
}

// Check whether a transaction with the given hash exists.
pub fn transaction_exists(db: &KyveraDb, hash: &str) -> Result<bool, String> {
    KyveraDb::exists(&db.transactions, hash.as_bytes())
}

// Get all transaction hashes sent by a given address.
// Returns them in nonce order (ascending) which is also
// chronological order for transactions from the same sender.
pub fn get_transactions_by_sender(
    db: &KyveraDb,
    address: &str,
) -> Result<Vec<String>, String> {
    let prefix = format!("{}{}", SENDER_PREFIX, address);
    let mut hashes = Vec::new();

    for result in db.transactions.scan_prefix(prefix.as_bytes()) {
        let (_, value) = result
            .map_err(|e| format!("Scan error: {}", e))?;
        let hash = String::from_utf8(value.to_vec())
            .map_err(|e| format!("Invalid hash bytes: {}", e))?;
        hashes.push(hash);
    }

    Ok(hashes)
}

// Get the most recent N transactions sent by an address.
// Useful for wallet history display.
pub fn get_recent_transactions_by_sender(
    db: &KyveraDb,
    address: &str,
    limit: usize,
) -> Result<Vec<Transaction>, String> {
    let hashes = get_transactions_by_sender(db, address)?;

    // Take the last `limit` hashes (most recent nonces)
    let recent_hashes: Vec<String> = hashes
        .into_iter()
        .rev()
        .take(limit)
        .collect();

    let mut transactions = Vec::new();
    for hash in recent_hashes {
        if let Some(tx) = get_transaction(db, &hash)? {
            transactions.push(tx);
        }
    }

    Ok(transactions)
}

// Get the total number of transactions stored.
// This counts both primary and secondary index entries
// so the real transaction count is approximately half.
pub fn transaction_count(db: &KyveraDb) -> usize {
    // Count only primary entries (those that don't start with the sender prefix)
    db.transactions
        .scan_prefix(&[])
        .filter(|r| {
            if let Ok((k, _)) = r {
                let key_str = String::from_utf8_lossy(&k);
                !key_str.starts_with(SENDER_PREFIX)
            } else {
                false
            }
        })
        .count()
}

// Save all transactions in a block to the database.
// Called when a block is accepted into the chain.
pub fn save_block_transactions(
    db: &KyveraDb,
    transactions: &[Transaction],
) -> Result<(), String> {
    for tx in transactions {
        save_transaction(db, tx)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::KyveraDb;
    use crate::types::transaction::{Transaction, TransactionType};

    fn make_tx(sender: &str, receiver: &str, nonce: u64, hash: &str) -> Transaction {
        let mut tx = Transaction::new(
            sender.to_string(),
            receiver.to_string(),
            1_000_000_000,
            1_000_000,
            nonce,
            TransactionType::Transfer,
            vec![],
        );
        // Normally the hash is computed by the transaction builder
        // but for storage tests we set it directly
        tx.hash = hash.to_string();
        tx.signature = "test_signature".to_string();
        tx
    }

    fn addr(n: u8) -> String {
        format!("kyv1{}", hex::encode([n; 32]))
    }

    #[test]
    fn test_save_and_get_transaction() {
        let db = KyveraDb::open_temp().unwrap();
        let tx = make_tx(&addr(1), &addr(2), 0, &format!("{:064}", 1));

        save_transaction(&db, &tx).unwrap();

        let loaded = get_transaction(&db, &tx.hash).unwrap();
        assert!(loaded.is_some());

        let loaded = loaded.unwrap();
        assert_eq!(loaded.hash, tx.hash);
        assert_eq!(loaded.sender, tx.sender);
        assert_eq!(loaded.nonce, 0);
    }

    #[test]
    fn test_transaction_exists() {
        let db = KyveraDb::open_temp().unwrap();
        let tx = make_tx(&addr(1), &addr(2), 0, &format!("{:064}", 1));

        assert!(!transaction_exists(&db, &tx.hash).unwrap());
        save_transaction(&db, &tx).unwrap();
        assert!(transaction_exists(&db, &tx.hash).unwrap());
    }

    #[test]
    fn test_get_nonexistent_transaction_returns_none() {
        let db = KyveraDb::open_temp().unwrap();
        let result = get_transaction(&db, &format!("{:064}", 99)).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_get_transactions_by_sender() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        let receiver = addr(2);

        // Save 3 transactions from the same sender
        for nonce in 0..3u64 {
            let tx = make_tx(&sender, &receiver, nonce, &format!("{:064}", nonce + 1));
            save_transaction(&db, &tx).unwrap();
        }

        // Also save a transaction from a different sender
        let other_tx = make_tx(&addr(3), &receiver, 0, &format!("{:064}", 99));
        save_transaction(&db, &other_tx).unwrap();

        let hashes = get_transactions_by_sender(&db, &sender).unwrap();
        assert_eq!(hashes.len(), 3);
    }

    #[test]
    fn test_transactions_returned_in_nonce_order() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);

        // Save in reverse nonce order
        for nonce in [2u64, 0, 1] {
            let tx = make_tx(&sender, &addr(2), nonce, &format!("{:064x}", nonce + 10));
            save_transaction(&db, &tx).unwrap();
        }

        let hashes = get_transactions_by_sender(&db, &sender).unwrap();
        let txs: Vec<Transaction> = hashes.iter()
            .filter_map(|h| get_transaction(&db, h).unwrap())
            .collect();

        // Should be in ascending nonce order
        assert_eq!(txs[0].nonce, 0);
        assert_eq!(txs[1].nonce, 1);
        assert_eq!(txs[2].nonce, 2);
    }

    #[test]
    fn test_save_block_transactions() {
        let db = KyveraDb::open_temp().unwrap();

        let txs: Vec<Transaction> = (0..5u64)
            .map(|i| make_tx(&addr(1), &addr(2), i, &format!("{:064}", i + 1)))
            .collect();

        save_block_transactions(&db, &txs).unwrap();

        assert_eq!(transaction_count(&db), 5);
    }

    #[test]
    fn test_cannot_save_transaction_with_empty_hash() {
        let db = KyveraDb::open_temp().unwrap();
        let mut tx = make_tx(&addr(1), &addr(2), 0, "");
        tx.hash = String::new();

        let result = save_transaction(&db, &tx);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_recent_transactions_limit() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);

        for nonce in 0..10u64 {
            let tx = make_tx(&sender, &addr(2), nonce, &format!("{:064}", nonce + 1));
            save_transaction(&db, &tx).unwrap();
        }

        let recent = get_recent_transactions_by_sender(&db, &sender, 3).unwrap();
        assert_eq!(recent.len(), 3);
    }
}