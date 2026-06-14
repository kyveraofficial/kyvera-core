use crate::types::transaction::{Transaction, TransactionType};
use crate::storage::db::KyveraDb;
use crate::storage::account_store::get_account;
use std::collections::{BTreeMap, HashMap, HashSet};

// The mempool holds transactions that have been received and validated
// but not yet included in a block. Miners pull from here in fee-priority
// order when building micro blocks.
//
// Design notes:
// - Transactions are keyed by hash for O(1) lookup and double-spend checks.
// - A fee-ordered index (BTreeMap keyed by fee, descending via Reverse)
//   lets the miner grab the highest-fee transactions first without
//   scanning the whole pool.
// - A per-sender nonce tracker prevents two transactions from the same
//   sender with the same nonce sitting in the pool simultaneously —
//   this is the double-spend check at the mempool layer.
// - A hard size cap with eviction by lowest fee keeps the pool bounded
//   under spam/congestion.

// Maximum number of transactions the mempool will hold at once.
// When full, the lowest-fee transaction is evicted to make room
// for a higher-fee incoming transaction. If the incoming transaction's
// fee is not higher than the current lowest, it is rejected outright.
pub const MAX_MEMPOOL_SIZE: usize = 50_000;

#[derive(Debug)]
pub enum MempoolError {
    // Transaction hash already in the pool
    AlreadyExists,
    // Sender already has a pending transaction with this nonce
    DuplicateNonce { address: String, nonce: u64 },
    // Sender cannot afford amount + fee given current state
    InsufficientBalance { address: String, required: u64, available: u64 },
    // Nonce does not match the account's current on-chain nonce
    // when there are no other pending transactions from this sender
    InvalidNonce { expected: u64, got: u64 },
    // Pool is full and incoming fee is not high enough to evict anything
    PoolFullFeeTooLow,
    // Transaction failed basic structural checks
    MalformedTransaction(String),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MempoolError::AlreadyExists =>
                write!(f, "Transaction already in mempool"),
            MempoolError::DuplicateNonce { address, nonce } =>
                write!(f, "Sender {} already has a pending transaction with nonce {}", &address[..12], nonce),
            MempoolError::InsufficientBalance { address, required, available } =>
                write!(f, "{} cannot afford transaction: needs {} has {}", &address[..12], required, available),
            MempoolError::InvalidNonce { expected, got } =>
                write!(f, "Invalid nonce: expected {} got {}", expected, got),
            MempoolError::PoolFullFeeTooLow =>
                write!(f, "Mempool is full and this transaction's fee is too low to evict anything"),
            MempoolError::MalformedTransaction(reason) =>
                write!(f, "Malformed transaction: {}", reason),
        }
    }
}

// A wrapper that gives us a total ordering on (fee, hash) so the
// BTreeMap can hold multiple transactions with the same fee without
// collisions, while still ordering primarily by fee.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FeeKey {
    fee: u64,
    hash: String,
}

pub struct Mempool {
    // Primary storage — hash -> transaction
    transactions: HashMap<String, Transaction>,

    // Fee-ordered index. Iterating in reverse gives highest fee first.
    fee_index: BTreeMap<FeeKey, ()>,

    // Tracks (sender, nonce) pairs currently in the pool to prevent
    // duplicate-nonce submissions from the same sender.
    pending_nonces: HashSet<(String, u64)>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            transactions: HashMap::new(),
            fee_index: BTreeMap::new(),
            pending_nonces: HashSet::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    pub fn contains(&self, hash: &str) -> bool {
        self.transactions.contains_key(hash)
    }

    pub fn get(&self, hash: &str) -> Option<&Transaction> {
        self.transactions.get(hash)
    }

    // Attempt to add a transaction to the pool.
    // Performs structural checks, double-spend/nonce checks against
    // both the pool and on-chain state, and balance checks against
    // on-chain state (pending pool effects are not netted here —
    // that happens at block-build time).
    pub fn add_transaction(
        &mut self,
        tx: Transaction,
        db: &KyveraDb,
    ) -> Result<(), MempoolError> {
        validate_structure(&tx)?;

        if self.transactions.contains_key(&tx.hash) {
            return Err(MempoolError::AlreadyExists);
        }

        let sender_key = (tx.sender.clone(), tx.nonce);
        if self.pending_nonces.contains(&sender_key) {
            return Err(MempoolError::DuplicateNonce {
                address: tx.sender.clone(),
                nonce: tx.nonce,
            });
        }

        // Coinbase-style sentinel senders never go through the mempool.
        // Validate against on-chain account state.
        let account = get_account(db, &tx.sender)
            .map_err(MempoolError::MalformedTransaction)?;

        let account = account.unwrap_or_else(|| crate::types::account::Account::new(tx.sender.clone()));

        let required = match tx.transaction_type {
            TransactionType::Transfer | TransactionType::StakeLock => {
                tx.amount.saturating_add(tx.fee)
            }
            TransactionType::StakeUnlock |
            TransactionType::ContractDeploy |
            TransactionType::ContractCall => tx.fee,
        };

        if account.balance < required {
            return Err(MempoolError::InsufficientBalance {
                address: tx.sender.clone(),
                required,
                available: account.balance,
            });
        }

        // If this is the only pending tx from this sender, the nonce
        // must match their current on-chain nonce exactly. If they
        // already have pending transactions, we allow sequential
        // nonces above the on-chain value (handled by the duplicate
        // check above preventing the same nonce twice).
        let has_other_pending = self.pending_nonces.iter()
            .any(|(addr, _)| addr == &tx.sender);

        if !has_other_pending && tx.nonce != account.nonce {
            return Err(MempoolError::InvalidNonce {
                expected: account.nonce,
                got: tx.nonce,
            });
        }

        // Enforce pool size cap with lowest-fee eviction
        if self.transactions.len() >= MAX_MEMPOOL_SIZE {
            self.evict_for(tx.fee)?;
        }

        self.insert(tx);
        Ok(())
    }

    // Insert without any validation — used internally after checks pass,
    // and directly by tests that want to bypass validation.
    fn insert(&mut self, tx: Transaction) {
        let key = FeeKey { fee: tx.fee, hash: tx.hash.clone() };
        self.pending_nonces.insert((tx.sender.clone(), tx.nonce));
        self.fee_index.insert(key, ());
        self.transactions.insert(tx.hash.clone(), tx);
    }

    // Remove the single lowest-fee transaction to make room, but only
    // if the incoming fee is strictly higher than that lowest fee.
    fn evict_for(&mut self, incoming_fee: u64) -> Result<(), MempoolError> {
        let lowest = self.fee_index.keys().next().cloned();

        match lowest {
            None => Ok(()), // pool reports full but is empty — should not happen
            Some(lowest_key) => {
                if incoming_fee <= lowest_key.fee {
                    return Err(MempoolError::PoolFullFeeTooLow);
                }
                self.remove(&lowest_key.hash);
                Ok(())
            }
        }
    }

    // Remove a transaction by hash. Used after a block includes it,
    // or during eviction.
    pub fn remove(&mut self, hash: &str) -> Option<Transaction> {
        let tx = self.transactions.remove(hash)?;
        let key = FeeKey { fee: tx.fee, hash: tx.hash.clone() };
        self.fee_index.remove(&key);
        self.pending_nonces.remove(&(tx.sender.clone(), tx.nonce));
        Some(tx)
    }

    // Return up to `limit` transactions ordered by fee, highest first.
    // Does not remove them from the pool — the caller (block producer)
    // removes them explicitly once the block is finalised.
    pub fn top_by_fee(&self, limit: usize) -> Vec<Transaction> {
        self.fee_index
            .keys()
            .rev()
            .take(limit)
            .filter_map(|key| self.transactions.get(&key.hash).cloned())
            .collect()
    }

    // Remove a batch of transactions by hash — called once a block
    // containing them has been accepted.
    pub fn remove_batch(&mut self, hashes: &[String]) {
        for hash in hashes {
            self.remove(hash);
        }
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

// Basic structural validation independent of chain state.
fn validate_structure(tx: &Transaction) -> Result<(), MempoolError> {
    if tx.hash.is_empty() {
        return Err(MempoolError::MalformedTransaction("empty hash".to_string()));
    }
    if tx.signature.is_empty() {
        return Err(MempoolError::MalformedTransaction("empty signature".to_string()));
    }
    if tx.sender.is_empty() || tx.receiver.is_empty() {
        return Err(MempoolError::MalformedTransaction("empty sender or receiver".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::db::KyveraDb;
    use crate::storage::account_store::credit_account;

    fn addr(n: u8) -> String {
        format!("kyv1{}", hex::encode([n; 32]))
    }

    fn make_tx(sender: &str, receiver: &str, amount: u64, fee: u64, nonce: u64, hash_seed: u64) -> Transaction {
        let mut tx = Transaction::new(
            sender.to_string(), receiver.to_string(),
            amount, fee, nonce,
            TransactionType::Transfer, vec![],
        );
        tx.hash = format!("{:064}", hash_seed);
        tx.signature = "sig".to_string();
        tx
    }

    #[test]
    fn test_add_valid_transaction() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let mut pool = Mempool::new();
        let tx = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 0, 1);

        pool.add_transaction(tx.clone(), &db).unwrap();
        assert_eq!(pool.len(), 1);
        assert!(pool.contains(&tx.hash));
    }

    #[test]
    fn test_duplicate_transaction_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let mut pool = Mempool::new();
        let tx = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 0, 1);

        pool.add_transaction(tx.clone(), &db).unwrap();
        let result = pool.add_transaction(tx, &db);
        assert!(matches!(result, Err(MempoolError::AlreadyExists)));
    }

    #[test]
    fn test_duplicate_nonce_from_same_sender_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let mut pool = Mempool::new();
        let tx1 = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 0, 1);
        let tx2 = make_tx(&sender, &addr(3), 2_000_000_000, 1_000_000, 0, 2);

        pool.add_transaction(tx1, &db).unwrap();
        let result = pool.add_transaction(tx2, &db);
        assert!(matches!(result, Err(MempoolError::DuplicateNonce { .. })));
    }

    #[test]
    fn test_insufficient_balance_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 1_000_000).unwrap();

        let mut pool = Mempool::new();
        let tx = make_tx(&sender, &addr(2), 100_000_000_000, 1_000_000, 0, 1);

        let result = pool.add_transaction(tx, &db);
        assert!(matches!(result, Err(MempoolError::InsufficientBalance { .. })));
    }

    #[test]
    fn test_wrong_initial_nonce_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let mut pool = Mempool::new();
        // Account nonce is 0 but tx claims nonce 3
        let tx = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 3, 1);

        let result = pool.add_transaction(tx, &db);
        assert!(matches!(result, Err(MempoolError::InvalidNonce { .. })));
    }

    #[test]
    fn test_sequential_nonces_from_same_sender_allowed() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let mut pool = Mempool::new();
        let tx0 = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 0, 1);
        let tx1 = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 1, 2);
        let tx2 = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 2, 3);

        pool.add_transaction(tx0, &db).unwrap();
        pool.add_transaction(tx1, &db).unwrap();
        pool.add_transaction(tx2, &db).unwrap();

        assert_eq!(pool.len(), 3);
    }

    #[test]
    fn test_top_by_fee_ordering() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 1_000_000_000_000).unwrap();

        let mut pool = Mempool::new();
        // Different fees, different nonces so they can all coexist
        let low  = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 0, 1);
        let high = make_tx(&sender, &addr(2), 1_000_000_000, 5_000_000, 1, 2);
        let mid  = make_tx(&sender, &addr(2), 1_000_000_000, 3_000_000, 2, 3);

        pool.add_transaction(low, &db).unwrap();
        pool.add_transaction(high.clone(), &db).unwrap();
        pool.add_transaction(mid, &db).unwrap();

        let top = pool.top_by_fee(3);
        assert_eq!(top[0].hash, high.hash);
        assert_eq!(top[0].fee, 5_000_000);
        assert_eq!(top[2].fee, 1_000_000);
    }

    #[test]
    fn test_remove_transaction() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let mut pool = Mempool::new();
        let tx = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 0, 1);
        pool.add_transaction(tx.clone(), &db).unwrap();

        let removed = pool.remove(&tx.hash);
        assert!(removed.is_some());
        assert_eq!(pool.len(), 0);
        assert!(!pool.contains(&tx.hash));
    }

    #[test]
    fn test_remove_batch() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 1_000_000_000_000).unwrap();

        let mut pool = Mempool::new();
        let tx0 = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 0, 1);
        let tx1 = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 1, 2);

        pool.add_transaction(tx0.clone(), &db).unwrap();
        pool.add_transaction(tx1.clone(), &db).unwrap();

        pool.remove_batch(&[tx0.hash.clone(), tx1.hash.clone()]);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_after_removal_nonce_can_be_reused() {
        let db = KyveraDb::open_temp().unwrap();
        let sender = addr(1);
        credit_account(&db, &sender, 100_000_000_000).unwrap();

        let mut pool = Mempool::new();
        let tx = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 0, 1);
        pool.add_transaction(tx.clone(), &db).unwrap();
        pool.remove(&tx.hash);

        // Same nonce, different hash — should now be accepted again
        let tx2 = make_tx(&sender, &addr(2), 1_000_000_000, 1_000_000, 0, 2);
        pool.add_transaction(tx2, &db).unwrap();
        assert_eq!(pool.len(), 1);
    }

    #[test]
    fn test_malformed_transaction_rejected() {
        let db = KyveraDb::open_temp().unwrap();
        let mut pool = Mempool::new();

        let mut tx = make_tx(&addr(1), &addr(2), 1_000_000_000, 1_000_000, 0, 1);
        tx.signature = String::new();

        let result = pool.add_transaction(tx, &db);
        assert!(matches!(result, Err(MempoolError::MalformedTransaction(_))));
    }
}