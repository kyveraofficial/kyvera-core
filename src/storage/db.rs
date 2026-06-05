use sled::{Db, Tree};

// KyveraDb is the single database handle for the entire node.
// All storage operations go through here — blocks, transactions,
// accounts, and chain metadata all live in separate sled Trees
// (think of them as namespaced key-value stores) within one database.
//
// Sled gives us:
// - ACID transactions
// - Crash recovery — if the node dies mid-write, the database
//   recovers to a consistent state on next startup
// - Concurrent reads — multiple threads can read simultaneously
// - Sequential writes — sled handles the locking internally
//
// The database lives on disk at the path given at construction.
// On a full node this will be something like ~/.kyvera/chain/db

pub struct KyveraDb {
    // The underlying sled database
    pub db: Db,

    // Separate trees for each data type.
    // Keeping them separate means a scan over blocks does not
    // touch account data and vice versa — better performance
    // and cleaner separation of concerns.

    // Blocks stored by hash: block_hash -> serialized Block
    pub blocks_by_hash: Tree,

    // Blocks stored by height: height_bytes -> block_hash
    // Lets us look up blocks by number efficiently
    pub blocks_by_height: Tree,

    // Account state: address -> serialized Account
    pub accounts: Tree,

    // Transactions: tx_hash -> serialized Transaction
    pub transactions: Tree,

    // Chain metadata: string key -> serialized value
    // Stores things like current chain tip, total supply, etc.
    pub metadata: Tree,
}

impl KyveraDb {
    // Open or create the database at the given path.
    // If the directory does not exist, sled creates it.
    // If it exists, sled opens the existing database.
    pub fn open(path: &str) -> Result<Self, String> {
        let db = sled::open(path)
            .map_err(|e| format!("Failed to open database at {}: {}", path, e))?;

        let blocks_by_hash = db.open_tree("blocks_by_hash")
            .map_err(|e| format!("Failed to open blocks_by_hash tree: {}", e))?;

        let blocks_by_height = db.open_tree("blocks_by_height")
            .map_err(|e| format!("Failed to open blocks_by_height tree: {}", e))?;

        let accounts = db.open_tree("accounts")
            .map_err(|e| format!("Failed to open accounts tree: {}", e))?;

        let transactions = db.open_tree("transactions")
            .map_err(|e| format!("Failed to open transactions tree: {}", e))?;

        let metadata = db.open_tree("metadata")
            .map_err(|e| format!("Failed to open metadata tree: {}", e))?;

        Ok(KyveraDb {
            db,
            blocks_by_hash,
            blocks_by_height,
            accounts,
            transactions,
            metadata,
        })
    }

    // Open a temporary in-memory database for testing.
    // Data is lost when the handle is dropped.
    // Every test gets a fresh empty database this way.
    pub fn open_temp() -> Result<Self, String> {
        let db = sled::Config::new()
            .temporary(true)
            .open()
            .map_err(|e| format!("Failed to open temp database: {}", e))?;

        let blocks_by_hash   = db.open_tree("blocks_by_hash")
            .map_err(|e| e.to_string())?;
        let blocks_by_height = db.open_tree("blocks_by_height")
            .map_err(|e| e.to_string())?;
        let accounts         = db.open_tree("accounts")
            .map_err(|e| e.to_string())?;
        let transactions     = db.open_tree("transactions")
            .map_err(|e| e.to_string())?;
        let metadata         = db.open_tree("metadata")
            .map_err(|e| e.to_string())?;

        Ok(KyveraDb {
            db,
            blocks_by_hash,
            blocks_by_height,
            accounts,
            transactions,
            metadata,
        })
    }

    // Flush all pending writes to disk.
    // Call this after writing important data like a new block.
    // Sled buffers writes for performance — flush makes them durable.
    pub fn flush(&self) -> Result<(), String> {
        self.db.flush()
            .map(|_| ())
            .map_err(|e| format!("Flush failed: {}", e))
    }

    // Write a raw key-value pair to a tree.
    pub fn write(tree: &Tree, key: &[u8], value: &[u8]) -> Result<(), String> {
        tree.insert(key, value)
            .map(|_| ())
            .map_err(|e| format!("Write failed: {}", e))
    }

    // Read a raw value from a tree.
    pub fn read(tree: &Tree, key: &[u8]) -> Result<Option<Vec<u8>>, String> {
        tree.get(key)
            .map(|opt| opt.map(|v| v.to_vec()))
            .map_err(|e| format!("Read failed: {}", e))
    }

    // Delete a key from a tree.
    pub fn delete(tree: &Tree, key: &[u8]) -> Result<(), String> {
        tree.remove(key)
            .map(|_| ())
            .map_err(|e| format!("Delete failed: {}", e))
    }

    // Check if a key exists in a tree.
    pub fn exists(tree: &Tree, key: &[u8]) -> Result<bool, String> {
        tree.contains_key(key)
            .map_err(|e| format!("Exists check failed: {}", e))
    }

    // Count the number of entries in a tree.
    pub fn count(tree: &Tree) -> usize {
        tree.len()
    }

    // Store a metadata value by string key.
    pub fn set_metadata(&self, key: &str, value: &[u8]) -> Result<(), String> {
        Self::write(&self.metadata, key.as_bytes(), value)
    }

    // Read a metadata value by string key.
    pub fn get_metadata(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Self::read(&self.metadata, key.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_temp_database() {
        let db = KyveraDb::open_temp().unwrap();
        // All trees should be accessible and empty
        assert_eq!(KyveraDb::count(&db.blocks_by_hash), 0);
        assert_eq!(KyveraDb::count(&db.accounts), 0);
        assert_eq!(KyveraDb::count(&db.transactions), 0);
    }

    #[test]
    fn test_write_and_read() {
        let db = KyveraDb::open_temp().unwrap();

        let key   = b"test_key";
        let value = b"test_value";

        KyveraDb::write(&db.metadata, key, value).unwrap();
        let result = KyveraDb::read(&db.metadata, key).unwrap();

        assert_eq!(result, Some(value.to_vec()));
    }

    #[test]
    fn test_read_nonexistent_key_returns_none() {
        let db = KyveraDb::open_temp().unwrap();
        let result = KyveraDb::read(&db.metadata, b"does_not_exist").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_exists() {
        let db = KyveraDb::open_temp().unwrap();

        assert!(!KyveraDb::exists(&db.metadata, b"key").unwrap());
        KyveraDb::write(&db.metadata, b"key", b"value").unwrap();
        assert!(KyveraDb::exists(&db.metadata, b"key").unwrap());
    }

    #[test]
    fn test_delete() {
        let db = KyveraDb::open_temp().unwrap();

        KyveraDb::write(&db.metadata, b"key", b"value").unwrap();
        assert!(KyveraDb::exists(&db.metadata, b"key").unwrap());

        KyveraDb::delete(&db.metadata, b"key").unwrap();
        assert!(!KyveraDb::exists(&db.metadata, b"key").unwrap());
    }

    #[test]
    fn test_metadata_helpers() {
        let db = KyveraDb::open_temp().unwrap();

        db.set_metadata("chain_tip", b"some_hash").unwrap();
        let result = db.get_metadata("chain_tip").unwrap();

        assert_eq!(result, Some(b"some_hash".to_vec()));
    }

    #[test]
    fn test_count() {
        let db = KyveraDb::open_temp().unwrap();

        assert_eq!(KyveraDb::count(&db.accounts), 0);

        KyveraDb::write(&db.accounts, b"addr1", b"data1").unwrap();
        KyveraDb::write(&db.accounts, b"addr2", b"data2").unwrap();

        assert_eq!(KyveraDb::count(&db.accounts), 2);
    }

    #[test]
    fn test_multiple_trees_are_independent() {
        let db = KyveraDb::open_temp().unwrap();

        // Writing to blocks tree should not affect accounts tree
        KyveraDb::write(&db.blocks_by_hash, b"same_key", b"block_data").unwrap();

        let in_blocks   = KyveraDb::read(&db.blocks_by_hash, b"same_key").unwrap();
        let in_accounts = KyveraDb::read(&db.accounts,       b"same_key").unwrap();

        assert!(in_blocks.is_some());
        assert!(in_accounts.is_none());
    }
}