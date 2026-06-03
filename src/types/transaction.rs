use serde::{Deserialize, Serialize};
use chrono::Utc;

// Every movement of value or execution of logic on Kyvera
// goes through a transaction. This is the base type for all of them.
// The type field determines how the rest of the fields are interpreted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    // Unique identifier for this transaction.
    // Computed as a hash of the transaction contents.
    // Empty until the transaction is signed and finalised.
    pub hash: String,

    // Who is sending this transaction.
    // Derived from their Dilithium public key.
    pub sender: String,

    // Who is receiving. For contract deployments this will be
    // the contract address generated at deployment time.
    pub receiver: String,

    // Amount of KYV being transferred, in smallest units (10^-9).
    // Zero for pure contract calls that don't move value.
    pub amount: u64,

    // Fee the sender is willing to pay for this transaction.
    // Higher fee = picked up by miners faster during congestion.
    // Split 50% burn, 40% validators, 10% treasury at protocol level.
    pub fee: u64,

    // Per-account counter that increments with every transaction.
    // Prevents the same transaction from being submitted twice.
    // Node rejects any transaction whose nonce doesn't match
    // the sender's current on-chain nonce exactly.
    pub nonce: u64,

    // The Dilithium3 signature over this transaction's contents.
    // Empty until the wallet signs it. Never broadcast unsigned.
    pub signature: String,

    // Millisecond timestamp of when the transaction was created.
    // Nodes reject transactions that are too far in the past or future.
    pub timestamp: i64,

    // What kind of transaction this is.
    // Determines validation rules and how it gets executed.
    pub transaction_type: TransactionType,

    // Optional payload for smart contract calls and deployments.
    // Empty for plain KYV transfers.
    pub data: Vec<u8>,
}

// The different things a transaction can do on Kyvera.
// Keep this list tight. Every new type is a new attack surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TransactionType {
    // Plain KYV transfer from one address to another.
    // Most common transaction type by far.
    Transfer,

    // Lock KYV into the staking contract to become a validator.
    // Amount field determines which tier you qualify for.
    StakeLock,

    // Unlock staked KYV back to the wallet.
    // Subject to an unbonding period before funds are released.
    StakeUnlock,

    // Deploy a new smart contract to the KVM.
    // Contract bytecode goes in the data field.
    // Receiver field will hold the generated contract address.
    ContractDeploy,

    // Call a function on an existing smart contract.
    // Receiver is the contract address.
    // data field contains the encoded function call and arguments.
    ContractCall,
}

impl Transaction {
    pub fn new(
        sender: String,
        receiver: String,
        amount: u64,
        fee: u64,
        nonce: u64,
        transaction_type: TransactionType,
        data: Vec<u8>,
    ) -> Self {
        Transaction {
            // Hash gets computed and set when the transaction is signed.
            // A transaction without a hash is not ready to broadcast.
            hash: String::new(),
            sender,
            receiver,
            amount,
            fee,
            nonce,
            // Signature gets filled in by the wallet after construction.
            signature: String::new(),
            timestamp: Utc::now().timestamp_millis(),
            transaction_type,
            data,
        }
    }

    // A transaction is considered signed if it has both a hash
    // and a signature. Both are required before broadcasting.
    pub fn is_signed(&self) -> bool {
        !self.hash.is_empty() && !self.signature.is_empty()
    }

    // Quick check for whether this is a plain value transfer.
    // Used in the fee calculation and mempool prioritisation logic.
    pub fn is_transfer(&self) -> bool {
        self.transaction_type == TransactionType::Transfer
    }

    // Contract deployments carry bytecode in the data field.
    // They're handled differently in the KVM execution path.
    pub fn is_contract_deploy(&self) -> bool {
        self.transaction_type == TransactionType::ContractDeploy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction::new(
            "sender_address".to_string(),
            "receiver_address".to_string(),
            // 10 KYV
            10_000_000_000,
            // 0.001 KYV fee
            1_000_000,
            0,
            TransactionType::Transfer,
            vec![],
        );

        assert_eq!(tx.amount, 10_000_000_000);
        assert_eq!(tx.fee, 1_000_000);
        assert_eq!(tx.nonce, 0);
        assert!(tx.hash.is_empty());
        assert!(tx.signature.is_empty());
        assert!(tx.timestamp > 0);
    }

    #[test]
    fn test_transaction_not_signed_on_creation() {
        let tx = Transaction::new(
            "sender".to_string(),
            "receiver".to_string(),
            1_000_000_000,
            1_000_000,
            0,
            TransactionType::Transfer,
            vec![],
        );

        // Should never be considered signed straight out of new()
        assert!(!tx.is_signed());
    }

    #[test]
    fn test_transaction_type_checks() {
        let transfer = Transaction::new(
            "sender".to_string(),
            "receiver".to_string(),
            1_000_000_000,
            1_000_000,
            0,
            TransactionType::Transfer,
            vec![],
        );

        let deploy = Transaction::new(
            "sender".to_string(),
            "contract_address".to_string(),
            0,
            5_000_000,
            1,
            TransactionType::ContractDeploy,
            // Pretend this is bytecode
            vec![0x00, 0x61, 0x73, 0x6d],
        );

        assert!(transfer.is_transfer());
        assert!(!transfer.is_contract_deploy());
        assert!(deploy.is_contract_deploy());
        assert!(!deploy.is_transfer());
    }

    #[test]
    fn test_transaction_serialization() {
        // Transactions travel over the network and get written to disk
        // constantly. Round trip has to be lossless.
        let tx = Transaction::new(
            "sender_address".to_string(),
            "receiver_address".to_string(),
            5_000_000_000,
            1_000_000,
            42,
            TransactionType::Transfer,
            vec![],
        );

        let json = serde_json::to_string(&tx).unwrap();
        let decoded: Transaction = serde_json::from_str(&json).unwrap();

        assert_eq!(tx, decoded);
        assert_eq!(decoded.nonce, 42);
        assert_eq!(decoded.amount, 5_000_000_000);
    }
}