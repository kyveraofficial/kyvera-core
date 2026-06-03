use serde::{Deserialize, Serialize};

// Represents a single account on the Kyvera network.
// Every wallet address maps to one of these in the state trie.
// Gets read and written on every transaction that touches the address.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Account {
    // The wallet address. Derived from the Dilithium public key.
    // This is the key used to look up the account in the state trie.
    pub address: String,

    // Spendable KYV balance in smallest units (10^-9).
    // Does not include staked balance — that's locked separately.
    pub balance: u64,

    // How much KYV this account has locked in the staking contract.
    // Not spendable until StakeUnlock is submitted and the
    // unbonding period passes.
    pub staked_balance: u64,

    // Increments every time this account sends a transaction.
    // The node rejects any incoming transaction whose nonce
    // doesn't match this value exactly. Prevents replay attacks.
    pub nonce: u64,

    // Which validator tier this account currently holds.
    // None means not a validator — just a regular wallet.
    // Tier is determined by staked_balance at epoch boundaries.
    pub validator_tier: Option<ValidatorTier>,

    // Whether this address is a smart contract.
    // Contract accounts have code stored separately in the KVM.
    // They can receive calls but can't initiate transactions themselves.
    pub is_contract: bool,

    // The epoch block at which this account last received
    // a staking reward. Used to calculate pending rewards
    // without scanning the entire chain history.
    pub last_reward_epoch: u64,
}

// The three validator tiers defined in the Proof of Kinesis spec.
// Each tier has a minimum stake requirement and a reward multiplier.
// All tiers are reachable through mining alone — no purchase needed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ValidatorTier {
    // 500 KYV minimum stake.
    // Basic micro block validation. Standard reward rate.
    // Entry point for anyone who has been mining for a while.
    Igniter,

    // 5,000 KYV minimum stake.
    // Full epoch block participation and network routing.
    // 15% bonus on top of base validator rewards.
    Kinetic,

    // 25,000 KYV minimum stake.
    // Core epoch validation, governance rights, KYV-Guard registry.
    // 35% bonus on top of base validator rewards.
    // These are the backbone of the network.
    Nexus,
}

impl ValidatorTier {
    // Minimum stake required to qualify for each tier.
    // These are protocol constants — not governance adjustable.
    pub fn minimum_stake(&self) -> u64 {
        match self {
            ValidatorTier::Igniter => 500_000_000_000,
            ValidatorTier::Kinetic => 5_000_000_000_000,
            ValidatorTier::Nexus  => 25_000_000_000_000,
        }
    }

    // Reward multiplier in basis points on top of base rate.
    // 0 = standard, 1500 = +15%, 3500 = +35%.
    pub fn reward_bonus_bps(&self) -> u64 {
        match self {
            ValidatorTier::Igniter => 0,
            ValidatorTier::Kinetic => 1500,
            ValidatorTier::Nexus   => 3500,
        }
    }

    // Derive the correct tier from a staked balance.
    // Returns None if the balance doesn't meet Igniter minimum.
    // Used at epoch boundaries to assign or strip validator status.
    pub fn from_staked_balance(staked: u64) -> Option<ValidatorTier> {
        if staked >= ValidatorTier::Nexus.minimum_stake() {
            Some(ValidatorTier::Nexus)
        } else if staked >= ValidatorTier::Kinetic.minimum_stake() {
            Some(ValidatorTier::Kinetic)
        } else if staked >= ValidatorTier::Igniter.minimum_stake() {
            Some(ValidatorTier::Igniter)
        } else {
            None
        }
    }
}

impl Account {
    // Creates a fresh account with zero balance.
    // Every new wallet starts here.
    pub fn new(address: String) -> Self {
        Account {
            address,
            balance: 0,
            staked_balance: 0,
            nonce: 0,
            validator_tier: None,
            is_contract: false,
            last_reward_epoch: 0,
        }
    }

    // Total KYV associated with this account.
    // Spendable balance plus locked staking balance.
    // Useful for display purposes in a wallet or explorer.
    pub fn total_balance(&self) -> u64 {
        self.balance + self.staked_balance
    }

    // Check if this account can afford to send a transaction.
    // Fee comes out of spendable balance, not staked balance.
    pub fn can_afford(&self, amount: u64, fee: u64) -> bool {
        self.balance >= amount + fee
    }

    // Re-evaluate and update the validator tier based on
    // current staked balance. Called at every epoch boundary.
    pub fn update_validator_tier(&mut self) {
        self.validator_tier = ValidatorTier::from_staked_balance(self.staked_balance);
    }

    pub fn is_validator(&self) -> bool {
        self.validator_tier.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_account_starts_empty() {
        let account = Account::new("kyv1_test_address".to_string());

        assert_eq!(account.balance, 0);
        assert_eq!(account.staked_balance, 0);
        assert_eq!(account.nonce, 0);
        assert!(account.validator_tier.is_none());
        assert!(!account.is_contract);
        assert!(!account.is_validator());
    }

    #[test]
    fn test_total_balance() {
        let mut account = Account::new("kyv1_test_address".to_string());
        account.balance = 10_000_000_000;
        account.staked_balance = 500_000_000_000;

        assert_eq!(account.total_balance(), 510_000_000_000);
    }

    #[test]
    fn test_can_afford() {
        let mut account = Account::new("kyv1_test_address".to_string());
        account.balance = 10_000_000_000;

        // 9 KYV + 0.001 KYV fee, should pass
        assert!(account.can_afford(9_000_000_000, 1_000_000));

        // 10 KYV + 0.001 KYV fee, should fail — not enough for fee
        assert!(!account.can_afford(10_000_000_000, 1_000_000));
    }

    #[test]
    fn test_validator_tier_from_stake() {
        // Below Igniter minimum
        assert!(ValidatorTier::from_staked_balance(100_000_000_000).is_none());

        // Exactly Igniter minimum — 500 KYV
        assert_eq!(
            ValidatorTier::from_staked_balance(500_000_000_000),
            Some(ValidatorTier::Igniter)
        );

        // Exactly Kinetic minimum — 5000 KYV
        assert_eq!(
            ValidatorTier::from_staked_balance(5_000_000_000_000),
            Some(ValidatorTier::Kinetic)
        );

        // Exactly Nexus minimum — 25000 KYV
        assert_eq!(
            ValidatorTier::from_staked_balance(25_000_000_000_000),
            Some(ValidatorTier::Nexus)
        );
    }

    #[test]
    fn test_update_validator_tier() {
        let mut account = Account::new("kyv1_test_address".to_string());

        // No stake — no tier
        account.update_validator_tier();
        assert!(account.validator_tier.is_none());

        // Stake enough for Igniter
        account.staked_balance = 500_000_000_000;
        account.update_validator_tier();
        assert_eq!(account.validator_tier, Some(ValidatorTier::Igniter));

        // Stake more — jumps to Kinetic
        account.staked_balance = 5_000_000_000_000;
        account.update_validator_tier();
        assert_eq!(account.validator_tier, Some(ValidatorTier::Kinetic));

        // Stake enough for Nexus
        account.staked_balance = 25_000_000_000_000;
        account.update_validator_tier();
        assert_eq!(account.validator_tier, Some(ValidatorTier::Nexus));
    }

    #[test]
    fn test_account_serialization() {
        let mut account = Account::new("kyv1_test_address".to_string());
        account.balance = 50_000_000_000;
        account.staked_balance = 500_000_000_000;
        account.update_validator_tier();

        let json = serde_json::to_string(&account).unwrap();
        let decoded: Account = serde_json::from_str(&json).unwrap();

        assert_eq!(account, decoded);
        assert_eq!(decoded.validator_tier, Some(ValidatorTier::Igniter));
    }
}