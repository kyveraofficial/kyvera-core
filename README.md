# kyvera-core

Core protocol library for the Kyvera blockchain.

Kyvera is a Layer 1 blockchain built from scratch in Rust. It runs on a consensus
mechanism called Proof of Kinesis (PoK), is quantum-resistant from the genesis block,
and is designed so that anyone with a CPU or a phone can participate from zero.

This repository is the heart of the protocol. Everything that defines what Kyvera is
at a fundamental level lives here — the data types, the cryptography, the consensus
logic, the virtual machine, the drainer protection stack. The node software, wallet,
and block explorer will be built on top of what gets written in this library.

---

## What is being built

Kyvera is not a fork. It is not a token on another chain. It is a ground-up Layer 1
blockchain with its own mainnet (Kyvera Continuum), its own consensus mechanism, and
its own cryptographic stack. The goal is a chain that includes everybody — not just
people with expensive hardware, venture capital backing, or years of technical experience.

A few things that make it different from existing chains:

**Quantum resistant from block zero.** Every wallet on Kyvera uses CRYSTALS-Dilithium
signatures instead of ECDSA. Node communication uses CRYSTALS-Kyber. Epoch blocks carry
SPHINCS+ counter-signatures. There is no elliptic curve cryptography anywhere in the
protocol. Bitcoin, Ethereum, and Solana will eventually have to migrate. Kyvera never will.

**Mine from nothing.** The Proof of Kinesis mining algorithm is ASIC-resistant and
designed to run on consumer CPUs and mobile devices. No mining farms. No industrial
hardware. The only requirement is that you show up.

**Dual-block architecture.** Micro blocks confirm transactions in 2 to 3 seconds.
Epoch blocks provide full cryptographic finality every 10 minutes. The two-layer design
exists because post-quantum signatures are 38 times larger than ECDSA signatures —
applying them to every transaction would destroy throughput. Separating speed from
security solves that without compromising either.

**Five-layer drainer protection.** Transaction simulation, hardcoded spending caps,
mandatory approval expiry, on-chain anomaly detection, and quantum replay protection.
All of it enforced at the consensus layer, not the wallet layer.

**Rust-native smart contracts.** The Kyvera Virtual Machine runs Rust bytecode.
Memory safety is guaranteed at compile time. Entire categories of vulnerabilities
that have cost EVM chains billions of dollars cannot exist in KVM.

---

## Project status

Currently in active development. Month 1 of an 18-month roadmap to mainnet.

The core data types are defined and tested. Cryptography integration is next.

Full roadmap: [Kyvera 18-Month Development Roadmap](../Kyvera_Roadmap_18Month.docx)

---

## Repository structure
kyvera-core/
├── src/
│   ├── lib.rs              # Crate root, module declarations
│   └── types/
│       ├── mod.rs          # Types module root
│       ├── block.rs        # Block and BlockHeader structs
│       ├── transaction.rs  # Transaction struct and TransactionType enum
│       └── account.rs      # Account struct and ValidatorTier enum
├── Cargo.toml
└── README.md

More modules will be added as development progresses:
- `src/crypto/` — Dilithium, Kyber, SPHINCS+ integration
- `src/consensus/` — Proof of Kinesis mining and staking logic
- `src/storage/` — Chain state and database layer
- `src/mempool/` — Transaction pool and fee management
- `src/network/` — P2P networking and chain sync
- `src/vm/` — Kyvera Virtual Machine
- `src/drainer/` — Five-layer drainer protection stack

---

## Running the tests

You need Rust installed. If you do not have it:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Clone the repository and run the test suite:

```bash
git clone https://github.com/kyveraofficial/kyvera-core
cd kyvera-core
cargo test
```

Expected output:
running 13 tests
test types::account::tests::test_account_serialization ... ok
test types::account::tests::test_can_afford ... ok
test types::account::tests::test_new_account_starts_empty ... ok
test types::account::tests::test_total_balance ... ok
test types::account::tests::test_update_validator_tier ... ok
test types::account::tests::test_validator_tier_from_stake ... ok
test types::block::tests::test_block_creation ... ok
test types::block::tests::test_block_header_creation ... ok
test types::block::tests::test_block_serialization ... ok
test types::transaction::tests::test_transaction_creation ... ok
test types::transaction::tests::test_transaction_not_signed_on_creation ... ok
test types::transaction::tests::test_transaction_serialization ... ok
test types::transaction::tests::test_transaction_type_checks ... ok
test result: ok. 13 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

---

## Tokenomics

| Property | Value |
|---|---|
| Ticker | KYV |
| Total supply | 1,500,000,000 KYV |
| Mining allocation | 60% — open to everyone |
| Genesis block reward | 50 KYV |
| Halving interval | Every 290,000 epoch blocks (~5.5 years) |
| Consensus | Proof of Kinesis (PoK) |
| Smart contracts | Rust-native via KVM |
| Quantum resistant | Yes — from genesis block zero |

---

## Validator tiers

| Tier | Minimum stake | Reward bonus |
|---|---|---|
| Igniter | 500 KYV | Standard |
| Kinetic | 5,000 KYV | +15% |
| Nexus | 25,000 KYV | +35% |

Every tier is reachable through mining alone. No purchase required.

---

## Whitepaper

The full technical specification is available in the whitepaper. It covers the complete
protocol design including Proof of Kinesis consensus, dual-block architecture,
post-quantum cryptographic implementation, tokenomics, the drainer protection stack,
governance model, and security analysis.

---

## License

MIT

---

*One ecosystem. One chain. No gatekeepers.*