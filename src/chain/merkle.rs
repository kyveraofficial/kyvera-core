use crate::chain::hash::sha3_256_hex;

// A Merkle tree is how a block commits to all its transactions
// in a single 32-byte hash. Instead of hashing all transactions
// together, we build a binary tree where each leaf is a transaction
// hash and each parent is the hash of its two children.
// The root of the tree — the Merkle root — goes in the block header.
//
// This gives us two useful properties:
// 1. You can verify a single transaction is in a block using only
//    a small proof (log2 N hashes) rather than downloading the
//    entire block. Critical for light clients.
// 2. Changing any transaction changes the Merkle root, which changes
//    the block hash, which breaks the chain. Tamper-evident by design.

// A Merkle proof — the minimum set of hashes needed to prove
// that a specific transaction is included in a specific block.
// A verifier only needs this proof plus the Merkle root —
// they do not need any other transactions in the block.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    // The transaction hash being proved
    pub leaf_hash: String,
    // The sibling hashes needed to reconstruct the root
    pub siblings: Vec<(String, ProofDirection)>,
    // The Merkle root to verify against
    pub root: String,
}

// Which side the sibling is on at each level of the proof.
// Needed because hash(A, B) != hash(B, A).
#[derive(Debug, Clone, PartialEq)]
pub enum ProofDirection {
    Left,
    Right,
}

// Build a Merkle tree from a list of transaction hashes and
// return the root hash. Empty block gets a well-known empty root.
pub fn compute_merkle_root(transaction_hashes: &[String]) -> String {
    if transaction_hashes.is_empty() {
        // Empty block — hash of the string "empty" as a sentinel value
        // so an empty block root is distinguishable from a real hash
        return sha3_256_hex(b"kyvera-empty-block");
    }

    if transaction_hashes.len() == 1 {
        return transaction_hashes[0].clone();
    }

    // Build the bottom layer — leaves are the transaction hashes
    let mut current_layer: Vec<String> = transaction_hashes.to_vec();

    // Work up the tree layer by layer until we reach the root
    while current_layer.len() > 1 {
        current_layer = build_next_layer(&current_layer);
    }

    current_layer.remove(0)
}

// Build one layer of the Merkle tree from the layer below it.
// If a layer has an odd number of nodes, the last node is
// duplicated — standard Merkle tree convention.
fn build_next_layer(layer: &[String]) -> Vec<String> {
    let mut next_layer = Vec::new();
    let mut i = 0;

    while i < layer.len() {
        let left = &layer[i];
        // If there is no right sibling, duplicate the left node
        let right = if i + 1 < layer.len() {
            &layer[i + 1]
        } else {
            &layer[i]
        };

        next_layer.push(hash_pair(left, right));
        i += 2;
    }

    next_layer
}

// Hash two child nodes together to produce their parent.
// We always sort the inputs so hash(A,B) == hash(B,A) is NOT true —
// position matters. Left child always comes before right child.
// This is intentional — it means the proof direction matters.
fn hash_pair(left: &str, right: &str) -> String {
    let combined = format!("{}{}", left, right);
    sha3_256_hex(combined.as_bytes())
}

// Generate a Merkle proof for a specific transaction in a block.
// Returns None if the transaction is not in the list.
// The proof contains just enough sibling hashes that a verifier
// can reconstruct the Merkle root independently.
pub fn generate_proof(
    transaction_hashes: &[String],
    target_hash: &str,
) -> Option<MerkleProof> {
    if transaction_hashes.is_empty() {
        return None;
    }

    // Find the target in the leaves
    let target_index = transaction_hashes
        .iter()
        .position(|h| h == target_hash)?;

    let root = compute_merkle_root(transaction_hashes);
    let mut siblings = Vec::new();
    let mut current_layer: Vec<String> = transaction_hashes.to_vec();
    let mut current_index = target_index;

    // Walk up the tree collecting siblings at each level
    while current_layer.len() > 1 {
        let sibling_index;
        let direction;

        if current_index % 2 == 0 {
            // Current node is a left child — sibling is to the right
            sibling_index = if current_index + 1 < current_layer.len() {
                current_index + 1
            } else {
                current_index // Duplicated node case
            };
            direction = ProofDirection::Right;
        } else {
            // Current node is a right child — sibling is to the left
            sibling_index = current_index - 1;
            direction = ProofDirection::Left;
        }

        siblings.push((current_layer[sibling_index].clone(), direction));
        current_layer = build_next_layer(&current_layer);
        current_index /= 2;
    }

    Some(MerkleProof {
        leaf_hash: target_hash.to_string(),
        siblings,
        root,
    })
}

// Verify a Merkle proof against a known root.
// Returns true only if the proof correctly reconstructs the root.
// This is what light clients call — they get the proof from a full
// node and verify it locally without trusting the full node.
pub fn verify_proof(proof: &MerkleProof) -> bool {
    let mut current_hash = proof.leaf_hash.clone();

    for (sibling, direction) in &proof.siblings {
        current_hash = match direction {
            ProofDirection::Right => hash_pair(&current_hash, sibling),
            ProofDirection::Left  => hash_pair(sibling, &current_hash),
        };
    }

    current_hash == proof.root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::hash::sha3_256_hex;

    fn make_hashes(n: usize) -> Vec<String> {
        (0..n)
            .map(|i| sha3_256_hex(format!("transaction_{}", i).as_bytes()))
            .collect()
    }

    #[test]
    fn test_empty_block_has_known_root() {
        let root = compute_merkle_root(&[]);
        // Empty block root should be deterministic
        assert_eq!(root, sha3_256_hex(b"kyvera-empty-block"));
    }

    #[test]
    fn test_single_transaction_root_is_tx_hash() {
        let hashes = make_hashes(1);
        let root = compute_merkle_root(&hashes);
        // Single transaction — root is just that transaction's hash
        assert_eq!(root, hashes[0]);
    }

    #[test]
    fn test_two_transactions() {
        let hashes = make_hashes(2);
        let root = compute_merkle_root(&hashes);
        // Root should be hash of the two transaction hashes combined
        let expected = hash_pair(&hashes[0], &hashes[1]);
        assert_eq!(root, expected);
        assert_eq!(root.len(), 64);
    }

    #[test]
    fn test_merkle_root_is_deterministic() {
        let hashes = make_hashes(8);
        let root1 = compute_merkle_root(&hashes);
        let root2 = compute_merkle_root(&hashes);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_changing_one_transaction_changes_root() {
        let mut hashes = make_hashes(4);
        let root1 = compute_merkle_root(&hashes);

        // Tamper with one transaction
        hashes[2] = sha3_256_hex(b"tampered transaction");
        let root2 = compute_merkle_root(&hashes);

        // Root must change when any transaction changes
        assert_ne!(root1, root2);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let hashes = make_hashes(8);
        let target = &hashes[3];

        let proof = generate_proof(&hashes, target).unwrap();

        // Proof should verify correctly against the real root
        assert!(verify_proof(&proof));
        assert_eq!(proof.root, compute_merkle_root(&hashes));
    }

    #[test]
    fn test_proof_for_every_transaction_in_block() {
        let hashes = make_hashes(7);

        for hash in &hashes {
            let proof = generate_proof(&hashes, hash).unwrap();
            assert!(verify_proof(&proof),
                "Proof failed for transaction {}", hash);
        }
    }

    #[test]
    fn test_tampered_proof_fails_verification() {
        let hashes = make_hashes(4);
        let mut proof = generate_proof(&hashes, &hashes[0]).unwrap();

        // Tamper with the leaf hash
        proof.leaf_hash = sha3_256_hex(b"fake transaction");

        assert!(!verify_proof(&proof));
    }

    #[test]
    fn test_proof_for_nonexistent_transaction_returns_none() {
        let hashes = make_hashes(4);
        let fake_hash = sha3_256_hex(b"not in this block");

        let proof = generate_proof(&hashes, &fake_hash);
        assert!(proof.is_none());
    }

    #[test]
    fn test_odd_number_of_transactions() {
        // Odd number triggers the node duplication path
        let hashes = make_hashes(5);
        let root = compute_merkle_root(&hashes);
        assert_eq!(root.len(), 64);

        // Every transaction should still have a valid proof
        for hash in &hashes {
            let proof = generate_proof(&hashes, hash).unwrap();
            assert!(verify_proof(&proof));
        }
    }

    #[test]
    fn test_large_block() {
        // 128 transactions — realistic block size
        let hashes = make_hashes(128);
        let root = compute_merkle_root(&hashes);
        assert_eq!(root.len(), 64);

        // Spot check a few proofs
        for i in [0, 1, 63, 64, 127] {
            let proof = generate_proof(&hashes, &hashes[i]).unwrap();
            assert!(verify_proof(&proof),
                "Proof failed for transaction at index {}", i);
        }
    }
}