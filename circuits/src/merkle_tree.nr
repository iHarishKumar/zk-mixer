use dep::poseidon::poseidon2::Poseidon2;

pub fn compute_merkle_root(leaf: Field, merkle_tree: [Field; 20], is_even: [bool; 20]) -> Field {
    // Temporary variable to store the hash for the current level we are working on
    let mut hash: Field = leaf;

    // increment through the levels
    for i in 0..20 {
        let (left, right) = if is_even[i] {
            (hash, merkle_tree[i])
        } else {
            (merkle_tree[i], hash)
        };
        hash = Poseidon2::hash([left, right], 2);
    }

    // return root of the Merkle tree
    hash
}
