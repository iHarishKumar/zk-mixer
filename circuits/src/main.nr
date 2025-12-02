use dep::poseidon::poseidon2::Poseidon2;
mod merkle_tree;

fn main(
    // Public Inputs
    root: pub Field,
    nullifier_hash: pub Field,
    recipient: pub Field, // Added to prevent front-running

    // Private Inputs
    nullifier: Field,
    secret: Field,
    merkle_proof: [Field; 20],
    is_even: [bool; 20],
) {
    // compute the commitment poseidon(nullifier, secret)
    let commitment = Poseidon2::hash([nullifier, secret], 2);

    // check that the nullifier matches the nullifier hash
    let computed_nullifier_hash = Poseidon2::hash([nullifier], 1);

    assert(computed_nullifier_hash == nullifier_hash);

    // Check that the commitment is in the Merkle tree
    let computed_root = merkle_tree::compute_merkle_root(commitment, merkle_proof, is_even);

    assert(computed_root == root);

    // let recipient_binding = recipient * recipient;

    // assert(recipient_binding == recipient* recipient);
}
