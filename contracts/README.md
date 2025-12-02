# ZK Mixer Project

- Deposit: Users can deposit ETH into the mixer to break the connection between depositor and withdrawer
- Withdraw: Users will withdraw using a ZK Proof (Noir - generated off-chain) of knowledge of their deposit
- We will only allow users to deposit a fixed amount of ETH (0.001ETH)

## Proof
- Calculate the commitment using the secret and nullifier
- We need to check that the commitment is present in the Merkle tree
  - Proposed root
  - Merkle root
- Check the nullifier matches the (public) nullifier hash

### Private inputs
- Secret 
- Nullifier
- Merkle proof (intermediate nodes required to reconstruct the tree)
- Boolean to say whether node has an even index

# Public Inputs
- Proposed Root
- Nullifier Hash