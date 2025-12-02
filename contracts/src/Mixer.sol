// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

/**
 * @title Mixer (Educational Adaptation of Tornado Cash)
 * @notice This smart contract is a simplified and modified version of the Tornado Cash protocol,
 *         developed purely for educational purposes as part of a blockchain development course.
 * @dev The original design and cryptographic structure are inspired by Tornado Cash:
 *      https://github.com/tornadocash/tornado-core
 *
 * @author Harish Kumar Gunjalli
 * @notice Do not deploy this contract to mainnet or use it for handling real funds.
 *         This contract is unaudited and intended for demonstration only.
 */

import {IVerifier} from "./Verifier.sol";
import {IncrementalMerkleTree} from "./IncrementalMerkleTree.sol";
import {Poseidon2} from "@poseidon/src/Poseidon2.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract Mixer is IncrementalMerkleTree, ReentrancyGuard {
    IVerifier public immutable i_verifier;

    mapping(bytes32 => bool) public s_commitments;
    mapping(bytes32 => bool) public s_nullifierHashes;
    uint256 public constant DENOMINATION = 0.001 ether;

    // Errors
    error Mixer_CommitmentAlreadyAdded(bytes32 commitment);
    error Mixer_DepositAmountNotCorrect(
        uint256 amountSent,
        uint256 expectedAmount
    );
    error Mixer_NullifierAlreadyUsed(bytes32 nullifierHash);
    error Mixer_InvalidProof();
    error Mixer_UnknowRoot();
    error Mixer_PaymentFailed(uint256 amount);

    event Deposit(bytes32 indexed commitment, uint32 index, uint256 timestamp);
    event Withdrawal(
        address indexed recipient,
        bytes32 nullifierHash,
        uint256 timestamp
    );

    constructor(
        IVerifier _verifier,
        Poseidon2 _hasher,
        uint32 _merkleTreeDepth
    ) IncrementalMerkleTree(_merkleTreeDepth, _hasher) ReentrancyGuard() {
        i_verifier = _verifier;
    }

    // @notice Deposit funds into the mixer
    // @param _commitment The pseiden commitment of the nullifier and secret (generated off-chain)
    function deposit(bytes32 _commitment) external payable nonReentrant {
        // Check whether the commit has already been used so we can prevent a deposit being added twice
        if (s_commitments[_commitment]) {
            revert Mixer_CommitmentAlreadyAdded(_commitment);
        }
        // allow the user to send ETH and make sure it is of the correct fixed amount (denomination)
        if (msg.value != DENOMINATION) {
            revert Mixer_DepositAmountNotCorrect(msg.value, DENOMINATION);
        }
        // Add the commitment to the on-chain incremental Merkel tree containing all the commitments
        uint32 insertedIndex = _insert(_commitment);
        s_commitments[_commitment] = true;

        emit Deposit(_commitment, insertedIndex, block.timestamp);
    }

    // @notice Withdraw funds from the mixer in a private manner
    // @param _proof The zk proof of knowledge of the deposit (they know a valid commitment, SNARK Proof)
    // @param _nullifierHash The poseidon commitment of the nullifier (generated off-chain)
    function withdraw(
        bytes memory _proof,
        bytes32 _root,
        bytes32 _nullifierHash,
        address payable _recipient
    ) external nonReentrant {
        // Check that the root that was used in the proof matches the on-chain proof
        if (!isKnownRoot(_root)) {
            revert Mixer_UnknowRoot();
        }
        // Check that the nullifier has not been used to prevent double spending
        if (s_nullifierHashes[_nullifierHash]) {
            revert Mixer_NullifierAlreadyUsed(_nullifierHash);
        }
        s_nullifierHashes[_nullifierHash] = true;
        // Check that the proof is valid by calling the verifier contract
        bytes32[] memory publicInputs = new bytes32[](3);
        publicInputs[0] = _root;
        publicInputs[1] = _nullifierHash;
        publicInputs[2] = bytes32(uint256(uint160(address(_recipient))));
        if (!i_verifier.verify(_proof, publicInputs)) {
            revert Mixer_InvalidProof();
        }
        // Send the funds
        (bool success, ) = _recipient.call{value: DENOMINATION}("");
        if (!success) {
            revert Mixer_PaymentFailed(DENOMINATION);
        }

        emit Withdrawal(_recipient, _nullifierHash, block.timestamp);
    }
}
