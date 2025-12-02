// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Mixer} from "../src/Mixer.sol";
import {IncrementalMerkleTree} from "../src/IncrementalMerkleTree.sol";
import {Poseidon2} from "@poseidon/src/Poseidon2.sol";
import {HonkVerifier, IVerifier} from "../src/Verifier.sol";

import {Test, console} from "forge-std/Test.sol";
import "forge-std/console.sol";

contract MixerTest is Test {
    Mixer public mixer;
    IVerifier public verifier;
    Poseidon2 public hasher; // The Poseidon hasher used for the mixer

    address public recipient = makeAddr("recipient");

    function setUp() public {
        // 1. Deploy the verifier
        verifier = new HonkVerifier();

        // 2. Deploy the Hasher contract (Poseidon2)
        hasher = new Poseidon2();

        // 3. Deploy the Mixer contract
        // The mixer constructor arguments are:
        // - IVerifier _verifier: The verifier contract instance.
        // - IHasher _hasher: The hasher contract instance(e.g. Poseidon2)
        // - uint32 _merkleTreeDepth: The depth of the incremental merkle tree
        mixer = new Mixer(IVerifier(verifier), hasher, 20);
    }

    function _getCommitment()
        internal
        returns (bytes32 _commitment, bytes32 _nullifier, bytes32 _secret)
    {
        // This function will use Foundry's FFI to call an external script(e.g. JS).
        // The script will
        // 1. Generate two random 32-byte values (representing, for example, a nullifier and a secret).
        // 2. Hash these two values together using the Poseidon hash function.
        // 3. Return the resulting bytes32 commitment.

        // FFI Implementation(conceptual):
        string[] memory inputs = new string[](3);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "js-script/generateCommitment.ts";

        bytes memory result = vm.ffi(inputs);
        (_commitment, _nullifier, _secret) = abi.decode(
            result,
            (bytes32, bytes32, bytes32)
        );
    }

    function _getProof(
        bytes32 _nullifier,
        bytes32 _secret,
        address _recipient,
        bytes32[] memory _leaves
    ) internal returns (bytes memory _proof, bytes32[] memory _publicInputs) {
        string[] memory inputs = new string[](6 + _leaves.length);
        inputs[0] = "npx";
        inputs[1] = "tsx";
        inputs[2] = "js-script/generateProof.ts";
        inputs[3] = vm.toString(_nullifier);
        inputs[4] = vm.toString(_secret);
        inputs[5] = vm.toString(bytes32(uint256(uint160(_recipient))));
        for (uint256 i = 0; i < _leaves.length; i++) {
            inputs[6 + i] = vm.toString(_leaves[i]);
        }

        bytes memory result = vm.ffi(inputs);
        (_proof, _publicInputs) = abi.decode(result, (bytes, bytes32[]));
    }

    function testMakeDeposit() public {
        // Steps for the test:
        // 1. Create a commitment
        // 2. Make a deposit into the mixer contract
        //   mixer.deposit(_commitment); -> This will need to be payable and send ETH

        (
            bytes32 _commitment,
            bytes32 _nullifier,
            bytes32 _secret
        ) = _getCommitment();

        // Log the commitment for verification during testing
        console.log("Commitment from the TS script");
        console.logBytes32(_commitment);

        // Before calling the deposit function, set the expectation for the Deposit event that is being emitted
        vm.expectEmit(true, false, false, true);
        emit Mixer.Deposit(_commitment, 0, block.timestamp);

        // Call to send ETH to the deposit function
        mixer.deposit{value: mixer.DENOMINATION()}(_commitment);
    }

    function testMakeWithdrawal() public {
        // 1. Make a deposit to have something to withdraw
        (
            bytes32 _commitment,
            bytes32 _nullifier,
            bytes32 _secret
        ) = _getCommitment();

        vm.expectEmit(true, false, false, true);
        emit Mixer.Deposit(_commitment, 0, block.timestamp);
        mixer.deposit{value: mixer.DENOMINATION()}(_commitment);

        // 2. Prepare inputs for proof generation
        // Create a proof
        // Get the leaves of the tree (hacky way of testing). Ideally, this should be done off-chain by tracking and ordering the events and reconstructing the proof
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = _commitment; // _commitment is generated from the deposit function and captured in the Deposit event

        (bytes memory _proof, bytes32[] memory _publicInputs) = _getProof(
            _nullifier,
            _secret,
            recipient,
            leaves
        );

        assertTrue(verifier.verify(_proof, _publicInputs));

        assertEq(
            recipient.balance,
            0,
            "Recipient initial balance should be zero"
        );
        assertEq(
            address(mixer).balance,
            mixer.DENOMINATION(),
            "Mixer initial balance incorrect after deposit"
        );

        // 3. Make the withdrawal (to be implemented)
        mixer.withdraw(
            _proof,
            _publicInputs[0], // Merkle root
            _publicInputs[1], // Nullifier hash
            payable(address(uint160(uint256(_publicInputs[2])))) // Recipient
        );

        assertEq(
            recipient.balance,
            mixer.DENOMINATION(),
            "Recipient did not receive funds"
        );
        assertEq(
            address(mixer).balance,
            0,
            "Mixer balance not zero after withdrawal"
        );
    }

    function testAnotherAddressSendProof() public {
        // 1. Make a deposit (by the original user/sender)
        (
            bytes32 _commitment,
            bytes32 _nullifier,
            bytes32 _secret
        ) = _getCommitment();
        // For brevity, console logs and event emission are omitted here
        mixer.deposit{value: mixer.DENOMINATION()}(_commitment);

        // 2. Create a proof (for the original recipient)
        bytes32[] memory leaves = new bytes32[](1);
        leaves[0] = _commitment;
        // 'recipient' here is the original intended recipient (e.g., user.address)
        // for whom the proof is generated.
        (bytes memory _proof, bytes32[] memory _publicInputs) = _getProof(
            _nullifier,
            _secret,
            recipient,
            leaves
        );

        // Optional: Verify the proof is initially valid against its own public inputs
        assertTrue(verifier.verify(_proof, _publicInputs));

        // 3. Make a withdrawal - Attacker tries to use the proof for their own address
        address attacker_address = makeAddr("attacker"); // Create a new attacker address
        vm.prank(attacker_address); // Simulate the call coming from the attacker

        // Expect the withdrawal to revert
        // _publicInputs[0] is root, _publicInputs[1] is nullifierHash
        // The last argument is the recipient address for the withdrawal
        vm.expectRevert(); // General revert expectation
        mixer.withdraw(
            _proof,
            _publicInputs[0],
            _publicInputs[1],
            payable(attacker_address)
        );
    }
}
