import { Barretenberg, Fr } from "@aztec/bb.js";
import { ethers } from "ethers";

export default async function generateCommitment(): Promise<string> {
  // Initialize the Barretenberg WASM
  const bb = await Barretenberg.new();

  // Generate random nullifier and secret as field elements
  const nullifier = Fr.random();
  const secret = Fr.random();

  // Create the commitment by hasing the nullifier and secret using Poseidon2
  const commitment = await bb.poseidon2Hash([nullifier, secret]);

  // ABI encode the commitment(which is an Field type) into a bytes32 hex string
  // The commitment (an Field object) is converted to a Buffer
  // This buffer is then ABI-encoded as a bytes32 string, expected by Solidity
  const result = ethers.AbiCoder.defaultAbiCoder().encode(["bytes32", "bytes32", "bytes32"], [commitment.toBuffer(), nullifier.toBuffer(), secret.toBuffer()]);

  return result; // Return the ABI encoded commitment as a hex string
}

// IIFE (Immediately Invoked Function Expression) to run the script
(async () => {
  generateCommitment()
    .then((result) => {
      // Write the ABI-encoded result to standard output for FFI
      // Foundry's FFI captures this stdout as the result in the Solidity test.
      process.stdout.write(result);
      process.exit(0); // Exit with success code
    })
    .catch((error) => {
      console.error("Error generating commitment:", error); // Log any errors to standard error
      process.exit(1); // Exit with failure code
    });
})();