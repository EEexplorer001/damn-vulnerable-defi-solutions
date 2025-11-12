// SPDX-License-Identifier: MIT
// Damn Vulnerable DeFi v4 (https://damnvulnerabledefi.xyz)
pragma solidity =0.8.25;

import {FixedPointMathLib} from "solady/utils/FixedPointMathLib.sol";
import {SafeTransferLib} from "solady/utils/SafeTransferLib.sol";
import {IERC20} from "@openzeppelin/contracts/interfaces/IERC20.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {BitMaps} from "@openzeppelin/contracts/utils/structs/BitMaps.sol";

// My Note: This is a typical reward distribution contract using Merkle trees to verify claims.
// For each token, it maps to a Distribution struct that holds the remaining amount to distribute,
// the next batch number, the Merkle roots for each batch, and a bitmap to track claimed rewards.
//
// Distribution: What is batch number? It is a way to group distributions. Each batch has its OWN Merkle root. 
// Each Merkle root corresponds to a set of different users and their respective reward amounts. You can think of
// batch number as different rounds of distributions. Each round has its own set of users and amounts to claim.
// What is the bitmap for claims? Look at the mapping(address claimer => mapping(uint256 word => uint256 bits)) claims;
// This is the layout of a bitmap:
//              word 0   word 1   word 2    ...
// claimer 1    uint256  uint256  uint256
//         2    uint256  uint256  uint256
//      ...     ...      ...      ...
//
// Each uint256 word can track 256 claims (1 bit per claim). If a user has claimed their reward for a specific batch,
// we first calculate wordPosition = batchNumber / 256 and bitPosition = batchNumber % 256.
// Then we check if the bit at bitPosition in the uint256 at wordPosition is set (1) or not (0).
// If it's set, the user has already claimed their reward for that batch. If not, they can claim it, and we set that bit to 1 to mark it as claimed.
// This is a gas-efficient way to track multiple claims without needing a separate boolean for each claim.
// 
// So for these claimers, we can track their claims for as many as 2^256 batches!
// In this case, claimers are the addresses that are eligible to claim rewards.

struct Distribution {
    uint256 remaining;
    uint256 nextBatchNumber;
    mapping(uint256 batchNumber => bytes32 root) roots;
    mapping(address claimer => mapping(uint256 word => uint256 bits)) claims;
}

struct Claim {
    uint256 batchNumber;
    uint256 amount;
    uint256 tokenIndex;
    bytes32[] proof;
}

/**
 * An efficient token distributor contract based on Merkle proofs and bitmaps
 */
contract TheRewarderDistributor {
    using BitMaps for BitMaps.BitMap;

    address public immutable owner = msg.sender;

    mapping(IERC20 token => Distribution) public distributions;

    error StillDistributing();
    error InvalidRoot();
    error AlreadyClaimed();
    error InvalidProof();
    error NotEnoughTokensToDistribute();

    event NewDistribution(IERC20 token, uint256 batchNumber, bytes32 newMerkleRoot, uint256 totalAmount);

    function getRemaining(address token) external view returns (uint256) {
        return distributions[IERC20(token)].remaining;
    }

    function getNextBatchNumber(address token) external view returns (uint256) {
        return distributions[IERC20(token)].nextBatchNumber;
    }

    function getRoot(address token, uint256 batchNumber) external view returns (bytes32) {
        return distributions[IERC20(token)].roots[batchNumber];
    }

    function createDistribution(IERC20 token, bytes32 newRoot, uint256 amount) external {
        if (amount == 0) revert NotEnoughTokensToDistribute();
        if (newRoot == bytes32(0)) revert InvalidRoot();
        if (distributions[token].remaining != 0) revert StillDistributing();

        distributions[token].remaining = amount;

        uint256 batchNumber = distributions[token].nextBatchNumber;
        distributions[token].roots[batchNumber] = newRoot;
        distributions[token].nextBatchNumber++;

        SafeTransferLib.safeTransferFrom(address(token), msg.sender, address(this), amount);

        emit NewDistribution(token, batchNumber, newRoot, amount);
    }

    function clean(IERC20[] calldata tokens) external {
        for (uint256 i = 0; i < tokens.length; i++) {
            IERC20 token = tokens[i];
            if (distributions[token].remaining == 0) {
                token.transfer(owner, token.balanceOf(address(this)));
            }
        }
    }

    // My Note: This function allows users to claim their rewards for multiple tokens in a single transaction.
    // We can see that the function uses _setClaimed to update the claim status in the bitmap.
    // So the function updates the claim status in the bitmap only for these two cases:
    // 1. When the token changes (i.e., we are processing a claim for a different token than the previous one).
    // 2. When we reach the last claim in the inputClaims array.
    // But here is a pitfall in the code: In the else branch, amount is accumulative for the same token, and
    // there is no call to _setClaimed. This means that if a user submits multiple claims for the same token,
    // they can get away with only the last claim being marked as claimed in the bitmap (with wrong accumulative amount).
    // And since the Merkle proof verification is done for each individual claim, each claim could potentially succeed.
    //
    // Allow claiming rewards of multiple tokens in a single transaction
    function claimRewards(Claim[] memory inputClaims, IERC20[] memory inputTokens) external {
        Claim memory inputClaim;
        IERC20 token;
        uint256 bitsSet; // accumulator
        uint256 amount;

        for (uint256 i = 0; i < inputClaims.length; i++) {
            inputClaim = inputClaims[i];

            uint256 wordPosition = inputClaim.batchNumber / 256;
            uint256 bitPosition = inputClaim.batchNumber % 256;

            if (token != inputTokens[inputClaim.tokenIndex]) {
                if (address(token) != address(0)) {
                    if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
                }

                token = inputTokens[inputClaim.tokenIndex];
                bitsSet = 1 << bitPosition; // set bit at given position
                amount = inputClaim.amount;
            } else {
                bitsSet = bitsSet | 1 << bitPosition;
                amount += inputClaim.amount;
                // @audit Missing _setClaimed call here for the same token
            }

            // for the last claim
            if (i == inputClaims.length - 1) {
                if (!_setClaimed(token, amount, wordPosition, bitsSet)) revert AlreadyClaimed();
            }

            bytes32 leaf = keccak256(abi.encodePacked(msg.sender, inputClaim.amount));
            bytes32 root = distributions[token].roots[inputClaim.batchNumber];

            if (!MerkleProof.verify(inputClaim.proof, root, leaf)) revert InvalidProof();

            inputTokens[inputClaim.tokenIndex].transfer(msg.sender, inputClaim.amount);
        }
    }

    function _setClaimed(IERC20 token, uint256 amount, uint256 wordPosition, uint256 newBits) private returns (bool) {
        uint256 currentWord = distributions[token].claims[msg.sender][wordPosition];
        if ((currentWord & newBits) != 0) return false;

        // update state
        distributions[token].claims[msg.sender][wordPosition] = currentWord | newBits;
        distributions[token].remaining -= amount;

        return true;
    }
}
