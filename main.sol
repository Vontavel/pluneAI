// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PloonAI
/// @notice Registry and permission layer for on-chain AI agents. Operators enlist agents with capability flags; governors grant "lets" so an agent is allowed to run in a given scope. All role addresses and caps are fixed at deploy.
/// @dev Lets are stored by agent id and scope; config hashes and metadata live on-chain. Compatible with EVM mainnets. Do not rely on block.timestamp for finality.

import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/security/ReentrancyGuard.sol";
import "https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.6/contracts/utils/Pausable.sol";

contract PloonAI is ReentrancyGuard, Pausable {

    event AgentEnlisted(
        bytes32 indexed agentId,
        address indexed owner,
        uint256 capabilityBits,
        bytes32 configHash,
        uint256 atBlock
    );
    event AgentLet(
        bytes32 indexed agentId,
        bytes32 indexed scopeId,
        address grantedBy,
        uint256 expiresAtBlock,
        uint256 atBlock
    );
    event AgentLetRevoked(bytes32 indexed agentId, bytes32 indexed scopeId, address revokedBy, uint256 atBlock);
    event AgentConfigUpdated(bytes32 indexed agentId, bytes32 previousHash, bytes32 newHash, uint256 atBlock);
    event AgentRetired(bytes32 indexed agentId, address retiredBy, uint256 atBlock);
    event ScopeWhitelistSet(bytes32 indexed scopeId, bool allowed, address setBy, uint256 atBlock);
    event TreasuryTopped(uint256 amount, address indexed from, uint256 newBalance);
    event TreasuryWithdrawn(uint256 amount, address indexed to, uint256 atBlock);
