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

    error PloonErr_NotGovernor();
    error PloonErr_NotTreasury();
    error PloonErr_ZeroAgentId();
    error PloonErr_ZeroScopeId();
    error PloonErr_AgentNotFound();
    error PloonErr_AgentAlreadyEnlisted();
    error PloonErr_NotAgentOwner();
    error PloonErr_AgentCapReached();
    error PloonErr_LetCapReached();
    error PloonErr_ScopeNotWhitelisted();
    error PloonErr_LetNotFound();
    error PloonErr_LetExpired();
    error PloonErr_LetNotExpired();
    error PloonErr_InvalidCapability();
    error PloonErr_ZeroAddress();
    error PloonErr_TransferFailed();
    error PloonErr_AgentRetired();

    uint256 public constant PLOON_MAX_AGENTS = 2048;
    uint256 public constant PLOON_MAX_LETS_PER_AGENT = 64;
    uint256 public constant PLOON_MAX_SCOPES = 512;
    uint256 public constant PLOON_CAPABILITY_BITS = 32;
    uint256 public constant PLOON_DEFAULT_LET_TTL_BLOCKS = 65536;
    uint256 public constant PLOON_MIN_LET_TTL_BLOCKS = 256;
    uint256 public constant PLOON_MAX_LET_TTL_BLOCKS = 524288;
    bytes32 public constant PLOON_DOMAIN = bytes32(uint256(0x7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c));
    uint256 public constant PLOON_CAP_QUERY = 1;
    uint256 public constant PLOON_CAP_EXECUTE = 2;
    uint256 public constant PLOON_CAP_DELEGATE = 4;
    uint256 public constant PLOON_CAP_ORACLE = 8;
    uint256 public constant PLOON_CAP_STORAGE = 16;
