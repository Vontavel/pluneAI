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
    uint256 public constant PLOON_CAP_ALL = 31;
    uint256 public constant PLOON_VERSION = 1;
    uint256 public constant PLOON_CONFIG_HASH_BYTES = 32;
    uint256 public constant PLOON_SCOPE_ID_BYTES = 32;
    uint256 public constant PLOON_BPS_DENOM = 10000;
    uint256 public constant PLOON_TREASURY_FEE_BPS = 0;
    uint256 public constant PLOON_ENLIST_FEE_WEI = 0;
    uint256 public constant PLOON_LET_FEE_WEI = 0;

    address public immutable ploonGovernor;
    address public immutable ploonTreasury;
    uint256 public immutable genesisBlock;
    bytes32 public immutable ploonSeed;

    uint256 public agentCount;
    uint256 public totalLetsGranted;
    uint256 public totalLetsRevoked;
    uint256 public treasuryBalance;
    uint256 public scopeWhitelistCount;

    struct AgentRecord {
        bytes32 agentId;
        address owner;
        uint256 capabilityBits;
        bytes32 configHash;
        uint256 enlistedAtBlock;
        bool retired;
    }
    struct LetRecord {
        bytes32 agentId;
        bytes32 scopeId;
        address grantedBy;
        uint256 grantedAtBlock;
        uint256 expiresAtBlock;
        bool revoked;
    }

    mapping(bytes32 => AgentRecord) private _agents;
    mapping(bytes32 => bytes32[]) private _letIdsByAgent;
    mapping(bytes32 => LetRecord) private _lets;
    mapping(bytes32 => bool) private _scopeWhitelist;
    mapping(address => bytes32[]) private _agentIdsByOwner;
    bytes32[] private _agentIdList;
    bytes32[] private _scopeIdList;
    uint256 private _letNonce;

    modifier onlyGovernor() {
        if (msg.sender != ploonGovernor) revert PloonErr_NotGovernor();
        _;
    }

    modifier onlyTreasury() {
        if (msg.sender != ploonTreasury) revert PloonErr_NotTreasury();
        _;
    }

    constructor() {
        ploonGovernor = address(0xa3E7f2b9C1d4e6A0c8B5f9D2e7a4F1b6C3d8E0);
        ploonTreasury = address(0x5F8c2e1B9d7A4f0C6e3D9b2a5F8c1E4d7B0a3);
        genesisBlock = block.number;
        ploonSeed = keccak256(abi.encodePacked(block.timestamp, block.prevrandao, block.chainid, "ploon_ai"));
        agentCount = 0;
        totalLetsGranted = 0;
        totalLetsRevoked = 0;
        treasuryBalance = 0;
        scopeWhitelistCount = 0;
        _letNonce = 0;
        _seedScopes();
    }

    function _seedScopes() private {
        bytes32[] memory scopes = new bytes32[](8);
        scopes[0] = keccak256("scope.default");
        scopes[1] = keccak256("scope.query");
        scopes[2] = keccak256("scope.execute");
        scopes[3] = keccak256("scope.oracle");
        scopes[4] = keccak256("scope.storage");
        scopes[5] = keccak256("scope.delegate");
        scopes[6] = keccak256("scope.mainnet");
        scopes[7] = keccak256("scope.testnet");
        for (uint256 i = 0; i < scopes.length && scopeWhitelistCount < PLOON_MAX_SCOPES; i++) {
            if (!_scopeWhitelist[scopes[i]]) {
                _scopeWhitelist[scopes[i]] = true;
                _scopeIdList.push(scopes[i]);
                scopeWhitelistCount++;
            }
        }
    }

    function enlistAgent(bytes32 agentId, uint256 capabilityBits, bytes32 configHash)
        external
        whenNotPaused
        nonReentrant
    {
        if (agentId == bytes32(0)) revert PloonErr_ZeroAgentId();
        if (agentCount >= PLOON_MAX_AGENTS) revert PloonErr_AgentCapReached();
        AgentRecord storage a = _agents[agentId];
        if (a.enlistedAtBlock != 0) revert PloonErr_AgentAlreadyEnlisted();
        if (capabilityBits > PLOON_CAP_ALL) capabilityBits = capabilityBits & PLOON_CAP_ALL;
        a.agentId = agentId;
        a.owner = msg.sender;
        a.capabilityBits = capabilityBits;
        a.configHash = configHash;
        a.enlistedAtBlock = block.number;
        a.retired = false;
        _agentIdList.push(agentId);
        _agentIdsByOwner[msg.sender].push(agentId);
        agentCount++;
        emit AgentEnlisted(agentId, msg.sender, capabilityBits, configHash, block.number);
    }

    function letAgent(bytes32 agentId, bytes32 scopeId, uint256 ttlBlocks)
        external
        onlyGovernor
        whenNotPaused
        nonReentrant
    {
        if (agentId == bytes32(0)) revert PloonErr_ZeroAgentId();
        if (scopeId == bytes32(0)) revert PloonErr_ZeroScopeId();
        AgentRecord storage a = _agents[agentId];
        if (a.enlistedAtBlock == 0 || a.retired) revert PloonErr_AgentNotFound();
        if (!_scopeWhitelist[scopeId]) revert PloonErr_ScopeNotWhitelisted();
        bytes32[] storage letIds = _letIdsByAgent[agentId];
        if (letIds.length >= PLOON_MAX_LETS_PER_AGENT) revert PloonErr_LetCapReached();
        if (ttlBlocks < PLOON_MIN_LET_TTL_BLOCKS) ttlBlocks = PLOON_MIN_LET_TTL_BLOCKS;
        if (ttlBlocks > PLOON_MAX_LET_TTL_BLOCKS) ttlBlocks = PLOON_MAX_LET_TTL_BLOCKS;
        uint256 expiresAt = block.number + ttlBlocks;
        bytes32 letId = keccak256(abi.encodePacked(agentId, scopeId, block.number, _letNonce));
        _letNonce++;
        _lets[letId] = LetRecord({
            agentId: agentId,
            scopeId: scopeId,
            grantedBy: msg.sender,
            grantedAtBlock: block.number,
            expiresAtBlock: expiresAt,
            revoked: false
        });
        letIds.push(letId);
        totalLetsGranted++;
        emit AgentLet(agentId, scopeId, msg.sender, expiresAt, block.number);
    }

    function revokeLet(bytes32 letId) external onlyGovernor whenNotPaused nonReentrant {
        LetRecord storage l = _lets[letId];
        if (l.grantedAtBlock == 0) revert PloonErr_LetNotFound();
        if (l.revoked) return;
        l.revoked = true;
        totalLetsRevoked++;
        emit AgentLetRevoked(l.agentId, l.scopeId, msg.sender, block.number);
    }

    function updateAgentConfig(bytes32 agentId, bytes32 newConfigHash) external whenNotPaused nonReentrant {
        if (agentId == bytes32(0)) revert PloonErr_ZeroAgentId();
        AgentRecord storage a = _agents[agentId];
        if (a.enlistedAtBlock == 0 || a.retired) revert PloonErr_AgentNotFound();
        if (msg.sender != a.owner) revert PloonErr_NotAgentOwner();
        bytes32 prev = a.configHash;
        a.configHash = newConfigHash;
        emit AgentConfigUpdated(agentId, prev, newConfigHash, block.number);
    }

    function retireAgent(bytes32 agentId) external whenNotPaused nonReentrant {
        if (agentId == bytes32(0)) revert PloonErr_ZeroAgentId();
        AgentRecord storage a = _agents[agentId];
        if (a.enlistedAtBlock == 0 || a.retired) revert PloonErr_AgentNotFound();
        if (msg.sender != a.owner && msg.sender != ploonGovernor) revert PloonErr_NotAgentOwner();
        a.retired = true;
        emit AgentRetired(agentId, msg.sender, block.number);
    }

    function setScopeWhitelist(bytes32 scopeId, bool allowed) external onlyGovernor whenNotPaused {
        if (scopeId == bytes32(0)) revert PloonErr_ZeroScopeId();
        bool prev = _scopeWhitelist[scopeId];
        _scopeWhitelist[scopeId] = allowed;
        if (!prev && allowed) {
            _scopeIdList.push(scopeId);
            scopeWhitelistCount++;
        }
        emit ScopeWhitelistSet(scopeId, allowed, msg.sender, block.number);
    }

    function topTreasury() external payable whenNotPaused {
        if (msg.value == 0) return;
        treasuryBalance += msg.value;
        emit TreasuryTopped(msg.value, msg.sender, treasuryBalance);
    }

    function withdrawTreasury(uint256 amount) external onlyTreasury nonReentrant {
        if (amount > treasuryBalance) amount = treasuryBalance;
        if (amount == 0) return;
        treasuryBalance -= amount;
        (bool ok,) = payable(ploonTreasury).call{value: amount}("");
        if (!ok) revert PloonErr_TransferFailed();
        emit TreasuryWithdrawn(amount, msg.sender, block.number);
    }

    function pause() external onlyGovernor {
        _pause();
    }

    function unpause() external onlyGovernor {
        _unpause();
    }

    function getAgent(bytes32 agentId)
        external
        view
        returns (address owner, uint256 capabilityBits, bytes32 configHash, uint256 enlistedAtBlock, bool retired)
    {
        AgentRecord storage a = _agents[agentId];
        if (a.enlistedAtBlock == 0) revert PloonErr_AgentNotFound();
        return (a.owner, a.capabilityBits, a.configHash, a.enlistedAtBlock, a.retired);
    }

    function getLet(bytes32 letId)
        external
        view
        returns (
            bytes32 agentId,
            bytes32 scopeId,
            address grantedBy,
            uint256 grantedAtBlock,
            uint256 expiresAtBlock,
            bool revoked
        )
    {
        LetRecord storage l = _lets[letId];
        if (l.grantedAtBlock == 0) revert PloonErr_LetNotFound();
        return (
            l.agentId,
            l.scopeId,
            l.grantedBy,
            l.grantedAtBlock,
            l.expiresAtBlock,
            l.revoked
        );
    }

    function isAgentLet(bytes32 agentId, bytes32 scopeId) external view returns (bool) {
        bytes32[] storage letIds = _letIdsByAgent[agentId];
        for (uint256 i = 0; i < letIds.length; i++) {
            LetRecord storage l = _lets[letIds[i]];
            if (l.scopeId == scopeId && !l.revoked && block.number <= l.expiresAtBlock) return true;
        }
        return false;
    }

    function getLetIdsForAgent(bytes32 agentId) external view returns (bytes32[] memory) {
        return _letIdsByAgent[agentId];
    }

    function getAgentIdsByOwner(address owner) external view returns (bytes32[] memory) {
        return _agentIdsByOwner[owner];
    }

    function getAgentCount() external view returns (uint256) {
        return agentCount;
    }

    function getAgentIdAt(uint256 index) external view returns (bytes32) {
        if (index >= _agentIdList.length) revert PloonErr_AgentNotFound();
        return _agentIdList[index];
    }

    function getScopeWhitelist(bytes32 scopeId) external view returns (bool) {
        return _scopeWhitelist[scopeId];
    }

    function getScopeCount() external view returns (uint256) {
        return _scopeIdList.length;
    }

    function getScopeIdAt(uint256 index) external view returns (bytes32) {
        if (index >= _scopeIdList.length) revert PloonErr_LetNotFound();
        return _scopeIdList[index];
    }

    function getRegistryStats()
        external
        view
        returns (
            uint256 agents,
            uint256 letsGranted,
            uint256 letsRevoked,
            uint256 scopes,
            uint256 treasuryBal
        )
    {
        return (agentCount, totalLetsGranted, totalLetsRevoked, scopeWhitelistCount, treasuryBalance);
    }

    function hasCapability(bytes32 agentId, uint256 capBit) external view returns (bool) {
        AgentRecord storage a = _agents[agentId];
        if (a.enlistedAtBlock == 0 || a.retired) return false;
        return (a.capabilityBits & capBit) != 0;
    }

    function getCapabilityName(uint256 capBit) external pure returns (string memory) {
        if (capBit == PLOON_CAP_QUERY) return "Query";
        if (capBit == PLOON_CAP_EXECUTE) return "Execute";
        if (capBit == PLOON_CAP_DELEGATE) return "Delegate";
        if (capBit == PLOON_CAP_ORACLE) return "Oracle";
        if (capBit == PLOON_CAP_STORAGE) return "Storage";
        if (capBit == PLOON_CAP_ALL) return "All";
        return "";
    }

    function getActiveLetCountForAgent(bytes32 agentId) external view returns (uint256) {
        bytes32[] storage letIds = _letIdsByAgent[agentId];
        uint256 count = 0;
        for (uint256 i = 0; i < letIds.length; i++) {
            LetRecord storage l = _lets[letIds[i]];
            if (!l.revoked && block.number <= l.expiresAtBlock) count++;
        }
        return count;
    }

    function getGenesisBlock() external view returns (uint256) {
        return genesisBlock;
    }

    function getPloonSeed() external view returns (bytes32) {
        return ploonSeed;
    }

    function validateCapabilityBits(uint256 bits) external pure returns (uint256) {
        return bits & PLOON_CAP_ALL;
    }

    function isScopeAllowed(bytes32 scopeId) external view returns (bool) {
        return _scopeWhitelist[scopeId];
    }

    function getLetDetails(bytes32 letId)
        external
        view
        returns (
            bytes32 agentId,
            bytes32 scopeId,
            bool active
        )
    {
        LetRecord storage l = _lets[letId];
        if (l.grantedAtBlock == 0) revert PloonErr_LetNotFound();
        bool active = !l.revoked && block.number <= l.expiresAtBlock;
        return (l.agentId, l.scopeId, active);
    }

    function getAgentOwner(bytes32 agentId) external view returns (address) {
        AgentRecord storage a = _agents[agentId];
        if (a.enlistedAtBlock == 0) revert PloonErr_AgentNotFound();
        return a.owner;
    }

    function getAgentConfigHash(bytes32 agentId) external view returns (bytes32) {
        AgentRecord storage a = _agents[agentId];
        if (a.enlistedAtBlock == 0) revert PloonErr_AgentNotFound();
        return a.configHash;
    }

    function isAgentRetired(bytes32 agentId) external view returns (bool) {
        return _agents[agentId].retired;
    }

    function getAgentEnlistedBlock(bytes32 agentId) external view returns (uint256) {
        AgentRecord storage a = _agents[agentId];
        if (a.enlistedAtBlock == 0) revert PloonErr_AgentNotFound();
        return a.enlistedAtBlock;
    }

    function getMaxAgents() external pure returns (uint256) {
        return PLOON_MAX_AGENTS;
    }

    function getMaxLetsPerAgent() external pure returns (uint256) {
        return PLOON_MAX_LETS_PER_AGENT;
    }

    function getDefaultLetTtlBlocks() external pure returns (uint256) {
        return PLOON_DEFAULT_LET_TTL_BLOCKS;
    }

    function getVersion() external pure returns (uint256) {
        return PLOON_VERSION;
    }

    function getGovernor() external view returns (address) {
        return ploonGovernor;
    }

    function getTreasury() external view returns (address) {
        return ploonTreasury;
    }

    function agentExists(bytes32 agentId) external view returns (bool) {
        return _agents[agentId].enlistedAtBlock != 0;
    }

    function getTotalAgentIdListLength() external view returns (uint256) {
        return _agentIdList.length;
    }

    function getScopeIdListLength() external view returns (uint256) {
        return _scopeIdList.length;
    }

    function computeLetId(bytes32 agentId, bytes32 scopeId, uint256 nonce) external view returns (bytes32) {
        return keccak256(abi.encodePacked(agentId, scopeId, block.number, nonce));
    }

    function getLetNonce() external view returns (uint256) {
        return _letNonce;
    }

    function getTreasuryBalance() external view returns (uint256) {
        return treasuryBalance;
