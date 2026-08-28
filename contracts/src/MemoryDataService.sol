// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

import {DataService} from "@graphprotocol/horizon/data-service/DataService.sol";
import {DataServiceFees} from "@graphprotocol/horizon/data-service/extensions/DataServiceFees.sol";
import {
    DataServicePausableUpgradeable
} from "@graphprotocol/horizon/data-service/extensions/DataServicePausableUpgradeable.sol";
import {IGraphPayments} from "@graphprotocol/horizon/interfaces/IGraphPayments.sol";
import {IGraphTallyCollector} from "@graphprotocol/horizon/interfaces/IGraphTallyCollector.sol";

import {IMemoryDataService} from "./interfaces/IMemoryDataService.sol";

/// @title MemoryDataService
/// @notice End-to-end encrypted, user-owned agent memory, metered per call on compass's rails.
///
/// Deliberately knows as little as possible. It registers providers, records what they claim to
/// commit to, counts operations, and routes `collect()` at the shared `GraphTallyCollector`. It
/// holds no memory, no namespaces, no keys and no user identities.
///
/// @dev The one substantive divergence from the compass template it forks: **compass keys its
///      registry on subgraph deployments; this one does NOT key on memory namespaces.** A public
///      registry of namespaces would leak who keeps memory, with whom, how much, and since when —
///      permanently, attached to an address. Namespaces never touch the chain. docs/design.md §
///      "What does NOT go on chain".
contract MemoryDataService is
    OwnableUpgradeable,
    UUPSUpgradeable,
    DataService,
    DataServiceFees,
    DataServicePausableUpgradeable,
    IMemoryDataService
{
    /// @notice Minimum GRT a provider must provision. Lower than a query-serving service: holding
    ///         encrypted blobs is cheaper to run and the collateral should reflect that.
    uint256 public constant MIN_PROVISION = 1_000e18;

    uint64 public constant MIN_THAWING_PERIOD = 14 days;

    /// @notice Burned on collection, PPM.
    uint256 public constant BURN_CUT_PPM = 10_000; // 1%
    /// @notice Retained by the data service, PPM.
    uint256 public constant DATA_SERVICE_CUT_PPM = 10_000; // 1%

    /// @notice Stake locked per unit of fees collected, released after the dispute window.
    uint256 public constant STAKE_TO_FEES_RATIO = 5;

    mapping(address => bool) public registeredProviders;
    mapping(address => address) public paymentsDestination;
    mapping(address => Commitment) internal _commitments;
    mapping(address => Usage) internal _usage;

    IGraphTallyCollector private immutable GRAPH_TALLY_COLLECTOR;

    uint64 public minThawingPeriod;

    uint256[50] private __gap;

    constructor(address controller, address graphTallyCollector) DataService(controller) {
        GRAPH_TALLY_COLLECTOR = IGraphTallyCollector(graphTallyCollector);
        _disableInitializers();
    }

    function initialize(address owner_, address pauseGuardian) external initializer {
        __Ownable_init(owner_);
        __DataService_init();
        __DataServicePausable_init();

        minThawingPeriod = MIN_THAWING_PERIOD;
        _setProvisionTokensRange(MIN_PROVISION, type(uint256).max);
        _setThawingPeriodRange(MIN_THAWING_PERIOD, type(uint64).max);
        _setVerifierCutRange(0, uint32(1_000_000));
        _setPauseGuardian(pauseGuardian, true);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    // ── Governance ───────────────────────────────────────────────────────────

    function setMinThawingPeriod(uint64 period) external onlyOwner {
        if (period < MIN_THAWING_PERIOD) revert ThawingPeriodTooShort(MIN_THAWING_PERIOD, period);
        minThawingPeriod = period;
    }

    function setPauseGuardian(address guardian, bool allowed) external onlyOwner {
        _setPauseGuardian(guardian, allowed);
    }

    function withdrawFees(address to, uint256 amount) external onlyOwner {
        require(to != address(0), "zero address");
        _graphToken().transfer(to, amount);
        emit FeesWithdrawn(to, amount);
    }

    // ── Provider lifecycle ───────────────────────────────────────────────────

    /// @param data ABI-encoded (string endpoint, uint64 maxItems, bool supportsBlindIndex,
    ///        address paymentsDestination).
    function register(address serviceProvider, bytes calldata data) external override whenNotPaused {
        _requireAuthorizedForProvision(serviceProvider);
        if (registeredProviders[serviceProvider]) revert ProviderAlreadyRegistered(serviceProvider);

        (string memory endpoint, uint64 maxItems, bool blindIndex, address dest) =
            abi.decode(data, (string, uint64, bool, address));
        if (bytes(endpoint).length == 0) revert EmptyEndpoint();

        _checkProvisionTokens(serviceProvider);

        registeredProviders[serviceProvider] = true;
        paymentsDestination[serviceProvider] = dest == address(0) ? serviceProvider : dest;
        _commitments[serviceProvider] =
            Commitment({endpoint: endpoint, maxItems: maxItems, supportsBlindIndex: blindIndex, active: true});

        emit ProviderRegistered(serviceProvider, endpoint, maxItems, blindIndex);
    }

    /// @dev `IDataService` declares `register` but not `deregister`; this is ours.
    function deregister(address serviceProvider, bytes calldata) external {
        _requireAuthorizedForProvision(serviceProvider);
        if (!registeredProviders[serviceProvider]) revert ProviderNotRegistered(serviceProvider);
        registeredProviders[serviceProvider] = false;
        _commitments[serviceProvider].active = false;
        emit ProviderDeregistered(serviceProvider);
    }

    /// @param data ABI-encoded (string endpoint, uint64 maxItems, bool supportsBlindIndex).
    function updateCommitment(address serviceProvider, bytes calldata data) external whenNotPaused {
        _requireAuthorizedForProvision(serviceProvider);
        if (!registeredProviders[serviceProvider]) revert ProviderNotRegistered(serviceProvider);

        (string memory endpoint, uint64 maxItems, bool blindIndex) = abi.decode(data, (string, uint64, bool));
        if (bytes(endpoint).length == 0) revert EmptyEndpoint();

        Commitment storage c = _commitments[serviceProvider];
        c.endpoint = endpoint;
        c.maxItems = maxItems;
        c.supportsBlindIndex = blindIndex;
        emit CommitmentUpdated(serviceProvider, endpoint, maxItems, blindIndex);
    }

    function setPaymentsDestination(address destination) external {
        if (!registeredProviders[msg.sender]) revert ProviderNotRegistered(msg.sender);
        address dest = destination == address(0) ? msg.sender : destination;
        paymentsDestination[msg.sender] = dest;
        emit PaymentsDestinationSet(msg.sender, dest);
    }

    /// @notice Declare that this provider is serving.
    /// @dev There is no per-resource start/stop here the way there is for a subgraph or a chain —
    ///      a memory provider is either serving or it is not. These toggle `commitment.active`,
    ///      which gives a provider a way to say **"I have stopped"** without tearing down its
    ///      registration and provision. That signal is worth having: a registry whose only states
    ///      are "registered" and "gone" cannot distinguish a provider taking a maintenance window
    ///      from one that quietly stopped answering months ago, and consumers end up discovering
    ///      the difference themselves.
    function startService(address serviceProvider, bytes calldata) external override whenNotPaused {
        _requireAuthorizedForProvision(serviceProvider);
        if (!registeredProviders[serviceProvider]) revert ProviderNotRegistered(serviceProvider);
        _commitments[serviceProvider].active = true;
        emit ServingStateChanged(serviceProvider, true);
    }

    /// @notice Declare that this provider has stopped serving, without deregistering.
    function stopService(address serviceProvider, bytes calldata) external override {
        _requireAuthorizedForProvision(serviceProvider);
        if (!registeredProviders[serviceProvider]) revert ProviderNotRegistered(serviceProvider);
        _commitments[serviceProvider].active = false;
        emit ServingStateChanged(serviceProvider, false);
    }

    // ── Collection ───────────────────────────────────────────────────────────

    /// @notice Collect query fees and record cumulative per-operation usage.
    /// @param data ABI-encoded (SignedRAV, uint256 tokensToCollect, Usage cumulative).
    /// @dev The counters are **self-reported and unprovable**. They are recorded anyway so that a
    ///      provider's forget-to-write ratio is a public number somebody can ask about, which is
    ///      the only observable a user has that deletion happens at all. Monotonicity is enforced:
    ///      a provider may exaggerate, but may not quietly rewrite history downwards.
    function collect(address serviceProvider, IGraphPayments.PaymentTypes paymentType, bytes calldata data)
        external
        override
        whenNotPaused
        returns (uint256 fees)
    {
        if (paymentType != IGraphPayments.PaymentTypes.QueryFee) revert InvalidPaymentType();
        if (!registeredProviders[serviceProvider]) revert ProviderNotRegistered(serviceProvider);

        (IGraphTallyCollector.SignedRAV memory signedRav, uint256 tokensToCollect, Usage memory reported) =
            abi.decode(data, (IGraphTallyCollector.SignedRAV, uint256, Usage));

        if (signedRav.rav.serviceProvider != serviceProvider) {
            revert InvalidServiceProvider(serviceProvider, signedRav.rav.serviceProvider);
        }

        Usage storage prev = _usage[serviceProvider];
        if (
            reported.writes < prev.writes || reported.reads < prev.reads || reported.searches < prev.searches
                || reported.forgets < prev.forgets
        ) revert UsageWentBackwards();
        _usage[serviceProvider] = reported;

        _releaseStake(serviceProvider, 0);

        uint256 balanceBefore = _graphToken().balanceOf(address(this));
        fees = GRAPH_TALLY_COLLECTOR.collect(
            paymentType,
            abi.encode(signedRav, BURN_CUT_PPM + DATA_SERVICE_CUT_PPM, paymentsDestination[serviceProvider]),
            tokensToCollect
        );

        uint256 received = _graphToken().balanceOf(address(this)) - balanceBefore;
        if (received > 0) {
            uint256 burned = (received * BURN_CUT_PPM) / (BURN_CUT_PPM + DATA_SERVICE_CUT_PPM);
            _graphToken().burn(burned);
            emit FeesBurned(serviceProvider, burned);
        }

        if (fees > 0) {
            _lockStake(serviceProvider, fees * STAKE_TO_FEES_RATIO, block.timestamp + minThawingPeriod);
        }

        emit MemoryFeesCollected(serviceProvider, fees, reported);
    }

    /// @notice Not implemented. There is no way to prove a provider stored what it said, or
    ///         deleted what it billed for deleting — it holds ciphertext and we hold nothing.
    ///         Stubbing this to succeed would imply a guarantee that does not exist.
    function slash(address, bytes calldata) external pure override {
        revert("slashing not supported");
    }

    function acceptProvisionPendingParameters(address serviceProvider, bytes calldata) external override {
        _requireAuthorizedForProvision(serviceProvider);
        _acceptProvisionParameters(serviceProvider);
    }

    // ── Views ────────────────────────────────────────────────────────────────

    function isRegistered(address provider) external view override returns (bool) {
        return registeredProviders[provider];
    }

    function commitmentOf(address provider) external view override returns (Commitment memory) {
        return _commitments[provider];
    }

    function usageOf(address provider) external view override returns (Usage memory) {
        return _usage[provider];
    }
}
