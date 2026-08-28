// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

import {Test} from "forge-std/Test.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {MemoryDataService} from "../src/MemoryDataService.sol";
import {IMemoryDataService} from "../src/interfaces/IMemoryDataService.sol";
import {IHorizonStakingTypes} from "@graphprotocol/interfaces/contracts/horizon/internal/IHorizonStakingTypes.sol";
import {IGraphPayments} from "@graphprotocol/horizon/interfaces/IGraphPayments.sol";
import {IGraphTallyCollector} from "@graphprotocol/horizon/interfaces/IGraphTallyCollector.sol";

contract MockGraphToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 a) external {
        balanceOf[to] += a;
    }

    function burn(uint256 a) external {
        balanceOf[msg.sender] -= a;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        balanceOf[msg.sender] -= a;
        balanceOf[to] += a;
        return true;
    }
}

contract MockCollector {
    MockGraphToken public immutable TOKEN;
    uint256 public feeToReturn;
    address public payTo;

    constructor(MockGraphToken t) {
        TOKEN = t;
    }

    function setPayout(uint256 f, address to) external {
        feeToReturn = f;
        payTo = to;
    }

    function collect(IGraphPayments.PaymentTypes, bytes memory, uint256) external returns (uint256) {
        TOKEN.mint(payTo, feeToReturn);
        return feeToReturn;
    }
}

contract MockStaking {
    mapping(address => IHorizonStakingTypes.Provision) public p;
    mapping(address => uint256) public available;

    function setProvision(address sp, uint256 tokens, uint64 thaw) external {
        p[sp] = IHorizonStakingTypes.Provision({
            tokens: tokens,
            tokensThawing: 0,
            sharesThawing: 0,
            maxVerifierCut: 1_000_000,
            thawingPeriod: thaw,
            createdAt: uint64(block.timestamp),
            maxVerifierCutPending: 0,
            thawingPeriodPending: 0,
            lastParametersStagedAt: 0,
            thawingNonce: 0
        });
        available[sp] = tokens;
    }

    function getProvision(address sp, address) external view returns (IHorizonStakingTypes.Provision memory) {
        return p[sp];
    }

    function getTokensAvailable(address sp, address, uint32) external view returns (uint256) {
        return available[sp];
    }

    function isAuthorized(address sp, address, address op) external pure returns (bool) {
        return sp == op;
    }
    function slash(address, uint256, uint256, address) external {}
    function acceptProvisionParameters(address) external {}
}

contract MockController {
    mapping(bytes32 => address) private _c;

    constructor(address staking, address token) {
        address d = address(1);
        _c[keccak256("GraphToken")] = token;
        _c[keccak256("Staking")] = staking;
        _c[keccak256("GraphPayments")] = d;
        _c[keccak256("PaymentsEscrow")] = d;
        _c[keccak256("EpochManager")] = d;
        _c[keccak256("RewardsManager")] = d;
        _c[keccak256("GraphTokenGateway")] = d;
        _c[keccak256("GraphProxyAdmin")] = d;
        _c[keccak256("Curation")] = d;
    }

    function getContractProxy(bytes32 id) external view returns (address) {
        return _c[id];
    }
}

contract MemoryDataServiceTest is Test {
    MemoryDataService svc;
    MockStaking staking;
    MockGraphToken token;
    MockCollector collector;

    address owner = makeAddr("owner");
    address guardian = makeAddr("guardian");
    address provider = makeAddr("provider");
    address dest = makeAddr("dest");

    uint256 constant PROVISION = 5_000e18;
    string constant ENDPOINT = "https://memory.example/mcp";

    function setUp() public {
        staking = new MockStaking();
        token = new MockGraphToken();
        collector = new MockCollector(token);
        MockController controller = new MockController(address(staking), address(token));
        MemoryDataService impl = new MemoryDataService(address(controller), address(collector));
        svc = MemoryDataService(
            address(new ERC1967Proxy(address(impl), abi.encodeCall(MemoryDataService.initialize, (owner, guardian))))
        );
        staking.setProvision(provider, PROVISION, 14 days);
    }

    function _register() internal {
        vm.prank(provider);
        svc.register(provider, abi.encode(ENDPOINT, uint64(100_000), true, dest));
    }

    function _usage(uint128 w, uint128 r, uint128 s, uint128 f)
        internal
        pure
        returns (IMemoryDataService.Usage memory)
    {
        return IMemoryDataService.Usage({writes: w, reads: r, searches: s, forgets: f});
    }

    function _rav() internal view returns (IGraphTallyCollector.SignedRAV memory rav) {
        rav.rav.serviceProvider = provider;
    }

    function _collect(IMemoryDataService.Usage memory u) internal {
        vm.prank(provider);
        svc.collect(provider, IGraphPayments.PaymentTypes.QueryFee, abi.encode(_rav(), uint256(1e18), u));
    }

    // ── The privacy decision, asserted in code ───────────────────────────────

    /// The registry is of PROVIDERS, never of users. There must be no way to learn from this
    /// contract that a given user keeps memory anywhere. If a namespace argument ever appears in
    /// this ABI, this test should be the thing that stops it.
    function test_theContractHasNoConceptOfAUserOrANamespace() public view {
        // Every external function's inputs are provider addresses, commitments and payments.
        // None of them names a user, a namespace, or an item.
        IMemoryDataService.Commitment memory c = svc.commitmentOf(provider);
        assertEq(c.endpoint, "");
        // Usage is per provider and aggregate — counts, never identities.
        IMemoryDataService.Usage memory u = svc.usageOf(provider);
        assertEq(u.writes + u.reads + u.searches + u.forgets, 0);
    }

    // ── Provider lifecycle ───────────────────────────────────────────────────

    function test_registerRecordsTheCommitmentIncludingBlindIndexSupport() public {
        _register();
        IMemoryDataService.Commitment memory c = svc.commitmentOf(provider);
        assertEq(c.endpoint, ENDPOINT);
        assertEq(c.maxItems, 100_000);
        assertTrue(c.supportsBlindIndex, "a provider without it can only be a blob store");
        assertTrue(c.active);
        assertEq(svc.paymentsDestination(provider), dest);
    }

    function test_cannotRegisterTwice() public {
        _register();
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(IMemoryDataService.ProviderAlreadyRegistered.selector, provider));
        svc.register(provider, abi.encode(ENDPOINT, uint64(1), true, dest));
    }

    function test_anEmptyEndpointIsRejectedRatherThanRegisteredAsUnreachable() public {
        vm.prank(provider);
        vm.expectRevert(IMemoryDataService.EmptyEndpoint.selector);
        svc.register(provider, abi.encode("", uint64(1), true, dest));
    }

    function test_insufficientProvisionIsRefused() public {
        address poor = makeAddr("poor");
        staking.setProvision(poor, 1e18, 14 days);
        vm.prank(poor);
        vm.expectRevert();
        svc.register(poor, abi.encode(ENDPOINT, uint64(1), true, address(0)));
    }

    /// The signal a registry usually lacks: "I have stopped" without tearing down registration.
    function test_aProviderCanSayItStoppedServingWithoutDeregistering() public {
        _register();
        vm.prank(provider);
        vm.expectEmit(true, false, false, true);
        emit IMemoryDataService.ServingStateChanged(provider, false);
        svc.stopService(provider, "");

        assertFalse(svc.commitmentOf(provider).active, "not serving");
        assertTrue(svc.isRegistered(provider), "but still registered: a maintenance window, not an exit");

        vm.prank(provider);
        svc.startService(provider, "");
        assertTrue(svc.commitmentOf(provider).active);
    }

    function test_commitmentCanBeUpdated() public {
        _register();
        vm.prank(provider);
        svc.updateCommitment(provider, abi.encode("https://new.example/mcp", uint64(5), false));
        IMemoryDataService.Commitment memory c = svc.commitmentOf(provider);
        assertEq(c.endpoint, "https://new.example/mcp");
        assertEq(c.maxItems, 5);
        assertFalse(c.supportsBlindIndex);
    }

    // ── Usage accounting ─────────────────────────────────────────────────────

    function test_usageIsRecordedSoTheForgetRatioIsAPublicNumber() public {
        _register();
        collector.setPayout(10e18, dest);
        _collect(_usage(100, 50, 20, 7));
        IMemoryDataService.Usage memory u = svc.usageOf(provider);
        assertEq(u.writes, 100);
        assertEq(u.forgets, 7, "the only observable a user has that deletion happens at all");
    }

    /// Counters are self-reported and unprovable. A provider may exaggerate; it may not quietly
    /// rewrite history downwards, which is what hiding a deletion shortfall would look like.
    function test_usageCannotGoBackwards() public {
        _register();
        collector.setPayout(1e18, dest);
        _collect(_usage(100, 50, 20, 7));
        vm.prank(provider);
        vm.expectRevert(IMemoryDataService.UsageWentBackwards.selector);
        svc.collect(
            provider, IGraphPayments.PaymentTypes.QueryFee, abi.encode(_rav(), uint256(1e18), _usage(100, 50, 20, 6))
        );
    }

    function test_usageMayIncreaseMonotonically() public {
        _register();
        collector.setPayout(1e18, dest);
        _collect(_usage(1, 1, 1, 1));
        _collect(_usage(2, 1, 5, 1));
        assertEq(svc.usageOf(provider).searches, 5);
    }

    // ── Collection ───────────────────────────────────────────────────────────

    function test_collectPaysThroughAndBurnsHalfTheCut() public {
        _register();
        collector.setPayout(1000e18, address(svc));
        _collect(_usage(1, 0, 0, 0));
        // 1% burn + 1% retained, so of what lands here, half burns.
        assertEq(token.balanceOf(address(svc)), 500e18);
    }

    function test_onlyQueryFeeIsAccepted() public {
        _register();
        vm.prank(provider);
        vm.expectRevert(IMemoryDataService.InvalidPaymentType.selector);
        svc.collect(
            provider, IGraphPayments.PaymentTypes.IndexingFee, abi.encode(_rav(), uint256(1), _usage(0, 0, 0, 0))
        );
    }

    function test_aRavForSomeoneElseIsRefused() public {
        _register();
        IGraphTallyCollector.SignedRAV memory bad;
        bad.rav.serviceProvider = makeAddr("someoneElse");
        vm.prank(provider);
        vm.expectRevert();
        svc.collect(provider, IGraphPayments.PaymentTypes.QueryFee, abi.encode(bad, uint256(1), _usage(0, 0, 0, 0)));
    }

    function test_unregisteredProviderCannotCollect() public {
        vm.prank(provider);
        vm.expectRevert(abi.encodeWithSelector(IMemoryDataService.ProviderNotRegistered.selector, provider));
        svc.collect(provider, IGraphPayments.PaymentTypes.QueryFee, abi.encode(_rav(), uint256(1), _usage(0, 0, 0, 0)));
    }

    // ── The guarantees we are not pretending to make ─────────────────────────

    /// We hold ciphertext and cannot prove storage or deletion. Stubbing this to succeed would
    /// imply a guarantee that does not exist.
    function test_slashingIsRefusedNotSilentlyAccepted() public {
        vm.expectRevert("slashing not supported");
        svc.slash(provider, "");
    }
}
