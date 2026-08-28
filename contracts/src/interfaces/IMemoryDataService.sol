// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.27;

/// @title IMemoryDataService
/// @notice A Horizon data service for end-to-end encrypted, user-owned agent memory.
///
/// @dev **This registry is of providers, never of users.** Forking compass mechanically would have
///      keyed it on memory namespaces the way compass keys on subgraph deployments. A namespace is
///      a person's private thing: a public registry of them would leak who keeps memory, with
///      which provider, how much, and since when — permanently, against an address. Namespaces are
///      known to the user and their provider and never touch the chain. See docs/design.md.
interface IMemoryDataService {
    /// @notice What a provider commits to. Capacity is a claim, not a proof — there is no
    ///         verification primitive here any more than anywhere else in Horizon.
    /// @param endpoint Where the MCP surface lives.
    /// @param maxItems Items the provider claims it will hold. 0 means unspecified.
    /// @param supportsBlindIndex Whether the provider can serve keyed-bucket search (design §C).
    ///        A provider without it can only be a blob store for client-side search (§A).
    /// @param active False once stopped; kept for history.
    struct Commitment {
        string endpoint;
        uint64 maxItems;
        bool supportsBlindIndex;
        bool active;
    }

    /// @notice Per-operation counters. Public so a provider's behaviour is legible even though it
    ///         cannot be proven: notably the ratio of forgets to writes, which is the only
    ///         observable a user has that deletion is happening at all.
    struct Usage {
        uint128 writes;
        uint128 reads;
        uint128 searches;
        uint128 forgets;
    }

    /// @notice The four metered operations. Priced separately because they cost differently.
    enum Operation {
        Write,
        Read,
        Search,
        Forget
    }

    // ── Events ───────────────────────────────────────────────────────────────

    event ProviderRegistered(address indexed provider, string endpoint, uint64 maxItems, bool supportsBlindIndex);
    event ProviderDeregistered(address indexed provider);
    event CommitmentUpdated(address indexed provider, string endpoint, uint64 maxItems, bool supportsBlindIndex);
    event PaymentsDestinationSet(address indexed provider, address destination);

    /// @notice A provider declaring it has started or stopped serving, without deregistering.
    /// @dev The signal a registry usually lacks. "Registered" and "gone" cannot distinguish a
    ///      maintenance window from a provider that quietly stopped answering months ago, and
    ///      consumers end up finding out the hard way.
    event ServingStateChanged(address indexed provider, bool serving);

    /// @param counts Cumulative per-operation counts reported with this collection.
    event MemoryFeesCollected(address indexed provider, uint256 tokens, Usage counts);
    event FeesBurned(address indexed provider, uint256 tokens);
    event FeesWithdrawn(address indexed to, uint256 tokens);

    // ── Errors ───────────────────────────────────────────────────────────────

    error ProviderNotRegistered(address provider);
    error ProviderAlreadyRegistered(address provider);
    error InvalidPaymentType();
    error InvalidServiceProvider(address expected, address actual);
    error InsufficientProvision(uint256 required, uint256 actual);
    error ThawingPeriodTooShort(uint64 required, uint64 provided);
    error EmptyEndpoint();
    /// @dev Usage counters are cumulative and may only ever increase. A provider reporting a
    ///      lower count than last time is either buggy or rewriting history.
    error UsageWentBackwards();

    // ── Views ────────────────────────────────────────────────────────────────

    function isRegistered(address provider) external view returns (bool);
    function commitmentOf(address provider) external view returns (Commitment memory);
    function usageOf(address provider) external view returns (Usage memory);
}
