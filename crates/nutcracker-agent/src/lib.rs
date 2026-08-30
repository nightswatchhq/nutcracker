//! The local MCP shim.
//!
//! # Why this is local, and why that is not a detail
//!
//! compass runs its MCP server at the **provider**, because subgraph data is public and there is
//! nothing to hide. The obvious way to build memory is to copy that: a provider-hosted MCP server
//! an agent connects to directly.
//!
//! That design cannot be end-to-end encrypted, and the reason is worth stating slowly. If the
//! agent talks MCP straight to the provider, then either the agent sends plaintext — in which case
//! the provider has it — or the agent does the sealing itself, in which case the *agent* holds the
//! user's root key. "The agent" here means Claude, or Cursor, or whatever the user is running
//! today and something else next month. Handing a rotating cast of third-party clients the key
//! that protects everything you have ever told any of them is not user-owned memory.
//!
//! So the MCP server runs **on the user's machine**:
//!
//! ```text
//!   agent  ──MCP, plaintext, localhost──▶  nutcracker-agent  ──HTTP, sealed──▶  provider
//!                                          (holds the root key)                 (holds nothing)
//! ```
//!
//! The agent gets an ergonomic API: `memory.write("we chose postgres")`. The provider gets opaque
//! bytes and bucket tokens. Neither is inconvenienced by the other, and the key never leaves the
//! machine it belongs to.
//!
//! The consequence, which should be said out loud rather than discovered: **the provider's HTTP
//! surface is not MCP and is not meant to be spoken by an agent.** It is a sealed-payload
//! transport. Anything claiming to be an agent-facing remote memory MCP server is holding your
//! keys.

pub mod embedder;
pub mod http;
pub mod tools;
pub mod transport;

pub use http::HttpTransport;
pub use tools::{tool_definitions, MemoryTools, ToolError};
pub use transport::{ProviderTransport, TransportError};
