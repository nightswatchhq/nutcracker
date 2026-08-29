//! A runnable nutcracker provider.
//!
//! HTTP over the sealed store. It holds no keys and no plaintext, and the wire format gives it
//! nowhere to put either. See `docs/design.md`.

pub mod routes;
pub mod wire;

pub use routes::{router, AppState};
