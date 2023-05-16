#![cfg_attr(feature = "sgx", no_std)]
extern crate alloc;
#[cfg(feature = "sgx")]
extern crate sgx_tstd as std;

pub use client::register_implementations;

// re-export module to properly feature gate sgx and regular std environment
#[cfg(feature = "sgx")]
pub(crate) mod sgx_reexport_prelude {
    pub use log_sgx as log;
    pub use thiserror_sgx as thiserror;
}

mod client;
pub mod context;
mod errors;
