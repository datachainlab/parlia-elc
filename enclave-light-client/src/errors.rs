#[cfg(feature = "sgx")]
use crate::sgx_reexport_prelude::*;
use alloc::vec::Vec;

use ibc::core::ics23_commitment::error::Error as ICS23Error;
use ibc::core::ics24_host::path::PathError;
use lcp_types::Height;
use light_client::LightClientInstanceError;

use parlia_ibc_lc::errors::Error as ParliaIBCLCError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("ICS23Error: {0}")]
    ICS23(ICS23Error),
    #[error("ParliaIBCLCError: {0:?}")]
    ParliaIBCLC(ParliaIBCLCError),
    #[error("UnexpectedHeight: {0}")]
    UnexpectedHeight(Height),
    #[error("PathError: {0}")]
    Path(PathError),
    #[error("UnexpectedCommitmentValue: {0:X?}")]
    UnexpectedCommitmentValue(Vec<u8>),
}

impl LightClientInstanceError for Error {}
