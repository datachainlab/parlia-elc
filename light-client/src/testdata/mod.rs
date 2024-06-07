use crate::header::eth_header::ETHHeader;
use crate::header::eth_headers::ETHHeaders;
use crate::misc::{ChainId, Validators};
use crate::testdata::localnet::Localnet;
use alloc::boxed::Box;

pub mod localnet;

pub trait TestData {
    fn network(&self) -> ChainId;
    fn epoch_header(&self) -> ETHHeader;
    fn epoch_header_plus_1(&self) -> ETHHeader;
    fn epoch_header_plus_2(&self) -> ETHHeader;
    fn epoch_header_plus_3(&self) -> ETHHeader;
    fn headers_before_checkpoint(&self) -> ETHHeaders;
    fn headers_across_checkpoint(&self) -> ETHHeaders;
    fn headers_after_checkpoint(&self) -> ETHHeaders;
    fn previous_validators(&self) -> Validators;
}

pub fn localnet() -> Box<dyn TestData> {
    Box::new(Localnet)
}

// TODO Modify testnet / mainnet after each HF released
