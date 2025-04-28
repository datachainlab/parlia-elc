use crate::fixture::localnet::Localnet;
use crate::header::eth_header::ETHHeader;
use crate::header::eth_headers::ETHHeaders;
use crate::misc::{Address, ChainId, Hash, Validators};
use alloc::boxed::Box;
use alloc::vec::Vec;

use crate::fork_spec::{ForkSpec, HeightOrTimestamp};
use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

pub mod localnet;

pub trait Network {
    fn network(&self) -> ChainId;
    fn previous_epoch_header(&self) -> ETHHeader;
    fn epoch_header_rlp(&self) -> Vec<u8>;
    fn epoch_header(&self) -> ETHHeader {
        decode_header(self.epoch_header_rlp())
    }
    fn epoch_header_plus_1_rlp(&self) -> Vec<u8>;
    fn epoch_header_plus_1(&self) -> ETHHeader {
        decode_header(self.epoch_header_plus_1_rlp())
    }
    fn epoch_header_plus_2(&self) -> ETHHeader;
    fn epoch_header_plus_3(&self) -> ETHHeader;
    fn headers_before_checkpoint(&self) -> ETHHeaders;
    fn headers_across_checkpoint(&self) -> ETHHeaders;
    fn headers_after_checkpoint(&self) -> ETHHeaders;
    fn previous_validators(&self) -> Validators {
        self.previous_epoch_header()
            .epoch
            .unwrap()
            .validators()
            .clone()
    }
    fn ibc_store_address(&self) -> Address;
    fn success_update_client_non_epoch_input(&self) -> UpdateClientNonEpochInput;
    fn success_update_client_epoch_input(&self) -> UpdateClientEpochInput;
    fn success_update_client_continuous_input(&self) -> Vec<Vec<Vec<u8>>>;
    fn error_update_client_non_neighboring_epoch_input(&self) -> Vec<u8>;
    fn success_create_client(&self) -> (Vec<u8>, Vec<u8>, u64, u64);
}

pub struct UpdateClientNonEpochInput {
    pub header: Vec<u8>,
    pub trusted_height: u64,
    pub trusted_current_validators_hash: Hash,
    pub trusted_previous_validators_hash: Hash,
}

pub struct UpdateClientEpochInput {
    pub header: Vec<u8>,
    pub trusted_height: u64,
    pub trusted_current_validators_hash: Hash,
    pub trusted_previous_validators_hash: Hash,
    pub new_current_validators_hash: Hash,
    pub new_previous_validators_hash: Hash,
}

pub fn localnet() -> Box<dyn Network> {
    Box::new(Localnet)
}

pub fn decode_header(rlp_header: Vec<u8>) -> ETHHeader {
    let mut header: ETHHeader = EthHeader { header: rlp_header }.try_into().unwrap();
    header
        .set_boundary_epochs(&[fork_spec_after_pascal(), fork_spec_after_lorentz()])
        .unwrap();
    header
}

pub fn fork_spec_after_pascal() -> ForkSpec {
    ForkSpec {
        height_or_timestamp: HeightOrTimestamp::Height(0),
        additional_header_item_count: 1,
        epoch_length: 200,
        max_turn_length: 64,
        gas_limit_bound_divider: 256,
    }
}

pub fn fork_spec_after_lorentz() -> ForkSpec {
    ForkSpec {
        height_or_timestamp: HeightOrTimestamp::Height(1),
        additional_header_item_count: 1,
        epoch_length: 500,
        max_turn_length: 64,
        gas_limit_bound_divider: 1024,
    }
}

pub fn fork_spec_after_maxwell() -> ForkSpec {
    ForkSpec {
        height_or_timestamp: HeightOrTimestamp::Height(2),
        additional_header_item_count: 1,
        epoch_length: 1000,
        max_turn_length: 64,
        gas_limit_bound_divider: 1024,
    }
}
