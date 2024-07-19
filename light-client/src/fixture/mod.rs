use crate::fixture::localnet::Localnet;
use crate::header::eth_header::{get_validator_bytes, ETHHeader};
use crate::header::eth_headers::ETHHeaders;
use crate::misc::{Address, ChainId, Hash, Validators};
use alloc::boxed::Box;
use alloc::vec::Vec;
use hex_literal::hex;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

pub mod localnet;

pub trait Network {
    fn network(&self) -> ChainId;
    fn previous_epoch_header(&self) -> ETHHeader;
    fn epoch_header(&self) -> ETHHeader;
    fn epoch_header_plus_1(&self) -> ETHHeader;
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
    fn error_update_client_non_neighboring_epoch_input(&self) -> (Vec<u8>, u64);
    fn error_update_client_input(&self) -> UpdateClientErrorInput;
}

pub struct UpdateClientNonEpochInput {
    pub header: Vec<u8>,
    pub trusted_height: u64,
    pub trusted_current_validators_hash: Hash,
    pub trusted_previous_validators_hash: Hash,
    pub expected_storage_root: Hash,
}

pub struct UpdateClientEpochInput {
    pub header: Vec<u8>,
    pub trusted_height: u64,
    pub trusted_current_validators_hash: Hash,
    pub trusted_previous_validators_hash: Hash,
    pub new_current_validators_hash: Hash,
    pub new_previous_validators_hash: Hash,
    pub expected_storage_root: Hash,
}

pub struct UpdateClientErrorInput {
    pub header: Vec<u8>,
    pub trusted_height: u64,
    pub trusted_current_validators_hash: Hash,
    pub trusted_previous_validators_hash: Hash,
}

pub fn localnet() -> Box<dyn Network> {
    Box::new(Localnet)
}

pub fn decode_header(rlp_header: Vec<u8>) -> ETHHeader {
    EthHeader { header: rlp_header }.try_into().unwrap()
}

// TODO Modify testnet / mainnet after each HF released
