#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fraction {
    #[prost(uint64, tag="1")]
    pub numerator: u64,
    #[prost(uint64, tag="2")]
    pub denominator: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientState {
    #[prost(uint64, tag="1")]
    pub chain_id: u64,
    #[prost(bytes="vec", tag="2")]
    pub ibc_store_address: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag="3")]
    pub latest_height: ::core::option::Option<super::super::super::core::client::v1::Height>,
    #[prost(message, optional, tag="4")]
    pub trust_level: ::core::option::Option<Fraction>,
    #[prost(uint64, tag="5")]
    pub trusting_period: u64,
    #[prost(bool, tag="6")]
    pub frozen: bool,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthHeader {
    #[prost(bytes="vec", tag="1")]
    pub header: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Header {
    #[prost(string, tag="1")]
    pub identifier: ::prost::alloc::string::String,
    #[prost(message, repeated, tag="3")]
    pub headers: ::prost::alloc::vec::Vec<EthHeader>,
    #[prost(message, optional, tag="4")]
    pub trusted_height: ::core::option::Option<super::super::super::core::client::v1::Height>,
    #[prost(bytes="vec", tag="5")]
    pub account_proof: ::prost::alloc::vec::Vec<u8>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusState {
    #[prost(bytes="vec", tag="1")]
    pub state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag="2")]
    pub timestamp: u64,
    #[prost(bytes="vec", repeated, tag="3")]
    pub validator_set: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
