#[derive(::serde::Serialize, ::serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Fraction {
    #[prost(uint64, tag = "1")]
    pub numerator: u64,
    #[prost(uint64, tag = "2")]
    pub denominator: u64,
}
#[derive(::serde::Serialize, ::serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientState {
    #[prost(uint64, tag = "1")]
    pub chain_id: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ibc_store_address: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub latest_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(message, optional, tag = "4")]
    pub trust_level: ::core::option::Option<Fraction>,
    #[prost(uint64, tag = "5")]
    pub trusting_period: u64,
    #[prost(bool, tag = "6")]
    pub frozen: bool,
}
#[derive(::serde::Serialize, ::serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthHeader {
    #[prost(bytes = "vec", tag = "1")]
    pub header: ::prost::alloc::vec::Vec<u8>,
}
#[derive(::serde::Serialize, ::serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Header {
    #[prost(message, repeated, tag = "1")]
    pub headers: ::prost::alloc::vec::Vec<EthHeader>,
    #[prost(message, optional, tag = "2")]
    pub trusted_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(bytes = "vec", tag = "3")]
    pub account_proof: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub previous_validators: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub current_validators: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
}
#[derive(::serde::Serialize, ::serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusState {
    #[prost(bytes = "vec", tag = "1")]
    pub state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub timestamp: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub validators_hash: ::prost::alloc::vec::Vec<u8>,
}
#[derive(::serde::Serialize, ::serde::Deserialize)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Misbehaviour {
    #[prost(string, tag = "1")]
    pub client_id: ::prost::alloc::string::String,
    #[prost(message, optional, tag = "2")]
    pub header_1: ::core::option::Option<Header>,
    #[prost(message, optional, tag = "3")]
    pub header_2: ::core::option::Option<Header>,
}
