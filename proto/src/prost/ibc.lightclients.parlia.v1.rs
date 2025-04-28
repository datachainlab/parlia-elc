#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ForkSpec {
    /// The number of headers prior to Pascal HF is set to 0.
    /// For example, the number of headers before Pascal HF is set to 1 because of the addition of the requestsHash.
    #[prost(uint64, tag = "3")]
    pub additional_header_item_count: u64,
    #[prost(uint64, tag = "4")]
    pub epoch_length: u64,
    #[prost(uint64, tag = "5")]
    pub max_turn_length: u64,
    #[prost(uint64, tag = "6")]
    pub gas_limit_bound_divider: u64,
    #[prost(oneof = "fork_spec::HeightOrTimestamp", tags = "1, 2")]
    pub height_or_timestamp: ::core::option::Option<fork_spec::HeightOrTimestamp>,
}
/// Nested message and enum types in `ForkSpec`.
pub mod fork_spec {
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum HeightOrTimestamp {
        #[prost(uint64, tag = "1")]
        Height(u64),
        #[prost(uint64, tag = "2")]
        Timestamp(u64),
    }
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ClientState {
    #[prost(uint64, tag = "1")]
    pub chain_id: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub ibc_store_address: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub ibc_commitments_slot: ::prost::alloc::vec::Vec<u8>,
    #[prost(message, optional, tag = "4")]
    pub latest_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(message, optional, tag = "5")]
    pub trusting_period: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
    #[prost(message, optional, tag = "6")]
    pub max_clock_drift: ::core::option::Option<
        super::super::super::super::google::protobuf::Duration,
    >,
    #[prost(bool, tag = "7")]
    pub frozen: bool,
    #[prost(message, repeated, tag = "8")]
    pub fork_specs: ::prost::alloc::vec::Vec<ForkSpec>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct EthHeader {
    #[prost(bytes = "vec", tag = "1")]
    pub header: ::prost::alloc::vec::Vec<u8>,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Header {
    #[prost(message, repeated, tag = "1")]
    pub headers: ::prost::alloc::vec::Vec<EthHeader>,
    #[prost(message, optional, tag = "2")]
    pub trusted_height: ::core::option::Option<
        super::super::super::core::client::v1::Height,
    >,
    #[prost(bytes = "vec", repeated, tag = "3")]
    pub current_validators: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub previous_validators: ::prost::alloc::vec::Vec<::prost::alloc::vec::Vec<u8>>,
    #[prost(uint32, tag = "5")]
    pub current_turn_length: u32,
    #[prost(uint32, tag = "6")]
    pub previous_turn_length: u32,
}
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ConsensusState {
    #[prost(bytes = "vec", tag = "1")]
    pub state_root: ::prost::alloc::vec::Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub timestamp: u64,
    #[prost(bytes = "vec", tag = "3")]
    pub current_validators_hash: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub previous_validators_hash: ::prost::alloc::vec::Vec<u8>,
}
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
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProveState {
    #[prost(bytes = "vec", tag = "1")]
    pub account_proof: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub commitment_proof: ::prost::alloc::vec::Vec<u8>,
}
