use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;

use light_client::types::{Any, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::ConsensusState as RawConsensusState;

use crate::misc::{new_timestamp, Hash};

use super::errors::Error;

pub const PARLIA_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ConsensusState";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusState {
    /// the storage root of the IBC contract
    pub state_root: Hash,
    /// timestamp from execution payload
    pub timestamp: Time,
    /// finalized header's validator set.Only epoch headers contain validator set
    pub validators_hash: Hash,
    pub validators_size: u64,
}

impl ConsensusState {
    /// canonicalize canonicalizes some fields of specified client state
    /// target fields: nothing
    pub fn canonicalize(self) -> Self {
        self
    }
}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(value: RawConsensusState) -> Result<Self, Self::Error> {
        let state_root: Hash = value
            .state_root
            .try_into()
            .map_err(Error::UnexpectedConsensusStateRoot)?;
        let timestamp = new_timestamp(value.timestamp)?;
        let validators_hash: Hash = value
            .validators_hash
            .try_into()
            .map_err(Error::UnexpectedValidatorsHashSize)?;
        Ok(Self {
            state_root,
            timestamp,
            validators_hash,
            validators_size: value.validator_size,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        Self {
            state_root: value.state_root.to_vec(),
            timestamp: value.timestamp.as_unix_timestamp_secs(),
            validators_hash: value.validators_hash.into(),
            validator_size: value.validators_size,
        }
    }
}

impl TryFrom<IBCAny> for ConsensusState {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Self, Self::Error> {
        if any.type_url != PARLIA_CONSENSUS_STATE_TYPE_URL {
            return Err(Error::UnknownConsensusStateType(any.type_url));
        }
        RawConsensusState::decode(any.value.as_slice())
            .map_err(Error::ProtoDecodeError)?
            .try_into()
    }
}

impl From<ConsensusState> for IBCAny {
    fn from(value: ConsensusState) -> Self {
        let value: RawConsensusState = value.into();
        let mut v = Vec::new();
        value
            .encode(&mut v)
            .expect("encoding to `Any` from `ParliaConsensusState`");
        Self {
            type_url: PARLIA_CONSENSUS_STATE_TYPE_URL.to_owned(),
            value: v,
        }
    }
}

impl From<ConsensusState> for Any {
    fn from(value: ConsensusState) -> Self {
        IBCAny::from(value).into()
    }
}

impl TryFrom<Any> for ConsensusState {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}

#[cfg(test)]
mod test {

    use hex_literal::hex;
    use light_client::types::Any;

    use crate::consensus_state::ConsensusState;

    #[test]
    fn test_try_from_any() {
        // This is ibc-parlia-relay's unit test data
        let relayer_consensus_state_protobuf = hex!("0a2a2f6962632e6c69676874636c69656e74732e7061726c69612e76312e436f6e73656e737573537461746512440a20c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4701a2073b0a7eec725ec1c4016d9cba46fbdac22478f8eadb6690067b2aa943afa0a9c").to_vec();
        let any: Any = relayer_consensus_state_protobuf.try_into().unwrap();
        let cs: ConsensusState = any.try_into().unwrap();

        // Check if the result are same as relayer's one
        assert_eq!(
            hex!("73b0a7eec725ec1c4016d9cba46fbdac22478f8eadb6690067b2aa943afa0a9c"),
            cs.validators_hash
        );
        assert_eq!(0, cs.timestamp.as_unix_timestamp_secs());
        assert_eq!(
            hex!("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"),
            cs.state_root
        );
    }
}
