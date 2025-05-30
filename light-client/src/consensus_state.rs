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
    /// After Lorentz HF, the unit is millisecond. Before that, it was seconds.
    pub timestamp: Time,
    pub current_validators_hash: Hash,
    pub previous_validators_hash: Hash,
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
        let current_validators_hash: Hash = value
            .current_validators_hash
            .try_into()
            .map_err(Error::UnexpectedValidatorsHashSize)?;
        let previous_validators_hash: Hash = value
            .previous_validators_hash
            .try_into()
            .map_err(Error::UnexpectedValidatorsHashSize)?;
        Ok(Self {
            state_root,
            timestamp,
            current_validators_hash,
            previous_validators_hash,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        Self {
            state_root: value.state_root.to_vec(),
            timestamp: (value.timestamp.as_unix_timestamp_nanos() / 1_000_000) as u64,
            current_validators_hash: value.current_validators_hash.into(),
            previous_validators_hash: value.previous_validators_hash.into(),
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

impl TryFrom<ConsensusState> for IBCAny {
    type Error = Error;

    fn try_from(value: ConsensusState) -> Result<Self, Self::Error> {
        let value: RawConsensusState = value.into();
        let mut v = Vec::new();
        value.encode(&mut v).map_err(Error::ProtoEncodeError)?;
        Ok(Self {
            type_url: PARLIA_CONSENSUS_STATE_TYPE_URL.to_owned(),
            value: v,
        })
    }
}

impl TryFrom<ConsensusState> for Any {
    type Error = Error;

    fn try_from(value: ConsensusState) -> Result<Self, Self::Error> {
        Ok(IBCAny::try_from(value)?.into())
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
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::ConsensusState as RawConsensusState;

    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;

    #[test]
    fn test_success_try_from_any() {
        let cs = hex!("0a2a2f6962632e6c69676874636c69656e74732e7061726c69612e76312e436f6e73656e7375735374617465126d0a20e0cecaaf108b444908180c46807c7891991377cc43669273e779c5c0c5cbd77c10c88db8afd6321a204e013ddc6238ab26c478ce824c78b5938efa2d4e5eb73e9c9a3172ffca99c7ee22203acf3e01a40afb77b433f11eb9a311cbc5326957d5d3e9e9428439d17b76ead0").to_vec();
        let cs: Any = cs.try_into().unwrap();
        let cs: ConsensusState = cs.try_into().unwrap();

        assert_eq!(
            hex!("4e013ddc6238ab26c478ce824c78b5938efa2d4e5eb73e9c9a3172ffca99c7ee"),
            cs.current_validators_hash
        );
        assert_eq!(
            hex!("3acf3e01a40afb77b433f11eb9a311cbc5326957d5d3e9e9428439d17b76ead0"),
            cs.previous_validators_hash
        );
        assert_eq!(
            1741171853000,
            cs.timestamp.as_unix_timestamp_nanos() / 1_000_000
        );
        assert_eq!(
            hex!("e0cecaaf108b444908180c46807c7891991377cc43669273e779c5c0c5cbd77c"),
            cs.state_root
        );
    }

    #[test]
    fn test_error_try_from() {
        let mut cs = RawConsensusState {
            state_root: vec![10],
            timestamp: 0,
            current_validators_hash: vec![0],
            previous_validators_hash: vec![1],
        };

        let err = ConsensusState::try_from(cs.clone()).unwrap_err();
        match err {
            Error::UnexpectedConsensusStateRoot(state_root) => {
                assert_eq!(state_root, vec![10]);
            }
            err => unreachable!("{:?}", err),
        }

        cs.state_root = [1u8; 32].to_vec();
        let err = ConsensusState::try_from(cs.clone()).unwrap_err();
        match err {
            Error::UnexpectedValidatorsHashSize(hash) => {
                assert_eq!(hash, vec![0]);
            }
            err => unreachable!("{:?}", err),
        }

        cs.current_validators_hash = [1u8; 32].to_vec();
        let err = ConsensusState::try_from(cs).unwrap_err();
        match err {
            Error::UnexpectedValidatorsHashSize(hash) => {
                assert_eq!(hash, vec![1]);
            }
            err => unreachable!("{:?}", err),
        }
    }
}
