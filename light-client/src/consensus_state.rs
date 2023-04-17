use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;
use core::ops::Add;
use core::time::Duration;

use lcp_types::{Any, Time};
use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use prost::Message as _;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::ConsensusState as RawConsensusState;

use crate::misc::{new_timestamp, Hash, Validators};

use super::errors::Error;

pub const PARLIA_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ConsensusState";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusState {
    pub state_root: Hash,
    pub timestamp: Time,
    // Only epoch headers contain validator set
    pub validator_set: Validators,
}

impl ConsensusState {
    pub fn assert_not_expired(&self, now: Time, trusting_period: Duration) -> Result<(), Error> {
        if self.timestamp > now {
            return Err(Error::IllegalTimestamp(self.timestamp, now));
        }
        let deadline = self
            .timestamp
            .add(trusting_period)
            .map_err(Error::UnexpectedTimestamp)?;
        if deadline.as_unix_timestamp_secs() < now.as_unix_timestamp_secs() {
            Err(Error::HeaderNotWithinTrustingPeriod(deadline, now))
        } else {
            Ok(())
        }
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
        let validator_set = value.validator_set;
        Ok(Self {
            state_root,
            timestamp,
            validator_set,
        })
    }
}

impl From<ConsensusState> for RawConsensusState {
    fn from(value: ConsensusState) -> Self {
        Self {
            state_root: value.state_root.to_vec(),
            timestamp: value.timestamp.as_unix_timestamp_secs(),
            validator_set: value.validator_set,
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
    use core::time::Duration;
    use hex_literal::hex;
    use std::ops::{Add, Sub};

    use lcp_types::Time;

    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;

    #[test]
    fn test_assert_not_expired() {
        let consensus_state = ConsensusState {
            state_root: [0_u8; 32],
            timestamp: Time::from_unix_timestamp_secs(1560000000).unwrap(),
            validator_set: vec![],
        };

        // now is after trusting period
        let now = consensus_state.timestamp.add(Duration::new(1, 1)).unwrap();
        match consensus_state
            .assert_not_expired(now, Duration::new(1, 0))
            .unwrap_err()
        {
            Error::HeaderNotWithinTrustingPeriod(a, b) => {
                assert_eq!(
                    a,
                    consensus_state.timestamp.add(Duration::new(1, 0)).unwrap()
                );
                assert_eq!(b, now);
            }
            e => unreachable!("{:?}", e),
        }

        // now is within trusting period
        assert!(consensus_state
            .assert_not_expired(now, Duration::new(1, 1))
            .is_ok());

        // illegal timestamp
        let now = consensus_state.timestamp.sub(Duration::new(1, 0)).unwrap();
        match consensus_state
            .assert_not_expired(now, Duration::new(0, 0))
            .unwrap_err()
        {
            Error::IllegalTimestamp(t1, t2) => {
                assert_eq!(t1, consensus_state.timestamp);
                assert_eq!(t2, now);
            }
            e => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_try_from_any() {
        // This is ibc-parlia-relay's unit test data
        let relayer_consensus_state_protobuf = vec![
            10, 42, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115,
            46, 112, 97, 114, 108, 105, 97, 46, 118, 49, 46, 67, 111, 110, 115, 101, 110, 115, 117,
            115, 83, 116, 97, 116, 101, 18, 240, 3, 10, 32, 195, 96, 136, 113, 9, 143, 33, 181,
            150, 7, 239, 63, 185, 65, 42, 9, 29, 233, 36, 106, 209, 40, 26, 146, 245, 176, 125,
            194, 244, 101, 183, 160, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            26, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let any: lcp_types::Any = relayer_consensus_state_protobuf.try_into().unwrap();
        let cs: ConsensusState = any.try_into().unwrap();

        // Check if the result are same as relayer's one
        assert_eq!(21, cs.validator_set.len());
        for val in cs.validator_set {
            assert_eq!(
                hex!("0000000000000000000000000000000000000000").to_vec(),
                val
            );
        }
        assert_eq!(0, cs.timestamp.as_unix_timestamp_secs());
        assert_eq!(
            hex!("c3608871098f21b59607ef3fb9412a091de9246ad1281a92f5b07dc2f465b7a0"),
            cs.state_root
        );
    }
}
