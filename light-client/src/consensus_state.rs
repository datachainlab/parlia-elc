use alloc::borrow::ToOwned as _;

use alloc::vec::Vec;
use core::ops::Add;
use core::time::Duration;

use ibc_proto::google::protobuf::Any as IBCAny;
use ibc_proto::protobuf::Protobuf;
use lcp_types::{Any, Time, TimeError};
use prost::Message as _;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::ConsensusState as RawConsensusState;

use crate::client_state::ClientState;
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
    pub fn assert_within_trust_period(
        &self,
        now: Time,
        trusting_period: Duration,
    ) -> Result<(), Error> {
        if self.timestamp > now {
            return Err(Error::IllegalTimestamp(self.timestamp, now));
        }
        let deadline = self
            .timestamp
            .add(trusting_period)
            .map_err(Error::UnexpectedTimestamp)?;
        if deadline < now {
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
            .map_err(Error::UnexpectedStateRoot)?;
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
            timestamp: value.timestamp.as_unix_timestamp_nanos() as u64, //TODO
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
    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;
    use crate::misc::new_timestamp;
    use core::time::Duration;
    use lcp_types::Time;
    use std::ops::{Add, Sub};

    #[test]
    fn test_assert_within_trust_period() {
        let consensus_state = ConsensusState {
            state_root: [0 as u8; 32],
            timestamp: Time::from_unix_timestamp_secs(1560000000).unwrap(),
            validator_set: vec![],
        };

        // now is after trusting period
        let now = consensus_state.timestamp.add(Duration::new(1, 1)).unwrap();
        match consensus_state
            .assert_within_trust_period(now, Duration::new(1, 0))
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
            .assert_within_trust_period(now, Duration::new(1, 1))
            .is_ok());

        // illegal timestamp
        let now = consensus_state.timestamp.sub(Duration::new(1, 0)).unwrap();
        match consensus_state
            .assert_within_trust_period(now, Duration::new(0, 0))
            .unwrap_err()
        {
            Error::IllegalTimestamp(t1, t2) => {
                assert_eq!(t1, consensus_state.timestamp);
                assert_eq!(t2, now);
            }
            e => unreachable!("{:?}", e),
        }
    }
}
