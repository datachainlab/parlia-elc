use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;

use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::consensus_state::ConsensusState as IBCConsensusState;
use ibc::core::ics02_client::error::ClientError;
use ibc::core::ics23_commitment::commitment::CommitmentRoot;
use ibc::timestamp::Timestamp;
use ibc_proto::google::protobuf::Any;
use ibc_proto::protobuf::Protobuf;
use prost::Message as _;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::ConsensusState as RawConsensusState;

use crate::misc::{Hash, NanoTime, new_ibc_timestamp, Validators};

use super::errors::Error;

pub const PARLIA_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ConsensusState";

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConsensusState {
    pub state_root: CommitmentRoot,
    pub timestamp: ibc::timestamp::Timestamp,
    // Only epoch headers contain validator set
    pub validator_set: Validators,
}

impl ConsensusState {
    pub fn state_root(&self) -> Result<Hash, Error> {
        self.state_root
            .as_bytes()
            .try_into()
            .map_err(|_| Error::UnexpectedStateRoot(self.state_root.clone().into_vec()))
    }

    pub fn assert_within_trust_period(
        &self,
        now: ibc::timestamp::Timestamp,
        trusting_period: NanoTime,
    ) -> Result<(), Error> {
        // We can't use std::time in the TEE environment.
        let now_nano = now.nanoseconds();
        let timestamp = self.timestamp.nanoseconds();
        if now_nano < timestamp {
            return Err(Error::UnexpectedTimestamp(timestamp));
        }
        if (now_nano - timestamp) > trusting_period {
            let expires_at = new_ibc_timestamp(timestamp + trusting_period)?;
            Err(Error::ICS02Error(ClientError::HeaderNotWithinTrustPeriod {
                latest_time: expires_at,
                update_time: now,
            }))
        } else {
            Ok(())
        }
    }
}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = ClientError;

    fn try_from(value: RawConsensusState) -> Result<Self, Self::Error> {
        let state_root = CommitmentRoot::from_bytes(value.state_root.as_slice());
        let timestamp = new_ibc_timestamp(value.timestamp)?;
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
            state_root: value.state_root.into_vec(),
            timestamp: value.timestamp.nanoseconds(),
            validator_set: value.validator_set,
        }
    }
}

impl Protobuf<RawConsensusState> for ConsensusState {}
impl Protobuf<Any> for ConsensusState {}

impl IBCConsensusState for ConsensusState {
    fn root(&self) -> &CommitmentRoot {
        &self.state_root
    }

    fn timestamp(&self) -> Timestamp {
        self.timestamp
    }
}

impl TryFrom<Any> for ConsensusState {
    type Error = ClientError;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        if any.type_url != PARLIA_CONSENSUS_STATE_TYPE_URL {
            return Err(ClientError::UnknownConsensusStateType {
                consensus_state_type: any.type_url,
            });
        }
        RawConsensusState::decode(any.value.as_slice())
            .map_err(ClientError::Decode)?
            .try_into()
    }
}

impl From<ConsensusState> for Any {
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

#[cfg(test)]
mod test {
    use ibc::core::ics23_commitment::commitment::CommitmentRoot;

    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;
    use crate::misc::new_ibc_timestamp;

    #[test]
    fn test_assert_within_trust_period() {
        let as_seconds = 1_000_000_000;
        let consensus_state = ConsensusState {
            state_root: CommitmentRoot::from_bytes(&[]),
            timestamp: new_ibc_timestamp(1560000000 * as_seconds).unwrap(),
            validator_set: vec![],
        };

        let now = new_ibc_timestamp(consensus_state.timestamp.nanoseconds() + as_seconds).unwrap();
        match consensus_state
            .assert_within_trust_period(now, 0)
            .unwrap_err()
        {
            Error::ICS02Error(_) => assert!(true),
            e => unreachable!("{:?}", e),
        }
        assert!(consensus_state
            .assert_within_trust_period(now, as_seconds)
            .is_ok());

        let now = new_ibc_timestamp(consensus_state.timestamp.nanoseconds() - as_seconds).unwrap();
        match consensus_state
            .assert_within_trust_period(now, 0)
            .unwrap_err()
        {
            Error::UnexpectedTimestamp(tm) => {
                assert_eq!(tm, consensus_state.timestamp.nanoseconds())
            }
            e => unreachable!("{:?}", e),
        }
    }
}
