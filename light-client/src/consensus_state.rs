use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;
use ibc::core::ics02_client::client_consensus::{self, AnyConsensusState};
use ibc::core::ics02_client::client_type::ClientType;
use ibc::core::ics02_client::error::Error as ICS02Error;
use ibc::core::ics23_commitment::commitment::CommitmentRoot;

use crate::misc::{new_ibc_timestamp, Hash, NanoTime, Validators};
use ibc_proto::google::protobuf::Any;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::ConsensusState as RawConsensusState;

use prost::Message as _;

use super::errors::Error;

pub const PARLIA_CONSENSUS_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ConsensusState";

#[derive(Clone, Debug)]
pub struct ConsensusState {
    pub state_root: CommitmentRoot,
    pub timestamp: ibc::timestamp::Timestamp,
    // Only epoch headers contain validator set
    pub validator_set: Validators,
}

impl ConsensusState {
    pub fn timestamp(&self) -> ibc::timestamp::Timestamp {
        self.timestamp
    }

    pub fn state_root(&self) -> Result<Hash, Error> {
        self.state_root
            .as_bytes()
            .try_into()
            .map_err(|_| Error::UnexpectedStateRoot)
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
            Err(Error::ICS02Error(
                ICS02Error::header_not_within_trust_period(expires_at, now),
            ))
        } else {
            Ok(())
        }
    }
}

impl TryFrom<RawConsensusState> for ConsensusState {
    type Error = Error;

    fn try_from(value: RawConsensusState) -> Result<Self, Error> {
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

impl client_consensus::ConsensusState for ConsensusState {
    type Error = Error;

    fn client_type(&self) -> ClientType {
        todo!();
    }

    fn root(&self) -> &CommitmentRoot {
        &self.state_root
    }

    fn wrap_any(self) -> AnyConsensusState {
        todo!();
    }
}

impl TryFrom<Any> for ConsensusState {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        if any.type_url != PARLIA_CONSENSUS_STATE_TYPE_URL {
            return Err(Error::UnexpectedTypeUrl(any.type_url));
        }
        RawConsensusState::decode(any.value.as_slice())
            .map_err(Error::ProtoDecodeError)?
            .try_into()
    }
}

impl TryFrom<ConsensusState> for Any {
    type Error = Error;

    fn try_from(value: ConsensusState) -> Result<Self, Error> {
        let value: RawConsensusState = value.into();
        let mut v = Vec::new();
        value.encode(&mut v).map_err(Error::ProtoEncodeError)?;
        Ok(Self {
            type_url: PARLIA_CONSENSUS_STATE_TYPE_URL.to_owned(),
            value: v,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;
    use crate::misc::new_ibc_timestamp;
    use ibc::core::ics23_commitment::commitment::CommitmentRoot;

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
