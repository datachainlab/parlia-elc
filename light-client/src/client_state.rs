use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;
use core::time::Duration;

use light_client::types::{Any, Height, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::ClientState as RawClientState;

use crate::commitment::resolve_account;
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::misbehaviour::Misbehaviour;
use crate::misc::{new_height, Address, ChainId, Hash};

pub const PARLIA_CLIENT_STATE_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.ClientState";

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ClientState {
    /// Chain parameters
    pub chain_id: ChainId,

    /// IBC Solidity parameters
    pub ibc_store_address: Address,
    pub ibc_commitments_slot: Hash,

    ///Light Client parameters
    pub trusting_period: Duration,
    pub max_clock_drift: Duration,

    /// State
    pub latest_height: Height,
    pub frozen: bool,
}

impl ClientState {
    /// canonicalize canonicalizes some fields of specified client state
    /// target fields: latest_height, frozen
    pub fn canonicalize(mut self) -> Self {
        self.latest_height = new_height(self.chain_id.version(), 0);
        self.frozen = false;
        self
    }

    pub fn freeze(mut self) -> Self {
        self.frozen = true;
        self
    }

    pub fn check_header_and_update_state(
        &self,
        now: Time,
        trusted_consensus_state: &ConsensusState,
        header: Header,
    ) -> Result<(ClientState, ConsensusState), Error> {
        // Ensure header is valid
        self.check_header(now, trusted_consensus_state, &header)?;

        let mut new_client_state = self.clone();
        let header_height = header.height();
        if new_client_state.latest_height < header_height {
            new_client_state.latest_height = header_height;
        }

        // Ensure world state is valid
        let account = resolve_account(
            header.state_root(),
            &header.account_proof()?,
            &new_client_state.ibc_store_address,
        )?;

        let new_consensus_state = ConsensusState {
            state_root: account
                .storage_root
                .try_into()
                .map_err(Error::UnexpectedStorageRoot)?,
            timestamp: header.timestamp()?,
            current_validators_hash: header.current_validators_hash(),
            previous_validators_hash: header.previous_validators_hash(),
        };

        Ok((new_client_state, new_consensus_state))
    }

    pub fn check_misbehaviour_and_update_state(
        &self,
        now: Time,
        h1_trusted_cs: &ConsensusState,
        h2_trusted_cs: &ConsensusState,
        misbehaviour: Misbehaviour,
    ) -> Result<ClientState, Error> {
        self.check_header(now, h1_trusted_cs, &misbehaviour.header_1)?;
        self.check_header(now, h2_trusted_cs, &misbehaviour.header_2)?;
        Ok(self.clone().freeze())
    }

    fn check_header(&self, now: Time, cs: &ConsensusState, header: &Header) -> Result<(), Error> {
        // Ensure last consensus state is within the trusting period
        validate_within_trusting_period(
            now,
            self.trusting_period,
            self.max_clock_drift,
            header.timestamp()?,
            cs.timestamp,
        )?;

        // Ensure header revision is same as chain revision
        let header_height = header.height();
        if header_height.revision_number() != self.chain_id.version() {
            return Err(Error::UnexpectedHeaderRevision(
                self.chain_id.version(),
                header_height.revision_number(),
            ));
        }
        // Ensure header is valid
        header.verify(&self.chain_id)
    }
}

// https://github.com/datachainlab/ethereum-ibc-rs/blob/678f0d1efcdb06c5008fcc0a8785838708ee1a7d/crates/ibc/src/client_state.rs#L572
fn validate_within_trusting_period(
    current_timestamp: Time,
    trusting_period: Duration,
    clock_drift: Duration,
    untrusted_header_timestamp: Time,
    trusted_consensus_state_timestamp: Time,
) -> Result<(), Error> {
    let trusting_period_end =
        (trusted_consensus_state_timestamp + trusting_period).map_err(Error::TimeError)?;
    let drifted_current_timestamp = (current_timestamp + clock_drift).map_err(Error::TimeError)?;

    if !trusting_period_end.gt(&current_timestamp) {
        return Err(Error::OutOfTrustingPeriod(
            current_timestamp,
            trusting_period_end,
        ));
    }
    if !drifted_current_timestamp.gt(&untrusted_header_timestamp) {
        return Err(Error::HeaderFromFuture(
            current_timestamp,
            clock_drift,
            untrusted_header_timestamp,
        ));
    }
    Ok(())
}

impl TryFrom<RawClientState> for ClientState {
    type Error = Error;

    fn try_from(value: RawClientState) -> Result<Self, Self::Error> {
        let raw_latest_height = value
            .latest_height
            .as_ref()
            .ok_or(Error::MissingLatestHeight)?;

        let chain_id = ChainId::new(value.chain_id);

        let latest_height = new_height(
            raw_latest_height.revision_number,
            raw_latest_height.revision_height,
        );

        let raw_ibc_store_address = value.ibc_store_address.clone();
        let ibc_store_address = raw_ibc_store_address
            .try_into()
            .map_err(|_| Error::UnexpectedStoreAddress(value.ibc_store_address))?;

        let raw_ibc_commitments_slot = value.ibc_commitments_slot.clone();
        let ibc_commitments_slot = raw_ibc_commitments_slot
            .try_into()
            .map_err(|_| Error::UnexpectedStoreAddress(value.ibc_commitments_slot))?;

        let trusting_period = value
            .trusting_period
            .ok_or(Error::MissingTrustingPeriod)?
            .try_into()
            .map_err(|_| Error::MissingTrustingPeriod)?;

        let max_clock_drift = value
            .max_clock_drift
            .ok_or(Error::NegativeMaxClockDrift)?
            .try_into()
            .map_err(|_| Error::NegativeMaxClockDrift)?;

        let frozen = value.frozen;

        Ok(Self {
            chain_id,
            ibc_store_address,
            ibc_commitments_slot,
            latest_height,
            trusting_period,
            max_clock_drift,
            frozen,
        })
    }
}

impl From<ClientState> for RawClientState {
    fn from(value: ClientState) -> Self {
        Self {
            chain_id: value.chain_id.id(),
            ibc_store_address: value.ibc_store_address.to_vec(),
            ibc_commitments_slot: value.ibc_commitments_slot.to_vec(),
            latest_height: Some(parlia_ibc_proto::ibc::core::client::v1::Height {
                revision_number: value.latest_height.revision_number(),
                revision_height: value.latest_height.revision_height(),
            }),
            trusting_period: Some(value.trusting_period.into()),
            max_clock_drift: Some(value.max_clock_drift.into()),
            frozen: value.frozen.to_owned(),
        }
    }
}

impl TryFrom<IBCAny> for ClientState {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Self, Self::Error> {
        if any.type_url != PARLIA_CLIENT_STATE_TYPE_URL {
            return Err(Error::UnknownClientStateType(any.type_url));
        }
        RawClientState::decode(any.value.as_slice())
            .map_err(Error::ProtoDecodeError)?
            .try_into()
    }
}

impl From<ClientState> for IBCAny {
    fn from(value: ClientState) -> Self {
        let value: RawClientState = value.into();
        let mut v = Vec::new();
        value
            .encode(&mut v)
            .expect("encoding to `Any` from `ParliaClientState`");
        Self {
            type_url: PARLIA_CLIENT_STATE_TYPE_URL.to_owned(),
            value: v,
        }
    }
}

impl From<ClientState> for Any {
    fn from(value: ClientState) -> Self {
        IBCAny::from(value).into()
    }
}

impl TryFrom<Any> for ClientState {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;
    use std::time::Duration;
    use time::{macros::datetime, OffsetDateTime};

    use crate::client_state::{validate_within_trusting_period, ClientState};
    use crate::errors::Error;
    use light_client::types::{Any, Time};

    #[test]
    fn test_try_from_any() {
        let cs = hex!("0a272f6962632e6c69676874636c69656e74732e7061726c69612e76312e436c69656e745374617465124d08381214151f3951fa218cac426edfe078fa9e5c6dcea5001a200000000000000000000000000000000000000000000000000000000000000000220510af9da90f2a040880a305320410c0843d").to_vec();
        let cs: Any = cs.try_into().unwrap();
        let cs: ClientState = cs.try_into().unwrap();

        assert_eq!(0, cs.latest_height.revision_number());
        assert_eq!(32132783, cs.latest_height.revision_height());
        assert_eq!(56, cs.chain_id.id());
        assert_eq!(0, cs.chain_id.version());
        assert_eq!(86400, cs.trusting_period.as_secs());
        assert_eq!(1, cs.max_clock_drift.as_millis());
        assert_eq!(
            hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
            cs.ibc_store_address
        );
        assert_eq!(
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            cs.ibc_commitments_slot
        );
    }

    #[test]
    fn test_trusting_period_validation() {
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let untrusted_header_timestamp = datetime!(2023-08-20 0:00 UTC);
            let trusted_state_timestamp = datetime!(2023-08-20 0:00 UTC);
            validate_and_assert_no_error(
                current_timestamp,
                1,
                1,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
        }

        // trusting_period
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let untrusted_header_timestamp = current_timestamp - Duration::new(0, 1);
            let trusted_state_timestamp = untrusted_header_timestamp - Duration::new(0, 1);
            validate_and_assert_trusting_period_error(
                current_timestamp,
                1,
                0,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
            validate_and_assert_trusting_period_error(
                current_timestamp,
                2,
                0,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
            validate_and_assert_no_error(
                current_timestamp,
                3,
                0,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
        }

        // clock drift
        {
            let current_timestamp = datetime!(2023-08-20 0:00 UTC);
            let untrusted_header_timestamp = current_timestamp + Duration::new(0, 1);
            let trusted_state_timestamp = current_timestamp;
            validate_and_assert_clock_drift_error(
                current_timestamp,
                1,
                0,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
            validate_and_assert_clock_drift_error(
                current_timestamp,
                1,
                1,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
            validate_and_assert_no_error(
                current_timestamp,
                1,
                2,
                untrusted_header_timestamp,
                trusted_state_timestamp,
            );
        }
    }

    fn validate_and_assert_no_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_within_trusting_period(
            Time::from_unix_timestamp_nanos(current_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
            Duration::from_nanos(trusting_period),
            Duration::from_nanos(clock_drift),
            Time::from_unix_timestamp_nanos(
                untrusted_header_timestamp.unix_timestamp_nanos() as u128
            )
            .unwrap(),
            Time::from_unix_timestamp_nanos(trusted_state_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
        );
        assert!(result.is_ok());
    }

    fn validate_and_assert_trusting_period_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_within_trusting_period(
            Time::from_unix_timestamp_nanos(current_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
            Duration::from_nanos(trusting_period),
            Duration::from_nanos(clock_drift),
            Time::from_unix_timestamp_nanos(
                untrusted_header_timestamp.unix_timestamp_nanos() as u128
            )
            .unwrap(),
            Time::from_unix_timestamp_nanos(trusted_state_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
        );
        if let Err(e) = result {
            match e {
                Error::OutOfTrustingPeriod(_current_timestamp, _trusting_period_end) => {}
                _ => panic!("unexpected error: {e}"),
            }
        } else {
            panic!("expected error");
        }
    }

    fn validate_and_assert_clock_drift_error(
        current_timestamp: OffsetDateTime,
        trusting_period: u64,
        clock_drift: u64,
        untrusted_header_timestamp: OffsetDateTime,
        trusted_state_timestamp: OffsetDateTime,
    ) {
        let result = validate_within_trusting_period(
            Time::from_unix_timestamp_nanos(current_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
            Duration::from_nanos(trusting_period),
            Duration::from_nanos(clock_drift),
            Time::from_unix_timestamp_nanos(
                untrusted_header_timestamp.unix_timestamp_nanos() as u128
            )
            .unwrap(),
            Time::from_unix_timestamp_nanos(trusted_state_timestamp.unix_timestamp_nanos() as u128)
                .unwrap(),
        );
        if let Err(e) = result {
            match e {
                Error::HeaderFromFuture(_current_timestamp, _clock_drift, _header_timestamp) => {}
                _ => panic!("unexpected error: {e}"),
            }
        } else {
            panic!("expected error");
        }
    }
}
