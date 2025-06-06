use alloc::borrow::ToOwned as _;
use alloc::vec::Vec;
use core::time::Duration;

use light_client::types::{Any, Height, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::ClientState as RawClientState;

use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::fork_spec::{ForkSpec, HeightOrTimestamp};
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

    /// fork specs
    pub fork_specs: Vec<ForkSpec>,
}

impl ClientState {
    /// canonicalize canonicalizes some fields of specified client state
    /// target fields: latest_height, frozen
    pub fn canonicalize(mut self) -> Self {
        self.latest_height = new_height(self.chain_id.version(), 0);
        self.frozen = false;
        self.fork_specs = vec![];
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
        mut header: Header,
    ) -> Result<(ClientState, ConsensusState), Error> {
        // Ensure header is valid
        self.check_header(now, trusted_consensus_state, &mut header)?;
        let mut new_client_state = self.clone();

        // Update fork specs if timestamp
        for fs in &mut new_client_state.fork_specs.iter_mut() {
            if let HeightOrTimestamp::Time(ts) = fs.height_or_timestamp {
                // second must be forks spec timestamp
                if header.eth_header().all.len() >= 2 {
                    let h = &header.eth_header().all[1];
                    if ts <= h.milli_timestamp() {
                        fs.height_or_timestamp = HeightOrTimestamp::Height(h.number)
                    }
                }
            }
        }

        let header_height = header.height();
        if new_client_state.latest_height < header_height {
            new_client_state.latest_height = header_height;
        }

        let new_consensus_state = ConsensusState {
            state_root: *header.state_root(),
            timestamp: header.timestamp()?,
            current_validators_hash: header.current_epoch_validators_hash(),
            previous_validators_hash: header.previous_epoch_validators_hash(),
        };

        Ok((new_client_state, new_consensus_state))
    }

    pub fn check_misbehaviour_and_update_state(
        &self,
        now: Time,
        h1_trusted_cs: &ConsensusState,
        h2_trusted_cs: &ConsensusState,
        misbehaviour: &mut Misbehaviour,
    ) -> Result<ClientState, Error> {
        self.check_header(now, h1_trusted_cs, &mut misbehaviour.header_1)?;
        self.check_header(now, h2_trusted_cs, &mut misbehaviour.header_2)?;
        Ok(self.clone().freeze())
    }

    fn check_header(
        &self,
        now: Time,
        cs: &ConsensusState,
        header: &mut Header,
    ) -> Result<(), Error> {
        // Ensure last consensus state is within the trusting period
        let ts = header.timestamp()?;
        validate_within_trusting_period(
            now,
            self.trusting_period,
            self.max_clock_drift,
            ts,
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

        // Ensure satisfying fork specs
        header.assign_fork_spec(&self.fork_specs)?;

        // Ensure header is valid
        header.verify(&self.chain_id, cs)
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

        if chain_id.version() != raw_latest_height.revision_number {
            return Err(Error::UnexpectedLatestHeightRevision(
                chain_id.version(),
                raw_latest_height.revision_number,
            ));
        }

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
            .map_err(|_| Error::UnexpectedCommitmentSlot(value.ibc_commitments_slot))?;

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

        let mut fork_specs = Vec::with_capacity(value.fork_specs.len());
        for fs in value.fork_specs {
            let fork_spec = ForkSpec::try_from(fs)?;
            fork_specs.push(fork_spec)
        }

        Ok(Self {
            chain_id,
            ibc_store_address,
            ibc_commitments_slot,
            latest_height,
            trusting_period,
            max_clock_drift,
            frozen,
            fork_specs,
        })
    }
}

impl From<ClientState> for RawClientState {
    fn from(value: ClientState) -> Self {
        let fork_specs = value.fork_specs.into_iter().map(|fs| fs.into()).collect();
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
            fork_specs,
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

impl TryFrom<ClientState> for IBCAny {
    type Error = Error;

    fn try_from(value: ClientState) -> Result<Self, Self::Error> {
        let value: RawClientState = value.into();
        let mut v = Vec::new();
        value.encode(&mut v).map_err(Error::ProtoEncodeError)?;
        Ok(Self {
            type_url: PARLIA_CLIENT_STATE_TYPE_URL.to_owned(),
            value: v,
        })
    }
}

impl TryFrom<ClientState> for Any {
    type Error = Error;
    fn try_from(value: ClientState) -> Result<Self, Error> {
        Ok(IBCAny::try_from(value)?.into())
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
    use parlia_ibc_proto::ibc::core::client::v1::Height;
    use rstest::rstest;

    use crate::consensus_state::ConsensusState;
    use crate::fixture::*;
    use crate::header::epoch::Epoch;
    use crate::header::eth_header::ETHHeader;
    use crate::header::eth_headers::ETHHeaders;

    use crate::fork_spec::{ForkSpec, HeightOrTimestamp};
    use crate::header::Header;
    use crate::misc::{new_timestamp, ChainId};
    use alloc::boxed::Box;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::ForkSpec as RawForkSpec;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::{
        ClientState as RawClientState, EthHeader,
    };

    fn after_pascal() -> ForkSpec {
        ForkSpec {
            height_or_timestamp: HeightOrTimestamp::Height(0),
            additional_header_item_count: 1, // requestsHash
            epoch_length: 200,
            max_turn_length: 9,
            enable_header_msec: false,
            gas_limit_bound_divider: 256,
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_check_header_and_update_state(#[case] hp: Box<dyn Network>) {
        let cs = ClientState {
            chain_id: hp.network(),
            ibc_store_address: [0u8; 20],
            ibc_commitments_slot: [0u8; 32],
            trusting_period: Duration::from_millis(1001),
            max_clock_drift: Default::default(),
            latest_height: Default::default(),
            frozen: false,
            fork_specs: vec![after_pascal()],
        };

        // fail: check_header
        let h = &hp.epoch_header();
        let cons_state = ConsensusState {
            state_root: [0u8; 32],
            timestamp: new_timestamp(h.milli_timestamp()).unwrap(),
            current_validators_hash: hp.previous_epoch_header().epoch.unwrap().hash(),
            previous_validators_hash: hp.previous_epoch_header().epoch.unwrap().hash(),
        };
        let header = Header::new(
            ETHHeaders {
                target: hp.epoch_header(),
                all: vec![],
            },
            Height {
                revision_number: 0,
                revision_height: h.number - 1,
            },
            hp.previous_epoch_header().epoch.unwrap(),
            hp.epoch_header().epoch.unwrap(),
        );
        let now = new_timestamp(h.milli_timestamp() + 1).unwrap();
        let err = cs
            .check_header_and_update_state(now, &cons_state, header.clone())
            .unwrap_err();
        match err {
            Error::InvalidVerifyingHeaderLength(number, size) => {
                assert_eq!(number, h.number);
                assert_eq!(size, header.eth_header().all.len());
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_check_header(#[case] hp: Box<dyn Network>) {
        let header_fn = |revision: u64, h: &ETHHeader, h_rlp: alloc::vec::Vec<u8>| {
            let trusted_height = Height {
                revision_number: revision,
                revision_height: h.number - 1,
            };
            let raw = RawHeader {
                headers: vec![EthHeader { header: h_rlp }],
                trusted_height: Some(trusted_height),
                current_validators: if h.is_epoch() {
                    h.epoch.clone().unwrap().validators().clone()
                } else {
                    vec![h.coinbase.clone()]
                },
                previous_validators: vec![h.coinbase.clone()],
                previous_turn_length: 1,
                current_turn_length: 1,
            };
            raw.try_into().unwrap()
        };

        let cs = ClientState {
            chain_id: ChainId::new(10),
            ibc_store_address: [0u8; 20],
            ibc_commitments_slot: [0u8; 32],
            trusting_period: Duration::from_millis(1001),
            max_clock_drift: Default::default(),
            latest_height: Default::default(),
            frozen: false,
            fork_specs: vec![after_pascal()],
        };
        let mut cons_state = ConsensusState {
            state_root: [0u8; 32],
            timestamp: new_timestamp(0).unwrap(),
            current_validators_hash: Epoch::new(vec![[0u8; 20].to_vec()].into(), 1).hash(),
            previous_validators_hash: Epoch::new(vec![[0u8; 20].to_vec()].into(), 1).hash(),
        };

        // fail: validate_trusting_period
        let h = hp.epoch_header();
        let now = new_timestamp(h.milli_timestamp() - 1).unwrap();
        cons_state.timestamp = new_timestamp(h.milli_timestamp()).unwrap();
        let mut header = header_fn(0, &h, hp.epoch_header_rlp());
        let err = cs.check_header(now, &cons_state, &mut header).unwrap_err();
        match err {
            Error::HeaderFromFuture(_, _, _) => {}
            err => unreachable!("{:?}", err),
        }

        // fail: revision check
        let h = hp.epoch_header();
        let now = new_timestamp(h.milli_timestamp() + 1).unwrap();
        cons_state.timestamp = new_timestamp(h.milli_timestamp()).unwrap();
        let mut header = header_fn(1, &h, hp.epoch_header_rlp());
        let err = cs.check_header(now, &cons_state, &mut header).unwrap_err();
        match err {
            Error::UnexpectedHeaderRevision(n1, n2) => {
                assert_eq!(cs.chain_id.version(), n1);
                assert_eq!(header.height().revision_number(), n2);
            }
            err => unreachable!("{:?}", err),
        }

        // fail: verify_validator_set
        let h = hp.epoch_header();
        let mut header = header_fn(0, &h, hp.epoch_header_rlp());
        let err = cs.check_header(now, &cons_state, &mut header).unwrap_err();
        match err {
            Error::UnexpectedUntrustedValidatorsHashInEpoch(h1, h2, _, _, _) => {
                assert_eq!(h1.revision_height(), h.number - 1);
                assert_eq!(h2, h.number);
            }
            err => unreachable!("{:?}", err),
        }

        // fail: header.verify
        let h = hp.epoch_header();
        cons_state.current_validators_hash = Epoch::new(vec![h.coinbase.clone()].into(), 1).hash();
        let mut header = header_fn(0, &h, hp.epoch_header_rlp());
        let err = cs.check_header(now, &cons_state, &mut header).unwrap_err();
        match err {
            Error::UnexpectedCoinbase(number) => {
                assert_eq!(number, h.number);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[test]
    fn test_success_try_from_any() {
        let cs = hex!("0a272f6962632e6c69676874636c69656e74732e7061726c69612e76312e436c69656e7453746174651253088f4e1214aa43d337145e8930d01cb4e60abf6595c692921e1a201ee222554989dda120e26ecacf756fe1235cd8d726706b57517715dde4f0c900220410dffb012a040880a305320410c0843d420410001815").to_vec();
        let cs: Any = cs.try_into().unwrap();
        let cs: ClientState = cs.try_into().unwrap();

        assert_eq!(0, cs.latest_height.revision_number());
        assert_eq!(32223, cs.latest_height.revision_height());
        assert_eq!(9999, cs.chain_id.id());
        assert_eq!(0, cs.chain_id.version());
        assert_eq!(86400, cs.trusting_period.as_secs());
        assert_eq!(1, cs.max_clock_drift.as_millis());
        assert_eq!(
            hex!("aa43d337145E8930d01cb4E60Abf6595C692921E"),
            cs.ibc_store_address
        );
        assert_eq!(
            hex!("1ee222554989dda120e26ecacf756fe1235cd8d726706b57517715dde4f0c900"),
            cs.ibc_commitments_slot
        );
    }

    #[test]
    fn test_error_try_from() {
        let mut cs = RawClientState {
            chain_id: 9999,
            ibc_store_address: vec![0],
            ibc_commitments_slot: vec![1],
            latest_height: None,
            trusting_period: None,
            max_clock_drift: None,
            frozen: false,
            fork_specs: vec![RawForkSpec::from(after_pascal())],
        };
        let err = ClientState::try_from(cs.clone()).unwrap_err();
        match err {
            Error::MissingLatestHeight => {}
            err => unreachable!("{:?}", err),
        }

        cs.latest_height = Some(Height {
            revision_number: 1,
            revision_height: 0,
        });
        let err = ClientState::try_from(cs.clone()).unwrap_err();
        match err {
            Error::UnexpectedLatestHeightRevision(e1, e2) => {
                assert_eq!(e1, 0);
                assert_eq!(e2, 1);
            }
            err => unreachable!("{:?}", err),
        }

        cs.latest_height = Some(Height::default());
        let err = ClientState::try_from(cs.clone()).unwrap_err();
        match err {
            Error::UnexpectedStoreAddress(address) => {
                assert_eq!(address, vec![0]);
            }
            err => unreachable!("{:?}", err),
        }

        cs.ibc_store_address = [1u8; 20].to_vec();
        let err = ClientState::try_from(cs.clone()).unwrap_err();
        match err {
            Error::UnexpectedCommitmentSlot(address) => {
                assert_eq!(address, vec![1]);
            }
            err => unreachable!("{:?}", err),
        }

        cs.ibc_commitments_slot = [1u8; 32].to_vec();
        let err = ClientState::try_from(cs.clone()).unwrap_err();
        match err {
            Error::MissingTrustingPeriod => {}
            err => unreachable!("{:?}", err),
        }

        cs.trusting_period = Some(parlia_ibc_proto::google::protobuf::Duration::default());
        let err = ClientState::try_from(cs).unwrap_err();
        match err {
            Error::NegativeMaxClockDrift => {}
            err => unreachable!("{:?}", err),
        }
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
