use light_client::types::{Any, Height, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

use crate::consensus_state::ConsensusState;
use crate::fork_spec::{find_target_fork_spec, get_boundary_epochs, ForkSpec, HeightOrTimestamp};
use crate::header::epoch::{EitherEpoch, Epoch, TrustedEpoch, UntrustedEpoch};
use crate::header::eth_header::ETHHeader;

use crate::header::eth_headers::ETHHeaders;
use crate::misc::{new_height, new_timestamp, ChainId, Hash};

use super::errors::Error;

pub const PARLIA_HEADER_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Header";

// inner header is module private
pub mod constant;
pub mod eth_header;
pub mod eth_headers;
pub mod validator_set;
pub mod vote_attestation;

pub mod epoch;

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    headers: ETHHeaders,
    trusted_height: Height,
    previous_epoch: Epoch,
    current_epoch: Epoch,

    fork_specs: alloc::vec::Vec<ForkSpec>,
}

impl Header {
    pub(crate) fn eth_header(&self) -> &ETHHeaders {
        &self.headers
    }

    pub fn height(&self) -> Height {
        new_height(
            self.trusted_height.revision_number(),
            self.headers.target.number,
        )
    }

    pub fn timestamp(&self) -> Result<Time, Error> {
        new_timestamp(self.headers.target.milli_timestamp())
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    pub fn state_root(&self) -> &Hash {
        &self.headers.target.root
    }

    pub fn previous_epoch_validators_hash(&self) -> Hash {
        self.previous_epoch.hash()
    }

    pub fn current_epoch_validators_hash(&self) -> Hash {
        self.current_epoch.hash()
    }

    pub fn block_hash(&self) -> &Hash {
        &self.headers.target.hash
    }

    /// Finds the next epoch information based on the given headers.
    ///
    /// This function iterates through the provided headers to find the next epoch information.
    /// It checks if the current epoch block number matches the header number and retrieves the next epoch details.
    pub fn assign_fork_spec(&mut self, fork_specs: &[ForkSpec]) -> Result<(), Error> {
        let mut fork_specs = fork_specs.to_vec();
        for header in &mut self.headers.all {
            header.verify_fork_rule(&fork_specs)?;
        }
        // Ensure HF height is required for target without seeking next headers
        self.headers.target.set_boundary_epochs(&fork_specs)?;
        // Verify epoch is really epoch
        self.headers.target.verify_epoch_info()?;

        // Try to set HF height
        if !fork_specs.is_empty() {
            let last_index = fork_specs.len() - 1;
            let last = &mut fork_specs[last_index];
            if let HeightOrTimestamp::Time(time) = last.height_or_timestamp {
                for header in &mut self.headers.all {
                    if header.milli_timestamp() >= time {
                        last.height_or_timestamp = HeightOrTimestamp::Height(header.number);
                        break;
                    }
                }
            }
        }

        for header in &mut self.headers.all {
            // Set boundary epoch to verify header size.
            header.set_boundary_epochs(&fork_specs)?;
            // Verify epoch is really epoch
            header.verify_epoch_info()?;
        }

        self.fork_specs = fork_specs;
        Ok(())
    }

    pub fn verify(
        &self,
        chain_id: &ChainId,
        consensus_state: &ConsensusState,
    ) -> Result<(), Error> {
        let (c_val, p_val) = verify_epoch(
            consensus_state,
            &self.headers.target,
            self.trusted_height,
            &self.previous_epoch,
            &self.current_epoch,
            &self.fork_specs,
        )?;
        self.headers.verify(chain_id, &c_val, &p_val)
    }
}

/// Verifies the vote attestation of the current `ETHHeader` against its parent header.
///
/// This function checks the vote attestation of the current header to ensure that
/// the target block is the direct parent of the current block and the source block
/// is the highest justified block.
///
fn verify_epoch<'a>(
    consensus_state: &ConsensusState,
    target: &ETHHeader,
    trusted_height: Height,
    previous_epoch: &'a Epoch,
    current_epoch: &'a Epoch,
    fork_specs: &[ForkSpec],
) -> Result<(EitherEpoch<'a>, TrustedEpoch<'a>), Error> {
    let is_epoch = target.is_epoch();

    let trusted_time = (consensus_state.timestamp.as_unix_timestamp_nanos() / 1_000_000) as u64;
    let trusted_fs =
        find_target_fork_spec(fork_specs, trusted_height.revision_height(), trusted_time)?;
    let trusted_epoch = get_boundary_epochs(trusted_fs, fork_specs)?
        .current_epoch_block_number(trusted_height.revision_height());

    if is_epoch {
        let header_previous_epoch = target.previous_epoch_block_number()?;
        if header_previous_epoch != trusted_epoch {
            return Err(Error::UnexpectedTrustedEpoch(
                trusted_height.revision_height(),
                target.number,
                header_previous_epoch,
                trusted_epoch,
            ));
        }
        let previous_trusted = previous_epoch.hash() == consensus_state.current_validators_hash;
        if !previous_trusted {
            return Err(Error::UnexpectedUntrustedValidatorsHashInEpoch(
                trusted_height,
                target.number,
                previous_epoch.hash(),
                consensus_state.current_validators_hash,
                trusted_epoch,
            ));
        }

        let epoch_info = target
            .epoch
            .as_ref()
            .ok_or_else(|| Error::MissingEpochInfoInEpochBlock(target.number))?;
        if epoch_info.hash() != current_epoch.hash() {
            return Err(Error::UnexpectedCurrentValidatorsHashInEpoch(
                trusted_height,
                target.number,
                epoch_info.hash(),
                current_epoch.hash(),
            ));
        }

        Ok((
            EitherEpoch::Untrusted(UntrustedEpoch::new(current_epoch)),
            TrustedEpoch::new(previous_epoch),
        ))
    } else {
        let header_epoch = target.current_epoch_block_number()?;
        if header_epoch != trusted_epoch {
            return Err(Error::UnexpectedTrustedEpoch(
                trusted_height.revision_height(),
                target.number,
                header_epoch,
                trusted_epoch,
            ));
        }
        let previous_trusted = previous_epoch.hash() == consensus_state.previous_validators_hash;
        if !previous_trusted {
            return Err(Error::UnexpectedPreviousValidatorsHash(
                trusted_height,
                target.number,
                previous_epoch.hash(),
                consensus_state.previous_validators_hash,
                trusted_epoch,
            ));
        }
        let current_trusted = current_epoch.hash() == consensus_state.current_validators_hash;
        if !current_trusted {
            return Err(Error::UnexpectedCurrentValidatorsHash(
                trusted_height,
                target.number,
                current_epoch.hash(),
                consensus_state.current_validators_hash,
                trusted_epoch,
            ));
        }
        Ok((
            EitherEpoch::Trusted(TrustedEpoch::new(current_epoch)),
            TrustedEpoch::new(previous_epoch),
        ))
    }
}

impl TryFrom<RawHeader> for Header {
    type Error = Error;

    fn try_from(value: RawHeader) -> Result<Header, Self::Error> {
        let trusted_height = value
            .trusted_height
            .as_ref()
            .ok_or(Error::MissingTrustedHeight)?;
        let trusted_height = new_height(
            trusted_height.revision_number,
            trusted_height.revision_height,
        );

        // All the header revision must be same as the revision of trusted_height.
        let headers = ETHHeaders::try_from(value.headers.clone())?;

        if headers.target.number <= trusted_height.revision_height() {
            return Err(Error::UnexpectedTrustedHeight(
                headers.target.number,
                trusted_height.revision_height(),
            ));
        }

        if value.previous_validators.is_empty() {
            return Err(Error::MissingPreviousValidators(headers.target.number));
        }

        // Epoch header contains validator set
        let current_epoch = headers.target.clone().epoch.unwrap_or(Epoch::new(
            value.current_validators.into(),
            value.current_turn_length as u8,
        ));
        if current_epoch.validators().is_empty() {
            return Err(Error::MissingCurrentValidators(headers.target.number));
        }

        Ok(Self {
            headers,
            trusted_height,
            previous_epoch: Epoch::new(
                value.previous_validators.into(),
                value.previous_turn_length as u8,
            ),
            current_epoch,
            fork_specs: vec![],
        })
    }
}

impl TryFrom<IBCAny> for Header {
    type Error = Error;

    fn try_from(any: IBCAny) -> Result<Header, Self::Error> {
        if any.type_url != PARLIA_HEADER_TYPE_URL {
            return Err(Error::UnknownHeaderType(any.type_url));
        }
        let raw = RawHeader::decode(any.value.as_slice()).map_err(Error::ProtoDecodeError)?;
        raw.try_into()
    }
}

impl TryFrom<Any> for Header {
    type Error = Error;

    fn try_from(any: Any) -> Result<Self, Self::Error> {
        IBCAny::from(any).try_into()
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;

    use crate::fixture::*;
    use crate::header::epoch::{EitherEpoch, Epoch};
    use crate::header::eth_headers::ETHHeaders;
    use crate::header::validator_set::ValidatorSet;
    use crate::header::{verify_epoch, Header};
    use crate::misc::{new_height, Hash, Validators};
    use alloc::boxed::Box;

    use light_client::types::{Height as LCPHeight, Time};
    use parlia_ibc_proto::ibc::core::client::v1::Height;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::{EthHeader, Header as RawHeader};
    use rstest::rstest;

    impl Header {
        pub(crate) fn new(
            headers: ETHHeaders,
            trusted_height: Height,
            previous_epoch: Epoch,
            current_epoch: Epoch,
        ) -> Self {
            Self {
                headers,
                trusted_height: LCPHeight::new(
                    trusted_height.revision_number,
                    trusted_height.revision_height,
                ),
                previous_epoch,
                current_epoch,
                fork_specs: vec![fork_spec_after_pascal(), fork_spec_after_lorentz()],
            }
        }
    }
    const BLOCKS_PER_EPOCH: u64 = 500;

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_missing_trusted_height(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header_plus_1();
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_plus_1_rlp(),
            }],
            trusted_height: None,
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::MissingTrustedHeight => {}
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_unexpected_trusted_height(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header_plus_1();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number,
        };
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_plus_1_rlp(),
            }],
            trusted_height: Some(trusted_height.clone()),
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedTrustedHeight(number, trusted_number) => {
                assert_eq!(number, h.number);
                assert_eq!(trusted_number, trusted_height.revision_height);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_previous_validators_is_empty(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header_plus_1();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_plus_1_rlp(),
            }],
            trusted_height: Some(trusted_height),
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![],
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::MissingPreviousValidators(number) => {
                assert_eq!(number, h.number);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_current_validators_is_empty(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header_plus_1();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_plus_1_rlp(),
            }],
            trusted_height: Some(trusted_height),
            current_validators: vec![],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::MissingCurrentValidators(number) => {
                assert_eq!(number, h.number);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_try_from(#[case] hp: Box<dyn Network>) {
        let h = &hp.epoch_header();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![EthHeader {
                header: hp.epoch_header_rlp(),
            }],
            trusted_height: Some(trusted_height.clone()),
            current_validators: hp.epoch_header().epoch.unwrap().validators().clone(),
            previous_validators: hp.previous_validators(),
            current_turn_length: 1,
            previous_turn_length: 1,
        };
        let mut result = Header::try_from(raw.clone()).unwrap();
        result
            .headers
            .target
            .set_boundary_epochs(&[fork_spec_after_pascal(), fork_spec_after_lorentz()])
            .unwrap();
        assert_eq!(result.headers.target, *h);
        assert_eq!(
            result.trusted_height.revision_height(),
            trusted_height.revision_height
        );
        assert_eq!(
            result.trusted_height.revision_number(),
            trusted_height.revision_number
        );
        assert_eq!(result.previous_epoch.validators(), &raw.previous_validators);
        assert_eq!(result.current_epoch.validators(), &raw.current_validators);
    }

    fn to_validator_set(h: Hash) -> ValidatorSet {
        let validators: Validators = vec![vec![1]];
        let mut v: ValidatorSet = validators.into();
        v.hash = h;
        v
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_validator_set(#[case] hp: Box<dyn Network>) {
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: Epoch::new(to_validator_set([1u8; 32]), 1).hash(),
            previous_validators_hash: Epoch::new(to_validator_set([2u8; 32]), 1).hash(),
        };

        // epoch
        let header = hp.epoch_header();
        let trusted_height = new_height(0, header.number - 1);
        let current_epoch = &hp.epoch_header().epoch.unwrap();
        let previous_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let (c_val, _) = verify_epoch(
            &cs,
            &hp.epoch_header(),
            trusted_height,
            previous_epoch,
            current_epoch,
            &[fork_spec_after_pascal(), fork_spec_after_lorentz()],
        )
        .unwrap();
        match c_val {
            EitherEpoch::Untrusted(_r) => {}
            _ => unreachable!("unexpected trusted"),
        }

        // not epoch
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: Epoch::new(to_validator_set([1u8; 32]), 1).hash(),
            previous_validators_hash: Epoch::new(to_validator_set([2u8; 32]), 1).hash(),
        };
        let header = hp.epoch_header_plus_1();
        let trusted_height = new_height(0, hp.epoch_header().number);
        let current_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([2u8; 32]), 1);
        let (c_val, _p_val) = verify_epoch(
            &cs,
            &header,
            trusted_height,
            previous_epoch,
            current_epoch,
            &[fork_spec_after_pascal(), fork_spec_after_lorentz()],
        )
        .unwrap();
        match c_val {
            EitherEpoch::Trusted(r) => {
                assert_eq!(r.validators(), current_epoch.validators());
            }
            _ => unreachable!("unexpected untrusted"),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_validator_set(#[case] hp: Box<dyn Network>) {
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: Epoch::new(to_validator_set([1u8; 32]), 1).hash(),
            previous_validators_hash: Epoch::new(to_validator_set([2u8; 32]), 1).hash(),
        };

        let trusted_height = new_height(0, BLOCKS_PER_EPOCH - 1);
        let current_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([2u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header(),
            trusted_height,
            previous_epoch,
            current_epoch,
            &[fork_spec_after_pascal(), fork_spec_after_lorentz()],
        )
        .unwrap_err();
        match err {
            Error::UnexpectedTrustedEpoch(t, _, _, _) => {
                assert_eq!(t, trusted_height.revision_height());
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height =
            new_height(0, hp.epoch_header().previous_epoch_block_number().unwrap());
        let err = verify_epoch(
            &cs,
            &hp.epoch_header(),
            trusted_height,
            previous_epoch,
            current_epoch,
            &[fork_spec_after_pascal(), fork_spec_after_lorentz()],
        )
        .unwrap_err();
        match err {
            Error::UnexpectedUntrustedValidatorsHashInEpoch(t, _, hash, cons_hash, _) => {
                assert_eq!(t, trusted_height);
                assert_eq!(hash, previous_epoch.hash());
                assert_eq!(cons_hash, cs.current_validators_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(0, BLOCKS_PER_EPOCH);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header_plus_1(),
            trusted_height,
            previous_epoch,
            current_epoch,
            &[fork_spec_after_pascal(), fork_spec_after_lorentz()],
        )
        .unwrap_err();
        match err {
            Error::UnexpectedTrustedEpoch(t, _, _, _) => {
                assert_eq!(t, trusted_height.revision_height());
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(
            0,
            hp.epoch_header_plus_1()
                .current_epoch_block_number()
                .unwrap(),
        );
        let current_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([3u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header_plus_1(),
            trusted_height,
            previous_epoch,
            current_epoch,
            &[fork_spec_after_pascal(), fork_spec_after_lorentz()],
        )
        .unwrap_err();
        match err {
            Error::UnexpectedPreviousValidatorsHash(t, _, hash, cons_hash, _) => {
                assert_eq!(t, trusted_height);
                assert_eq!(hash, previous_epoch.hash());
                assert_eq!(cons_hash, cs.previous_validators_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(0, hp.epoch_header().current_epoch_block_number().unwrap());
        let current_epoch = &Epoch::new(to_validator_set([3u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([2u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header_plus_1(),
            trusted_height,
            previous_epoch,
            current_epoch,
            &[fork_spec_after_pascal(), fork_spec_after_lorentz()],
        )
        .unwrap_err();
        match err {
            Error::UnexpectedCurrentValidatorsHash(t, _, hash, cons_hash, _) => {
                assert_eq!(t, trusted_height);
                assert_eq!(hash, current_epoch.hash());
                assert_eq!(cons_hash, cs.current_validators_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: Epoch::new(to_validator_set([4u8; 32]), 1).hash(),
            previous_validators_hash: Epoch::new(to_validator_set([2u8; 32]), 1).hash(),
        };
        let trusted_height =
            new_height(0, hp.epoch_header().previous_epoch_block_number().unwrap());
        let current_epoch = &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch = &Epoch::new(to_validator_set([4u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &hp.epoch_header(),
            trusted_height,
            previous_epoch,
            current_epoch,
            &[fork_spec_after_pascal(), fork_spec_after_lorentz()],
        )
        .unwrap_err();
        match err {
            Error::UnexpectedCurrentValidatorsHashInEpoch(t, _, header_hash, request_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(header_hash, hp.epoch_header().epoch.unwrap().hash());
                assert_eq!(request_hash, current_epoch.hash());
            }
            _ => unreachable!("err {:?}", err),
        }
    }
}
