use alloc::vec::Vec;

use light_client::types::{Any, Height, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

use crate::commitment::decode_eip1184_rlp_proof;
use crate::consensus_state::ConsensusState;
use crate::header::epoch::{EitherEpoch, Epoch, TrustedEpoch, UntrustedEpoch};
use crate::header::eth_header::ETHHeader;

use crate::header::eth_headers::ETHHeaders;
use crate::misc::{new_height, new_timestamp, ChainId, Hash};

use super::errors::Error;

use self::constant::BLOCKS_PER_EPOCH;

pub const PARLIA_HEADER_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Header";

// inner header is module private
pub mod constant;
pub mod eth_header;
pub mod eth_headers;
pub mod validator_set;
pub mod vote_attestation;

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    account_proof: Vec<u8>,
    headers: ETHHeaders,
    trusted_height: Height,
    previous_epoch: Epoch,
    current_epoch: Epoch,
}

impl Header {
    pub fn height(&self) -> Height {
        new_height(
            self.trusted_height.revision_number(),
            self.headers.target.number,
        )
    }

    pub fn timestamp(&self) -> Result<Time, Error> {
        new_timestamp(self.headers.target.timestamp)
    }

    pub fn account_proof(&self) -> Result<Vec<Vec<u8>>, Error> {
        decode_eip1184_rlp_proof(&self.account_proof)
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

    pub fn verify(
        &self,
        chain_id: &ChainId,
        consensus_state: &ConsensusState,
    ) -> Result<(), Error> {
        let (c_val, p_val) = verify_epoch(
            consensus_state,
            &self.headers.target,
            self.height(),
            self.trusted_height,
            &self.previous_epoch,
            &self.current_epoch,
        )?;
        self.headers.verify(chain_id, &c_val, &p_val)
    }
}

fn verify_epoch<'a>(
    consensus_state: &ConsensusState,
    target: &ETHHeader,
    height: Height,
    trusted_height: Height,
    previous_epoch: &'a Epoch,
    current_epoch: &'a Epoch,
) -> Result<(EitherEpoch<'a>, TrustedEpoch<'a>), Error> {
    let is_epoch = target.is_epoch();
    let header_epoch = height.revision_height() / BLOCKS_PER_EPOCH;
    let trusted_epoch = trusted_height.revision_height() / BLOCKS_PER_EPOCH;

    if is_epoch {
        if header_epoch != trusted_epoch + 1 {
            return Err(Error::UnexpectedTrustedHeight(
                trusted_height.revision_height(),
                height.revision_height(),
            ));
        }
        let previous_trusted = previous_epoch.hash() == consensus_state.current_validators_hash;
        if !previous_trusted {
            return Err(Error::UnexpectedPreviousValidatorsHash(
                trusted_height,
                height,
                previous_epoch.hash(),
                consensus_state.current_validators_hash,
            ));
        }

        let val_in_extra = target.get_validator_set()?;
        if val_in_extra.hash != current_epoch.hash() {
            return Err(Error::UnexpectedCurrentValidatorsHash(
                trusted_height,
                height,
                val_in_extra.hash,
                current_epoch.hash(),
            ));
        }

        Ok((
            EitherEpoch::Untrusted(UntrustedEpoch::new(current_epoch)),
            TrustedEpoch::new(previous_epoch),
        ))
    } else {
        if header_epoch != trusted_epoch {
            return Err(Error::UnexpectedTrustedHeight(
                trusted_height.revision_height(),
                height.revision_height(),
            ));
        }
        let previous_trusted = previous_epoch.hash() == consensus_state.previous_validators_hash;
        if !previous_trusted {
            return Err(Error::UnexpectedPreviousValidatorsHash(
                trusted_height,
                height,
                previous_epoch.hash(),
                consensus_state.previous_validators_hash,
            ));
        }
        let current_trusted = current_epoch.hash() == consensus_state.current_validators_hash;
        if !current_trusted {
            return Err(Error::UnexpectedCurrentValidatorsHash(
                trusted_height,
                height,
                current_epoch.hash(),
                consensus_state.current_validators_hash,
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
        let current_validators = if headers.target.is_epoch() {
            headers
                .target
                .get_validator_bytes()
                .ok_or_else(|| Error::MissingValidatorInEpochBlock(headers.target.number))?
        } else {
            value.current_validators
        };
        if current_validators.is_empty() {
            return Err(Error::MissingCurrentValidators(headers.target.number));
        }

        Ok(Self {
            account_proof: value.account_proof,
            headers,
            trusted_height,
            previous_epoch: Epoch::new(value.previous_validators.into(), value.previous_turn_term as u8),
            current_epoch: Epoch::new(current_validators.into(), value.current_turn_term as u8),
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
pub(crate) mod testdata;
mod epoch;

#[cfg(test)]
pub(crate) mod test {
    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;

    use crate::header::eth_headers::ETHHeaders;
    use crate::header::testdata::{header_31297200, header_31297201, validators_in_31297000};
    use crate::header::validator_set::ValidatorSet;
    use crate::header::{verify_epoch, Header};
    use crate::misc::{new_height, Hash, Validators};
    use light_client::types::Time;
    use parlia_ibc_proto::ibc::core::client::v1::Height;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;
    use crate::header::epoch::{EitherEpoch, Epoch};

    impl Header {
        pub(crate) fn eth_header(&self) -> &ETHHeaders {
            &self.headers
        }
    }

    #[test]
    fn test_error_try_from_missing_trusted_height() {
        let h = &header_31297201();
        let raw = RawHeader {
            headers: vec![h.try_into().unwrap()],
            trusted_height: None,
            account_proof: vec![],
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_term: 1,
            previous_turn_term: 1
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::MissingTrustedHeight => {}
            err => unreachable!("{:?}", err),
        }
    }

    #[test]
    fn test_error_try_from_unexpected_trusted_height() {
        let h = &header_31297201();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number,
        };
        let raw = RawHeader {
            headers: vec![h.try_into().unwrap()],
            trusted_height: Some(trusted_height.clone()),
            account_proof: vec![],
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_term: 1,
            previous_turn_term: 1
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

    #[test]
    fn test_error_try_from_previous_validators_is_empty() {
        let h = &header_31297201();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![h.try_into().unwrap()],
            trusted_height: Some(trusted_height),
            account_proof: vec![],
            current_validators: vec![h.coinbase.clone()],
            previous_validators: vec![],
            current_turn_term: 1,
            previous_turn_term: 1
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::MissingPreviousValidators(number) => {
                assert_eq!(number, h.number);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[test]
    fn test_error_try_from_current_validators_is_empty() {
        let h = &header_31297201();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![h.try_into().unwrap()],
            trusted_height: Some(trusted_height),
            account_proof: vec![],
            current_validators: vec![],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_term: 1,
            previous_turn_term: 1
        };
        let err = Header::try_from(raw).unwrap_err();
        match err {
            Error::MissingCurrentValidators(number) => {
                assert_eq!(number, h.number);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[test]
    fn test_success_try_from() {
        let h = &header_31297200();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![h.try_into().unwrap()],
            trusted_height: Some(trusted_height.clone()),
            account_proof: vec![],
            current_validators: header_31297200().get_validator_bytes().unwrap(),
            previous_validators: validators_in_31297000(),
            current_turn_term: 1,
            previous_turn_term: 1
        };
        let result = Header::try_from(raw.clone()).unwrap();
        assert_eq!(result.headers.target, *h);
        assert_eq!(
            result.trusted_height.revision_height(),
            trusted_height.revision_height
        );
        assert_eq!(
            result.trusted_height.revision_number(),
            trusted_height.revision_number
        );
        assert_eq!(
            result.previous_epoch.validators(),
            &raw.previous_validators
        );
        assert_eq!(
            result.current_epoch.validators(),
            &raw.current_validators
        );
    }

    #[test]
    fn test_success_try_from2() {
        let h = &header_31297201();
        let trusted_height = Height {
            revision_number: 0,
            revision_height: h.number - 1,
        };
        let raw = RawHeader {
            headers: vec![h.try_into().unwrap()],
            trusted_height: Some(trusted_height.clone()),
            account_proof: vec![],
            current_validators: vec![header_31297200().coinbase],
            previous_validators: vec![h.coinbase.clone()],
            current_turn_term: 1,
            previous_turn_term: 1
        };
        let result = Header::try_from(raw.clone()).unwrap();
        assert_eq!(result.headers.target, *h);
        assert_eq!(
            result.trusted_height.revision_height(),
            trusted_height.revision_height
        );
        assert_eq!(
            result.trusted_height.revision_number(),
            trusted_height.revision_number
        );
        assert_eq!(
            result.previous_epoch.validators(),
            &raw.previous_validators
        );
        assert_eq!(
            result.current_epoch.validators(),
            &raw.current_validators
        );
    }

    fn to_validator_set(h: Hash) -> ValidatorSet {
        let validators: Validators = vec![vec![1]];
        let mut v: ValidatorSet = validators.into();
        v.hash = h;
        v
    }

    #[test]
    fn test_success_verify_validator_set() {
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: [1u8; 32],
            previous_validators_hash: [2u8; 32],
        };

        // epoch
        let height = new_height(0, 400);
        let trusted_height = new_height(0, 201);
        let current_epoch= &Epoch::new(header_31297200().get_validator_set().unwrap(), 1);
        let previous_epoch= &Epoch::new(to_validator_set(cs.current_validators_hash), 1);
        let (c_val, p_val) = verify_epoch(
            &cs,
            &header_31297200(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap();
        match c_val {
            EitherEpoch::Untrusted(r) => {
                assert!(r.try_borrow(&p_val).is_err())
            }
            _ => unreachable!("unexpected trusted"),
        }

        // not epoch
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: [1u8; 32],
            previous_validators_hash: [2u8; 32],
        };
        let height = new_height(0, 599);
        let trusted_height = new_height(0, 400);
        let current_epoch= &Epoch::new(to_validator_set(cs.current_validators_hash), 1);
        let previous_epoch= &Epoch::new(to_validator_set(cs.previous_validators_hash), 1);
        let (c_val, _p_val) = verify_epoch(
            &cs,
            &header_31297201(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap();
        match c_val {
            EitherEpoch::Trusted(r) => {
                assert_eq!(r.validators(), current_epoch.validators());
            }
            _ => unreachable!("unexpected untrusted"),
        }
    }

    #[test]
    fn test_error_verify_validator_set() {
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: [1u8; 32],
            previous_validators_hash: [2u8; 32],
        };

        let height = new_height(0, 400);
        let trusted_height = new_height(0, 199);
        let current_epoch= &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch= &Epoch::new(to_validator_set([2u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &header_31297200(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedTrustedHeight(t, h) => {
                assert_eq!(t, trusted_height.revision_height());
                assert_eq!(h, height.revision_height());
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(0, 200);
        let previous_validators = &Epoch::new(to_validator_set([3u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &header_31297200(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedPreviousValidatorsHash(t, h, hash, cons_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(hash, previous_epoch.hash());
                assert_eq!(cons_hash, cons_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let height = new_height(0, 401);
        let trusted_height = new_height(0, 200);
        let err = verify_epoch(
            &cs,
            &header_31297201(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedTrustedHeight(t, h) => {
                assert_eq!(t, trusted_height.revision_height());
                assert_eq!(h, height.revision_height());
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(0, 400);
        let current_epoch= &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch= &Epoch::new(to_validator_set([3u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &header_31297201(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedPreviousValidatorsHash(t, h, hash, cons_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(hash, previous_epoch.hash());
                assert_eq!(cons_hash, cons_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(0, 400);
        let current_epoch= &Epoch::new(to_validator_set([3u8; 32]), 1);
        let previous_epoch= &Epoch::new(to_validator_set([2u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &header_31297201(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedCurrentValidatorsHash(t, h, hash, cons_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(hash, current_epoch.hash());
                assert_eq!(cons_hash, cons_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: [4u8; 32],
            previous_validators_hash: [2u8; 32],
        };
        let height = new_height(0, 400);
        let trusted_height = new_height(0, 399);
        let current_epoch= &Epoch::new(to_validator_set([1u8; 32]), 1);
        let previous_epoch= &Epoch::new(to_validator_set([4u8; 32]), 1);
        let err = verify_epoch(
            &cs,
            &header_31297200(),
            height,
            trusted_height,
            previous_epoch,
            current_epoch,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedCurrentValidatorsHash(t, h, header_hash, request_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(
                    header_hash,
                    header_31297200().get_validator_set().unwrap().hash
                );
                assert_eq!(request_hash, current_epoch.hash());
            }
            _ => unreachable!("err {:?}", err),
        }
    }
}
