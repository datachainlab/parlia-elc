use alloc::vec::Vec;

use light_client::types::{Any, Height, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

use crate::commitment::decode_eip1184_rlp_proof;
use crate::consensus_state::ConsensusState;

use crate::header::eth_headers::ETHHeaders;
use crate::header::validator_set::ValidatorSet;
use crate::misc::{new_height, new_timestamp, ChainId, Hash};

use super::errors::Error;

use self::constant::BLOCKS_PER_EPOCH;

pub const PARLIA_HEADER_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Header";

// inner header is module private
pub mod constant;
mod eth_header;
mod eth_headers;
pub(crate) mod validator_set;
mod vote_attestation;

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    account_proof: Vec<u8>,
    headers: ETHHeaders,
    trusted_height: Height,
    previous_validators: ValidatorSet,
    current_validators: ValidatorSet,
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

    pub fn previous_validators_hash(&self) -> Hash {
        self.previous_validators.hash
    }

    pub fn current_validators_hash(&self) -> Hash {
        self.current_validators.hash
    }

    pub fn verify(&self, chain_id: &ChainId) -> Result<(), Error> {
        self.headers.verify(
            chain_id,
            &self.current_validators.validators,
            &self.previous_validators.validators,
        )
    }

    pub fn block_hash(&self) -> &Hash {
        &self.headers.target.hash
    }

    pub fn verify_validator_set(&self, consensus_state: &ConsensusState) -> Result<(), Error> {
        verify_validator_set(
            consensus_state,
            self.headers.target.is_epoch(),
            self.height(),
            self.trusted_height,
            self.previous_validators_hash(),
            self.current_validators_hash(),
        )
    }
}

fn verify_validator_set(
    consensus_state: &ConsensusState,
    is_epoch: bool,
    height: Height,
    trusted_height: Height,
    previous_validators_hash: Hash,
    current_validators_hash: Hash,
) -> Result<(), Error> {
    let header_epoch = height.revision_height() / BLOCKS_PER_EPOCH;
    let trusted_epoch = trusted_height.revision_height() / BLOCKS_PER_EPOCH;

    if is_epoch {
        if header_epoch != trusted_epoch + 1 {
            return Err(Error::UnexpectedTrustedHeight(
                trusted_height.revision_height(),
                height.revision_height(),
            ));
        }
        if previous_validators_hash != consensus_state.current_validators_hash {
            return Err(Error::UnexpectedPreviousValidatorsHash(
                trusted_height,
                height,
                previous_validators_hash,
                consensus_state.current_validators_hash,
            ));
        }
    } else {
        if header_epoch != trusted_epoch {
            return Err(Error::UnexpectedTrustedHeight(
                trusted_height.revision_height(),
                height.revision_height(),
            ));
        }
        if previous_validators_hash != consensus_state.previous_validators_hash {
            return Err(Error::UnexpectedPreviousValidatorsHash(
                trusted_height,
                height,
                previous_validators_hash,
                consensus_state.previous_validators_hash,
            ));
        }
        if current_validators_hash != consensus_state.current_validators_hash {
            return Err(Error::UnexpectedCurrentValidatorsHash(
                trusted_height,
                height,
                current_validators_hash,
                consensus_state.current_validators_hash,
            ));
        }
    }
    Ok(())
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

        let previous_validators: ValidatorSet = value.previous_validators.into();
        if previous_validators.validators.is_empty() {
            return Err(Error::MissingPreviousTrustedValidators(
                headers.target.number,
            ));
        }

        // Epoch header contains validator set
        let current_validators: ValidatorSet = if headers.target.is_epoch() {
            headers
                .target
                .get_validator_bytes()
                .ok_or_else(|| Error::MissingValidatorInEpochBlock(headers.target.number))?
                .into()
        } else {
            value.current_validators.into()
        };
        if current_validators.validators.is_empty() {
            return Err(Error::MissingCurrentTrustedValidators(
                headers.target.number,
            ));
        }

        Ok(Self {
            account_proof: value.account_proof,
            headers,
            trusted_height,
            previous_validators,
            current_validators,
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
mod testdata;

#[cfg(test)]
mod test {
    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;
    use crate::header::verify_validator_set;
    use crate::misc::new_height;
    use light_client::types::Time;

    #[test]
    fn test_success_verify_validator_set() {
        let cs = ConsensusState {
            state_root: [0u8; 32],
            timestamp: Time::now(),
            current_validators_hash: [1u8; 32],
            previous_validators_hash: [2u8; 32],
        };

        let height = new_height(0, 400);
        let trusted_height = new_height(0, 201);
        let current_validators_hash = [3u8; 32];
        let previous_validators_hash = cs.current_validators_hash;
        verify_validator_set(
            &cs,
            true,
            height,
            trusted_height,
            previous_validators_hash,
            current_validators_hash,
        )
        .unwrap();

        let height = new_height(0, 599);
        let trusted_height = new_height(0, 400);
        let current_validators_hash = cs.current_validators_hash;
        let previous_validators_hash = cs.previous_validators_hash;
        verify_validator_set(
            &cs,
            false,
            height,
            trusted_height,
            previous_validators_hash,
            current_validators_hash,
        )
        .unwrap();
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
        let current_validators_hash = [1u8; 32];
        let previous_validators_hash = [2u8; 32];
        let err = verify_validator_set(
            &cs,
            true,
            height,
            trusted_height,
            previous_validators_hash,
            current_validators_hash,
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
        let previous_validators_hash = [3u8; 32];
        let err = verify_validator_set(
            &cs,
            true,
            height,
            trusted_height,
            previous_validators_hash,
            current_validators_hash,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedPreviousValidatorsHash(t, h, hash, cons_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(hash, previous_validators_hash);
                assert_eq!(cons_hash, cons_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let height = new_height(0, 401);
        let trusted_height = new_height(0, 200);
        let err = verify_validator_set(
            &cs,
            false,
            height,
            trusted_height,
            previous_validators_hash,
            current_validators_hash,
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
        let current_validators_hash = [1u8; 32];
        let previous_validators_hash = [3u8; 32];
        let err = verify_validator_set(
            &cs,
            false,
            height,
            trusted_height,
            previous_validators_hash,
            current_validators_hash,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedPreviousValidatorsHash(t, h, hash, cons_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(hash, previous_validators_hash);
                assert_eq!(cons_hash, cons_hash);
            }
            _ => unreachable!("err {:?}", err),
        }

        let trusted_height = new_height(0, 400);
        let current_validators_hash = [3u8; 32];
        let previous_validators_hash = [2u8; 32];
        let err = verify_validator_set(
            &cs,
            false,
            height,
            trusted_height,
            previous_validators_hash,
            current_validators_hash,
        )
        .unwrap_err();
        match err {
            Error::UnexpectedCurrentValidatorsHash(t, h, hash, cons_hash) => {
                assert_eq!(t, trusted_height);
                assert_eq!(h, height);
                assert_eq!(hash, current_validators_hash);
                assert_eq!(cons_hash, cons_hash);
            }
            _ => unreachable!("err {:?}", err),
        }
    }
}
