use alloc::vec::Vec;

use light_client::types::{Any, Height, Time};
use prost::Message as _;

use parlia_ibc_proto::google::protobuf::Any as IBCAny;
use parlia_ibc_proto::ibc::lightclients::parlia::v1::Header as RawHeader;

use crate::commitment::decode_eip1184_rlp_proof;
use crate::header::eth_header::ETHHeader;
use crate::header::validator_set::ValidatorSet;
use crate::misc::{new_height, new_timestamp, ChainId, Hash, Validators};

use super::errors::Error;

use self::constant::BLOCKS_PER_EPOCH;

pub const PARLIA_HEADER_TYPE_URL: &str = "/ibc.lightclients.parlia.v1.Header";

// inner header is module private
pub mod constant;
mod eth_header;
pub(crate) mod validator_set;
mod vote_attestation;

#[derive(Clone, Debug, PartialEq)]
pub struct Header {
    account_proof: Vec<u8>,
    target: ETHHeader,
    parent: ETHHeader,
    trusted_height: Height,
    parent_validators: ValidatorSet,
    target_validators: ValidatorSet,
    previous_target_validators: ValidatorSet,
}

impl Header {
    pub fn height(&self) -> Height {
        new_height(self.trusted_height.revision_number(), self.target.number)
    }

    pub fn parent_height(&self) -> Height {
        new_height(self.trusted_height.revision_number(), self.parent.number)
    }

    pub fn timestamp(&self) -> Result<Time, Error> {
        new_timestamp(self.target.timestamp)
    }

    pub fn account_proof(&self) -> Result<Vec<Vec<u8>>, Error> {
        decode_eip1184_rlp_proof(&self.account_proof)
    }

    pub fn trusted_height(&self) -> Height {
        self.trusted_height
    }

    pub fn state_root(&self) -> &Hash {
        &self.target.root
    }

    pub fn new_validators(&self) -> Result<Validators, Error> {
        if !self.target.is_epoch() {
            return Ok(vec![]);
        }
        self.target
            .get_validator_bytes()
            .ok_or_else(|| Error::MissingValidatorInEpochBlock(self.target.number))
    }

    pub fn parent_validators(&self) -> &ValidatorSet {
        &self.parent_validators
    }

    pub fn previous_target_validators(&self) -> &ValidatorSet {
        &self.previous_target_validators
    }

    pub fn target_validators(&self) -> &ValidatorSet {
        &self.target_validators
    }

    pub fn verify(&self, chain_id: &ChainId) -> Result<(), Error> {
        self.target.verify_cascading_fields(&self.parent)?;
        let (target_vote_attestation, parent_vote_attestation) =
            self.target.verify_vote_attestation(&self.parent)?;
        target_vote_attestation.verify(&self.target_validators.validators)?;
        parent_vote_attestation.verify(&self.parent_validators.validators)?;

        self.target
            .verify_seal(&self.target_validators.validators, chain_id)?;
        self.parent
            .verify_seal(&self.parent_validators.validators, chain_id)?;

        Ok(())
    }

    pub fn block_hash(&self) -> &Hash {
        &self.target.hash
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

        let target = ETHHeader::try_from(value.target.ok_or(Error::EmptyHeader)?)?;
        let parent = ETHHeader::try_from(value.parent.ok_or(Error::EmptyHeader)?)?;

        // Ensure target height is greater than or equals to trusted height.
        let trusted_header_height = trusted_height.revision_height();
        if target.number <= trusted_header_height {
            return Err(Error::UnexpectedTrustedHeight(
                target.number,
                trusted_header_height,
            ));
        }

        let parent_validators: ValidatorSet = value.parent_validators.clone().try_into()?;
        if parent_validators.validators.is_empty() {
            return Err(Error::MissingParentTrustedValidators(target.number));
        }

        // Epoch header contains validator set
        let target_validators: ValidatorSet = value.target_validators.clone().try_into()?;
        if target_validators.validators.is_empty() {
            return Err(Error::MissingTargetTrustedValidators(target.number));
        }

        let previous_target_validators: ValidatorSet =
            value.previous_target_validators.clone().try_into()?;
        if previous_target_validators.validators.is_empty() {
            return Err(Error::MissingPreviousTargetTrustedValidators(target.number));
        }

        Ok(Self {
            account_proof: value.account_proof,
            target,
            parent,
            trusted_height,
            parent_validators,
            target_validators,
            previous_target_validators,
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
