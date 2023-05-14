use lcp_types::Height;

use parlia_ibc_proto::ibc::lightclients::parlia::v1::ValidatorSet as RawValidatorSet;

use crate::errors::Error;
use crate::header::eth_header::ETHHeader;
use crate::misc::{keccak_256_vec, new_height, Hash, Validators};

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSet {
    epoch_height: Height,
    validators: Validators,
    hash: Hash,
}

impl ValidatorSet {
    pub fn validators(&self) -> &Validators {
        &self.validators
    }

    pub fn height(&self) -> &Height {
        &self.epoch_height
    }

    pub fn hash(&self) -> &Hash {
        &self.hash
    }

    pub fn new(revision_number: u64, value: &ETHHeader) -> Self {
        let validators = value.new_validators.clone();
        let hash = keccak_256_vec(&validators);
        Self {
            epoch_height: new_height(revision_number, value.number),
            validators,
            hash,
        }
    }
}

impl TryFrom<RawValidatorSet> for ValidatorSet {
    type Error = Error;

    fn try_from(value: RawValidatorSet) -> Result<Self, Self::Error> {
        let height = value
            .epoch_height
            .ok_or(Error::MissingTrustedValidatorsHeight)?;
        let validators = value.validators;
        let hash = keccak_256_vec(&validators);
        Ok(Self {
            epoch_height: new_height(height.revision_number, height.revision_height),
            validators,
            hash,
        })
    }
}
