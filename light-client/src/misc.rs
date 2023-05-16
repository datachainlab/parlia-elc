use crate::errors::Error;

use alloc::vec::Vec;
use rlp::{Decodable, Rlp};

pub type Validator = Vec<u8>;
pub type Validators = Vec<Validator>;
pub type Address = [u8; 20];
pub type BlockNumber = u64;
pub type Hash = [u8; 32];
pub type NanoTime = u64;

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ChainId {
    id: u64,
    version: u64,
}

impl ChainId {
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn new(id: u64) -> Self {
        ChainId { id, version: 0 }
    }

    pub fn version(&self) -> u64 {
        self.version
    }
}

pub trait ValidatorReader {
    fn read(&self, height: ibc::Height) -> Result<Validators, Error>;
}

pub struct Account {
    // nonce,
    // balance
    /// storage root hash
    pub storage_root: Vec<u8>,
    // code_hash
}

impl<'a> TryFrom<Rlp<'a>> for Account {
    type Error = Error;

    fn try_from(value: Rlp<'a>) -> Result<Self, Self::Error> {
        let storage_root = value
            .at(2)
            .map_err(Error::RLPDecodeError)?
            .as_val::<Vec<u8>>()
            .map_err(Error::RLPDecodeError)?;
        Ok(Self { storage_root })
    }
}

/// RlpIterator returns an error instead of None on next() unlike the rlp::RlpIterator.
pub(crate) struct RlpIterator<'a> {
    rlp: Rlp<'a>,
    index: usize,
}

impl<'a> RlpIterator<'a> {
    pub fn new(rlp: Rlp<'a>) -> Self {
        Self { rlp, index: 0 }
    }

    pub fn try_next(&mut self) -> Result<Rlp<'a>, Error> {
        let index = self.index;
        let result = self.rlp.at(index).map_err(Error::RLPDecodeError)?;
        self.index += 1;
        Ok(result)
    }

    pub fn try_next_as_list<T: Decodable>(&mut self) -> Result<Vec<T>, Error> {
        let next = self.try_next()?;
        next.as_list().map_err(Error::RLPDecodeError)
    }

    pub fn try_next_as_val<T: Decodable>(&mut self) -> Result<T, Error> {
        let next = self.try_next()?;
        next.as_val().map_err(Error::RLPDecodeError)
    }
}

pub(crate) fn required_block_count_to_finalize(validators: &Validators) -> usize {
    let validator_size = validators.len();
    if validator_size % 2 == 1 {
        validator_size / 2 + 1
    } else {
        validator_size / 2
    }
}

pub(crate) fn new_ibc_height_with_chain_id(
    chain_id: &ChainId,
    height: BlockNumber,
) -> Result<ibc::Height, Error> {
    new_ibc_height(chain_id.version(), height)
}

pub(crate) fn new_ibc_height(
    revision_number: u64,
    height: BlockNumber,
) -> Result<ibc::Height, Error> {
    //TODO Ethereum based block number uses big.Int. It can be bigger than u64.
    ibc::Height::new(revision_number, height).map_err(Error::ICS02Error)
}

pub(crate) fn new_ibc_timestamp(nano: u64) -> Result<ibc::timestamp::Timestamp, Error> {
    ibc::timestamp::Timestamp::from_nanoseconds(nano).map_err(Error::ICSTimestamp)
}
