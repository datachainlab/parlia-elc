use alloc::vec::Vec;

use lcp_types::{Height, Time};
use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Decodable, Rlp};

use crate::errors::Error;

pub type Validator = Vec<u8>;
pub type Validators = Vec<Validator>;
pub type Address = [u8; 20];
pub type BlockNumber = u64;
pub type Hash = [u8; 32];

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
        //TODO support upgrade. currently follow the ethereum-elc-
        ChainId { id, version: 0 }
    }

    pub fn version(&self) -> u64 {
        self.version
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

    pub fn try_next_as_val<T: Decodable>(&mut self) -> Result<T, Error> {
        let next = self.try_next()?;
        next.as_val().map_err(Error::RLPDecodeError)
    }
}

pub fn new_height(revision_number: u64, height: BlockNumber) -> Height {
    Height::new(revision_number, height)
}

pub fn new_timestamp(second: u64) -> Result<Time, Error> {
    Time::from_unix_timestamp_secs(second).map_err(Error::TimeError)
}

pub fn keccak_256_vec(targets: &[Vec<u8>]) -> Hash {
    let flatten: Vec<u8> = targets.iter().flat_map(|x| x.clone()).collect();
    keccak_256(flatten.as_slice())
}
