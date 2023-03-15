use alloc::vec::Vec;
use alloc::string::String;

use k256::ecdsa::signature;
use lcp_types::{Time, TimeError};

use crate::misc::{Address, BlockNumber, NanoTime};

#[derive(Debug)]
pub enum Error {
    LCPError(light_client::Error),

    // data conversion error
    TimeError(TimeError),
    RLPDecodeError(rlp::DecoderError),
    ProtoDecodeError(prost::DecodeError),
    UnknownHeaderType(String),
    UnknownClientStateType(String),
    UnknownConsensusStateType(String),

    // ClientState error
    MissingLatestHeight,
    MissingTrustLevel,
    UnexpectedStoreAddress(Vec<u8>),

    // ConsensusState error
    AccountNotFound(Address),
    UnexpectedStateNonExistingValue(Vec<u8>),
    UnexpectedStateExistingValue(Vec<u8>, Vec<u8>),
    UnexpectedStateValueMismatch(Vec<u8>),
    UnexpectedStateIncompleteProof(Vec<u8>),
    UnexpectedStateHashMismatch(Vec<u8>),
    UnexpectedStateDecodeError(Vec<u8>),
    UnexpectedStateHashDecodeError(Vec<u8>),
    UnexpectedTimestamp(NanoTime),
    UnexpectedStateRoot(Vec<u8>),

    // Header error
    HeaderNotWithinTrustingPeriod(Time, Time),
    InvalidTrustThreshold(u64, u64),
    MissingTrustedHeight,
    UnexpectedTrustedHeight(BlockNumber, BlockNumber),
    EmptyHeader,
    InsufficientHeaderToVerify(usize, usize),
    UnexpectedHeaderRevision(u64, u64),
    UnexpectedSignature(BlockNumber, signature::Error),
    MissingVanityInExtraData(BlockNumber, usize, usize),
    MissingSignatureInExtraData(BlockNumber, usize, usize),
    UnexpectedValidatorInNonEpochBlock(BlockNumber),
    UnexpectedValidatorInEpochBlock(BlockNumber),
    UnexpectedMixHash(BlockNumber),
    UnexpectedUncleHash(BlockNumber),
    UnexpectedDifficulty(BlockNumber, u64),
    UnexpectedNonce(BlockNumber),
    UnexpectedRecoveryId(BlockNumber),
    UnexpectedEncodedPoint(BlockNumber),
    UnexpectedAddress(BlockNumber),
    UnexpectedCoinbase(BlockNumber),
    UnexpectedDoubleSign(BlockNumber, Address),
    MissingSignerInValidator(BlockNumber, Address),
    UnexpectedGasDiff(BlockNumber, u64, u64),
    UnexpectedGasUsed(BlockNumber, u64, u64),
    UnexpectedHeaderRelation(BlockNumber, BlockNumber),
}


