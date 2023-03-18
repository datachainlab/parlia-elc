use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::{write, Formatter};

use k256::ecdsa::signature;
use lcp_types::{ClientId, Height, Time, TimeError};

use crate::misc::{Address, BlockNumber};

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
    ClientFrozen(ClientId),
    UnexpectedLatestHeight(Height, Height),

    // ConsensusState error
    AccountNotFound(Address),
    UnexpectedStateNonExistingValue(Vec<u8>),
    UnexpectedStateExistingValue(Vec<u8>, Vec<u8>),
    UnexpectedStateValueMismatch(Vec<u8>),
    UnexpectedStateIncompleteProof(Vec<u8>),
    UnexpectedStateHashMismatch(Vec<u8>),
    UnexpectedStateDecodeError(Vec<u8>),
    UnexpectedStateHashDecodeError(Vec<u8>),
    UnexpectedTimestamp(TimeError),
    IllegalTimestamp(Time, Time),
    UnexpectedStateRoot(Vec<u8>),
    UnexpectedCommitmentValue(Vec<u8>),

    // Header error
    HeaderNotWithinTrustingPeriod(Time, Time),
    InvalidTrustThreshold(u64, u64),
    MissingTrustedHeight,
    MissingTrustingPeriod,
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

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::LCPError(e) => write!(f, "LCPError: {}", e),
            Error::TimeError(e) => write!(f, "TimeError: {}", e),
            Error::RLPDecodeError(e) => write!(f, "RLPDecodeError : {}", e),
            Error::ProtoDecodeError(e) => write!(f, "ProtoDecodeError: {}", e),
            Error::UnknownHeaderType(e) => write!(f, "UnknownHeaderType: {}", e),
            Error::UnknownClientStateType(e) => write!(f, "UnknownClientStateType: {}", e),
            Error::UnknownConsensusStateType(e) => write!(f, "UnknownClientStateType: {}", e),
            Error::MissingLatestHeight => write!(f, "MissingLatestHeight"),
            Error::MissingTrustLevel => write!(f, "MissingTrustLevel"),
            Error::UnexpectedStoreAddress(e) => write!(f, "UnexpectedStoreAddress: {:?}", e),
            Error::ClientFrozen(e) => write!(f, "ClientFrozen: {}", e),
            Error::UnexpectedLatestHeight(e1, e2) => {
                write!(f, "UnexpectedLatestHeight: {} {}", e1, e2)
            }
            Error::AccountNotFound(e) => write!(f, "AccountNotFound: {:?}", e),
            Error::UnexpectedStateNonExistingValue(e) => {
                write!(f, "UnexpectedStateNonExistingValue: {:?}", e)
            }
            Error::UnexpectedStateExistingValue(e1, e2) => {
                write!(f, "UnexpectedStateExistingValue: {:?} {:?}", e1, e2)
            }
            Error::UnexpectedStateValueMismatch(e) => {
                write!(f, "UnexpectedStateValueMismatch: {:?}", e)
            }
            Error::UnexpectedStateIncompleteProof(e) => {
                write!(f, "UnexpectedStateIncompleteProof: {:?}", e)
            }
            Error::UnexpectedStateHashMismatch(e) => {
                write!(f, "UnexpectedStateHashMismatch: {:?}", e)
            }
            Error::UnexpectedStateDecodeError(e) => {
                write!(f, "UnexpectedStateDecodeError: {:?}", e)
            }
            Error::UnexpectedStateHashDecodeError(e) => {
                write!(f, "UnexpectedStateHashDecodeError: {:?}", e)
            }
            Error::UnexpectedTimestamp(e) => write!(f, "UnexpectedTimestamp: {}", e),
            Error::UnexpectedStateRoot(e) => write!(f, "UnexpectedStateRoot: {:?}", e),
            Error::UnexpectedCommitmentValue(e) => write!(f, "UnexpectedCommitmentValue: {:?}", e),
            Error::HeaderNotWithinTrustingPeriod(e1, e2) => {
                write!(f, "HeaderNotWithinTrustingPeriod: {} {}", e1, e2)
            }
            Error::InvalidTrustThreshold(e1, e2) => {
                write!(f, "InvalidTrustThreshold: {} {}", e1, e2)
            }
            Error::MissingTrustedHeight => write!(f, "MissingTrustedHeight"),
            Error::UnexpectedTrustedHeight(e1, e2) => {
                write!(f, "UnexpectedTrustedHeight: {} {}", e1, e2)
            }
            Error::EmptyHeader => write!(f, "EmptyHeader"),
            Error::InsufficientHeaderToVerify(e1, e2) => {
                write!(f, "InsufficientHeaderToVerify: {} {}", e1, e2)
            }
            Error::UnexpectedHeaderRevision(e1, e2) => {
                write!(f, "UnexpectedHeaderRevision: {} {}", e1, e2)
            }
            Error::UnexpectedSignature(e1, e2) => write!(f, "UnexpectedSignature: {} {}", e1, e2),
            Error::MissingVanityInExtraData(e1, e2, e3) => {
                write!(f, "MissingVanityInExtraData: {} {} {}", e1, e2, e3)
            }
            Error::MissingSignatureInExtraData(e1, e2, e3) => {
                write!(f, "MissingSignatureInExtraData: {} {} {}", e1, e2, e3)
            }
            Error::UnexpectedValidatorInNonEpochBlock(e) => {
                write!(f, "UnexpectedValidatorInNonEpochBlock: {}", e)
            }
            Error::UnexpectedValidatorInEpochBlock(e) => {
                write!(f, "UnexpectedValidatorInEpochBlock: {}", e)
            }
            Error::UnexpectedMixHash(e) => write!(f, "UnexpectedMixHash: {}", e),
            Error::UnexpectedUncleHash(e) => write!(f, "UnexpectedUncleHash: {}", e),
            Error::UnexpectedDifficulty(e1, e2) => write!(f, "UnexpectedDifficulty: {} {}", e1, e2),
            Error::UnexpectedNonce(e) => write!(f, "UnexpectedNonce: {}", e),
            Error::UnexpectedRecoveryId(e) => write!(f, "UnexpectedRecoveryId: {}", e),
            Error::UnexpectedEncodedPoint(e) => write!(f, "UnexpectedEncodedPoint: {}", e),
            Error::UnexpectedAddress(e) => write!(f, "UnexpectedAddress: {}", e),
            Error::UnexpectedCoinbase(e) => write!(f, "UnexpectedCoinbase: {}", e),
            Error::UnexpectedDoubleSign(e1, e2) => {
                write!(f, "UnexpectedDoubleSign: {} {:?}", e1, e2)
            }
            Error::MissingSignerInValidator(e1, e2) => {
                write!(f, "MissingSignerInValidator: {} {:?}", e1, e2)
            }
            Error::UnexpectedGasDiff(e1, e2, e3) => {
                write!(f, "UnexpectedGasDiff: {} {} {}", e1, e2, e3)
            }
            Error::UnexpectedGasUsed(e1, e2, e3) => {
                write!(f, "UnexpectedGasUsed: {} {} {}", e1, e2, e3)
            }
            Error::UnexpectedHeaderRelation(e1, e2) => {
                write!(f, "UnexpectedHeaderRelation: {} {}", e1, e2)
            }
            Error::MissingTrustingPeriod => write!(f, "MissingTrustingPeriod"),
            Error::IllegalTimestamp(e1, e2) => write!(f, "IllegalTimestamp: {} {}", e1, e2),
        }
    }
}

impl light_client::LightClientSpecificError for Error {}
