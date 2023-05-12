use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Formatter;

use k256::ecdsa::signature;
use lcp_types::{ClientId, Height, Time, TimeError};

use crate::misc::{Address, BlockNumber, Hash};

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
    UnexpectedStateNonExistingValue(Hash, Vec<Vec<u8>>, Option<Vec<u8>>, Vec<u8>),
    UnexpectedStateExistingValue(Hash, Vec<Vec<u8>>, Vec<u8>, Vec<u8>),
    UnexpectedStateValueMismatch(Hash, Vec<Vec<u8>>, Option<Vec<u8>>, Vec<u8>),
    UnexpectedStateIncompleteProof(Hash, Vec<Vec<u8>>, Option<Vec<u8>>, Vec<u8>),
    UnexpectedStateHashMismatch(Hash, Vec<Vec<u8>>, Option<Vec<u8>>, Vec<u8>),
    UnexpectedStateDecodeError(Hash, Vec<Vec<u8>>, Option<Vec<u8>>, Vec<u8>),
    UnexpectedStateHashDecodeError(Hash, Vec<Vec<u8>>, Option<Vec<u8>>, Vec<u8>),
    UnexpectedTimestamp(TimeError),
    IllegalTimestamp(Time, Time),
    UnexpectedStateRoot(Vec<u8>),
    UnexpectedStorageRoot(Vec<u8>),
    UnexpectedConsensusStateRoot(Vec<u8>),
    UnexpectedCommitmentValue(Vec<u8>),
    UnexpectedHeader(usize, alloc::boxed::Box<Error>),
    UnexpectedValidatorsHash(Vec<u8>),
    UnexpectedPreviousValidatorsHash(Height, Hash, Hash),
    UnexpectedCurrentValidatorsHash(Height, Hash, Hash),

    // Header error
    MissingPreviousTrustedValidators(BlockNumber),
    MissingCurrentTrustedValidators(BlockNumber),
    MissingTrustedValidatorsHeight,
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
    PreviousValidatorSetNotFound(BlockNumber),
    CurrentValidatorSetNotFound(BlockNumber),
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
    ProofRLPError(rlp::DecoderError),
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
            Error::UnexpectedStateNonExistingValue(e1, e2, e3, e4) => {
                write!(f, "UnexpectedStateNonExistingValue: root={:?}, proof={:?}, expected={:?}, key={:?}", e1,e2,e3,e4)
            }
            Error::UnexpectedStateExistingValue(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedStateExistingValue:root={:?}, proof={:?}, expected={:?}, key={:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedStateValueMismatch(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedStateValueMismatch: root={:?}, proof={:?}, expected={:?}, key={:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedStateIncompleteProof(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedStateIncompleteProof:root={:?}, proof={:?}, expected={:?}, key={:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedStateHashMismatch(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedStateHashMismatch: root={:?}, proof={:?}, expected={:?}, key={:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedStateDecodeError(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedStateDecodeError: root={:?}, proof={:?}, expected={:?}, key={:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedStateHashDecodeError(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedStateHashDecodeError:root={:?}, proof={:?}, expected={:?}, key={:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedTimestamp(e) => write!(f, "UnexpectedTimestamp: {}", e),
            Error::UnexpectedStateRoot(e) => write!(f, "UnexpectedStateRoot: {:?}", e),
            Error::UnexpectedConsensusStateRoot(e) => {
                write!(f, "UnexpectedConsensusStateRoot: {:?}", e)
            }
            Error::UnexpectedStorageRoot(e) => write!(f, "UnexpectedStorageRoot: {:?}", e),
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
            Error::UnexpectedHeader(e1, e3) => write!(f, "UnexpectedHeader: {} {:?}", e1, e3),
            Error::PreviousValidatorSetNotFound(e) => {
                write!(f, "PreviousValidatorSetNotFound: target={}", e)
            }
            Error::CurrentValidatorSetNotFound(e) => {
                write!(f, "CurrentValidatorSetNotFound: target={}", e)
            }
            Error::ProofRLPError(e) => write!(f, "ProofRLPError : {}", e),
            Error::UnexpectedValidatorsHash(e) => write!(f, "UnexpectedValidatorsHash : {:?}", e),
            Error::UnexpectedPreviousValidatorsHash(e1, e2, e3) => write!(
                f,
                "UnexpectedPreviousValidatorsHash : {} {:?} {:?}",
                e1, e2, e3
            ),
            Error::UnexpectedCurrentValidatorsHash(e1, e2, e3) => write!(
                f,
                "UnexpectedCurrentValidatorsHash : {} {:?} {:?}",
                e1, e2, e3
            ),
            Error::MissingPreviousTrustedValidators(e) => {
                write!(f, "MissingPreviousTrustedValidators : {:?}", e)
            }
            Error::MissingCurrentTrustedValidators(e) => {
                write!(f, "MissingCurrentTrustedValidators : {:?}", e)
            }
            Error::MissingTrustedValidatorsHeight => {
                write!(f, "MissingTrustedValidatorsHeight")
            }
        }
    }
}

impl light_client::LightClientSpecificError for Error {}
