use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Formatter;

use k256::ecdsa::signature;
use light_client::types::{ClientId, Height, Time, TimeError};
use trie_db::TrieError;

use crate::misc::{Address, BlockNumber, Hash};

type BoxedTrieError = alloc::boxed::Box<TrieError<primitive_types::H256, rlp::DecoderError>>;

#[derive(Debug)]
pub enum Error {
    // data conversion error
    TimestampOverflowError(u128),
    TimeError(TimeError),
    RLPDecodeError(rlp::DecoderError),
    ProtoDecodeError(prost::DecodeError),
    UnknownHeaderType(String),
    UnknownClientStateType(String),
    UnknownConsensusStateType(String),
    UnknownMisbehaviourType(String),

    // ClientState error
    MissingLatestHeight,
    UnexpectedStoreAddress(Vec<u8>),
    ClientFrozen(ClientId),
    UnexpectedLatestHeight(Height, Height),

    // ConsensusState error
    AccountNotFound(Address),
    UnexpectedStateValue(Hash, Vec<Vec<u8>>, Option<Vec<u8>>, Vec<u8>),
    IllegalTimestamp(Time, Time),
    UnexpectedStateRoot(Vec<u8>),
    UnexpectedStorageRoot(Vec<u8>),
    UnexpectedConsensusStateRoot(Vec<u8>),
    UnexpectedHeader(usize, alloc::boxed::Box<Error>),
    UnexpectedValidatorsHashSize(Vec<u8>),

    // Header error
    MissingPreviousTrustedValidators(BlockNumber),
    MissingCurrentTrustedValidators(BlockNumber),
    OutOfTrustingPeriod(Time, Time),
    HeaderFromFuture(Time, core::time::Duration, Time),
    MissingTrustedHeight,
    MissingTrustingPeriod,
    NegativeMaxClockDrift,
    UnexpectedTrustedHeight(BlockNumber, BlockNumber),
    EmptyHeader,
    UnexpectedHeaderRevision(u64, u64),
    UnexpectedSignature(BlockNumber, signature::Error),
    MissingVanityInExtraData(BlockNumber, usize, usize),
    MissingSignatureInExtraData(BlockNumber, usize, usize),
    UnexpectedMixHash(BlockNumber),
    UnexpectedUncleHash(BlockNumber),
    UnexpectedDifficulty(BlockNumber, u64),
    UnexpectedNonce(BlockNumber),
    UnexpectedRecoveryId(BlockNumber),
    UnexpectedEncodedPoint(BlockNumber),
    UnexpectedAddress(BlockNumber),
    UnexpectedCoinbase(BlockNumber),
    MissingSignerInValidator(BlockNumber, Address),
    UnexpectedGasDiff(BlockNumber, u64, u64),
    UnexpectedGasUsed(BlockNumber, u64, u64),
    UnexpectedHeaderRelation(BlockNumber, BlockNumber),
    ProofRLPError(rlp::DecoderError),
    InvalidProofFormatError(Vec<u8>),
    MissingValidatorInEpochBlock(BlockNumber),
    UnexpectedPreviousValidatorsHash(Height, Height, Hash, Hash),
    UnexpectedCurrentValidatorsHash(Height, Height, Hash, Hash),
    InvalidVerifyingHeaderLength(BlockNumber, usize),
    ValidatorNotTrusted(Hash),

    // Vote attestation
    UnexpectedTooManyHeadersToFinalize(BlockNumber, usize),
    UnexpectedVoteRelation(BlockNumber, usize, Option<alloc::boxed::Box<Error>>),
    UnexpectedSourceInGrandChild(BlockNumber, BlockNumber, Hash, Hash),
    UnexpectedVoteLength(usize),
    UnexpectedVoteAttestationExtraLength(usize),
    UnexpectedTargetVoteAttestationRelation(BlockNumber, BlockNumber, Hash, Hash),
    UnexpectedSourceVoteAttestationRelation(BlockNumber, BlockNumber, Hash, Hash),
    UnexpectedBLSSignature(BlockNumber, milagro_bls::AmclError),
    UnexpectedBLSPubkey(BlockNumber, milagro_bls::AmclError),
    FailedToVerifyBLSSignature(BlockNumber, usize),
    InsufficientValidatorCount(BlockNumber, usize, usize),
    UnexpectedVoteAddressCount(BlockNumber, usize, usize),
    UnexpectedBLSSignatureLength(Vec<u8>),

    // Misbehaviour
    MissingHeader1,
    MissingHeader2,
    UnexpectedClientId(String),
    UnexpectedDifferentHeight(Height, Height),
    UnexpectedSameBlockHash(Height),
    TrieError(BoxedTrieError),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TimestampOverflowError(e) => write!(f, "TimestampOverflowError: {}", e),
            Error::TimeError(e) => write!(f, "TimeError: {}", e),
            Error::RLPDecodeError(e) => write!(f, "RLPDecodeError : {}", e),
            Error::ProtoDecodeError(e) => write!(f, "ProtoDecodeError: {}", e),
            Error::UnknownHeaderType(e) => write!(f, "UnknownHeaderType: {}", e),
            Error::UnknownClientStateType(e) => write!(f, "UnknownClientStateType: {}", e),
            Error::UnknownConsensusStateType(e) => write!(f, "UnknownClientStateType: {}", e),
            Error::MissingLatestHeight => write!(f, "MissingLatestHeight"),
            Error::UnexpectedStoreAddress(e) => write!(f, "UnexpectedStoreAddress: {:?}", e),
            Error::ClientFrozen(e) => write!(f, "ClientFrozen: {}", e),
            Error::UnexpectedLatestHeight(e1, e2) => {
                write!(f, "UnexpectedLatestHeight: {} {}", e1, e2)
            }
            Error::AccountNotFound(e) => write!(f, "AccountNotFound: {:?}", e),
            Error::UnexpectedStateRoot(e) => write!(f, "UnexpectedStateRoot: {:?}", e),
            Error::UnexpectedConsensusStateRoot(e) => {
                write!(f, "UnexpectedConsensusStateRoot: {:?}", e)
            }
            Error::UnexpectedStorageRoot(e) => write!(f, "UnexpectedStorageRoot: {:?}", e),
            Error::OutOfTrustingPeriod(e1, e2) => {
                write!(f, "OutOfTrustingPeriod: {} {}", e1, e2)
            }
            Error::HeaderFromFuture(e1, e2, e3) => {
                write!(f, "HeaderFromFuture: {} {:?} {}", e1, e2, e3)
            }
            Error::MissingTrustedHeight => write!(f, "MissingTrustedHeight"),
            Error::UnexpectedTrustedHeight(e1, e2) => {
                write!(f, "UnexpectedTrustedHeight: {} {}", e1, e2)
            }
            Error::EmptyHeader => write!(f, "EmptyHeader"),
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
            Error::UnexpectedValidatorsHashSize(e) => {
                write!(f, "UnexpectedValidatorsHashSize: {:?}", e)
            }
            Error::UnexpectedUncleHash(e) => write!(f, "UnexpectedUncleHash: {}", e),
            Error::UnexpectedDifficulty(e1, e2) => write!(f, "UnexpectedDifficulty: {} {}", e1, e2),
            Error::UnexpectedNonce(e) => write!(f, "UnexpectedNonce: {}", e),
            Error::UnexpectedRecoveryId(e) => write!(f, "UnexpectedRecoveryId: {}", e),
            Error::UnexpectedEncodedPoint(e) => write!(f, "UnexpectedEncodedPoint: {}", e),
            Error::UnexpectedAddress(e) => write!(f, "UnexpectedAddress: {}", e),
            Error::UnexpectedCoinbase(e) => write!(f, "UnexpectedCoinbase: {}", e),
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
            Error::NegativeMaxClockDrift => write!(f, "NegativeMaxClockDrift"),
            Error::IllegalTimestamp(e1, e2) => write!(f, "IllegalTimestamp: {} {}", e1, e2),
            Error::UnexpectedHeader(e1, e3) => write!(f, "UnexpectedHeader: {} {:?}", e1, e3),
            Error::ProofRLPError(e) => write!(f, "ProofRLPError : {}", e),
            Error::MissingHeader1 => write!(f, "MissingHeader1"),
            Error::MissingHeader2 => write!(f, "MissingHeader2"),
            Error::UnexpectedClientId(e1) => write!(f, "UnexpectedClientId : {}", e1),
            Error::UnexpectedDifferentHeight(e1, e2) => {
                write!(f, "UnexpectedDifferentHeight : {} {}", e1, e2)
            }
            Error::UnexpectedSameBlockHash(e1) => {
                write!(f, "UnexpectedSameBlockHash : {}", e1)
            }
            Error::UnknownMisbehaviourType(e1) => write!(f, "UnknownMisbehaviourType : {}", e1),
            Error::UnexpectedStateValue(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedStateValue : {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::TrieError(e1) => {
                write!(f, "TrieError : {:?}", e1)
            }
            Error::InvalidProofFormatError(e1) => {
                write!(f, "InvalidProofFormatError : {:?}", e1)
            }
            Error::UnexpectedVoteLength(e1) => {
                write!(f, "UnexpectedVoteLength : {:?}", e1)
            }
            Error::UnexpectedVoteAttestationExtraLength(e1) => {
                write!(f, "UnexpectedVoteAttestationExtraLength : {:?}", e1)
            }
            Error::UnexpectedTargetVoteAttestationRelation(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedTargetVoteAttestationRelation : {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedSourceVoteAttestationRelation(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedSourceVoteAttestationRelation : {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedBLSSignature(e1, e2) => {
                write!(f, "UnexpectedBLSSignature : {:?} {:?}", e1, e2)
            }
            Error::FailedToVerifyBLSSignature(e1, e2) => {
                write!(f, "FailedToVerifyBLSSignature : {:?} {:?}", e1, e2)
            }
            Error::UnexpectedVoteAddressCount(e1, e2, e3) => {
                write!(f, "UnexpectedVoteAddressCount : {:?} {:?} {:?}", e1, e2, e3)
            }
            Error::InsufficientValidatorCount(e1, e2, e3) => {
                write!(f, "InsufficientValidatorCount : {:?} {:?} {:?}", e1, e2, e3)
            }
            Error::UnexpectedBLSSignatureLength(e1) => {
                write!(f, "UnexpectedBLSSignatureLength : {:?}", e1)
            }
            Error::UnexpectedBLSPubkey(e1, e2) => {
                write!(f, "UnexpectedBLSPubkey : {:?} {:?}", e1, e2)
            }
            Error::MissingValidatorInEpochBlock(e1) => {
                write!(f, "MissingValidatorInEpochBlock : {:?}", e1)
            }
            Error::MissingPreviousTrustedValidators(e1) => {
                write!(f, "MissingPreviousTrustedValidators : {:?}", e1)
            }
            Error::MissingCurrentTrustedValidators(e1) => {
                write!(f, "MissingCurrentTrustedValidators : {:?}", e1)
            }
            Error::UnexpectedMixHash(e1) => {
                write!(f, "UnexpectedMixHash : {:?}", e1)
            }
            Error::UnexpectedPreviousValidatorsHash(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedPreviousValidatorsHash : {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedCurrentValidatorsHash(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedCurrentValidatorsHash : {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedSourceInGrandChild(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedSourceInGrandChild : {} {} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::InvalidVerifyingHeaderLength(e1, e2) => {
                write!(f, "InvalidVerifyingHeaderLength : {} {}", e1, e2)
            }
            Error::UnexpectedTooManyHeadersToFinalize(e1, e2) => {
                write!(f, "UnexpectedTooManyHeadersToFinalize : {} {}", e1, e2)
            }
            Error::UnexpectedVoteRelation(e1, e2, e3) => {
                write!(f, "UnexpectedVoteRelation : {} {} {:?}", e1, e2, e3)
            }
            Error::ValidatorNotTrusted(e1) => {
                write!(f, "ValidatorNotTrusted : {:?}", e1)
            }
        }
    }
}

impl light_client::LightClientSpecificError for Error {}
