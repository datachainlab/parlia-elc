use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Formatter;

use k256::ecdsa::signature;
use lcp_types::{ClientId, Height, Time, TimeError};
use trie_db::TrieError;

use crate::misc::{Address, BlockNumber, Hash};

type BoxedTrieError = alloc::boxed::Box<TrieError<primitive_types::H256, rlp::DecoderError>>;

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
    UnknownMisbehaviourType(String),

    // ClientState error
    MissingLatestHeight,
    MissingTrustLevel,
    UnexpectedStoreAddress(Vec<u8>),
    ClientFrozen(ClientId),
    UnexpectedLatestHeight(Height, Height),

    // ConsensusState error
    AccountNotFound(Address),
    UnexpectedStateValue(Hash, Vec<Vec<u8>>, Option<Vec<u8>>, Vec<u8>),
    UnexpectedTimestamp(TimeError),
    IllegalTimestamp(Time, Time),
    UnexpectedStateRoot(Vec<u8>),
    UnexpectedStorageRoot(Vec<u8>),
    UnexpectedConsensusStateRoot(Vec<u8>),
    UnexpectedCommitmentValue(Vec<u8>),
    UnexpectedHeader(usize, alloc::boxed::Box<Error>),
    UnexpectedValidatorsHashSize(Vec<u8>),

    // Header error
    MissingParentTrustedValidators(BlockNumber),
    MissingTargetTrustedValidators(BlockNumber),
    MissingPreviousTargetTrustedValidators(BlockNumber),
    MissingTrustedValidatorsHeight,
    HeaderNotWithinTrustingPeriod(Time, Time),
    InvalidTrustThreshold(u64, u64),
    MissingTrustedHeight,
    MissingTrustingPeriod,
    UnexpectedTrustedHeight(BlockNumber, BlockNumber),
    EmptyHeader,
    InsufficientHeaderToVerify(BlockNumber, usize, usize),
    InsufficientHeaderToVerifyAcrossCheckpoint(BlockNumber, u64, usize, usize, usize),
    UnexpectedHeaderRevision(u64, u64),
    UnexpectedSignature(BlockNumber, signature::Error),
    MissingVanityInExtraData(BlockNumber, usize, usize),
    MissingSignatureInExtraData(BlockNumber, usize, usize),
    UnexpectedValidatorHeight(BlockNumber),
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
    InvalidProofFormatError(Vec<u8>),
    InsufficientParentValidators(usize, usize),
    InsufficientTargetValidators(usize, usize),
    UnexpectedTargetValidatorsHash(Height, usize, Hash, Hash),
    UnexpectedParentValidatorsHash(Height, usize, Hash, Hash),
    UnexpectedPreviousTargetValidatorsHash(Height, usize, Hash, Hash),
    MissingValidatorInEpochBlock(BlockNumber),

    // Vote attestation
    UnexpectedVoteLength(usize),
    UnexpectedVoteAttestationExtraLength(usize),
    UnexpectedVoteAttestationRelation(BlockNumber, BlockNumber, Hash, Hash),
    UnexpectedBLSSignature(milagro_bls::AmclError),
    UnexpectedBLSPubkey(milagro_bls::AmclError),
    FailedToVerifyBLSSignature(usize),
    InsufficientValidatorCount(usize, usize),
    UnexpectedVoteAddressCount(usize, usize),
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
            Error::InsufficientHeaderToVerify(e1, e2, e3) => {
                write!(f, "InsufficientHeaderToVerify: {} {} {}", e1, e2, e3)
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
            Error::UnexpectedValidatorsHashSize(e) => {
                write!(f, "UnexpectedValidatorsHashSize: {:?}", e)
            }
            Error::UnexpectedTargetValidatorsHash(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedTargetValidatorsHash: {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedParentValidatorsHash(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedParentValidatorsHash: {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedPreviousTargetValidatorsHash(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedPreviousTargetValidatorsHash: {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
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
            Error::ProofRLPError(e) => write!(f, "ProofRLPError : {}", e),
            Error::MissingParentTrustedValidators(e) => {
                write!(f, "MissingParentTrustedValidators : {}", e)
            }
            Error::MissingTargetTrustedValidators(e) => {
                write!(f, "MissingTargetTrustedValidators : {}", e)
            }
            Error::MissingPreviousTargetTrustedValidators(e) => {
                write!(f, "MissingPreviousTargetTrustedValidators : {}", e)
            }
            Error::MissingTrustedValidatorsHeight => {
                write!(f, "MissingTrustedValidatorsHeight")
            }
            Error::InsufficientParentValidators(e1, e2) => {
                write!(f, "InsufficientParentValidators : {} {}", e1, e2)
            }
            Error::InsufficientTargetValidators(e1, e2) => {
                write!(f, "InsufficientTargetValidators : {} {}", e1, e2)
            }
            Error::InsufficientHeaderToVerifyAcrossCheckpoint(e1, e2, e3, e4, e5) => {
                write!(
                    f,
                    "InsufficientHeaderToVerifyAcrossCheckpoint : {} {} {} {} {}",
                    e1, e2, e3, e4, e5
                )
            }
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
            Error::UnexpectedVoteAttestationRelation(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedVoteAttestationRelation : {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedBLSSignature(e1) => {
                write!(f, "UnexpectedBLSSignature : {:?}", e1)
            }
            Error::FailedToVerifyBLSSignature(e1) => {
                write!(f, "FailedToVerifyBLSSignature : {:?} ", e1)
            }
            Error::UnexpectedVoteAddressCount(e1, e2) => {
                write!(f, "UnexpectedVoteAddressCount : {:?} {:?}", e1, e2,)
            }
            Error::InsufficientValidatorCount(e1, e2) => {
                write!(f, "InsufficientValidatorCount : {:?} {:?}", e1, e2)
            }
            Error::UnexpectedBLSSignatureLength(e1) => {
                write!(f, "UnexpectedBLSSignatureLength : {:?}", e1)
            }
            Error::UnexpectedBLSPubkey(e1) => {
                write!(f, "UnexpectedBLSPubkey : {:?}", e1)
            }
            Error::MissingValidatorInEpochBlock(e1) => {
                write!(f, "MissingValidatorInEpochBlock : {:?}", e1)
            }
            Error::UnexpectedValidatorHeight(e1) => {
                write!(f, "UnexpectedValidatorHeight : {:?}", e1)
            }
        }
    }
}

impl light_client::LightClientSpecificError for Error {}
