use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Formatter;

use crate::fork_spec::ForkSpec;
use crate::misc::{Address, BlockNumber, Hash};
use k256::ecdsa::signature;
use light_client::commitments::{CommitmentPrefix, Error as CommitmentError};
use light_client::types::{Any, ClientId, Height, Time, TimeError};
use trie_db::TrieError;

type BoxedTrieError = alloc::boxed::Box<TrieError<primitive_types::H256, rlp::DecoderError>>;

#[derive(Debug)]
pub enum Error {
    // data conversion error
    TimestampOverflowError(u128),
    TimeError(TimeError),
    RLPDecodeError(rlp::DecoderError),
    ProtoDecodeError(prost::DecodeError),
    ProtoEncodeError(prost::EncodeError),
    UnknownHeaderType(String),
    UnknownClientStateType(String),
    UnknownConsensusStateType(String),
    UnknownMisbehaviourType(String),
    UnexpectedClientType(String),
    LCPCommitmentError(CommitmentError),
    VerifyAccountError(alloc::boxed::Box<Error>),

    // ClientState error
    MissingLatestHeight,
    UnexpectedStoreAddress(Vec<u8>),
    UnexpectedCommitmentSlot(Vec<u8>),
    ClientFrozen(ClientId),
    UnexpectedProofHeight(Height, Height),
    UnexpectedRevisionHeight(u64),
    EmptyForkSpec,
    UnsupportedMinimumTimestampForkSpec(u64),
    UnsupportedMinimumHeightForkSpec(u64),
    UnsupportedMinimumTimestamp(Time),
    UnsupportedMinimumHeight(Height),

    // ConsensusState error
    AccountNotFound(Address),
    UnexpectedStateValue(
        Hash,
        Vec<Vec<u8>>,
        Option<Vec<u8>>,
        Vec<u8>,
        Option<Vec<u8>>,
    ),
    IllegalTimestamp(Time, Time),
    UnexpectedStateRoot(Vec<u8>),
    UnexpectedStorageRoot(Vec<u8>),
    UnexpectedConsensusStateRoot(Vec<u8>),
    UnexpectedHeader(usize, alloc::boxed::Box<Error>),
    UnexpectedValidatorsHashSize(Vec<u8>),

    // Header error
    MissingPreviousValidators(BlockNumber),
    MissingCurrentValidators(BlockNumber),
    OutOfTrustingPeriod(Time, Time),
    HeaderFromFuture(Time, core::time::Duration, Time),
    MissingTrustedHeight,
    MissingTrustingPeriod,
    NegativeMaxClockDrift,
    UnexpectedTrustedEpoch(BlockNumber, BlockNumber, BlockNumber, BlockNumber),
    UnexpectedTrustedHeight(BlockNumber, BlockNumber),
    EmptyHeader,
    UnexpectedHeaderRevision(u64, u64),
    UnexpectedLatestHeightRevision(u64, u64),
    UnexpectedSignature(BlockNumber, signature::Error),
    MissingVanityInExtraData(BlockNumber, usize, usize),
    MissingSignatureInExtraData(BlockNumber, usize, usize),
    UnexpectedMixHash(BlockNumber, Vec<u8>),
    UnexpectedNotEmptyMixHash(BlockNumber, Vec<u8>),
    UnexpectedMilliSecondValue(BlockNumber, u64),
    UnexpectedUncleHash(BlockNumber),
    UnexpectedDifficulty(BlockNumber, u64),
    UnexpectedNonce(BlockNumber),
    UnexpectedRecoveryId(BlockNumber),
    UnexpectedAddress(BlockNumber),
    UnexpectedCoinbase(BlockNumber),
    MissingSignerInValidator(BlockNumber, Address),
    UnexpectedGasDiff(BlockNumber, u64, u64),
    UnexpectedGasUsed(BlockNumber, u64, u64),
    UnexpectedHeaderRelation(BlockNumber, BlockNumber, Hash, Vec<u8>, u64, u64),
    ProofRLPError(rlp::DecoderError),
    InvalidProofFormatError(Vec<u8>),
    MissingValidatorInEpochBlock(BlockNumber),
    MissingTurnLengthInEpochBlock(BlockNumber),
    MissingEpochInfoInEpochBlock(BlockNumber),
    MissingNextValidatorSet(BlockNumber),
    UnexpectedPreviousValidatorsHash(Height, BlockNumber, Hash, Hash, BlockNumber),
    UnexpectedCurrentValidatorsHash(Height, BlockNumber, Hash, Hash, BlockNumber),
    InvalidVerifyingHeaderLength(BlockNumber, usize),
    InsufficientHonestValidator(Hash, usize, usize),
    MissingValidatorToVerifySeal(BlockNumber),
    MissingValidatorToVerifyVote(BlockNumber),
    UnexpectedNextCheckpointHeader(BlockNumber, BlockNumber),
    UnexpectedNextNextCheckpointHeader(BlockNumber, BlockNumber),
    MissingTrustedCurrentValidators(BlockNumber),
    UnexpectedDifficultyInTurn(BlockNumber, u64, usize),
    UnexpectedDifficultyNoTurn(BlockNumber, u64, usize),
    UnexpectedUntrustedValidatorsHashInEpoch(Height, BlockNumber, Hash, Hash, BlockNumber),
    UnexpectedCurrentValidatorsHashInEpoch(Height, BlockNumber, Hash, Hash),
    UnexpectedUntrustedValidators(BlockNumber, BlockNumber),
    MissingRequestsHash(BlockNumber),
    UnexpectedRequestsHash(BlockNumber, Vec<u8>),
    UnexpectedHeaderRLP(BlockNumber),
    MissingForkSpec(BlockNumber, u64),
    MissingForkSpecByHeight(BlockNumber),
    UnexpectedHeaderItemCount(BlockNumber, usize, u64),
    MissingEpochInfo(BlockNumber),
    UnexpectedEpochInfo(BlockNumber, BlockNumber),

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
    UnexpectedBLSSignatureLength(usize),
    UnexpectedTurnLength(u8),
    UnexpectedExtraDataLength(usize),

    // Fork Spec
    MissingTimestampOrHeightInForkSpec,
    UnexpectedForkSpecTimestampOrder(u64, u64),
    UnexpectedForkSpecHeightOrder(u64, u64),
    MissingForkHeightIntPreviousEpochCalculation(u64, ForkSpec),
    MissingForkHeightInBoundaryCalculation(ForkSpec),
    MissingBoundaryEpochs(BlockNumber),
    MissingPreviousForkSpec(ForkSpec),
    UnexpectedCurrentEpochInCalculatingNextEpoch(BlockNumber, BlockNumber, BlockNumber),
    UnexpectedMissingForkSpecInCurrentEpochCalculation(BlockNumber, alloc::boxed::Box<Error>),
    UnexpectedMissingForkSpecInPreviousEpochCalculation(BlockNumber, alloc::boxed::Box<Error>),
    UnexpectedPreviousEpochInCalculatingNextEpoch(BlockNumber, BlockNumber, BlockNumber),

    // Misbehaviour
    MissingHeader1,
    MissingHeader2,
    UnexpectedClientId(String),
    UnexpectedDifferentHeight(Height, Height),
    UnexpectedSameBlockHash(Height),

    TrieError(BoxedTrieError, Hash, Vec<Vec<u8>>, Vec<u8>),

    // Framework
    LCPError(light_client::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TimestampOverflowError(e) => write!(f, "TimestampOverflowError: {}", e),
            Error::TimeError(e) => write!(f, "TimeError: {}", e),
            Error::RLPDecodeError(e) => write!(f, "RLPDecodeError : {}", e),
            Error::ProtoDecodeError(e) => write!(f, "ProtoDecodeError: {}", e),
            Error::ProtoEncodeError(e) => write!(f, "ProtoEncodeError: {}", e),
            Error::UnknownHeaderType(e) => write!(f, "UnknownHeaderType: {}", e),
            Error::UnknownClientStateType(e) => write!(f, "UnknownClientStateType: {}", e),
            Error::UnknownConsensusStateType(e) => write!(f, "UnknownClientStateType: {}", e),
            Error::MissingLatestHeight => write!(f, "MissingLatestHeight"),
            Error::UnexpectedStoreAddress(e) => write!(f, "UnexpectedStoreAddress: {:?}", e),
            Error::UnexpectedCommitmentSlot(e) => write!(f, "UnexpectedCommitmentSlot: {:?}", e),
            Error::ClientFrozen(e) => write!(f, "ClientFrozen: {}", e),
            Error::UnexpectedProofHeight(e1, e2) => {
                write!(f, "UnexpectedProofHeight: {} {}", e1, e2)
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
            Error::UnexpectedTrustedEpoch(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedTrustedEpoch: {} {} header_epoch={} trusted_epoch={}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedTrustedHeight(e1, e2) => {
                write!(f, "UnexpectedTrustedHeight: {} {} ", e1, e2)
            }
            Error::EmptyHeader => write!(f, "EmptyHeader"),
            Error::UnexpectedHeaderRevision(e1, e2) => {
                write!(f, "UnexpectedHeaderRevision: {} {}", e1, e2)
            }
            Error::UnexpectedLatestHeightRevision(e1, e2) => {
                write!(f, "UnexpectedLatestHeightRevision: {} {}", e1, e2)
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
            Error::UnexpectedHeaderRelation(e1, e2, e3, e4, e5, e6) => {
                write!(
                    f,
                    "UnexpectedHeaderRelation: {} {} {:?} {:?} {} {}",
                    e1, e2, e3, e4, e5, e6
                )
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
            Error::UnexpectedStateValue(e1, e2, e3, e4, e5) => {
                write!(
                    f,
                    "UnexpectedStateValue : {:?} {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4, e5
                )
            }
            Error::TrieError(e1, e2, e3, e4) => {
                write!(f, "TrieError : {:?} {:?} {:?} {:?}", e1, e2, e3, e4)
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
            Error::MissingEpochInfoInEpochBlock(e1) => {
                write!(f, "MissingEpochInfoInEpochBlock : {:?}", e1)
            }
            Error::MissingTurnLengthInEpochBlock(e1) => {
                write!(f, "MissingTurnLengthInEpochBlock : {:?}", e1)
            }
            Error::MissingPreviousValidators(e1) => {
                write!(f, "MissingPreviousValidators : {:?}", e1)
            }
            Error::MissingCurrentValidators(e1) => {
                write!(f, "MissingCurrentValidators : {:?}", e1)
            }
            Error::UnexpectedMixHash(e1, e2) => {
                write!(f, "UnexpectedMixHash : {:?} {:?}", e1, e2)
            }
            Error::UnexpectedPreviousValidatorsHash(e1, e2, e3, e4, e5) => {
                write!(
                    f,
                    "UnexpectedPreviousValidatorsHash : {:?} {:?} {:?} {:?} trusted_epoch={}",
                    e1, e2, e3, e4, e5
                )
            }
            Error::UnexpectedCurrentValidatorsHash(e1, e2, e3, e4, e5) => {
                write!(
                    f,
                    "UnexpectedCurrentValidatorsHash : {:?} {:?} {:?} {:?} trusted_epoch={}",
                    e1, e2, e3, e4, e5
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
            Error::InsufficientHonestValidator(e1, e2, e3) => {
                write!(f, "InsufficientHonestValidator : {:?} {} {}", e1, e2, e3)
            }
            Error::MissingNextValidatorSet(e1) => {
                write!(f, "MissingNextValidatorSet : {}", e1)
            }
            Error::MissingValidatorToVerifySeal(e1) => {
                write!(f, "MissingValidatorToVerifySeal : {:?}", e1)
            }
            Error::MissingValidatorToVerifyVote(e1) => {
                write!(f, "MissingValidatorToVerifyVote : {:?}", e1)
            }
            Error::UnexpectedNextCheckpointHeader(e1, e2) => {
                write!(f, "UnexpectedNextCheckpointHeader : {} {}", e1, e2)
            }
            Error::UnexpectedNextNextCheckpointHeader(e1, e2) => {
                write!(f, "UnexpectedNextNextCheckpointHeader : {} {}", e1, e2)
            }
            Error::MissingTrustedCurrentValidators(e1) => {
                write!(f, "MissingTrustedCurrentValidators : {}", e1)
            }
            Error::UnexpectedClientType(e1) => {
                write!(f, "UnexpectedClientType : {}", e1)
            }
            Error::LCPCommitmentError(e1) => {
                write!(f, "LCPCommitmentError : {}", e1)
            }
            Error::LCPError(e1) => {
                write!(f, "LCPError: {}", e1)
            }
            Error::UnexpectedDifficultyInTurn(e1, e2, e3) => {
                write!(f, "UnexpectedDifficultyInTurn : {} {} {}", e1, e2, e3)
            }
            Error::UnexpectedDifficultyNoTurn(e1, e2, e3) => {
                write!(f, "UnexpectedDifficultyNoTurn : {} {} {}", e1, e2, e3)
            }
            Error::UnexpectedTurnLength(e1) => {
                write!(f, "UnexpectedTurnLength : {}", e1)
            }
            Error::UnexpectedExtraDataLength(e1) => {
                write!(f, "UnexpectedExtraDataLength: {}", e1)
            }
            Error::UnexpectedUntrustedValidatorsHashInEpoch(e1, e2, e3, e4, e5) => {
                write!(
                    f,
                    "UnexpectedUntrustedValidatorsHashInEpoch : {:?} {:?} {:?} {:?} trusted_epoch={}",
                    e1, e2, e3, e4, e5
                )
            }
            Error::UnexpectedCurrentValidatorsHashInEpoch(e1, e2, e3, e4) => {
                write!(
                    f,
                    "UnexpectedCurrentValidatorsHashInEpoch : {:?} {:?} {:?} {:?}",
                    e1, e2, e3, e4
                )
            }
            Error::UnexpectedUntrustedValidators(e1, e2) => {
                write!(f, "UnexpectedUntrustedValidators : {} {}", e1, e2)
            }
            Error::UnsupportedMinimumTimestamp(e1) => {
                write!(f, "UnsupportedMinimumTimestamp : {:?}", e1)
            }
            Error::UnsupportedMinimumHeight(e1) => {
                write!(f, "UnsupportedMinimumHeight : {:?}", e1)
            }
            Error::UnexpectedRevisionHeight(e1) => {
                write!(f, "UnexpectedRevisionHeight : {}", e1)
            }
            Error::MissingRequestsHash(e1) => {
                write!(f, "MissingRequestsHash : {}", e1)
            }
            Error::UnexpectedRequestsHash(e1, e2) => {
                write!(f, "UnexpectedRequestsHash : {} {:?}", e1, e2)
            }
            Error::UnexpectedHeaderRLP(e1) => {
                write!(f, "UnexpectedHeaderRLP : {}", e1)
            }
            Error::MissingForkSpec(e1, e2) => {
                write!(f, "MissingForkSpec : {}  {}", e1, e2)
            }
            Error::UnexpectedHeaderItemCount(e1, e2, e3) => {
                write!(f, "UnexpectedHeaderItemCount : {} {} {}", e1, e2, e3)
            }
            Error::MissingTimestampOrHeightInForkSpec => {
                write!(f, "MissingTimestampOrHeightInForkSpec")
            }
            Error::UnexpectedForkSpecTimestampOrder(e1, e2) => {
                write!(f, "UnexpectedForkSpecTimestampOrder : {} {}", e1, e2)
            }
            Error::UnexpectedForkSpecHeightOrder(e1, e2) => {
                write!(f, "UnexpectedForkSpecHeightOrder : {} {}", e1, e2)
            }
            Error::EmptyForkSpec => {
                write!(f, "EmptyForkSpec")
            }
            Error::UnsupportedMinimumTimestampForkSpec(e1) => {
                write!(f, "UnsupportedMinimumTimestampForkSpec : {}", e1)
            }
            Error::UnsupportedMinimumHeightForkSpec(e1) => {
                write!(f, "UnsupportedMinimumHeightForkSpec : {}", e1)
            }
            Error::VerifyAccountError(e1) => {
                write!(f, "VerifyAccountError : {}", e1)
            }
            Error::MissingForkSpecByHeight(e1) => {
                write!(f, "MissingForkSpecByHeight : {}", e1)
            }
            Error::MissingForkHeightIntPreviousEpochCalculation(e1, e2) => {
                write!(
                    f,
                    "MissingForkHeightIntPreviousEpochCalculation : {} {:?}",
                    e1, e2
                )
            }
            Error::MissingForkHeightInBoundaryCalculation(e1) => {
                write!(f, "MissingForkHeightInBoundaryCalculation : {:?}", e1)
            }
            Error::MissingBoundaryEpochs(e1) => {
                write!(f, "MissingBoundaryEpochs : {}", e1)
            }
            Error::MissingPreviousForkSpec(e1) => {
                write!(f, "MissingPreviousForkSpec : {:?}", e1)
            }
            Error::UnexpectedCurrentEpochInCalculatingNextEpoch(e1, e2, e3) => {
                write!(
                    f,
                    "UnexpectedCurrentEpochInCalculatingNextEpoch : {} {} {}",
                    e1, e2, e3
                )
            }
            Error::UnexpectedMissingForkSpecInCurrentEpochCalculation(e1, e2) => {
                write!(
                    f,
                    "UnexpectedMissingForkSpecInCurrentEpochCalculation : {} {:?} ",
                    e1, e2
                )
            }
            Error::UnexpectedMissingForkSpecInPreviousEpochCalculation(e1, e2) => {
                write!(
                    f,
                    "UnexpectedMissingForkSpecInPreviousEpochCalculation : {} {:?} ",
                    e1, e2
                )
            }
            Error::UnexpectedPreviousEpochInCalculatingNextEpoch(e1, e2, e3) => {
                write!(
                    f,
                    "UnexpectedPreviousEpochInCalculatingNextEpoch : {} {} {} ",
                    e1, e2, e3,
                )
            }
            Error::MissingEpochInfo(e1) => {
                write!(f, "MissingEpochInfo : {} ", e1)
            }
            Error::UnexpectedEpochInfo(e1, e2) => {
                write!(f, "UnexpectedEpochInfo : {} {}", e1, e2)
            }
            Error::UnexpectedNotEmptyMixHash(e1, e2) => {
                write!(f, "UnexpectedNotEmptyMixHash : {} {:?}", e1, e2)
            }
            Error::UnexpectedMilliSecondValue(e1, e2) => {
                write!(f, "UnexpectedMilliSecondValue : {} {}", e1, e2)
            }
        }
    }
}

#[derive(Debug)]
pub enum ClientError {
    LatestHeight {
        cause: Error,
        client_id: ClientId,
    },
    CreateClient {
        cause: Error,
        client_state: Any,
        consensus_sate: Any,
    },
    UpdateClient {
        cause: Error,
        client_id: ClientId,
        message: Any,
    },
    VerifyMembership {
        cause: Error,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
    },
    VerifyNonMembership {
        cause: Error,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        proof_height: Height,
        proof: Vec<u8>,
    },
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::LatestHeight {
                cause,
                client_id
            } => write!(
                f,
                "LatestHeight: cause={}\nclient_id={}",
                cause, client_id
            ),
            ClientError::CreateClient {cause, client_state, consensus_sate} => write!(
                f,
                "CreateClient: cause={}\nclient_state={:?}\nconsensus_state={:?}",
                cause, client_state, consensus_sate
            ),
            ClientError::UpdateClient{cause, client_id, message} => write!(
                f,
                "UpdateClient: cause={}\nclient_id={:?}\nmessage={:?}",
                cause, client_id, message
            ),
            ClientError::VerifyMembership {
                cause, client_id,
                prefix,
                path,
                value,
                proof_height,
                proof
            } => write!(
                f,
                "VerifyMembership: cause={}\nclient_id={:?}\nprefix={:?}\npath={:?}\nvalue={:?}\nproof_height={:?}\nproof={:?}",
                cause, client_id, prefix, path, value, proof_height, proof
            ),
            ClientError::VerifyNonMembership {
                cause, client_id,
                prefix,
                path,
                proof_height,
                proof
            } => write!(
                f,
                "VerifyNonMembership: cause={}\nclient_id={:?}\nprefix={:?}\npath={:?}\nproof_height={:?}\nproof={:?}",
                cause, client_id, prefix, path, proof_height, proof
            ),
        }
    }
}
impl light_client::LightClientSpecificError for ClientError {}
