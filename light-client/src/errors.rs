use alloc::string::String;
use alloc::vec::Vec;

use ibc::core::ics02_client::error::Error as ICS02Error;
use ibc::timestamp::ParseTimestampError;
use ibc::Height;
use k256::ecdsa::signature;
use prost::{DecodeError as ProtoDecodeError, EncodeError as ProtoEncodeError};
use rlp::DecoderError;

use crate::misc::{Address, BlockNumber, NanoTime};

#[derive(Debug)]
pub enum Error {
    ICS02Error(ICS02Error),
    ICSTimestamp(ParseTimestampError),

    UnexpectedTypeUrl(String),

    // data conversion error
    ProtoDecodeError(ProtoDecodeError),
    ProtoEncodeError(ProtoEncodeError),
    RLPDecodeError(DecoderError),
    UnexpectedAnyConsensusState(Height),

    // ClientState error
    MissingLatestHeight,
    MissingTrustLevel,
    UnexpectedTrustingPeriod(u64, u64),
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
    MissingSignerInValidator(BlockNumber, Address),
    UnexpectedGasDiff(BlockNumber, u64, u64),
    UnexpectedGasUsed(BlockNumber, u64, u64),
    UnexpectedHeaderRelation(BlockNumber, BlockNumber),
}
