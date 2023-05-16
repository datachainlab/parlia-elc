use alloc::vec::Vec;

use ibc::core::ics02_client::error::ClientError;
use ibc::core::ContextError;
use ibc::timestamp::ParseTimestampError;
use k256::ecdsa::signature;
use rlp::DecoderError;

use crate::misc::{Address, BlockNumber, NanoTime};

#[derive(Debug)]
pub enum Error {
    ICS02Error(ClientError),
    ContextError(ContextError),
    ICSTimestamp(ParseTimestampError),

    // data conversion error
    RLPDecodeError(DecoderError),

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

impl From<Error> for ClientError {
    fn from(value: Error) -> Self {
        match value {
            Error::ICS02Error(ce) => ce,
            e => ClientError::Other {
                description: format!("{:?}", e),
            },
        }
    }
}

pub fn into_client_error(e: ContextError) -> ClientError {
    match e {
        ContextError::ClientError(e) => e,
        _ => ClientError::Other {
            description: format!("{:?}", e),
        },
    }
}
