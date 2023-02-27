use alloc::vec::Vec;

use ibc::core::ics02_client::error::ClientError;

use ibc::timestamp::ParseTimestampError;
use ibc::Height;

use crate::misc::{Address, BlockNumber, NanoTime};
use k256::ecdsa::signature;
use rlp::DecoderError;

#[derive(Debug)]
pub enum Error {
    ICS02Error(ClientError),
    ICSTimestamp(ParseTimestampError),

    // data conversion error
    RLPDecodeError(DecoderError),
    UnexpectedAnyConsensusState(Height),

    // ClientState error
    MissingLatestHeight,
    MissingTrustLevel,
    UnexpectedTrustingPeriod(u64, u64),

    // ConsensusState error
    AccountNotFound(Vec<Vec<u8>>),
    UnexpectedStateRoot,
    UnexpectedTimestamp(NanoTime),

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
