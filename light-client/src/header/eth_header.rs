use alloc::vec::Vec;

use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Rlp, RlpStream};

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;

use crate::errors::Error;
use crate::header::epoch::Epoch;
use crate::header::hardfork::PASCAL_TIMESTAMP;
use crate::header::vote_attestation::VoteAttestation;
use crate::misc::{Address, BlockNumber, ChainId, Hash, RlpIterator, Validators};

use super::BLOCKS_PER_EPOCH;

const DIFFICULTY_INTURN: u64 = 2;
const DIFFICULTY_NOTURN: u64 = 1;

pub(crate) const EXTRA_VANITY: usize = 32;
pub(crate) const EXTRA_SEAL: usize = 65;
const VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN: usize = 20;
const BLS_PUBKEY_LENGTH: usize = 48;
const VALIDATOR_BYTES_LENGTH: usize = VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN + BLS_PUBKEY_LENGTH;
const VALIDATOR_NUM_SIZE: usize = 1;

const TURN_LENGTH_SIZE: usize = 1;

const PARAMS_GAS_LIMIT_BOUND_DIVISOR: u64 = 256;

const EMPTY_UNCLE_HASH: Hash =
    hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");
const EMPTY_NONCE: [u8; 8] = hex!("0000000000000000");
const EMPTY_HASH: Hash = hex!("0000000000000000000000000000000000000000000000000000000000000000");

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ETHHeader {
    pub parent_hash: Vec<u8>,
    pub uncle_hash: Vec<u8>,
    pub coinbase: Vec<u8>,
    pub root: Hash,
    pub tx_hash: Vec<u8>,
    pub receipt_hash: Vec<u8>,
    pub bloom: Vec<u8>,
    pub difficulty: u64,
    pub number: BlockNumber,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_digest: Vec<u8>,
    pub nonce: Vec<u8>,
    pub base_fee_per_gas: Option<u64>,
    pub withdrawals_hash: Option<Vec<u8>>,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64>,
    pub parent_beacon_root: Option<Vec<u8>>,
    pub requests_hash: Option<Vec<u8>>,

    // calculated by RawETHHeader
    pub hash: Hash,
    pub epoch: Option<Epoch>,
}

impl ETHHeader {
    /// This extracts the Ethereum account address from a signed header.
    fn ecrecover(&self, chain_id: &ChainId) -> Result<Address, Error> {
        if self.extra_data.len() < EXTRA_SEAL {
            return Err(Error::MissingSignatureInExtraData(
                self.number,
                self.extra_data.len(),
                EXTRA_SEAL,
            ));
        }
        let signature = &self.extra_data[self.extra_data.len() - EXTRA_SEAL..];
        let rid = RecoveryId::from_byte(signature[EXTRA_SEAL - 1])
            .ok_or_else(|| Error::UnexpectedRecoveryId(self.number))?;
        let seal_hash = self.seal_hash(chain_id)?;
        let signature = Signature::try_from(&signature[..EXTRA_SEAL - 1])
            .map_err(|e| Error::UnexpectedSignature(self.number, e))?;
        let signer = VerifyingKey::recover_from_prehash(&seal_hash, &signature, rid)
            .map_err(|e| Error::UnexpectedSignature(self.number, e))?;
        let point = signer.as_affine().to_encoded_point(false);
        let pubkey: Vec<u8> = point.to_bytes().into();
        let address: Address = keccak_256(&pubkey[1..])[12..]
            .try_into()
            .map_err(|_e| Error::UnexpectedAddress(self.number))?;
        Ok(address)
    }

    /// This returns the hash of a block prior to it being sealed.
    fn seal_hash(&self, chain_id: &ChainId) -> Result<Hash, Error> {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream.append(&chain_id.id());
        stream.append(&self.parent_hash);
        stream.append(&self.uncle_hash);
        stream.append(&self.coinbase);
        stream.append(&self.root.to_vec());
        stream.append(&self.tx_hash);
        stream.append(&self.receipt_hash);
        stream.append(&self.bloom);
        stream.append(&self.difficulty);
        stream.append(&self.number);
        stream.append(&self.gas_limit);
        stream.append(&self.gas_used);
        stream.append(&self.timestamp);
        stream.append(&self.extra_data[..self.extra_data.len() - EXTRA_SEAL].to_vec());
        stream.append(&self.mix_digest);
        stream.append(&self.nonce);
        if let Some(parent_beacon_root) = &self.parent_beacon_root {
            if parent_beacon_root == &EMPTY_HASH {
                if let Some(value) = &self.base_fee_per_gas {
                    stream.append(value);
                } else {
                    stream.append_empty_data();
                }
                if let Some(value) = &self.withdrawals_hash {
                    stream.append(value);
                } else {
                    stream.append_empty_data();
                }
                if let Some(value) = &self.blob_gas_used {
                    stream.append(value);
                } else {
                    stream.append_empty_data();
                }
                if let Some(value) = &self.excess_blob_gas {
                    stream.append(value);
                } else {
                    stream.append_empty_data();
                }
                stream.append(parent_beacon_root);

                // https://github.com/bnb-chain/bsc/blob/e2f2111a85fecabb4782099338aca21bf58bde09/core/types/block.go#L776
                if let Some(value) = &self.requests_hash {
                    stream.append(value);
                }
            }
        }
        stream.finalize_unbounded_list();
        Ok(keccak_256(stream.out().as_ref()))
    }

    pub fn previous_epoch(&self) -> BlockNumber {
        let epoch_count = self.number / BLOCKS_PER_EPOCH;
        if epoch_count == 0 {
            return 0;
        }
        (epoch_count - 1) * BLOCKS_PER_EPOCH
    }

    pub fn current_epoch(&self) -> BlockNumber {
        let epoch_count = self.number / BLOCKS_PER_EPOCH;
        epoch_count * BLOCKS_PER_EPOCH
    }

    /// Verifies that all headers in the `ETHHeader` struct have valid cascading fields.
    ///
    /// https://github.com/bnb-chain/bsc/blob/b4773e8b5080f37e1c65c083b543f60c895abb70/consensus/parlia/parlia.go#L380
    pub fn verify_cascading_fields(&self, parent: &ETHHeader) -> Result<(), Error> {
        if self.gas_used > self.gas_limit {
            return Err(Error::UnexpectedGasUsed(
                self.number,
                self.gas_used,
                self.gas_limit,
            ));
        }

        if parent.number != self.number - 1
            || parent.hash != self.parent_hash.as_slice()
            || parent.timestamp >= self.timestamp
        {
            return Err(Error::UnexpectedHeaderRelation(
                parent.number,
                self.number,
                parent.hash,
                self.parent_hash.clone(),
                parent.timestamp,
                self.timestamp,
            ));
        }

        //Verify that the gas limit remains within allowed bounds
        let diff = if parent.gas_limit > self.gas_limit {
            parent.gas_limit - self.gas_limit
        } else {
            self.gas_limit - parent.gas_limit
        };
        let limit = parent.gas_limit / PARAMS_GAS_LIMIT_BOUND_DIVISOR;
        if diff >= limit {
            return Err(Error::UnexpectedGasDiff(self.number, diff, limit));
        }
        Ok(())
    }

    /// Verifies the seal of the current `ETHHeader`.
    ///
    /// https://github.com/bnb-chain/bsc/blob/7a19cd27b61b342d24a1584efc7fa00de4a5b4f5/consensus/parlia/parlia.go#L755
    pub fn verify_seal(
        &self,
        validating_epoch: &Epoch,
        chain_id: &ChainId,
    ) -> Result<Address, Error> {
        // Resolve the authorization key and check against validators
        let signer = self.ecrecover(chain_id)?;
        if self.coinbase.as_slice() != signer {
            return Err(Error::UnexpectedCoinbase(self.number));
        }

        let mut valid_signer = false;
        for validator in validating_epoch.validators().iter() {
            if validator[0..VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN] == signer {
                valid_signer = true;
                break;
            }
        }
        if !valid_signer {
            return Err(Error::MissingSignerInValidator(self.number, signer));
        }

        // Ensure that the difficulty corresponds to the turn-ness of the signer
        self.verify_validator_rotation(validating_epoch)?;

        Ok(signer)
    }

    /// Verifies the validator rotation for the current `ETHHeader`.
    ///
    /// This function checks if the validator rotation is correct by comparing the coinbase address
    /// with the expected in-turn validator address based on the current block number and epoch.
    /// It ensures that the difficulty corresponds to the turn-ness of the signer.
    ///
    fn verify_validator_rotation(&self, epoch: &Epoch) -> Result<(), Error> {
        let offset = (self.number / epoch.turn_length() as u64) as usize % epoch.validators().len();
        let inturn_validator = &epoch.validators()[offset][0..VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN];
        if inturn_validator == self.coinbase {
            if self.difficulty != DIFFICULTY_INTURN {
                return Err(Error::UnexpectedDifficultyInTurn(
                    self.number,
                    self.difficulty,
                    offset,
                ));
            }
        } else if self.difficulty != DIFFICULTY_NOTURN {
            return Err(Error::UnexpectedDifficultyNoTurn(
                self.number,
                self.difficulty,
                offset,
            ));
        }
        Ok(())
    }

    /// Verifies the target attestation of the current `ETHHeader` against its parent header.
    ///
    /// This function checks the target vote attestation of the current header to ensure that
    /// the target block is the direct parent of the current block.
    ///
    pub fn verify_target_attestation(&self, parent: &ETHHeader) -> Result<VoteAttestation, Error> {
        let target_vote_attestation = self.get_vote_attestation()?;
        let target_data = &target_vote_attestation.data;

        // The target block should be direct parent.
        if target_data.target_number != parent.number || target_data.target_hash != parent.hash {
            return Err(Error::UnexpectedTargetVoteAttestationRelation(
                target_data.target_number,
                parent.number,
                target_data.target_hash,
                parent.hash,
            ));
        }
        Ok(target_vote_attestation)
    }

    /// Verifies the vote attestation of the current `ETHHeader` against its parent header.
    ///
    /// https://github.com/bnb-chain/bsc/blob/7a19cd27b61b342d24a1584efc7fa00de4a5b4f5/consensus/parlia/parlia.go#L416
    pub fn verify_vote_attestation(&self, parent: &ETHHeader) -> Result<VoteAttestation, Error> {
        let vote_attestation = self.verify_target_attestation(parent)?;
        let vote_data = &vote_attestation.data;

        // The source block should be the highest justified block.
        let parent_vote_attestation = parent.get_vote_attestation()?;
        let parent_data = &parent_vote_attestation.data;
        if vote_data.source_number != parent_data.target_number
            || vote_data.source_hash != parent_data.target_hash
        {
            return Err(Error::UnexpectedSourceVoteAttestationRelation(
                vote_data.source_number,
                parent_data.target_number,
                vote_data.source_hash,
                parent_data.target_hash,
            ));
        }
        Ok(vote_attestation)
    }

    pub fn get_vote_attestation(&self) -> Result<VoteAttestation, Error> {
        if self.extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL {
            return Err(Error::UnexpectedVoteLength(self.extra_data.len()));
        }
        let attestation_bytes = if self.number % BLOCKS_PER_EPOCH != 0 {
            &self.extra_data[EXTRA_VANITY..self.extra_data.len() - EXTRA_SEAL]
        } else {
            let num = self.extra_data[EXTRA_VANITY] as usize;
            let start = EXTRA_VANITY
                + VALIDATOR_NUM_SIZE
                + (num * VALIDATOR_BYTES_LENGTH)
                + TURN_LENGTH_SIZE;
            let end = self.extra_data.len() - EXTRA_SEAL;
            if end <= start {
                return Err(Error::UnexpectedVoteLength(self.extra_data.len()));
            }
            &self.extra_data[start..end]
        };

        Rlp::new(attestation_bytes).try_into()
    }

    pub fn is_epoch(&self) -> bool {
        self.number % BLOCKS_PER_EPOCH == 0
    }
}

pub fn get_validator_bytes_and_turn_length(extra_data: &[u8]) -> Result<(Validators, u8), Error> {
    if extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL {
        return Err(Error::UnexpectedExtraDataLength(extra_data.len()));
    }
    let num = extra_data[EXTRA_VANITY] as usize;
    if num == 0 || extra_data.len() < EXTRA_VANITY + EXTRA_SEAL + num * VALIDATOR_BYTES_LENGTH {
        return Err(Error::UnexpectedExtraDataLength(extra_data.len()));
    }
    let start = EXTRA_VANITY + VALIDATOR_NUM_SIZE;
    let end = start + num * VALIDATOR_BYTES_LENGTH;
    let turn_length = extra_data[end];
    validate_turn_length(turn_length)?;
    Ok((
        extra_data[start..end]
            .chunks(VALIDATOR_BYTES_LENGTH)
            .map(|s| s.into())
            .collect(),
        turn_length,
    ))
}

pub fn validate_turn_length(turn_length: u8) -> Result<(), Error> {
    if !(turn_length == 1 || (3..=9).contains(&turn_length)) {
        return Err(Error::UnexpectedTurnLength(turn_length));
    }
    Ok(())
}

impl TryFrom<RawETHHeader> for ETHHeader {
    type Error = Error;

    /// This includes part of header verification.
    /// - verifyHeader: https://github.com/bnb-chain/bsc/blob/b4773e8b5080f37e1c65c083b543f60c895abb70/consensus/parlia/parlia.go#L324
    fn try_from(value: RawETHHeader) -> Result<Self, Self::Error> {
        let mut rlp = RlpIterator::new(Rlp::new(value.header.as_slice()));
        let parent_hash: Vec<u8> = rlp.try_next_as_val()?;
        let uncle_hash: Vec<u8> = rlp.try_next_as_val()?;
        let coinbase: Vec<u8> = rlp.try_next_as_val()?;
        let root: Hash = rlp
            .try_next_as_val::<Vec<u8>>()?
            .try_into()
            .map_err(Error::UnexpectedStateRoot)?;
        let tx_hash: Vec<u8> = rlp.try_next_as_val()?;
        let receipt_hash: Vec<u8> = rlp.try_next_as_val()?;
        let bloom: Vec<u8> = rlp.try_next_as_val()?;
        let difficulty = rlp.try_next_as_val()?;
        let number = rlp.try_next_as_val()?;
        let gas_limit = rlp.try_next_as_val()?;
        let gas_used = rlp.try_next_as_val()?;
        let timestamp = rlp.try_next_as_val()?;
        let extra_data: Vec<u8> = rlp.try_next_as_val()?;
        let mix_digest: Vec<u8> = rlp.try_next_as_val()?;
        let nonce: Vec<u8> = rlp.try_next_as_val()?;
        let base_fee_per_gas: Option<u64> = rlp.try_next_as_val().map(Some).unwrap_or(None);
        let withdrawals_hash: Option<Vec<u8>> = rlp.try_next_as_val().map(Some).unwrap_or(None);
        let blob_gas_used: Option<u64> = rlp.try_next_as_val().map(Some).unwrap_or(None);
        let excess_blob_gas: Option<u64> = rlp.try_next_as_val().map(Some).unwrap_or(None);
        let parent_beacon_root: Option<Vec<u8>> = rlp.try_next_as_val().map(Some).unwrap_or(None);
        let requests_hash: Option<Vec<u8>> = rlp.try_next_as_val().map(Some).unwrap_or(None);

        // Check that the extra-data contains the vanity, validators and signature
        let extra_size = extra_data.len();
        if extra_size < EXTRA_VANITY {
            return Err(Error::MissingVanityInExtraData(
                number,
                extra_size,
                EXTRA_VANITY,
            ));
        }
        if extra_size < EXTRA_VANITY + EXTRA_SEAL {
            return Err(Error::MissingSignatureInExtraData(
                number,
                extra_size,
                EXTRA_VANITY + EXTRA_SEAL,
            ));
        }

        // Ensure that the mix digest is zero as we don't have fork protection currently
        if mix_digest != EMPTY_HASH {
            return Err(Error::UnexpectedMixHash(number));
        }
        // Ensure that the block doesn't contain any uncles which are meaningless in PoA
        if uncle_hash != EMPTY_UNCLE_HASH {
            return Err(Error::UnexpectedUncleHash(number));
        }
        // Ensure that the block's difficulty is meaningful (may not be correct at this point)
        if number > 0 && difficulty != DIFFICULTY_INTURN && difficulty != DIFFICULTY_NOTURN {
            return Err(Error::UnexpectedDifficulty(number, difficulty));
        }

        // https://github.com/mapprotocol/map-contracts/blob/0477ccc5d16d0a0a3fe8749fed80b93d708587ca/lightclients/bsc/contracts/lib/Verify.sol#L124
        // geth doesn't check nonce but map-contrats does
        if nonce != EMPTY_NONCE {
            return Err(Error::UnexpectedNonce(number));
        }
        let hash: Hash = keccak_256(value.header.as_slice());

        let epoch = if number % BLOCKS_PER_EPOCH == 0 {
            let (validators, turn_length) = get_validator_bytes_and_turn_length(&extra_data)?;
            Some(Epoch::new(validators.into(), turn_length))
        } else {
            None
        };

        #[allow(clippy::absurd_extreme_comparisons)]
        if PASCAL_TIMESTAMP > 0 {
            if timestamp >= PASCAL_TIMESTAMP {
                if requests_hash.is_none() {
                    return Err(Error::MissingRequestsHash(number));
                }
                // Ensure no more header element.
                if rlp.try_next().is_ok() {
                    return Err(Error::UnexpectedHeaderRLP(number));
                }
            } else if timestamp < PASCAL_TIMESTAMP && requests_hash.is_some() {
                return Err(Error::UnexpectedRequestsHash(
                    number,
                    requests_hash.unwrap(),
                ));
            }
        }

        Ok(Self {
            parent_hash,
            uncle_hash,
            coinbase,
            root,
            tx_hash,
            receipt_hash,
            bloom,
            difficulty,
            number,
            gas_limit,
            gas_used,
            timestamp,
            extra_data,
            mix_digest,
            nonce,
            base_fee_per_gas,
            excess_blob_gas,
            withdrawals_hash,
            blob_gas_used,
            parent_beacon_root,
            requests_hash,
            hash,
            epoch,
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::errors::Error;
    use crate::header::eth_header::{
        ETHHeader, DIFFICULTY_INTURN, DIFFICULTY_NOTURN, EXTRA_SEAL, EXTRA_VANITY,
        PARAMS_GAS_LIMIT_BOUND_DIVISOR, VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN,
    };

    use rlp::RlpStream;
    use rstest::*;

    use crate::fixture::{decode_header, localnet, Network};
    use crate::header::epoch::Epoch;

    use alloc::boxed::Box;
    use hex_literal::hex;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;

    fn to_raw(header: &ETHHeader) -> RawETHHeader {
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream.append(&header.parent_hash);
        stream.append(&header.uncle_hash);
        stream.append(&header.coinbase);
        stream.append(&header.root.to_vec());
        stream.append(&header.tx_hash);
        stream.append(&header.receipt_hash);
        stream.append(&header.bloom);
        stream.append(&header.difficulty);
        stream.append(&header.number);
        stream.append(&header.gas_limit);
        stream.append(&header.gas_used);
        stream.append(&header.timestamp);
        stream.append(&header.extra_data);
        stream.append(&header.mix_digest);
        stream.append(&header.nonce);
        stream.finalize_unbounded_list();
        RawETHHeader {
            header: stream.out().to_vec(),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_missing_vanity(#[case] hp: Box<dyn Network>) {
        let mut header = hp.epoch_header_plus_1();
        header.extra_data = [0u8; EXTRA_VANITY - 1].to_vec();
        let raw = to_raw(&header);
        let err = ETHHeader::try_from(raw).unwrap_err();
        match err {
            Error::MissingVanityInExtraData(number, actual, min) => {
                assert_eq!(number, header.number);
                assert_eq!(actual, header.extra_data.len());
                assert_eq!(min, EXTRA_VANITY);
            }
            err => unreachable!("{:?}", err),
        };
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_missing_signature(#[case] hp: Box<dyn Network>) {
        let mut header = hp.epoch_header_plus_1();
        header.extra_data = [0u8; EXTRA_VANITY + EXTRA_SEAL - 1].to_vec();
        let raw = to_raw(&header);
        let err = ETHHeader::try_from(raw).unwrap_err();
        match err {
            Error::MissingSignatureInExtraData(number, actual, min) => {
                assert_eq!(number, header.number);
                assert_eq!(actual, header.extra_data.len());
                assert_eq!(min, EXTRA_VANITY + EXTRA_SEAL);
            }
            err => unreachable!("{:?}", err),
        };
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_unexpected_mix_hash(#[case] hp: Box<dyn Network>) {
        let mut header = hp.epoch_header_plus_1();
        header.mix_digest = vec![];
        let raw = to_raw(&header);
        let err = ETHHeader::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedMixHash(number) => {
                assert_eq!(number, header.number);
            }
            err => unreachable!("{:?}", err),
        };
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_unexpected_uncle_hash(#[case] hp: Box<dyn Network>) {
        let mut header = hp.epoch_header_plus_1();
        header.uncle_hash = vec![];
        let raw = to_raw(&header);
        let err = ETHHeader::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedUncleHash(number) => {
                assert_eq!(number, header.number);
            }
            err => unreachable!("{:?}", err),
        };
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_unexpected_difficulty(#[case] hp: Box<dyn Network>) {
        let mut header = hp.epoch_header_plus_1();
        header.difficulty = 10;
        let raw = to_raw(&header);
        let err = ETHHeader::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedDifficulty(number, actual) => {
                assert_eq!(number, header.number);
                assert_eq!(actual, header.difficulty);
            }
            err => unreachable!("{:?}", err),
        };
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_unexpected_nonce(#[case] hp: Box<dyn Network>) {
        let mut header = hp.epoch_header_plus_1();
        header.nonce = vec![];
        let raw = to_raw(&header);
        let err = ETHHeader::try_from(raw).unwrap_err();
        match err {
            Error::UnexpectedNonce(number) => {
                assert_eq!(number, header.number);
            }
            err => unreachable!("{:?}", err),
        };
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_seal(#[case] hp: Box<dyn Network>) {
        let prev_epoch = hp.previous_epoch_header().epoch.unwrap();
        let blocks = vec![
            hp.epoch_header(),
            hp.epoch_header_plus_1(),
            hp.epoch_header_plus_2(),
        ];
        for block in blocks {
            if let Err(e) = block.verify_seal(&prev_epoch, &hp.network()) {
                unreachable!("{} {:?}", block.number, e);
            }
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_seal(#[case] hp: Box<dyn Network>) {
        let prev_epoch = hp.previous_epoch_header().epoch.unwrap();
        let mut blocks = vec![hp.epoch_header_plus_1(), hp.epoch_header_plus_2()];

        for block in blocks.iter_mut() {
            let result = block.verify_seal(&Epoch::new(vec![].into(), 1), &hp.network());
            match result.unwrap_err() {
                Error::MissingSignerInValidator(number, address) => {
                    assert_eq!(block.number, number);
                    assert_eq!(block.coinbase, address);
                }
                e => unreachable!("{:?}", e),
            };
        }

        for block in blocks.iter_mut() {
            block.coinbase = vec![];
            let result = block.verify_seal(&prev_epoch, &hp.network());
            match result.unwrap_err() {
                Error::UnexpectedCoinbase(number) => assert_eq!(block.number, number),
                e => unreachable!("{:?}", e),
            };
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_cascading_fields(#[case] hp: Box<dyn Network>) {
        let blocks = vec![
            hp.epoch_header(),
            hp.epoch_header_plus_1(),
            hp.epoch_header_plus_2(),
        ];
        for (i, block) in blocks.iter().enumerate() {
            if i == 0 {
                continue;
            }
            if let Err(e) = block.verify_cascading_fields(&blocks[i - 1]) {
                unreachable!("{} {:?}", block.number, e);
            }
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_cascading_fields(#[case] hp: Box<dyn Network>) {
        let parent = hp.epoch_header();
        let mut block = hp.epoch_header_plus_1();
        block.gas_limit = 10000;
        block.gas_used = parent.gas_limit + 1;
        let result = block.verify_cascading_fields(&parent);
        match result.unwrap_err() {
            Error::UnexpectedGasUsed(number, used, limit) => {
                assert_eq!(block.number, number);
                assert_eq!(block.gas_used, used);
                assert_eq!(block.gas_limit, limit);
            }
            err => unreachable!("{:?}", err),
        }

        let parent = hp.epoch_header();
        let block = hp.epoch_header_plus_2();
        let result = block.verify_cascading_fields(&parent);
        match result.unwrap_err() {
            Error::UnexpectedHeaderRelation(
                parent_no,
                child_no,
                parent_hash,
                child_parent_hash,
                parent_ts,
                child_ts,
            ) => {
                assert_eq!(parent.number, parent_no);
                assert_eq!(block.number, child_no);
                assert_eq!(parent.hash, parent_hash);
                assert_eq!(block.parent_hash, child_parent_hash);
                assert_eq!(parent.timestamp, parent_ts);
                assert_eq!(block.timestamp, child_ts);
            }
            err => unreachable!("{:?}", err),
        }

        let parent = hp.epoch_header();
        let mut block = hp.epoch_header_plus_1();
        block.gas_used = 0;
        block.gas_limit = 0;
        let result = block.verify_cascading_fields(&parent);
        match result.unwrap_err() {
            Error::UnexpectedGasDiff(number, diff, limit) => {
                assert_eq!(block.number, number);
                assert_eq!(parent.gas_limit / PARAMS_GAS_LIMIT_BOUND_DIVISOR, limit);
                assert_eq!(parent.gas_limit - block.gas_limit, diff);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_success_verify_vote_attestation(#[case] hp: Box<dyn Network>) {
        let blocks = vec![
            hp.epoch_header(),
            hp.epoch_header_plus_1(),
            hp.epoch_header_plus_2(),
        ];
        for (i, block) in blocks.iter().enumerate() {
            if i == 0 {
                continue;
            }
            if let Err(e) = block.verify_vote_attestation(&blocks[i - 1]) {
                unreachable!("{} {:?}", block.number, e);
            }
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_vote_attestation(#[case] hp: Box<dyn Network>) {
        let header = hp.epoch_header_plus_1();
        let parent = hp.epoch_header_plus_1();
        let err = header.verify_vote_attestation(&parent).unwrap_err();
        match err {
            Error::UnexpectedTargetVoteAttestationRelation(
                source,
                parent_target,
                _source_hash,
                _parent_target_hash,
            ) => {
                assert_eq!(header.number - 1, source);
                assert_eq!(parent.number, parent_target);
            }
            err => unreachable!("{:?}", err),
        }

        let mut block = hp.epoch_header_plus_1();
        block.extra_data = vec![];
        let err = block
            .verify_vote_attestation(&hp.epoch_header())
            .unwrap_err();
        match err {
            Error::UnexpectedVoteLength(size) => {
                assert_eq!(size, block.extra_data.len());
            }
            err => unreachable!("{:?}", err),
        }

        let header = hp.epoch_header_plus_2();
        let mut parent = hp.epoch_header_plus_1();
        parent.extra_data = header.extra_data.clone();
        let err = header.verify_vote_attestation(&parent).unwrap_err();
        match err {
            Error::UnexpectedSourceVoteAttestationRelation(
                source,
                parent_target,
                _source_hash,
                _parent_target_hash,
            ) => {
                assert_eq!(parent.number - 1, source);
                assert_eq!(parent.number, parent_target);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_validator_rotation_inturn(#[case] hp: Box<dyn Network>) {
        let mut header = hp.epoch_header();
        header.difficulty = DIFFICULTY_NOTURN;
        let prev = hp.previous_epoch_header();
        match header
            .verify_validator_rotation(&prev.epoch.unwrap())
            .unwrap_err()
        {
            Error::UnexpectedDifficultyInTurn(e1, e2, _e3) => {
                assert_eq!(e1, header.number);
                assert_eq!(e2, header.difficulty);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_validator_rotation_noturn(#[case] hp: Box<dyn Network>) {
        let mut header = hp.epoch_header();
        header.difficulty = DIFFICULTY_INTURN;
        let prev = hp.previous_epoch_header();
        header.coinbase = prev.epoch.clone().unwrap().validators()[1]
            [0..VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN]
            .to_vec();
        match header
            .verify_validator_rotation(&prev.epoch.unwrap())
            .unwrap_err()
        {
            Error::UnexpectedDifficultyNoTurn(e1, e2, _e3) => {
                assert_eq!(e1, header.number);
                assert_eq!(e2, header.difficulty);
            }
            err => unreachable!("{:?}", err),
        }
    }
    #[test]
    fn test_success_bep466_header() {
        let header = hex!("f90370a04a99d244666a287d9aaa1a81aa5bba573f156865369023eaa53a4ba8bb303ad1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e04db2de85453e0936b441c339a26d10cfa71b50a0d0a25a7c6b93d5d2e8f7e2075d2886fa62840f31c127b880b7cd503e2d364163a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282071b8402625a008084678f4827b90111d883010503846765746888676f312e32332e35856c696e75780000002f5b9772f8ae0fb860959e5c417ecd8a5e5ddabd85485cf2cc4433f26beea076d77bbc6f461e4129881b8772bdae5fdd6ca927b571662ac5750d4abeca4f44a4406ab3254e0d98e6ee92b5b6396122853b45db2d18d24fb79e8397e253ca10a2a03b3b18e5961173b5f848820719a0e5ef3de482ecc3de5aea0efb17457d7edc5b1a39fc97c29cc5780b4665c9ca2082071aa04a99d244666a287d9aaa1a81aa5bba573f156865369023eaa53a4ba8bb303ad180aba9a203cbc9ac6e2eabbc44b15f7c526ec5f9d570a0addc005d5958d8415f760794e65762057ff9956dce68034d30cca6d9cc2ac3eb35f699d47c74931c470a01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec();
        let header = decode_header(header);
        let chain_id = localnet().network();

        let prev_epoch = hex!("f90484a0cdbf04705a1f6ed4989217c1e89f4c0ab22b3122df2f48c09e2fef3d0aa4b5b4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b2e42bc54d19116d2348ac83461e2e0915d508ada08b3fad7b45691957d1bf905d2601a14e12d48d1da89205d22b4eb582af803e3da0629579638c8423e2836b6ad04eed7a7dcda123a3f4b6d2ab488121fac9df6c10a03cd1ebc99cd975182c58de47be968c97658cff4c465e20654185f408a851403cb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028207088402625a008229a884678f47eeb90223d883010503846765746888676f312e32332e35856c696e75780000002f5b9772048fdaaa7e6631e438625ca25c857a3727ea28e565b5ad484c80ff8ed9a2aff68923f36e8975c377abd0c62a8a66ac0d2519b3eb4c14951312006c9e8b3829dc68cab6bcf0a7876ea32e7a748c697d01345145485561305b24958ec28bac0db09ee3e6cfc1769fd72b493a6c44118598abb600bec65e66aafd23acd46e0d1e0bda9d8101dbbdbf369fd9a13701eafb76870cb220843b8c6476824bfa15ad21d1bf47e3df7d8d99b105a24ebca95a84b035e6af22880b9eaf1d6a4a233920a57ecf09f8a6b89d7f5ca3cfe6484fe04db2de85453e0936b441c339a26d10cfa71b50b611e87c256a23edc8b7e55558abe1a7ff94262bacb53d600e657270ee6af9172c5a31c24498a162147dd7e1bfdcef9107f8ae0fb860a70e55ed7260c28c69880ca12370872c2059f0540ca88c1cb7a6ba772ed6e7f62a5e11c31e117ea483a4c6b46cf213681092f5273512ad15e030f52c3485838801a5ae99ece187028adbf6f543b34bd4a48199dc9b58ea47b16d06049a370a65f848820706a0ab18ec6cce429c9918cb4f354ffda5c0119871589de4829c9871ee7eddbce0ed820707a0cdbf04705a1f6ed4989217c1e89f4c0ab22b3122df2f48c09e2fef3d0aa4b5b48099019414f8ca7f80176785458468355225878402b80bbe64de4de083cbd909163b1c8dd0564e07516e6bbd0ec64381847f8f3d94d75992fd04243b538ba9348d01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec();
        let prev_epoch = decode_header(prev_epoch);

        header
            .verify_seal(&prev_epoch.epoch.unwrap(), &chain_id)
            .unwrap();
        assert!(&header.requests_hash.is_some());
        assert_eq!(32, header.requests_hash.unwrap().len());
    }

    #[cfg(feature = "dev")]
    mod dev_test_after_pascal {
        use crate::errors::Error;
        use crate::fixture::{decode_header, localnet};
        use crate::header::eth_header::ETHHeader;
        use hex_literal::hex;
        use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

        #[test]
        fn test_error_missing_request_hash() {
            // timestamp = 1721396460
            let raw_header = localnet().epoch_header_plus_1_rlp();
            let raw_header = EthHeader { header: raw_header };
            let result = ETHHeader::try_from(raw_header).unwrap_err();
            match result {
                Error::MissingRequestsHash(_) => {}
                _ => unreachable!(),
            }
        }

        #[test]
        fn test_error_invalid_header_rlp_length() {
            let mut header = hex!("f90370a04a99d244666a287d9aaa1a81aa5bba573f156865369023eaa53a4ba8bb303ad1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e04db2de85453e0936b441c339a26d10cfa71b50a0d0a25a7c6b93d5d2e8f7e2075d2886fa62840f31c127b880b7cd503e2d364163a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282071b8402625a008084678f4827b90111d883010503846765746888676f312e32332e35856c696e75780000002f5b9772f8ae0fb860959e5c417ecd8a5e5ddabd85485cf2cc4433f26beea076d77bbc6f461e4129881b8772bdae5fdd6ca927b571662ac5750d4abeca4f44a4406ab3254e0d98e6ee92b5b6396122853b45db2d18d24fb79e8397e253ca10a2a03b3b18e5961173b5f848820719a0e5ef3de482ecc3de5aea0efb17457d7edc5b1a39fc97c29cc5780b4665c9ca2082071aa04a99d244666a287d9aaa1a81aa5bba573f156865369023eaa53a4ba8bb303ad180aba9a203cbc9ac6e2eabbc44b15f7c526ec5f9d570a0addc005d5958d8415f760794e65762057ff9956dce68034d30cca6d9cc2ac3eb35f699d47c74931c470a01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec();
            // add unnecessary data
            header.push(0x80);
            let raw_header = EthHeader { header };
            let result = ETHHeader::try_from(raw_header).unwrap_err();
            match result {
                Error::UnexpectedHeaderRLP(_) => {}
                _ => unreachable!(),
            }
        }

        #[test]
        fn test_success_after_bep466() {
            // timestamp=1737443367
            let header = hex!("f90370a04a99d244666a287d9aaa1a81aa5bba573f156865369023eaa53a4ba8bb303ad1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e04db2de85453e0936b441c339a26d10cfa71b50a0d0a25a7c6b93d5d2e8f7e2075d2886fa62840f31c127b880b7cd503e2d364163a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282071b8402625a008084678f4827b90111d883010503846765746888676f312e32332e35856c696e75780000002f5b9772f8ae0fb860959e5c417ecd8a5e5ddabd85485cf2cc4433f26beea076d77bbc6f461e4129881b8772bdae5fdd6ca927b571662ac5750d4abeca4f44a4406ab3254e0d98e6ee92b5b6396122853b45db2d18d24fb79e8397e253ca10a2a03b3b18e5961173b5f848820719a0e5ef3de482ecc3de5aea0efb17457d7edc5b1a39fc97c29cc5780b4665c9ca2082071aa04a99d244666a287d9aaa1a81aa5bba573f156865369023eaa53a4ba8bb303ad180aba9a203cbc9ac6e2eabbc44b15f7c526ec5f9d570a0addc005d5958d8415f760794e65762057ff9956dce68034d30cca6d9cc2ac3eb35f699d47c74931c470a01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec();
            decode_header(header);
        }
    }

    #[cfg(feature = "dev")]
    mod dev_test_before_pascal {
        use crate::errors::Error;
        use crate::fixture::{decode_header, localnet};
        use crate::header::eth_header::ETHHeader;
        use hex_literal::hex;
        use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader;

        #[test]
        fn test_error_request_hash() {
            // timestamp=1737443367
            let header = hex!("f90370a04a99d244666a287d9aaa1a81aa5bba573f156865369023eaa53a4ba8bb303ad1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e04db2de85453e0936b441c339a26d10cfa71b50a0d0a25a7c6b93d5d2e8f7e2075d2886fa62840f31c127b880b7cd503e2d364163a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282071b8402625a008084678f4827b90111d883010503846765746888676f312e32332e35856c696e75780000002f5b9772f8ae0fb860959e5c417ecd8a5e5ddabd85485cf2cc4433f26beea076d77bbc6f461e4129881b8772bdae5fdd6ca927b571662ac5750d4abeca4f44a4406ab3254e0d98e6ee92b5b6396122853b45db2d18d24fb79e8397e253ca10a2a03b3b18e5961173b5f848820719a0e5ef3de482ecc3de5aea0efb17457d7edc5b1a39fc97c29cc5780b4665c9ca2082071aa04a99d244666a287d9aaa1a81aa5bba573f156865369023eaa53a4ba8bb303ad180aba9a203cbc9ac6e2eabbc44b15f7c526ec5f9d570a0addc005d5958d8415f760794e65762057ff9956dce68034d30cca6d9cc2ac3eb35f699d47c74931c470a01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b4218080a00000000000000000000000000000000000000000000000000000000000000000a0e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").to_vec();
            let raw_header = EthHeader { header };
            let result = ETHHeader::try_from(raw_header).unwrap_err();
            match result {
                Error::UnexpectedRequestsHash(_, _) => {}
                _ => unreachable!(),
            }
        }

        #[test]
        fn test_success_before_bep466() {
            // timestamp=1721396460
            let raw_header = localnet().epoch_header_plus_1_rlp();
            decode_header(raw_header);
        }
    }
}
