use alloc::vec::Vec;

use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Rlp, RlpStream};

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;

use crate::errors::Error;
use crate::header::epoch::Epoch;

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
const EMPTY_HASH: Hash =
    hex!("0000000000000000000000000000000000000000000000000000000000000000");

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
    pub base_fee_per_gas: Option<u64> ,
    pub withdrawals_hash: Option<Vec<u8>> ,
    pub blob_gas_used: Option<u64>,
    pub excess_blob_gas: Option<u64> ,
    pub parent_beacon_root: Option<Vec<u8>>,

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
        let pubkey: Vec<u8> = point
            .to_bytes()
            .try_into()
            .map_err(|_e| Error::UnexpectedEncodedPoint(self.number))?;
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
                if let Some(value ) = &self.base_fee_per_gas {
                    stream.append(value);
                }else {
                    stream.append_empty_data();
                }
                if let Some(value) = &self.withdrawals_hash{
                    stream.append(value);
                }else {
                    stream.append_empty_data();
                }
                if let Some(value) = &self.blob_gas_used {
                    stream.append(value);
                }else {
                    stream.append_empty_data();
                }
                if let Some(value) = &self.excess_blob_gas{
                    stream.append(value);
                }else {
                    stream.append_empty_data();
                }
                stream.append(parent_beacon_root);
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

    /// https://github.com/bnb-chain/bsc/blob/7a19cd27b61b342d24a1584efc7fa00de4a5b4f5/consensus/parlia/parlia.go#L755
    pub fn verify_seal(
        &self,
        validator_set: &Validators,
        chain_id: &ChainId,
    ) -> Result<Address, Error> {
        // Resolve the authorization key and check against validators
        let signer = self.ecrecover(chain_id)?;
        if self.coinbase.as_slice() != signer {
            return Err(Error::UnexpectedCoinbase(self.number));
        }

        let mut valid_signer = false;
        for validator in validator_set.iter() {
            if validator[0..VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN] == signer {
                valid_signer = true;
                break;
            }
        }
        if !valid_signer {
            return Err(Error::MissingSignerInValidator(self.number, signer));
        }

        // Don't check that the difficulty corresponds to the turn-ness of the signer

        Ok(signer)
    }

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
            if self.extra_data.len()
                <= EXTRA_VANITY + EXTRA_SEAL + VALIDATOR_NUM_SIZE + num * VALIDATOR_BYTES_LENGTH
            {
                return Err(Error::UnexpectedVoteLength(self.extra_data.len()));
            }
            let start = EXTRA_VANITY
                + VALIDATOR_NUM_SIZE
                + (num * VALIDATOR_BYTES_LENGTH)
                + TURN_LENGTH_SIZE;
            let end = self.extra_data.len() - EXTRA_SEAL;
            &self.extra_data[start..end]
        };

        Rlp::new(attestation_bytes).try_into()
    }

    pub fn is_epoch(&self) -> bool {
        self.number % BLOCKS_PER_EPOCH == 0
    }
}

// https://github.com/bnb-chain/bsc/blob/33e6f840d25edb95385d23d284846955327b0fcd/consensus/parlia/parlia.go#L342
pub fn get_validator_bytes_and_tern_term(extra_data: &[u8]) -> Option<(Validators, u8)> {
    if extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL {
        return None;
    }
    let num = extra_data[EXTRA_VANITY] as usize;
    if num == 0 || extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL + num * VALIDATOR_BYTES_LENGTH {
        return None;
    }
    let start = EXTRA_VANITY + VALIDATOR_NUM_SIZE;
    let end = start + num * VALIDATOR_BYTES_LENGTH;
    Some((
        extra_data[start..end]
            .chunks(VALIDATOR_BYTES_LENGTH)
            .map(|s| s.into())
            .collect(),
        extra_data[end],
    ))
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

        // create block hash
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream.append(&parent_hash);
        stream.append(&uncle_hash);
        stream.append(&coinbase);
        stream.append(&root.to_vec());
        stream.append(&tx_hash);
        stream.append(&receipt_hash);
        stream.append(&bloom);
        stream.append(&difficulty);
        stream.append(&number);
        stream.append(&gas_limit);
        stream.append(&gas_used);
        stream.append(&timestamp);
        stream.append(&extra_data);
        stream.append(&mix_digest);
        stream.append(&nonce);

        if base_fee_per_gas.is_some()
            || withdrawals_hash.is_some()
            || blob_gas_used.is_some()
            || excess_blob_gas.is_some()
            || parent_beacon_root.is_some()
        {
            if let Some(v) = base_fee_per_gas {
                stream.append(&v);
            } else {
                stream.append_empty_data();
            }
        }
        if withdrawals_hash.is_some()
            || blob_gas_used.is_some()
            || excess_blob_gas.is_some()
            || parent_beacon_root.is_some()
        {
            if let Some(v) = &withdrawals_hash {
                stream.append(v);
            } else {
                stream.append_empty_data();
            }
        }
        if blob_gas_used.is_some() || excess_blob_gas.is_some() || parent_beacon_root.is_some() {
            if let Some(v) = blob_gas_used {
                stream.append(&v);
            } else {
                stream.append_empty_data();
            }
        }
        if excess_blob_gas.is_some() || parent_beacon_root.is_some() {
            if let Some(v) = excess_blob_gas {
                stream.append(&v);
            } else {
                stream.append_empty_data();
            }
        }
        if parent_beacon_root.is_some() {
            if let Some(v) = &parent_beacon_root {
                stream.append(v);
            } else {
                stream.append_empty_data();
            }
        }
        stream.finalize_unbounded_list();
        let buffer_vec: Vec<u8> = stream.out().to_vec();
        let hash: Hash = keccak_256(&buffer_vec);

        let epoch = if number % BLOCKS_PER_EPOCH == 0 {
            let (validators, turn_length) = get_validator_bytes_and_tern_term(&extra_data)
                .ok_or_else(|| Error::MissingValidatorInEpochBlock(number))?;
            Some(Epoch::new(validators.into(), turn_length))
        } else {
            None
        };

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
            hash,
            epoch,
        })
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::errors::Error;
    use crate::header::eth_header::{
        ETHHeader, EXTRA_SEAL, EXTRA_VANITY, PARAMS_GAS_LIMIT_BOUND_DIVISOR,
    };

    use rlp::RlpStream;
    use rstest::*;

    use crate::fixture::{localnet, Network};
    use alloc::boxed::Box;
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
        let validators = hp.previous_validators();
        let blocks = vec![
            hp.epoch_header(),
            hp.epoch_header_plus_1(),
            hp.epoch_header_plus_2(),
        ];
        for block in blocks {
            if let Err(e) = block.verify_seal(&validators, &hp.network()) {
                unreachable!("{} {:?}", block.number, e);
            }
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_seal(#[case] hp: Box<dyn Network>) {
        let validators = hp.previous_validators();
        let mut blocks = vec![hp.epoch_header_plus_1(), hp.epoch_header_plus_2()];

        for block in blocks.iter_mut() {
            let result = block.verify_seal(&vec![], &hp.network());
            match result.unwrap_err() {
                Error::MissingSignerInValidator(number, address) => {
                    assert_eq!(block.number, number);
                    assert_eq!(block.coinbase, address);
                }
                e => unreachable!("{:?}", e),
            };
        }

        for mut block in blocks.iter_mut() {
            block.coinbase = vec![];
            let result = block.verify_seal(&validators, &hp.network());
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
}
