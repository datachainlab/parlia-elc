use alloc::vec::Vec;

use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Rlp, RlpStream};

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;

use crate::errors::Error;

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

const PARAMS_GAS_LIMIT_BOUND_DIVISOR: u64 = 256;

const EMPTY_UNCLE_HASH: Hash =
    hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347");
const EMPTY_NONCE: [u8; 8] = hex!("0000000000000000");
const EMPTY_MIX_HASH: Hash =
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

    // calculated by RawETHHeader
    pub hash: Hash,
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
        let mut stream = RlpStream::new_list(16);
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
            return Err(Error::UnexpectedHeaderRelation(parent.number, self.number));
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
            return Err(Error::UnexpectedVoteAttestationRelation(
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
            return Err(Error::UnexpectedVoteAttestationRelation(
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
            let start = EXTRA_VANITY + VALIDATOR_NUM_SIZE + (num * VALIDATOR_BYTES_LENGTH);
            let end = self.extra_data.len() - EXTRA_SEAL;
            &self.extra_data[start..end]
        };

        Rlp::new(attestation_bytes).try_into()
    }

    // https://github.com/bnb-chain/bsc/blob/33e6f840d25edb95385d23d284846955327b0fcd/consensus/parlia/parlia.go#L342
    pub fn get_validator_bytes(&self) -> Option<Validators> {
        if self.extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL {
            return None;
        }
        let num = self.extra_data[EXTRA_VANITY] as usize;
        if num == 0
            || self.extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL + num * VALIDATOR_BYTES_LENGTH
        {
            return None;
        }
        let start = EXTRA_VANITY + VALIDATOR_NUM_SIZE;
        let end = start + num * VALIDATOR_BYTES_LENGTH;
        Some(
            self.extra_data[start..end]
                .chunks(VALIDATOR_BYTES_LENGTH)
                .map(|s| s.into())
                .collect(),
        )
    }

    pub fn is_epoch(&self) -> bool {
        self.number % BLOCKS_PER_EPOCH == 0
    }
}

impl TryFrom<ETHHeader> for RawETHHeader {
    type Error = Error;

    fn try_from(header: ETHHeader) -> Result<Self, Self::Error> {
        let mut stream = RlpStream::new_list(15);
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
        Ok(RawETHHeader {
            header: stream.out().to_vec(),
        })
    }
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
        if mix_digest != EMPTY_MIX_HASH {
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
        let mut size = 15;
        if base_fee_per_gas.is_some() {
            size += 1;
        }
        let mut stream = RlpStream::new_list(size);
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
        //https://github.com/bnb-chain/bsc/blob/bb6bdc055d1a7f1f049c924028ad8aaf04291b3b/core/types/gen_header_rlp.go#L43
        if let Some(v) = base_fee_per_gas {
            stream.append(&v);
        }
        let buffer_vec: Vec<u8> = stream.out().to_vec();
        let hash: Hash = keccak_256(&buffer_vec);

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
            hash,
        })
    }
}

#[cfg(test)]
mod test {

    use crate::errors::Error;
    use crate::header::eth_header::PARAMS_GAS_LIMIT_BOUND_DIVISOR;

    use crate::header::testdata::*;

    #[test]
    fn test_success_verify_seal() {
        let validators = validators_in_31297000();
        let blocks = vec![
            header_31297199(),
            header_31297200(),
            header_31297201(),
            header_31297202(),
        ];
        for block in blocks {
            if let Err(e) = block.verify_seal(&validators, &mainnet()) {
                unreachable!("{} {:?}", block.number, e);
            }
        }
    }

    #[test]
    fn test_error_verify_seal() {
        let validators = validators_in_31297000();
        let mut blocks = vec![
            header_31297199(),
            header_31297200(),
            header_31297201(),
            header_31297202(),
        ];

        for block in blocks.iter_mut() {
            let result = block.verify_seal(&validators[0..1].to_vec(), &mainnet());
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
            let result = block.verify_seal(&validators, &mainnet());
            match result.unwrap_err() {
                Error::UnexpectedCoinbase(number) => assert_eq!(block.number, number),
                e => unreachable!("{:?}", e),
            };
        }
    }

    #[test]
    fn test_success_verify_cascading_fields() {
        let blocks = vec![
            header_31297199(),
            header_31297200(),
            header_31297201(),
            header_31297202(),
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

    #[test]
    fn test_error_verify_cascading_fields() {
        let parent = header_31297199();
        let mut block = header_31297200();
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

        let parent = header_31297199();
        let block = header_31297201();
        let result = block.verify_cascading_fields(&parent);
        match result.unwrap_err() {
            Error::UnexpectedHeaderRelation(parent_no, child_no) => {
                assert_eq!(parent.number, parent_no);
                assert_eq!(block.number, child_no);
            }
            err => unreachable!("{:?}", err),
        }

        let parent = header_31297199();
        let mut block = header_31297200();
        block.gas_used = 0;
        block.gas_limit = 0;
        let result = block.verify_cascading_fields(&parent);
        match result.unwrap_err() {
            Error::UnexpectedGasDiff(number, diff, limit) => {
                assert_eq!(block.number, number);
                assert_eq!(parent.gas_limit / PARAMS_GAS_LIMIT_BOUND_DIVISOR, limit);
                assert_eq!(140000000, diff);
            }
            err => unreachable!("{:?}", err),
        }
    }

    #[test]
    fn test_success_verify_vote_attestation() {
        let blocks = vec![
            header_31297199(),
            header_31297200(),
            header_31297201(),
            header_31297202(),
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

    #[test]
    fn test_error_verify_vote_attestation() {
        let header = header_31297201();
        let parent = header_31297201();
        let err = header.verify_vote_attestation(&parent).unwrap_err();
        match err {
            Error::UnexpectedVoteAttestationRelation(
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

        let mut block = header_31297200();
        block.extra_data = vec![];
        let err = block
            .verify_vote_attestation(&header_31297199())
            .unwrap_err();
        match err {
            Error::UnexpectedVoteLength(size) => {
                assert_eq!(size, block.extra_data.len());
            }
            err => unreachable!("{:?}", err),
        }
    }
}
