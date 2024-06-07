use alloc::vec::Vec;

use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Rlp, RlpStream};

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;

use crate::errors::Error;
use crate::header::epoch::Epoch;
use crate::header::validator_set::ValidatorSet;

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
            let start = EXTRA_VANITY + VALIDATOR_NUM_SIZE + (num * VALIDATOR_BYTES_LENGTH);
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
pub fn get_validator_bytes(extra_data: &[u8]) -> Option<Validators> {
    if extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL {
        return None;
    }
    let num = extra_data[EXTRA_VANITY] as usize;
    if num == 0 || extra_data.len() <= EXTRA_VANITY + EXTRA_SEAL + num * VALIDATOR_BYTES_LENGTH {
        return None;
    }
    let start = EXTRA_VANITY + VALIDATOR_NUM_SIZE;
    let end = start + num * VALIDATOR_BYTES_LENGTH;
    Some(
        extra_data[start..end]
            .chunks(VALIDATOR_BYTES_LENGTH)
            .map(|s| s.into())
            .collect(),
    )
}

pub fn get_turn_term(extra_data: &[u8]) -> Option<u8> {
    //TODO get turn term from extra-data
    return Some(1);
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
        // https://github.com/bnb-chain/bsc/blob/4b45c5993c87d12c520a89e0d3d059e4d6b6eb9c/core/types/gen_header_rlp.go#L57
        if base_fee_per_gas.is_some()
            || withdrawals_hash.is_some()
            || blob_gas_used.is_some()
            || excess_blob_gas.is_some()
        {
            if let Some(v) = base_fee_per_gas {
                stream.append(&v);
            } else {
                stream.append_empty_data();
            }
        }
        if withdrawals_hash.is_some() || blob_gas_used.is_some() || excess_blob_gas.is_some() {
            if let Some(v) = withdrawals_hash {
                stream.append(&v);
            } else {
                stream.append_empty_data();
            }
        }
        if blob_gas_used.is_some() || excess_blob_gas.is_some() {
            if let Some(v) = blob_gas_used {
                stream.append(&v);
            } else {
                stream.append_empty_data();
            }
        }
        if excess_blob_gas.is_some() {
            if let Some(v) = excess_blob_gas {
                stream.append(&v);
            } else {
                stream.append_empty_data();
            }
        }
        stream.finalize_unbounded_list();
        let buffer_vec: Vec<u8> = stream.out().to_vec();
        let hash: Hash = keccak_256(&buffer_vec);

        let epoch = if number % BLOCKS_PER_EPOCH == 0 {
            let validators: ValidatorSet = get_validator_bytes(&extra_data)
                .ok_or_else(|| Error::MissingValidatorInEpochBlock(number))?
                .into();
            let turn_term = get_turn_term(&extra_data)
                .ok_or_else(|| Error::MissingTurnTermInEpochBlock(number))?
                .into();
            Some(Epoch::new(validators, turn_term))
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
    use hex_literal::hex;

    use rlp::RlpStream;
    use rstest::*;

    use crate::fixture::localnet::*;
    use crate::fixture::{localnet, Network};
    use alloc::boxed::Box;
    use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;

    impl TryFrom<&ETHHeader> for RawETHHeader {
        type Error = Error;

        fn try_from(header: &ETHHeader) -> Result<Self, Self::Error> {
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

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_try_from_missing_vanity(#[case] hp: Box<dyn Network>) {
        let mut header = hp.epoch_header_plus_1();
        header.extra_data = [0u8; EXTRA_VANITY - 1].to_vec();
        let raw = RawETHHeader::try_from(&header).unwrap();
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
        let raw = RawETHHeader::try_from(&header).unwrap();
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
        let raw = RawETHHeader::try_from(&header).unwrap();
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
        let raw = RawETHHeader::try_from(&header).unwrap();
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
        let raw = RawETHHeader::try_from(&header).unwrap();
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
        let raw = RawETHHeader::try_from(&header).unwrap();
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
    fn test_success_try_from_with_bep336_field(#[case] hp: Box<dyn Network>) {
        let base_fn = || {
            let header = hp.epoch_header();
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
            stream
        };

        let mut stream = base_fn();
        stream.finalize_unbounded_list();
        let raw = RawETHHeader {
            header: stream.out().to_vec(),
        };
        let v = ETHHeader::try_from(raw).unwrap();
        assert_eq!(v.hash, hp.epoch_header().hash);

        // with base_fee_per_gas
        let base_fee_per_gas: u64 = 2;
        let mut stream = base_fn();
        stream.append(&base_fee_per_gas);
        stream.finalize_unbounded_list();
        let raw = RawETHHeader {
            header: stream.out().to_vec(),
        };
        ETHHeader::try_from(raw).unwrap();

        // with withdrawals_hash
        let withdrawals_hash = hp.epoch_header().tx_hash;
        let mut stream = base_fn();
        stream.append(&base_fee_per_gas);
        stream.append(&withdrawals_hash);
        stream.finalize_unbounded_list();
        let raw = RawETHHeader {
            header: stream.out().to_vec(),
        };
        ETHHeader::try_from(raw).unwrap();

        // with blob_gas_used
        let blob_gas_used: u64 = 3;
        let mut stream = base_fn();
        stream.append(&base_fee_per_gas);
        stream.append(&withdrawals_hash);
        stream.append(&blob_gas_used);
        stream.finalize_unbounded_list();
        let raw = RawETHHeader {
            header: stream.out().to_vec(),
        };
        ETHHeader::try_from(raw).unwrap();

        // with excess_blob_gas
        let excess_blob_gas: u64 = 4;
        let mut stream = base_fn();
        stream.append(&base_fee_per_gas);
        stream.append(&withdrawals_hash);
        stream.append(&blob_gas_used);
        stream.append(&excess_blob_gas);
        stream.finalize_unbounded_list();
        let raw = RawETHHeader {
            header: stream.out().to_vec(),
        };
        ETHHeader::try_from(raw).unwrap();

        // testnet after Tycho
        let mut stream = RlpStream::new();
        stream.begin_unbounded_list();
        stream.append(
            &hex!("bc7d1149db8ecb83b784b9418511e9997e12a0acf419ca344b952da42b25209a").to_vec(),
        );
        stream.append(
            &hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").to_vec(),
        );
        stream.append(&hex!("53387f3321fd69d1e030bb921230dfb188826aff").to_vec());
        stream.append(
            &hex!("6b295725152189db64d8afe76ebbc78d04ad3452ee5c0613d2cdde234aae6518").to_vec(),
        );
        stream.append(
            &hex!("b49a9e69547c01e22100afa0dac47ad573a73c8a456d368aa78a20a1be3b8f61").to_vec(),
        );
        stream.append(
            &hex!("3f1e435e6e4833d5ce8ff9fbdb1e8fc61b71c75f03de98e1dd96662363230fb4").to_vec(),
        );
        stream.append(&hex!("000020000000080100900040a00001000000400000020000000440002020081000001002000000000000000000000001020000040004100000111001000c60000240000100020008020100880000000020100000040400000000010000000000002c0020220200000006000028000800082200000000088000002010100008000040400482000000080080001000000008100400280000000040008000000020000080004000062008000010020000000000000000000020000080080000002080021012040028040002000002000000400000000408064000104002000060001200000010000000010040340000110020008040000420004000080000000000").to_vec());
        stream.append(&u64::from_str_radix("1", 16).unwrap());
        stream.append(&u64::from_str_radix("25b7469", 16).unwrap());
        stream.append(&u64::from_str_radix("42c1d80", 16).unwrap());
        stream.append(&u64::from_str_radix("14c285", 16).unwrap());
        stream.append(&u64::from_str_radix("661fc104", 16).unwrap());
        stream.append(&hex!("d883010405846765746888676f312e32312e36856c696e7578000000821df8b9f8b381f7b860881105fa9e628179b4be7c807d56d7f83e0354604a31a3a0610dc2cfd312f089cca6cf0dc22e0a675179cafcdd0fcd5309257163c6c53b48404671f1cbdb5d4c38de16ffc0e0951c4d3141de1748399ddf4fa51b4fadfbe0201b4d30a2b7fffef84c84025b7467a0dd8f3ec7f7613d048271569ed3b3712b1a8c91a9039ab0e15395b345a76459fa84025b7468a0bc7d1149db8ecb83b784b9418511e9997e12a0acf419ca344b952da42b25209a80174ffd16859a8984cb5c4420784ac48f5df3c5be2225f009d3f78a26ab8766fa05589316bb3d657c8b5f0796afcef09bb284c4bbef83d89d980fe6958022906e01").to_vec());
        stream.append(
            &hex!("0000000000000000000000000000000000000000000000000000000000000000").to_vec(),
        );
        stream.append(&hex!("0000000000000000").to_vec());
        stream.append(&u64::from_str_radix("0", 16).unwrap());
        stream.append(
            &hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421").to_vec(),
        );
        stream.append(&u64::from_str_radix("0", 16).unwrap());
        stream.append(&u64::from_str_radix("0", 16).unwrap());
        stream.finalize_unbounded_list();
        let raw = RawETHHeader {
            header: stream.out().to_vec(),
        };
        let hash = ETHHeader::try_from(raw).unwrap().hash;
        assert_eq!(
            hash,
            hex!("6de91bc2b08a30d2082b7d3077e6ad381d040373b706d231cff899b096322972")
        )
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
            if let Err(e) = block.verify_seal(&validators, &mainnet()) {
                unreachable!("{} {:?}", block.number, e);
            }
        }
    }

    #[rstest]
    #[case::localnet(localnet())]
    fn test_error_verify_seal(#[case] hp: Box<dyn Network>) {
        let validators = hp.previous_validators();
        let mut blocks = vec![
            hp.epoch_header(),
            hp.epoch_header_plus_1(),
            hp.epoch_header_plus_2(),
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
                assert_eq!(140000000, diff);
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
