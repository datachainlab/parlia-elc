use alloc::vec::Vec;

use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Rlp, RlpStream};

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;

use crate::errors::Error;
use crate::misc::{Address, BlockNumber, ChainId, Hash, RlpIterator, Validators};

use super::EPOCH_BLOCK_PERIOD;

const DIFFICULTY_INTURN: u64 = 2;
const DIFFICULTY_NOTURN: u64 = 1;

const EXTRA_VANITY: usize = 32;
const EXTRA_SEAL: usize = 65;
const VALIDATOR_BYTES_LENGTH: usize = 20;

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
    pub is_epoch: bool,
    pub new_validators: Validators, // epoch block only
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

    /// This checks header with parent header.
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

    /// This check header with validator_set.
    /// https://github.com/bnb-chain/bsc/blob/master/consensus/parlia/parlia.go#L546
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
            if validator.as_slice() == signer {
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
}

impl TryFrom<ETHHeader> for RawETHHeader {
    type Error = Error;

    fn try_from(header: ETHHeader) -> Result<Self, Self::Error> {
        let mut stream = RlpStream::new_list(15);
        stream.append_list(&header.parent_hash);
        stream.append_list(&header.uncle_hash);
        stream.append_list(&header.coinbase);
        stream.append_list(header.root.as_ref());
        stream.append_list(&header.tx_hash);
        stream.append_list(&header.receipt_hash);
        stream.append_list(&header.bloom);
        stream.append(&header.difficulty);
        stream.append(&header.number);
        stream.append(&header.gas_limit);
        stream.append(&header.gas_used);
        stream.append(&header.timestamp);
        stream.append_list(&header.extra_data);
        stream.append_list(&header.mix_digest);
        stream.append_list(&header.nonce);
        Ok(RawETHHeader {
            header: stream.out().to_vec(),
        })
    }
}

impl TryFrom<&RawETHHeader> for ETHHeader {
    type Error = Error;

    /// This includes part of header verification.
    /// - verifyHeader: https://github.com/bnb-chain/bsc/blob/b4773e8b5080f37e1c65c083b543f60c895abb70/consensus/parlia/parlia.go#L324
    fn try_from(value: &RawETHHeader) -> Result<Self, Self::Error> {
        let mut rlp = RlpIterator::new(Rlp::new(value.header.as_slice()));
        let parent_hash = rlp.try_next_as_list()?;
        let uncle_hash = rlp.try_next_as_list()?;
        let coinbase = rlp.try_next_as_list()?;
        let root: Hash = rlp
            .try_next_as_list()?
            .try_into()
            .map_err(Error::UnexpectedStateRoot)?;
        let tx_hash = rlp.try_next_as_list()?;
        let receipt_hash = rlp.try_next_as_list()?;
        let bloom = rlp.try_next_as_list()?;
        let difficulty = rlp.try_next_as_val()?;
        let number = rlp.try_next_as_val()?;
        let gas_limit = rlp.try_next_as_val()?;
        let gas_used = rlp.try_next_as_val()?;
        let timestamp = rlp.try_next_as_val()?;
        let extra_data = rlp.try_next_as_list()?;
        let mix_digest = rlp.try_next_as_list()?;
        let nonce = rlp.try_next_as_list()?;

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

        let is_epoch = number % EPOCH_BLOCK_PERIOD == 0;

        // Ensure that the extra-data contains a signer list on checkpoint, but none otherwize
        let signers_bytes_size = extra_size - EXTRA_VANITY - EXTRA_SEAL;
        if !is_epoch && signers_bytes_size != 0 {
            return Err(Error::UnexpectedValidatorInNonEpochBlock(number));
        }
        let new_validators: Validators = if is_epoch {
            if signers_bytes_size % VALIDATOR_BYTES_LENGTH != 0 {
                return Err(Error::UnexpectedValidatorInEpochBlock(number));
            }
            extra_data[EXTRA_VANITY..extra_size - EXTRA_SEAL]
                .chunks(VALIDATOR_BYTES_LENGTH)
                .map(|s| s.into())
                .collect()
        } else {
            vec![]
        };

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
        let mut stream = RlpStream::new_list(15);
        stream.append(&parent_hash.to_vec());
        stream.append(&uncle_hash.to_vec());
        stream.append(&coinbase.to_vec());
        stream.append(&root.to_vec());
        stream.append(&tx_hash.to_vec());
        stream.append(&receipt_hash.to_vec());
        stream.append(&bloom.to_vec());
        stream.append(&difficulty);
        stream.append(&number);
        stream.append(&gas_limit);
        stream.append(&gas_used);
        stream.append(&timestamp);
        stream.append(&extra_data);
        stream.append(&mix_digest.to_vec());
        stream.append(&nonce.to_vec());
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
            new_validators,
            hash,
            is_epoch,
        })
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;

    use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;

    use crate::errors::Error;
    use crate::header::eth_header::ETHHeader;
    use crate::header::eth_header::{EXTRA_VANITY, PARAMS_GAS_LIMIT_BOUND_DIVISOR};
    use crate::header::testdata::*;

    #[test]
    fn test_success_try_from_eth_header() {
        let mut header = create_non_epoch_block();
        let raw: RawETHHeader = header.clone().try_into().unwrap();
        let restore: ETHHeader = (&raw).try_into().unwrap();
        // automatically calculated
        header.hash = restore.hash;
        header.is_epoch = restore.is_epoch;
        header.new_validators = restore.new_validators.clone();
        assert!(!header.is_epoch);
        assert_eq!(
            header.hash,
            hex!("fb34966d5d9fd58249d21ee942a8388f1ae763fbb48fe9fcbf31c633564f56af")
        );
        assert_eq!(header.new_validators.len(), 0);
        assert_eq!(header, restore);
    }

    #[test]
    fn test_success_try_from_eth_header_epoch() {
        let mut header = create_epoch_block();
        let raw: RawETHHeader = header.clone().try_into().unwrap();
        let restore: ETHHeader = (&raw).try_into().unwrap();
        // automatically calculated
        header.hash = restore.hash;
        header.is_epoch = restore.is_epoch;
        header.new_validators = restore.new_validators.clone();
        assert!(header.is_epoch);
        assert_eq!(
            header.hash,
            hex!("66eef8f9b1ed19064a56d366288e0ae2bbd1a265cdd9891d42171433b2a3f128")
        );
        assert_eq!(header.new_validators.len(), 21);
        assert_eq!(
            header.new_validators[0],
            hex!("2465176c461afb316ebc773c61faee85a6515daa")
        );
        assert_eq!(
            header.new_validators[1],
            hex!("295e26495cef6f69dfa69911d9d8e4f3bbadb89b")
        );
        assert_eq!(
            header.new_validators[2],
            hex!("2d4c407bbe49438ed859fe965b140dcf1aab71a9")
        );
        assert_eq!(
            header.new_validators[3],
            hex!("3f349bbafec1551819b8be1efea2fc46ca749aa1")
        );
        assert_eq!(
            header.new_validators[4],
            hex!("61dd481a114a2e761c554b641742c973867899d3")
        );
        assert_eq!(
            header.new_validators[5],
            hex!("685b1ded8013785d6623cc18d214320b6bb64759")
        );
        assert_eq!(
            header.new_validators[6],
            hex!("70f657164e5b75689b64b7fd1fa275f334f28e18")
        );
        assert_eq!(
            header.new_validators[7],
            hex!("72b61c6014342d914470ec7ac2975be345796c2b")
        );
        assert_eq!(
            header.new_validators[8],
            hex!("733fda7714a05960b7536330be4dbb135bef0ed6")
        );
        assert_eq!(
            header.new_validators[9],
            hex!("7ae2f5b9e386cd1b50a4550696d957cb4900f03a")
        );
        assert_eq!(
            header.new_validators[10],
            hex!("8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73")
        );
        assert_eq!(
            header.new_validators[11],
            hex!("9bb832254baf4e8b4cc26bd2b52b31389b56e98b")
        );
        assert_eq!(
            header.new_validators[12],
            hex!("a6f79b60359f141df90a0c745125b131caaffd12")
        );
        assert_eq!(
            header.new_validators[13],
            hex!("b218c5d6af1f979ac42bc68d98a5a0d796c6ab01")
        );
        assert_eq!(
            header.new_validators[14],
            hex!("b4dd66d7c2c7e57f628210187192fb89d4b99dd4")
        );
        assert_eq!(
            header.new_validators[15],
            hex!("be807dddb074639cd9fa61b47676c064fc50d62c")
        );
        assert_eq!(
            header.new_validators[16],
            hex!("cc8e6d00c17eb431350c6c50d8b8f05176b90b11")
        );
        assert_eq!(
            header.new_validators[17],
            hex!("e2d3a739effcd3a99387d015e260eefac72ebea1")
        );
        assert_eq!(
            header.new_validators[18],
            hex!("e9ae3261a475a27bb1028f140bc2a7c843318afd")
        );
        assert_eq!(
            header.new_validators[19],
            hex!("ee226379db83cffc681495730c11fdde79ba4c0c")
        );
        assert_eq!(
            header.new_validators[20],
            hex!("ef0274e31810c9df02f98fafde0f841f4e66a1cd")
        );
        assert_eq!(header, restore);
    }

    #[test]
    fn test_error_try_from_eth_header() {
        let mut header = create_non_epoch_block();
        header.extra_data = [0; EXTRA_VANITY - 1].to_vec();
        match check_eth_header(header.clone()) {
            Error::MissingVanityInExtraData(number, _, _) => assert_eq!(number, header.number),
            e => unreachable!("{:?}", e),
        };

        let mut header = create_non_epoch_block();
        header.nonce = vec![];
        match check_eth_header(header.clone()) {
            Error::UnexpectedNonce(number) => assert_eq!(number, header.number),
            e => unreachable!("{:?}", e),
        };

        let mut header = create_non_epoch_block();
        header.extra_data = [0; EXTRA_VANITY + 1].to_vec();
        match check_eth_header(header.clone()) {
            Error::MissingSignatureInExtraData(number, _, _) => assert_eq!(number, header.number),
            e => unreachable!("{:?}", e),
        };

        let mut header = create_non_epoch_block();
        header.extra_data.push(1);
        match check_eth_header(header.clone()) {
            Error::UnexpectedValidatorInNonEpochBlock(number) => assert_eq!(number, header.number),
            e => unreachable!("{:?}", e),
        };

        let mut header = create_non_epoch_block();
        header.mix_digest = vec![];
        match check_eth_header(header.clone()) {
            Error::UnexpectedMixHash(number) => assert_eq!(number, header.number),
            e => unreachable!("{:?}", e),
        };

        let mut header = create_non_epoch_block();
        header.uncle_hash = vec![];
        match check_eth_header(header.clone()) {
            Error::UnexpectedUncleHash(number) => assert_eq!(number, header.number),
            e => unreachable!("{:?}", e),
        };

        let mut header = create_non_epoch_block();
        header.difficulty = 3;
        match check_eth_header(header.clone()) {
            Error::UnexpectedDifficulty(number, v) => {
                assert_eq!(number, header.number);
                assert_eq!(header.difficulty, v);
            }
            e => unreachable!("{:?}", e),
        };
    }

    #[test]
    fn test_success_verify_seal() {
        let epoch = fill(create_epoch_block());
        let non_epoch = fill(create_non_epoch_block());
        let result = non_epoch.verify_seal(&epoch.new_validators, &mainnet());
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_seal() {
        let epoch = fill(create_epoch_block());
        let mut non_epoch = fill(create_non_epoch_block());
        let mainnet = &mainnet();
        non_epoch.coinbase = vec![1];
        let result = non_epoch.verify_seal(&epoch.new_validators, mainnet);
        match result.unwrap_err() {
            Error::UnexpectedCoinbase(number) => assert_eq!(non_epoch.number, number),
            e => unreachable!("{:?}", e),
        };

        let non_epoch = fill(create_non_epoch_block());
        let result = non_epoch.verify_seal(&vec![], mainnet);
        match result.unwrap_err() {
            Error::MissingSignerInValidator(number, signer) => {
                assert_eq!(signer, non_epoch.coinbase.as_slice());
                assert_eq!(number, non_epoch.number);
            }
            e => unreachable!("{:?}", e),
        };
    }

    #[test]
    fn test_success_verify_cascading_fields() {
        let non_epoch = fill(create_non_epoch_block());
        let non_epoch_parent = fill(create_parent_non_epoch_block());
        let result = non_epoch.verify_cascading_fields(&non_epoch_parent);
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_cascading_fields() {
        let mut non_epoch = fill(create_non_epoch_block());
        non_epoch.gas_limit = 10000;
        non_epoch.gas_used = non_epoch.gas_limit + 1;
        let non_epoch_parent = fill(create_parent_non_epoch_block());
        let result = non_epoch.verify_cascading_fields(&non_epoch_parent);
        match result.unwrap_err() {
            Error::UnexpectedGasUsed(number, used, limit) => {
                assert_eq!(non_epoch.number, number);
                assert_eq!(non_epoch.gas_used, used);
                assert_eq!(non_epoch.gas_limit, limit);
            }
            err => unreachable!("{:?}", err),
        }

        let mut non_epoch = fill(create_non_epoch_block());
        let non_epoch_parent = fill(create_parent_non_epoch_block());
        non_epoch.number = non_epoch_parent.number + 2;
        error_relation(non_epoch, non_epoch_parent);

        let mut non_epoch = fill(create_non_epoch_block());
        let non_epoch_parent = fill(create_parent_non_epoch_block());
        non_epoch.parent_hash = non_epoch.hash.to_vec();
        error_relation(non_epoch, non_epoch_parent);

        let mut non_epoch = fill(create_non_epoch_block());
        let non_epoch_parent = fill(create_parent_non_epoch_block());
        non_epoch.timestamp = non_epoch_parent.timestamp;
        error_relation(non_epoch, non_epoch_parent);

        let mut non_epoch = fill(create_non_epoch_block());
        let mut non_epoch_parent = fill(create_parent_non_epoch_block());
        non_epoch_parent.gas_limit = 10000;
        non_epoch.gas_limit = 10;
        non_epoch.gas_used = non_epoch.gas_limit;
        let result = non_epoch.verify_cascading_fields(&non_epoch_parent);
        match result.unwrap_err() {
            Error::UnexpectedGasDiff(number, diff, limit) => {
                assert_eq!(non_epoch.number, number);
                assert_eq!(non_epoch_parent.gas_limit - non_epoch.gas_limit, diff);
                assert_eq!(
                    non_epoch_parent.gas_limit / PARAMS_GAS_LIMIT_BOUND_DIVISOR,
                    limit
                );
            }
            err => unreachable!("{:?}", err),
        }
    }

    fn error_relation(non_epoch: ETHHeader, non_epoch_parent: ETHHeader) {
        let result = non_epoch.verify_cascading_fields(&non_epoch_parent);
        match result.unwrap_err() {
            Error::UnexpectedHeaderRelation(parent, child) => {
                assert_eq!(non_epoch_parent.number, parent);
                assert_eq!(non_epoch.number, child);
            }
            err => unreachable!("{:?}", err),
        }
    }
}
