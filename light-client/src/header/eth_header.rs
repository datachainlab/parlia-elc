use alloc::vec::Vec;

use elliptic_curve::sec1::ToEncodedPoint;
use hex_literal::hex;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Rlp, RlpStream};

use parlia_ibc_proto::ibc::lightclients::parlia::v1::EthHeader as RawETHHeader;

use crate::errors::Error;
use crate::header::config::LUBAN_FORK;
use crate::misc::{Address, BlockNumber, ChainId, Hash, RlpIterator, Validators};

use super::BLOCKS_PER_EPOCH;

const DIFFICULTY_INTURN: u64 = 2;
const DIFFICULTY_NOTURN: u64 = 1;

const EXTRA_VANITY: usize = 32;
const EXTRA_SEAL: usize = 65;
const VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN: usize = 20;
const BLS_PUBKEY_LENGTH: usize = 48;
const VALIDATOR_BYTES_LENGTH: usize = VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN + BLS_PUBKEY_LENGTH;

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

impl TryFrom<&RawETHHeader> for ETHHeader {
    type Error = Error;

    /// This includes part of header verification.
    /// - verifyHeader: https://github.com/bnb-chain/bsc/blob/b4773e8b5080f37e1c65c083b543f60c895abb70/consensus/parlia/parlia.go#L324
    fn try_from(value: &RawETHHeader) -> Result<Self, Self::Error> {
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

        let is_epoch = number % BLOCKS_PER_EPOCH == 0;
        let is_luban = number >= LUBAN_FORK;

        // Ensure that the extra-data contains a signer list on checkpoint, but none otherwize
        let validators_bytes = &extra_data[EXTRA_VANITY..extra_data.len() - EXTRA_SEAL];
        let new_validators: Validators = if is_epoch {
            extract_validators(is_luban, validators_bytes)
                .ok_or_else(|| Error::UnexpectedValidatorInEpochBlock(number))?
        } else {
            if !is_luban && !validators_bytes.is_empty() {
                return Err(Error::UnexpectedValidatorInNonEpochBlock(number));
            }
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

        let base_fee_per_gas: Option<u64> = rlp.try_next_as_val().map(Some).unwrap_or(None);

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
            new_validators,
            hash,
            is_epoch,
        })
    }
}

fn extract_validators(is_luban: bool, validators_bytes: &[u8]) -> Option<Validators> {
    // https://github.com/bnb-chain/bsc/blob/33e6f840d25edb95385d23d284846955327b0fcd/consensus/parlia/parlia.go#L342
    if is_luban {
        let num = validators_bytes[0] as usize;
        if num == 0 || validators_bytes.len() <= num * VALIDATOR_BYTES_LENGTH {
            return None;
        }
        Some(
            validators_bytes[1..num * VALIDATOR_BYTES_LENGTH]
                .chunks(VALIDATOR_BYTES_LENGTH)
                // discard vote attestation
                .map(|s| s[..VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN].into())
                .collect(),
        )
    } else {
        if validators_bytes.len() % VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN != 0 {
            return None;
        }
        Some(
            validators_bytes
                .chunks(VALIDATOR_BYTES_LENGTH_BEFORE_LUBAN)
                .map(|s| s.into())
                .collect(),
        )
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
    use crate::misc::ChainId;

    fn check_eth_header(header: ETHHeader) -> Error {
        let raw: RawETHHeader = header.try_into().unwrap();
        let result: Result<ETHHeader, Error> = (&raw).try_into();
        assert!(result.is_err());
        result.unwrap_err()
    }

    #[test]
    fn test_success_try_from_eth_header() {
        let header = create_non_epoch_block();
        assert!(!header.is_epoch);
        assert_eq!(
            header.hash,
            hex!("fb34966d5d9fd58249d21ee942a8388f1ae763fbb48fe9fcbf31c633564f56af")
        );
        assert_eq!(header.new_validators.len(), 0);
    }

    #[test]
    fn test_success_try_from_eth_header_epoch() {
        let header = create_epoch_block();
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
        let epoch = create_epoch_block();
        let non_epoch = create_non_epoch_block();
        let result = non_epoch.verify_seal(&epoch.new_validators, &mainnet());
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_seal() {
        let epoch = create_epoch_block();
        let mut non_epoch = create_non_epoch_block();
        let mainnet = &mainnet();
        non_epoch.coinbase = vec![1];
        let result = non_epoch.verify_seal(&epoch.new_validators, mainnet);
        match result.unwrap_err() {
            Error::UnexpectedCoinbase(number) => assert_eq!(non_epoch.number, number),
            e => unreachable!("{:?}", e),
        };

        let non_epoch = create_non_epoch_block();
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
        let non_epoch = create_non_epoch_block();
        let non_epoch_parent = create_parent_non_epoch_block();
        let result = non_epoch.verify_cascading_fields(&non_epoch_parent);
        if let Err(e) = result {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_error_verify_cascading_fields() {
        let mut non_epoch = create_non_epoch_block();
        non_epoch.gas_limit = 10000;
        non_epoch.gas_used = non_epoch.gas_limit + 1;
        let non_epoch_parent = create_parent_non_epoch_block();
        let result = non_epoch.verify_cascading_fields(&non_epoch_parent);
        match result.unwrap_err() {
            Error::UnexpectedGasUsed(number, used, limit) => {
                assert_eq!(non_epoch.number, number);
                assert_eq!(non_epoch.gas_used, used);
                assert_eq!(non_epoch.gas_limit, limit);
            }
            err => unreachable!("{:?}", err),
        }

        let mut non_epoch = create_non_epoch_block();
        let non_epoch_parent = create_parent_non_epoch_block();
        non_epoch.number = non_epoch_parent.number + 2;
        error_relation(non_epoch, non_epoch_parent);

        let mut non_epoch = create_non_epoch_block();
        let non_epoch_parent = create_parent_non_epoch_block();
        non_epoch.parent_hash = non_epoch.hash.to_vec();
        error_relation(non_epoch, non_epoch_parent);

        let mut non_epoch = create_non_epoch_block();
        let non_epoch_parent = create_parent_non_epoch_block();
        non_epoch.timestamp = non_epoch_parent.timestamp;
        error_relation(non_epoch, non_epoch_parent);

        let mut non_epoch = create_non_epoch_block();
        let mut non_epoch_parent = create_parent_non_epoch_block();
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

    #[test]
    fn test_success_eth_header_epoch_luban() {
        // 29835600
        // https://testnet.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1c74150&boolean=false&apikey=
        let epoch = ETHHeader {
            parent_hash: hex!("cf8d34727ff1d895bb49ca4be60c3b24d98d8afa9ce78644924e4b9aa39df854").into(),
            uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
            coinbase: hex!("a2959d3f95eae5dc7d70144ce1b73b403b7eb6e0").into(),
            root: hex!("c7133b5d07000ef856e8ba4d0428e1dcccda9f508136048cfb9768a721140cf0"),
            tx_hash: hex!("ecea8cc02ace4aec001de6b9acf82265112d1af79df8a8e881e792d9d86e3828").into(),
            receipt_hash: hex!("6436b13afc8b98e5057510fcd59d912ea121b2645ef7e15cf79ef5999d96c5cf").into(),
            bloom: hex!("0400000000020808008002000000000000000000020380000000010202014800000200000000000000000020400000000000000013000000000000000020210800000000000080000020000805000004201000000202000000002000000000004000402000020000004000000804000408000000000808800000809008000010000000002000000000000100001020000000042100000000000000800000002003080100000001000000410000000040030000000082000080000000000050000000004a000000000000000400000000000000800c00100000004002400001000111000010020000010000000100000200000000008000000000000000000000").into(),
            difficulty: 2,
            number: u64::from_str_radix("1c74150", 16).unwrap(),
            gas_limit: u64::from_str_radix("2faf080", 16).unwrap(),
            gas_used: u64::from_str_radix("12a8a3", 16).unwrap(),
            timestamp: u64::from_str_radix("6462d9a2", 16).unwrap(),
            extra_data: hex!("d883010202846765746888676f312e31392e39856c696e7578000000110bea95071284214b9b9c85549ab3d2b972df0deef66ac2c9ab1757500d6f4fdee439b17cf8e43267f94bc759162fb68de676d2fe10cc4cde26dd06be7e345e9cbf4b1dbf86b262bc35552c16704d214347f29fa77f77da6d75d7c752b742ad4855bae330426b823e742da31f816cc83bc16d69a9134be0cfb4a1d17ec34f1b5b32d5c20440b8536b1e88f0f296c5d20b2a975c050e4220be276ace4892f4b41a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000980a75ecd1309ea12fa2ed87a8744fbfc9b863d589037a9ace3b590165ea1c0c5ac72bf600b7c88c1e435f41932c1132aae1bfa0bb68e46b96ccb12c3415e4d82af717d8a2959d3f95eae5dc7d70144ce1b73b403b7eb6e0b973c2d38487e58fd6e145491b110080fb14ac915a0411fc78f19e09a399ddee0d20c63a75d8f930f1694544ad2dc01bb71b214cb885500844365e95cd9942c7276e7fd8a2750ec6dded3dcdc2f351782310b0eadc077db59abca0f0cd26776e2e7acb9f3bce40b1fa5221fd1561226c6263cc5ff474cf03cceff28abc65c9cbae594f725c80e12d96c9b86c3400e529bfe184056e257c07940bb664636f689e8d2027c834681f8f878b73445261034e946bb2d901b4b878f8b27bb860a140cc9c8cc07d4ddf366440d9784efc88743d26af40f8956dd1c3501e560f745910bb14a5ec392f53cf78ddc2d2d69a146af287f7e079c3cbbfd3d446836d9b9397aa9a803b6c6b4f1cfc50baddbe2378cf194da35b9f4a1a32850114f1c5d9f84c8401c7414ea049d2e0876f51ce4693892331f8344a102aad88eb9e9bcfaa247cc9f898d1f8008401c7414fa0cf8d34727ff1d895bb49ca4be60c3b24d98d8afa9ce78644924e4b9aa39df8548022dc981e8703d3ca8b23fc032089667cb631cb28c32731762813bbf9fdb7e7a56b3945d65f2d72402a2abb9fbaf4bf094a3e5a542e175ecc54b426ee366b2ba200").to_vec(),
            mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
            nonce: hex!("0000000000000000").into(),
            // calculated in try_into
            hash: [0; 32],
            is_epoch: false,
            new_validators: vec![],
        };
        let raw: RawETHHeader = epoch.try_into().unwrap();
        let epoch: ETHHeader = (&raw).try_into().unwrap();
        assert!(epoch.is_epoch);
        assert_eq!(
            epoch.hash,
            hex!("51daf288b19c1b9bd6565be70c5bfb79c6fc470ce55ca684f6099c01b4ed7494")
        );
        assert_eq!(epoch.new_validators.len(), 7);
        assert_eq!(
            epoch.new_validators[0],
            hex!("1284214b9b9c85549ab3d2b972df0deef66ac2c9")
        );
        assert_eq!(
            epoch.new_validators[1],
            hex!("35552c16704d214347f29fa77f77da6d75d7c752")
        );
        assert_eq!(
            epoch.new_validators[2],
            hex!("96c5d20b2a975c050e4220be276ace4892f4b41a")
        );
        assert_eq!(
            epoch.new_validators[3],
            hex!("980a75ecd1309ea12fa2ed87a8744fbfc9b863d5")
        );
        assert_eq!(
            epoch.new_validators[4],
            hex!("a2959d3f95eae5dc7d70144ce1b73b403b7eb6e0")
        );
        assert_eq!(
            epoch.new_validators[5],
            hex!("b71b214cb885500844365e95cd9942c7276e7fd8")
        );
        assert_eq!(
            epoch.new_validators[6],
            hex!("f474cf03cceff28abc65c9cbae594f725c80e12d")
        );
        // same validator is used in this test block
        epoch
            .verify_seal(&epoch.new_validators, &ChainId::new(97))
            .unwrap();

        // 29835601
        // https://testnet.bscscan.com/api?module=proxy&action=eth_getBlockByNumber&tag=0x1c74151&boolean=false&apikey=
        let non_epoch = ETHHeader {
            parent_hash: hex!("51daf288b19c1b9bd6565be70c5bfb79c6fc470ce55ca684f6099c01b4ed7494").into(),
            uncle_hash: hex!("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347").into(),
            coinbase: hex!("b71b214cb885500844365e95cd9942c7276e7fd8").into(),
            root: hex!("5646e217cdf8ecd2a2f71cdbae086f2255f8d4ad2fc217b3c10c2385097b5f7d"),
            tx_hash: hex!("481e583b096ecd9d08b7c8210b8450afa603dd9296d2166731ec22eae00de817").into(),
            receipt_hash: hex!("1eb095a5269a3bb8aec05557b44e5daf541b3d72ce80e0f522ea4129d299e156").into(),
            bloom: hex!("002000000000080000800a0080000000000000000241808004000000020040000020100000000020000000204000400000000000100200000000000200200008480000000010000000200009042801a420100000834000400000200040000800080040200202000000000000000408040a00000000000c00410080100000001000000000000000000000090000002020000004a1000000080000204000200020030801001000010000004400000000000100000020030000802000000000000000080042000004000000000000000000004040008200111000000002400121018111000080220000010000200000000080000000000080000000000000000000").into(),
            difficulty: 2,
            number: u64::from_str_radix("1c74151", 16).unwrap(),
            gas_limit: u64::from_str_radix("2faf080", 16).unwrap(),
            gas_used: u64::from_str_radix("fe04f", 16).unwrap(),
            timestamp: u64::from_str_radix("6462d9a5", 16).unwrap(),
            extra_data: hex!("d883010202846765746888676f312e31392e39856c696e7578000000110bea95f8b27bb86095105771d583f97b9dd6a86d0ce6971f2b6bc986becac0a287214cfff3b6db8e5a6ca2f896bd99cd216756158bbc0ab40b64b0d211b9a967b7d4f505f800c75b93ef5edd9272ad69b338b6965cf5a9283d56bdf7df2420363cbc2484972eea7af84c8401c7414fa0cf8d34727ff1d895bb49ca4be60c3b24d98d8afa9ce78644924e4b9aa39df8548401c74150a051daf288b19c1b9bd6565be70c5bfb79c6fc470ce55ca684f6099c01b4ed749480d1bf2a480a6e9988d5f50823924bbccfe2c6dc94f66603c4bba805e14d732085408bce4f0f25b305c9c8a69b7050fd5d8106656235e414cc7885b4af2400d01400").to_vec(),
            mix_digest: hex!("0000000000000000000000000000000000000000000000000000000000000000").into(),
            nonce: hex!("0000000000000000").into(),
            // calculated in try_into
            hash: [0; 32],
            is_epoch: false,
            new_validators: vec![],
        };
        let raw: RawETHHeader = non_epoch.try_into().unwrap();
        let non_epoch: ETHHeader = (&raw).try_into().unwrap();
        assert!(!non_epoch.is_epoch);
        assert_eq!(
            non_epoch.hash,
            hex!("8a75dd8ac962e4c4ab33e17f83c453ebe3fc97f722cef4affef092fd70c79d5f")
        );
        assert_eq!(non_epoch.new_validators.len(), 0);

        // same validator is used in this test block
        non_epoch
            .verify_seal(&epoch.new_validators, &ChainId::new(97))
            .unwrap();

        non_epoch.verify_cascading_fields(&epoch).unwrap()
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
