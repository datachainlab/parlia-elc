use crate::errors::Error;
use crate::misc::{rlp_as_val, BlockNumber, Hash, RlpIterator, Validators};
use alloc::vec::Vec;
use milagro_bls::PublicKey;

use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Rlp, RlpStream};

pub(crate) const BLS_PUBKEY_LENGTH: usize = 48;
const MAX_ATTESTATION_EXTRA_LENGTH: usize = 256;

#[derive(Clone, Debug, PartialEq)]
pub struct VoteAddressBitSet {
    vote_address_set: Vec<bool>,
}

impl VoteAddressBitSet {
    fn new(value: u64) -> Self {
        Self {
            vote_address_set: format!("{:b}", value)
                .chars()
                .rev()
                .map(|v| v == '1')
                .collect(),
        }
    }
    pub fn test(&self, index: usize) -> bool {
        if index >= self.vote_address_set.len() {
            return false;
        }
        self.vote_address_set[index]
    }
    pub fn count(&self) -> usize {
        self.vote_address_set.iter().filter(|v| **v).count()
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VoteAttestation {
    pub vote_address_set: VoteAddressBitSet,
    pub app_signature: [u8; 96],
    pub data: VoteData,
    pub extra: Vec<u8>,
}

impl VoteAttestation {
    pub fn verify(&self, validators: &Validators) -> Result<(), Error> {
        if self.vote_address_set.count() > validators.len() {
            return Err(Error::UnexpectedVoteAddressCount(
                self.vote_address_set.count(),
                validators.len(),
            ));
        }
        let mut voted_addr = Vec::new();
        for (i, val) in validators.iter().enumerate() {
            if !self.vote_address_set.test(i) {
                continue;
            }
            let bls_pub_key_bytes = &val[val.len() - BLS_PUBKEY_LENGTH..];
            let bls_pub_key =
                PublicKey::from_bytes(bls_pub_key_bytes).map_err(Error::UnexpectedBLSPubkey)?;
            voted_addr.push(bls_pub_key);
        }

        let app_sig = milagro_bls::AggregateSignature::from_bytes(&self.app_signature)
            .map_err(Error::UnexpectedBLSSignature)?;
        let pub_keys_ref: Vec<&PublicKey> = voted_addr.iter().collect();
        if !app_sig.fast_aggregate_verify(self.data.hash().as_slice(), &pub_keys_ref) {
            return Err(Error::FailedToVerifyBLSSignature(pub_keys_ref.len()));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VoteData {
    pub source_number: BlockNumber,
    pub source_hash: Hash,
    pub target_number: BlockNumber,
    pub target_hash: Hash,
}

impl VoteData {
    pub fn hash(&self) -> Hash {
        let mut stream = RlpStream::new_list(4);
        stream.append(&self.source_number);
        stream.append(&self.source_hash.as_slice());
        stream.append(&self.target_number);
        stream.append(&self.target_hash.as_slice());
        keccak_256(stream.out().as_ref())
    }
}

impl<'a> TryFrom<Rlp<'a>> for VoteAttestation {
    type Error = Error;

    fn try_from(value: Rlp<'a>) -> Result<Self, Self::Error> {
        let mut rlp = RlpIterator::new(value);
        let vote_address_set: u64 = rlp.try_next_as_val()?;

        let app_signature: [u8; 96] = rlp
            .try_next_as_val::<Vec<u8>>()?
            .try_into()
            .map_err(Error::UnexpectedBLSSignatureLength)?;

        let vote = rlp.try_next()?;
        let source_number: u64 = rlp_as_val(&vote, 0)?;
        let source_hash: Vec<u8> = rlp_as_val(&vote, 1)?;
        let target_number: u64 = rlp_as_val(&vote, 2)?;
        let target_hash: Vec<u8> = rlp_as_val(&vote, 3)?;

        let extra: Vec<u8> = rlp.try_next_as_val()?;

        let attestation = VoteAttestation {
            vote_address_set: VoteAddressBitSet::new(vote_address_set),
            app_signature,
            data: VoteData {
                source_number,
                source_hash: source_hash.try_into().unwrap(),
                target_number,
                target_hash: target_hash.try_into().unwrap(),
            },
            extra,
        };
        if attestation.extra.len() > MAX_ATTESTATION_EXTRA_LENGTH {
            return Err(Error::UnexpectedVoteAttestationExtraLength(
                attestation.extra.len(),
            ));
        }
        Ok(attestation)
    }
}
#[cfg(test)]
mod test {
    use crate::header::testdata::{
        header_31297199, header_31297200, header_31297201, header_31297202, validators_in_31297000,
    };
    use crate::header::vote_attestation::{VoteAddressBitSet, VoteAttestation, VoteData};
    use hex_literal::hex;
    use rlp::Rlp;

    #[test]
    fn test_success_verify() {
        let validators = validators_in_31297000();
        let blocks = vec![
            header_31297199(),
            header_31297200(),
            header_31297201(),
            header_31297202(),
        ];
        for block in blocks.iter() {
            if let Err(e) = block.vote_attestation().unwrap().verify(&validators) {
                unreachable!("{} {:?}", block.number, e);
            }
        }
    }

    #[test]
    fn test_decode_vote_attestation() {
        // https://bscscan.com/block/31297119
        let attestation_bytes = hex!("f8b5830aefffb8608bce894fbb300b3d6bc233d98ea61ca1807a297d7b2cf8f1a899c3ab3b87a8b9b4b7cd60efe269bbe4663305e8a434fc0a5fe8d121e1b8d5e55e0d47de6557cd2199bfd744a88e6619901f97e7ed37cdec79552dfb3e7bb066f9f63b4bca9cd4f84c8401dd8e5da0d404f12419eb704e3c6fb55654b55d5c45d202d058b619341d44800b848483248401dd8e5ea0c262cb47c9a56e85a0555098e6a8e79f1765c7cea3cc624a3de8e6598173c6e880");
        let vote_attestation: VoteAttestation =
            Rlp::new(attestation_bytes.as_slice()).try_into().unwrap();
        assert_eq!(
            vote_attestation.vote_address_set,
            VoteAddressBitSet::new(716799)
        );
        assert_eq!(vote_attestation.app_signature, hex!("8bce894fbb300b3d6bc233d98ea61ca1807a297d7b2cf8f1a899c3ab3b87a8b9b4b7cd60efe269bbe4663305e8a434fc0a5fe8d121e1b8d5e55e0d47de6557cd2199bfd744a88e6619901f97e7ed37cdec79552dfb3e7bb066f9f63b4bca9cd4"));
        assert_eq!(vote_attestation.data.source_number, 31297117);
        assert_eq!(
            vote_attestation.data.source_hash,
            hex!("d404f12419eb704e3c6fb55654b55d5c45d202d058b619341d44800b84848324")
        );
        assert_eq!(vote_attestation.data.target_number, 31297118);
        assert_eq!(
            vote_attestation.data.target_hash,
            hex!("c262cb47c9a56e85a0555098e6a8e79f1765c7cea3cc624a3de8e6598173c6e8")
        );
        assert!(vote_attestation.extra.is_empty());

        // https://bscscan.com/block/31297200
        let attestation_bytes = hex!("f8b5830aefffb86097bc63a64e8d730014c39dcaac8f3309e37a11c06f0f5c233b55ba19c1f6c34d2d08de4b030ce825bb21fd884bc0fcb811336857419f5ca42a92ac149a4661a248de10f4ca6496069fdfd10d43bc74ccb81806b6ecd384617d1006b16dead7e4f84c8401dd8eaea0e61c6075d2ab24fcdc423764c21771cac6b241cbff89718f9cc8fc6459b4e7578401dd8eafa010c8358490a494a40c5c92aff8628fa770860a9d34e7fb7df38dfb208b0ddfc380");
        let vote_attestation: VoteAttestation =
            Rlp::new(attestation_bytes.as_slice()).try_into().unwrap();
        assert_eq!(
            vote_attestation.vote_address_set,
            VoteAddressBitSet::new(716799)
        );
        assert_eq!(vote_attestation.app_signature, hex!("97bc63a64e8d730014c39dcaac8f3309e37a11c06f0f5c233b55ba19c1f6c34d2d08de4b030ce825bb21fd884bc0fcb811336857419f5ca42a92ac149a4661a248de10f4ca6496069fdfd10d43bc74ccb81806b6ecd384617d1006b16dead7e4"));
        assert_eq!(vote_attestation.data.source_number, 31297198);
        assert_eq!(
            vote_attestation.data.source_hash,
            hex!("e61c6075d2ab24fcdc423764c21771cac6b241cbff89718f9cc8fc6459b4e757")
        );
        assert_eq!(vote_attestation.data.target_number, 31297199);
        assert_eq!(
            vote_attestation.data.target_hash,
            hex!("10c8358490a494a40c5c92aff8628fa770860a9d34e7fb7df38dfb208b0ddfc3")
        );
        assert!(vote_attestation.extra.is_empty());
    }

    #[test]
    fn test_vote_data_hash() {
        let data = VoteData {
            source_number: 31297117,
            source_hash: hex!("d404f12419eb704e3c6fb55654b55d5c45d202d058b619341d44800b84848324"),
            target_number: 31297118,
            target_hash: hex!("c262cb47c9a56e85a0555098e6a8e79f1765c7cea3cc624a3de8e6598173c6e8"),
        };
        assert_eq!(
            data.hash(),
            hex!("f9ec8e79b93b9be3a57c4ce6dddbf86bc8ae4035bbe3f100b9682be6ca9ec9f4")
        );

        let data = VoteData {
            source_number: 31297198,
            source_hash: hex!("e61c6075d2ab24fcdc423764c21771cac6b241cbff89718f9cc8fc6459b4e757"),
            target_number: 31297199,
            target_hash: hex!("10c8358490a494a40c5c92aff8628fa770860a9d34e7fb7df38dfb208b0ddfc3"),
        };
        assert_eq!(
            data.hash(),
            hex!("89808e1d31999d5165e870f772099951da583776730f5dae0754e277a5ff3f80")
        );
    }
}
