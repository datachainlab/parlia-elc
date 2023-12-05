use crate::errors::Error;
use crate::misc::{ceil_div, rlp_as_val, BlockNumber, Hash, RlpIterator, Validators};
use alloc::vec::Vec;
use milagro_bls::PublicKey;

use patricia_merkle_trie::keccak::keccak_256;
use rlp::{Rlp, RlpStream};

pub(crate) const BLS_PUBKEY_LENGTH: usize = 48;
const MAX_ATTESTATION_EXTRA_LENGTH: usize = 256;
const BLS_SIGNATURE_LENGTH: usize = 96;

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
    pub fn get(&self, index: usize) -> bool {
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
    pub fn verify(&self, number: BlockNumber, validators: &Validators) -> Result<(), Error> {
        if self.vote_address_set.count() > validators.len() {
            return Err(Error::UnexpectedVoteAddressCount(
                number,
                self.vote_address_set.count(),
                validators.len(),
            ));
        }
        let mut voted_addr = Vec::new();
        for (i, val) in validators.iter().enumerate() {
            if !self.vote_address_set.get(i) {
                continue;
            }
            let bls_pub_key_bytes = &val[val.len() - BLS_PUBKEY_LENGTH..];
            let bls_pub_key = PublicKey::from_bytes(bls_pub_key_bytes)
                .map_err(|e| Error::UnexpectedBLSPubkey(number, e))?;
            voted_addr.push(bls_pub_key);
        }

        let required = ceil_div(validators.len() * 2, 3);
        if voted_addr.len() < required {
            return Err(Error::InsufficientValidatorCount(
                number,
                voted_addr.len(),
                required,
            ));
        }

        let app_sig = milagro_bls::AggregateSignature::from_bytes(&self.app_signature)
            .map_err(|e| Error::UnexpectedBLSSignature(number, e))?;
        let pub_keys_ref: Vec<&PublicKey> = voted_addr.iter().collect();
        if !app_sig.fast_aggregate_verify(self.data.hash().as_slice(), &pub_keys_ref) {
            return Err(Error::FailedToVerifyBLSSignature(
                number,
                pub_keys_ref.len(),
            ));
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

        let app_signature: [u8; BLS_SIGNATURE_LENGTH] = rlp
            .try_next_as_val::<Vec<u8>>()?
            .try_into()
            .map_err(|v: Vec<u8>| Error::UnexpectedBLSSignatureLength(v.len()))?;

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
    use crate::errors::Error;
    use crate::header::testdata::{
        header_31297199, header_31297200, header_31297201, header_31297202, validators_in_31297000,
    };
    use crate::header::vote_attestation::{
        VoteAddressBitSet, VoteAttestation, VoteData, BLS_SIGNATURE_LENGTH,
        MAX_ATTESTATION_EXTRA_LENGTH,
    };
    use hex_literal::hex;
    use rlp::{Rlp, RlpStream};

    #[test]
    fn test_error_try_from_unexpected_bls_signature_length() {
        let mut stream = RlpStream::new_list(2);
        stream.append(&10_u64);
        stream.append(&[0u8; BLS_SIGNATURE_LENGTH + 1].to_vec());
        let raw = stream.out();
        let err = VoteAttestation::try_from(Rlp::new(&raw)).unwrap_err();
        match err {
            Error::UnexpectedBLSSignatureLength(size) => {
                assert_eq!(size, BLS_SIGNATURE_LENGTH + 1)
            }
            err => unreachable!("{:?}", err),
        };
    }

    #[test]
    fn test_error_try_from_vote_extra_length() {
        let mut vote_stream = RlpStream::new_list(4);
        vote_stream.append(&10_u64);
        vote_stream.append(&[1u8; 32].to_vec());
        vote_stream.append(&11_u64);
        vote_stream.append(&[0u8; 32].to_vec());
        let vote_data_size = vote_stream.len();
        let mut stream = RlpStream::new_list(vote_data_size + 3);
        stream.append(&10_u64);
        stream.append(&[0u8; BLS_SIGNATURE_LENGTH].to_vec());
        stream.append_raw(&vote_stream.out(), vote_data_size);
        stream.append(&[0u8; MAX_ATTESTATION_EXTRA_LENGTH + 1].to_vec());
        let raw = stream.out();
        let err = VoteAttestation::try_from(Rlp::new(&raw)).unwrap_err();
        match err {
            Error::UnexpectedVoteAttestationExtraLength(size) => {
                assert_eq!(size, MAX_ATTESTATION_EXTRA_LENGTH + 1)
            }
            err => unreachable!("{:?}", err),
        };
    }

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
            if let Err(e) = block
                .get_vote_attestation()
                .unwrap()
                .verify(block.number, &validators)
            {
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

    #[test]
    fn test_error_verify() {
        let mut validators = validators_in_31297000();
        validators.extend(validators.clone());
        let header = header_31297199();
        let vote = header.get_vote_attestation().unwrap();
        let err = vote.verify(header.number, &validators).unwrap_err();
        match err {
            Error::InsufficientValidatorCount(number, vote_count_in_extra, required) => {
                assert_eq!(number, header.number);
                assert_eq!(vote_count_in_extra, 17);
                assert_eq!(required, 28); //42 * 2 / 3
            }
            _ => unreachable!("invalid error {:?}", err),
        }

        let validators = validators_in_31297000()[0..16].to_vec();
        let err = vote.verify(header.number, &validators).unwrap_err();
        match err {
            Error::UnexpectedVoteAddressCount(number, vote_count_in_extra, val_size) => {
                assert_eq!(number, header.number);
                assert_eq!(vote_count_in_extra, 17);
                assert_eq!(val_size, validators.len());
            }
            _ => unreachable!("{} {:?}", header.number, err),
        }

        let mut validators = validators_in_31297000();
        for v in validators.iter_mut() {
            v.pop();
        }
        let err = vote.verify(header.number, &validators).unwrap_err();
        match err {
            Error::UnexpectedBLSPubkey(number, e) => {
                assert_eq!(header.number, number);
                assert_eq!(format!("{:?}", e), "InvalidPoint");
            }
            _ => unreachable!("{} {:?}", header.number, err),
        }

        let validators = validators_in_31297000();
        let header = header_31297199();
        let mut vote = header.get_vote_attestation().unwrap();
        vote.app_signature[0] = 1;
        let err = vote.verify(header.number, &validators).unwrap_err();
        match err {
            Error::UnexpectedBLSSignature(number, e) => {
                assert_eq!(number, header.number);
                assert_eq!(format!("{:?}", e), "InvalidG2Size");
            }
            _ => unreachable!("{} {:?}", header.number, err),
        }

        let validators = validators_in_31297000();
        let header = header_31297199();
        let mut vote = header.get_vote_attestation().unwrap();
        vote.vote_address_set.vote_address_set.pop();
        let err = vote.verify(header.number, &validators).unwrap_err();
        match err {
            Error::FailedToVerifyBLSSignature(number, e) => {
                assert_eq!(number, header.number);
                assert_eq!(e, 16);
            }
            _ => unreachable!("{} {:?}", header.number, err),
        }
    }

    #[test]
    fn test_vote_address_bitset() {
        let value = VoteAddressBitSet::new(0b0111);
        assert!(value.get(0));
        assert!(value.get(1));
        assert!(value.get(2));
        assert!(!value.get(3));
        assert!(!value.get(4));
        assert_eq!(value.count(), 3);
    }
}
