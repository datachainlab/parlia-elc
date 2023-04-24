use alloc::vec::Vec;

use hex_literal::hex;
use patricia_merkle_trie::{EIP1186Layout, keccak};
use patricia_merkle_trie::keccak::keccak_256;
use rlp::Rlp;
use trie_eip1186::VerifyError;

use crate::errors::Error;
use crate::misc::{Account, Address, Hash};

const IBC_COMMITMENTS_SLOT: [u8; 32] = hex!("0000000000000000000000000000000000000000000000000000000000000000");

pub fn calculate_ibc_commitment_storage_key(path: &str) -> Hash {
    keccak_256(
        &[
            &keccak_256(&path.as_bytes()),
            IBC_COMMITMENTS_SLOT.as_slice()
        ]
            .concat(),
    )
}

pub fn decode_eip1184_rlp_proof(proofs: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut proof_encoded: Vec<Vec<u8>> = Vec::with_capacity(proofs.len());
    let proofs = Rlp::new(proofs);
    for proof in proofs.iter() {
        let proof: Vec<Vec<u8>> = proof.as_list().map_err(Error::ProofRLPError)?;
        let proof = rlp::encode_list::<Vec<u8>, Vec<u8>>(&proof).into();
        proof_encoded.push(proof)
    }
    Ok(proof_encoded)
}


pub fn resolve_account(
    state_root: &Hash,
    account_proof: &[Vec<u8>],
    address: &Address,
) -> Result<Account, Error> {
    match verify_proof(state_root, account_proof, address, &None) {
        Ok(_) => Err(Error::AccountNotFound(*address)),
        Err(Error::UnexpectedStateExistingValue(_,_, value, _)) => Rlp::new(&value).try_into(),
        Err(err) => Err(err),
    }
}

pub fn verify_proof(
    root: &Hash,
    proof: &[Vec<u8>],
    key: &[u8],
    expected_value: &Option<Vec<u8>>,
) -> Result<(), Error> {
    let log_hash = *root;
    let log_proof = proof.to_vec();
    let expected_value = expected_value.as_ref().map(|e| rlp::encode(e).to_vec());
    let log_expected_value = expected_value.clone();
    trie_eip1186::verify_proof::<EIP1186Layout<keccak::KeccakHasher>>(
        &root.into(),
        proof,
        &keccak_256(key),
        expected_value.as_deref(),
    )
        .map_err(|err| match err {
            VerifyError::ExistingValue(value) => {
                Error::UnexpectedStateExistingValue(log_hash, log_proof, value, key.to_vec())
            }
            VerifyError::NonExistingValue(_) => Error::UnexpectedStateNonExistingValue(log_hash, log_proof, log_expected_value, key.to_vec()),
            VerifyError::DecodeError(_) => Error::UnexpectedStateDecodeError(log_hash, log_proof, log_expected_value, key.to_vec()),
            VerifyError::HashDecodeError(_) => Error::UnexpectedStateHashDecodeError(log_hash, log_proof, log_expected_value, key.to_vec()),
            VerifyError::HashMismatch(_) => Error::UnexpectedStateHashMismatch(log_hash, log_proof, log_expected_value, key.to_vec()),
            VerifyError::ValueMismatch(_) => Error::UnexpectedStateValueMismatch(log_hash, log_proof, log_expected_value, key.to_vec()),
            VerifyError::IncompleteProof => Error::UnexpectedStateIncompleteProof(log_hash, log_proof, log_expected_value, key.to_vec()),
        })
}

#[cfg(test)]
mod test {
    use alloc::borrow::ToOwned as _;

    use hex_literal::hex;
    use patricia_merkle_trie::keccak::keccak_256;
    use prost::Message;

    use crate::misc::{Account, Hash};
    use crate::proof::{calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof, resolve_account, verify_proof};

    #[test]
    fn test_resolve_account() {
        let address = hex!("a412becfedf8dccb2d56e5a88f5c1b87cc37ceef");
        let state_root: Hash =
            hex!("c7095cc31e155302a3ff06970f0df0efa1abf5fe6e4be6cc450cc5f9421c2c9f");
        let account_proof = vec![
            hex!("f873a12023b3309d10ca81366908080d27b9f3a46293a38eb039f35393e1af81413e70c8b84ff84d0489020000000000000000a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec(),
        ];
        let account = Account {
            storage_root: hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                .to_vec(),
        };
        let v = resolve_account(&state_root, &account_proof, &address);
        match v {
            Ok(actual) => assert_eq!(actual, account),
            Err(e) => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_verify_proof() {
        let key = hex!("0000000000000000000000000000000000000000000000000000000000000000");
        let storage_root = hex!("c5bbc7e086abad66f3d4b49cc39c27e4864834ce3d21d91692c513481bf9de1b");
        let storage_proof = vec![
            hex!("f8518080a051c7191217d318e27eed8b8f0b2c81df8ad258037ecdb3ee8808ab982623adba8080808080808080a028e886a776e1a5ccaf6819bc26ae7f83616639014e9751eb8d68eaaac54966448080808080").to_vec(),
            hex!("f7a0390decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e5639594ebed59a7f647152af99ef0fd8e3f7e81bd7b1fd7").to_vec(),
        ];
        let expected = hex!("ebed59a7f647152af99ef0fd8e3f7e81bd7b1fd7").to_vec();
        if let Err(e) = verify_proof(&storage_root, &storage_proof, &key, &Some(expected)) {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_verify_commitment_with_lcp_data() {
        let storage_root: Hash = [
            51, 143, 168, 48, 229, 178, 255, 245, 35, 4, 82, 182, 21, 136, 15, 201, 229, 227, 54, 146, 158, 189, 229, 10, 242, 165, 205, 60, 170, 52, 212, 78
        ];
        let storage_proof_rlp = vec![
            249, 2, 108, 249, 1, 145, 160, 243, 2, 132, 113, 118, 63, 160, 241, 161, 149, 174, 195, 18, 210, 53, 140, 244, 55, 106, 61, 135, 92, 126, 3, 174, 227, 145, 76, 246, 158, 163, 237, 128, 128, 160, 161, 243, 110, 96, 138, 107, 213, 87, 172, 13, 123, 131, 19, 176, 84, 242, 32, 18, 219, 20, 61, 136, 234, 214, 229, 63, 3, 59, 48, 2, 150, 137, 160, 175, 166, 191, 1, 133, 187, 201, 138, 8, 129, 81, 61, 81, 86, 33, 87, 198, 100, 189, 6, 230, 101, 136, 66, 66, 242, 24, 147, 184, 24, 61, 33, 160, 23, 83, 180, 210, 64, 112, 1, 189, 122, 120, 147, 18, 45, 252, 211, 143, 177, 16, 93, 219, 135, 216, 71, 156, 65, 241, 141, 38, 171, 247, 237, 182, 160, 210, 143, 238, 182, 140, 97, 22, 255, 66, 68, 225, 250, 55, 56, 89, 201, 28, 147, 181, 102, 138, 47, 37, 0, 189, 189, 203, 212, 152, 186, 241, 212, 160, 93, 33, 126, 80, 5, 168, 58, 116, 140, 187, 49, 219, 74, 219, 118, 193, 62, 119, 121, 235, 231, 13, 122, 189, 163, 187, 122, 145, 6, 196, 148, 3, 160, 9, 226, 194, 151, 8, 9, 20, 134, 217, 158, 89, 5, 196, 34, 23, 235, 234, 182, 193, 155, 131, 238, 116, 100, 192, 196, 214, 102, 88, 180, 15, 239, 160, 114, 77, 73, 24, 57, 36, 101, 1, 166, 27, 246, 128, 196, 20, 105, 243, 251, 51, 205, 247, 112, 2, 4, 109, 93, 1, 104, 71, 100, 138, 24, 237, 160, 209, 8, 0, 140, 126, 171, 172, 12, 93, 82, 67, 64, 234, 3, 152, 165, 245, 137, 166, 131, 218, 2, 177, 29, 84, 166, 186, 8, 42, 245, 54, 145, 160, 214, 233, 118, 109, 210, 194, 72, 219, 143, 9, 216, 125, 95, 190, 129, 254, 160, 111, 112, 122, 146, 103, 213, 223, 119, 10, 156, 212, 4, 60, 116, 180, 160, 90, 98, 164, 183, 88, 177, 161, 231, 114, 25, 237, 70, 112, 69, 253, 90, 125, 202, 100, 255, 155, 200, 174, 225, 111, 199, 221, 194, 180, 124, 109, 50, 160, 39, 152, 155, 234, 177, 15, 57, 47, 67, 85, 70, 121, 225, 22, 86, 184, 135, 250, 224, 143, 245, 81, 251, 117, 185, 11, 128, 32, 154, 54, 102, 126, 128, 128, 128, 248, 145, 128, 128, 128, 128, 128, 160, 103, 18, 133, 119, 55, 115, 130, 213, 70, 76, 86, 39, 144, 246, 223, 29, 254, 134, 177, 180, 108, 75, 102, 200, 241, 205, 231, 206, 19, 221, 182, 244, 128, 128, 160, 111, 93, 78, 118, 145, 122, 232, 53, 185, 114, 80, 95, 148, 212, 14, 218, 218, 253, 220, 68, 46, 148, 77, 193, 87, 179, 71, 171, 145, 93, 173, 118, 128, 128, 128, 128, 160, 192, 156, 224, 147, 42, 238, 11, 71, 160, 213, 233, 164, 59, 206, 68, 79, 86, 159, 212, 42, 109, 164, 91, 77, 164, 86, 88, 8, 192, 152, 241, 183, 128, 160, 8, 21, 54, 159, 64, 208, 81, 17, 118, 220, 29, 163, 73, 142, 1, 7, 9, 151, 63, 23, 186, 206, 165, 2, 3, 144, 30, 15, 37, 48, 164, 148, 128, 248, 67, 160, 32, 63, 196, 45, 223, 108, 27, 91, 178, 24, 206, 36, 225, 76, 64, 175, 158, 14, 177, 39, 165, 215, 96, 80, 211, 125, 115, 105, 226, 252, 74, 71, 161, 160, 34, 171, 87, 106, 125, 243, 139, 180, 134, 15, 251, 198, 95, 48, 213, 166, 101, 54, 251, 45, 142, 195, 213, 215, 212, 171, 154, 62, 173, 14, 67, 18
        ];
        let storage_proof = decode_eip1184_rlp_proof(&storage_proof_rlp).unwrap();

        let expected_value = vec![10, 12, 108, 99, 112, 45, 99, 108, 105, 101, 110, 116, 45, 48, 18, 35, 10, 1, 49, 18, 13, 79, 82, 68, 69, 82, 95, 79, 82, 68, 69, 82, 69, 68, 18, 15, 79, 82, 68, 69, 82, 95, 85, 78, 79, 82, 68, 69, 82, 69, 68, 24, 1, 34, 21, 10, 12, 108, 99, 112, 45, 99, 108, 105, 101, 110, 116, 45, 48, 26, 5, 10, 3, 105, 98, 99];
        let expected_value = keccak_256(&expected_value).to_vec();

        let path = calculate_ibc_commitment_storage_key("connections/connection-0");

        if let Err(e) = verify_proof(
            &storage_root,
            &storage_proof,
            path.as_slice(),
            &Some(expected_value),
        ) {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_verify_commitment_with_lc_data() {
        use ibc_proto::ibc::core::commitment::v1::MerklePrefix;
        use ibc_proto::ibc::core::connection::v1::{ConnectionEnd, Counterparty, Version};

        let storage_root : Hash = [
            82, 151, 170, 160, 133, 205, 75, 144, 49, 43, 13, 172, 81, 2, 52, 123, 17, 51, 253, 55, 100, 124, 234, 205, 131, 149, 248, 211, 22, 210, 2, 68
        ];
        let storage_proof_rlp = vec![
            249, 2, 108, 249, 1, 177, 160, 243, 2, 132, 113, 118, 63, 160, 241, 161, 149, 174, 195, 18, 210, 53, 140, 244, 55, 106, 61, 135, 92, 126, 3, 174, 227, 145, 76, 246, 158, 163, 237, 128, 160, 127, 209, 245, 74, 140, 45, 22, 54, 65, 152, 69, 181, 239, 59, 177, 124, 160, 102, 90, 184, 251, 217, 5, 60, 213, 213, 82, 239, 90, 170, 6, 2, 160, 41, 212, 235, 101, 41, 88, 83, 242, 202, 249, 194, 236, 70, 87, 205, 86, 210, 185, 20, 24, 165, 108, 78, 217, 227, 185, 171, 69, 147, 24, 214, 229, 160, 145, 96, 113, 245, 236, 179, 190, 225, 105, 241, 251, 65, 3, 235, 190, 98, 50, 95, 13, 58, 158, 126, 255, 126, 200, 182, 162, 184, 82, 48, 67, 136, 128, 160, 175, 124, 86, 245, 185, 249, 125, 146, 23, 9, 218, 185, 15, 109, 124, 33, 250, 59, 89, 96, 116, 82, 243, 65, 10, 193, 8, 40, 144, 139, 38, 64, 160, 224, 191, 86, 228, 105, 21, 42, 129, 130, 172, 228, 96, 248, 83, 25, 223, 99, 214, 201, 190, 202, 139, 42, 196, 142, 81, 92, 44, 50, 172, 251, 42, 160, 67, 76, 154, 154, 112, 58, 176, 167, 174, 126, 79, 134, 194, 208, 154, 245, 161, 106, 236, 125, 64, 136, 202, 72, 61, 70, 170, 12, 109, 132, 68, 213, 160, 170, 218, 158, 181, 234, 137, 42, 205, 212, 206, 113, 31, 185, 40, 158, 248, 185, 203, 175, 103, 31, 6, 150, 105, 26, 169, 115, 42, 94, 238, 154, 22, 160, 209, 8, 0, 140, 126, 171, 172, 12, 93, 82, 67, 64, 234, 3, 152, 165, 245, 137, 166, 131, 218, 2, 177, 29, 84, 166, 186, 8, 42, 245, 54, 145, 160, 183, 120, 101, 29, 90, 126, 76, 66, 215, 15, 21, 193, 218, 17, 65, 15, 9, 145, 242, 3, 203, 163, 150, 91, 77, 134, 86, 62, 207, 117, 71, 143, 160, 90, 98, 164, 183, 88, 177, 161, 231, 114, 25, 237, 70, 112, 69, 253, 90, 125, 202, 100, 255, 155, 200, 174, 225, 111, 199, 221, 194, 180, 124, 109, 50, 160, 187, 51, 102, 98, 64, 251, 30, 166, 130, 29, 10, 59, 50, 19, 246, 48, 184, 197, 144, 98, 5, 83, 71, 101, 160, 145, 11, 13, 122, 129, 16, 210, 128, 160, 67, 199, 95, 200, 128, 34, 48, 39, 12, 122, 115, 104, 117, 172, 182, 198, 69, 116, 151, 124, 143, 65, 129, 117, 79, 249, 190, 133, 168, 70, 52, 10, 128, 248, 113, 128, 160, 14, 147, 143, 255, 173, 177, 239, 236, 164, 203, 229, 21, 75, 174, 164, 236, 137, 188, 190, 203, 85, 8, 192, 11, 104, 183, 162, 207, 238, 101, 38, 67, 128, 128, 128, 160, 123, 103, 52, 98, 145, 109, 110, 134, 48, 20, 137, 241, 181, 253, 251, 6, 99, 206, 99, 49, 92, 213, 63, 76, 18, 22, 72, 175, 130, 0, 232, 129, 128, 128, 128, 128, 128, 128, 128, 160, 86, 19, 50, 171, 19, 198, 195, 87, 230, 246, 175, 58, 22, 123, 6, 172, 13, 14, 227, 136, 240, 15, 9, 31, 226, 129, 35, 102, 111, 56, 184, 89, 128, 128, 128, 248, 67, 160, 32, 63, 196, 45, 223, 108, 27, 91, 178, 24, 206, 36, 225, 76, 64, 175, 158, 14, 177, 39, 165, 215, 96, 80, 211, 125, 115, 105, 226, 252, 74, 71, 161, 160, 204, 217, 3, 153, 193, 37, 239, 8, 122, 231, 131, 230, 12, 221, 239, 188, 60, 214, 40, 96, 20, 190, 116, 18, 211, 1, 38, 31, 98, 207, 103, 255
        ];
        let storage_proof = decode_eip1184_rlp_proof(&storage_proof_rlp).unwrap();

        let connection_end = ConnectionEnd {
            client_id: "99-parlia-0".to_owned(),
            versions: vec![Version {
                identifier: "1".to_owned(),
                features: vec!["ORDER_ORDERED".to_owned(), "ORDER_UNORDERED".to_owned()],
            }],
            state: 3,
            counterparty: Some(Counterparty {
                client_id: "99-parlia-0".to_owned(),
                connection_id: "connection-0".to_owned(),
                prefix: Some(MerklePrefix {
                    key_prefix: hex!("696263").to_vec(),
                }),
            }),
            delay_period: 0,
        };
        let mut expected_value = alloc::vec::Vec::<u8>::new();
        connection_end.encode(&mut expected_value).unwrap();

        let path = calculate_ibc_commitment_storage_key("connections/connection-0");
        if let Err(e) = verify_proof(
            &storage_root,
            &storage_proof,
            path.as_slice(),
            &Some(keccak_256(&expected_value).to_vec()),
        ) {
            unreachable!("{:?}", e);
        }
    }
}