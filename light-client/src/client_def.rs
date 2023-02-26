use crate::client_state::ClientState;
use crate::consensus_state::ConsensusState;
use crate::header::Header;

use alloc::boxed::Box;
use alloc::vec::Vec;

use ibc::core::ics02_client::header::Header as IBCHeader;

use patricia_merkle_trie::keccak;
use patricia_merkle_trie::keccak::keccak_256;
use patricia_merkle_trie::EIP1186Layout;

use rlp::Rlp;
use trie_eip1186::{verify_proof, VerifyError};

use crate::errors::Error;
use crate::misc::{Account, Address, Hash, ValidatorReader};
use crate::path::Path;

pub struct ParliaClient(Box<dyn AccountResolver>);

impl Default for ParliaClient {
    fn default() -> Self {
        Self::new(DefaultAccountResolver)
    }
}

impl ParliaClient {
    pub fn check_header_and_update_state(
        &self,
        ctx: impl ValidatorReader,
        now: ibc::timestamp::Timestamp,
        client_state: &ClientState,
        trusted_consensus_state: &ConsensusState,
        header: &Header,
    ) -> Result<(ClientState, ConsensusState), Error> {
        // Ensure last consensus state is within the trusting period
        trusted_consensus_state.assert_within_trust_period(now, client_state.trusting_period)?;
        trusted_consensus_state
            .assert_within_trust_period(header.timestamp(), client_state.trusting_period)?;

        // Ensure header revision is same as chain revision
        let header_height = header.height();
        if header_height.revision_number() != client_state.chain_id.version() {
            return Err(Error::UnexpectedHeaderRevision(
                client_state.chain_id.version(),
                header_height.revision_number(),
            ));
        }

        // Ensure header is valid
        header.verify(ctx, &client_state.chain_id)?;

        let mut new_client_state = client_state.clone();
        new_client_state.latest_height = header.height();

        // Ensure world state is valid
        let account = self.0.get_account(
            header.state_root(),
            &header.account_proof()?,
            &new_client_state.ibc_store_address,
        )?;
        let new_consensus_state = ConsensusState {
            state_root: account.storage_root.into(),
            timestamp: header.timestamp(),
            validator_set: header.validator_set().clone(),
        };

        Ok((new_client_state, new_consensus_state))
    }

    pub fn verify_commitment(
        &self,
        storage_root: &Hash,
        storage_proof_rlp: &[u8],
        path: impl Path,
        expected_value: &Option<Vec<u8>>,
    ) -> Result<(), Error> {
        let storage_proof = Rlp::new(storage_proof_rlp);
        let storage_proof = storage_proof.as_list().map_err(Error::RLPDecodeError)?;
        Self::verify_proof(
            storage_root,
            &storage_proof,
            path.storage_key(),
            expected_value,
        )
    }

    pub fn new(account_resolver: impl AccountResolver + 'static) -> Self {
        Self(Box::new(account_resolver))
    }

    fn verify_proof(
        root: &Hash,
        proof: &[Vec<u8>],
        key: &[u8],
        expected_value: &Option<Vec<u8>>,
    ) -> Result<(), Error> {
        let expected_value = expected_value.as_ref().map(|e| rlp::encode(e).to_vec());
        verify_proof::<EIP1186Layout<keccak::KeccakHasher>>(
            &root.into(),
            proof,
            &keccak_256(key),
            expected_value.as_deref(),
        )
        .map_err(|err| match err {
            VerifyError::ExistingValue(value) => {
                Error::UnexpectedStateExistingValue(value, key.to_vec())
            }
            VerifyError::NonExistingValue(_) => {
                Error::UnexpectedStateNonExistingValue(key.to_vec())
            }
            VerifyError::DecodeError(_) => Error::UnexpectedStateDecodeError(key.to_vec()),
            VerifyError::HashDecodeError(_) => Error::UnexpectedStateHashDecodeError(key.to_vec()),
            VerifyError::HashMismatch(_) => Error::UnexpectedStateHashMismatch(key.to_vec()),
            VerifyError::ValueMismatch(_) => Error::UnexpectedStateValueMismatch(key.to_vec()),
            VerifyError::IncompleteProof => Error::UnexpectedStateIncompleteProof(key.to_vec()),
        })
    }
}

pub trait AccountResolver {
    fn get_account(
        &self,
        state_root: &Hash,
        account_proof: &[Vec<u8>],
        address: &Address,
    ) -> Result<Account, Error>;
}

struct DefaultAccountResolver;

impl AccountResolver for DefaultAccountResolver {
    fn get_account(
        &self,
        state_root: &Hash,
        account_proof: &[Vec<u8>],
        address: &Address,
    ) -> Result<Account, Error> {
        match ParliaClient::verify_proof(state_root, account_proof, address, &None) {
            Ok(_) => Err(Error::AccountNotFound(*address)),
            Err(Error::UnexpectedStateExistingValue(value, _)) => Rlp::new(&value).try_into(),
            Err(err) => Err(err),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::client_def::{AccountResolver, ParliaClient};
    use crate::misc::{
        new_ibc_height, new_ibc_timestamp, Account, Address, Hash, ValidatorReader, Validators,
    };
    use crate::path::YuiIBCPath;

    use std::prelude::rust_2015::Vec;

    use hex_literal::hex;

    use ibc::core::ics02_client::header::Header as IBCHeader;
    use ibc::core::ics23_commitment::commitment::CommitmentRoot;

    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;
    use crate::errors::Error;
    use crate::header;
    use crate::header::testdata::{create_epoch_block, create_previous_epoch_block, fill, to_rlp};

    #[test]
    fn test_get_account() {
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
        let client = ParliaClient::default();
        let v = client.0.get_account(&state_root, &account_proof, &address);
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
        if let Err(e) =
            ParliaClient::verify_proof(&storage_root, &storage_proof, &key, &Some(expected))
        {
            unreachable!("{:?}", e);
        }
    }

    #[test]
    fn test_verify_commitment_yui_ibc_mapping() {
        let storage_root = hex!("2a76cf6e2521e6a413a912d96a4220479c68283130d6cef6966f4ff1cf437a32");
        let storage_proof = to_rlp(vec![
            hex!("f8918080a0f0d0b833ffb94d6962b74e4b1d5bc5a7cceca74616832065750c00ddd9d1b329808080a0044f9d4608bdd7ff7943cee62a73ac4daeff3c495907afd494dce25436b0c534a0dd774c97b7b9a5ff4ba0073aa76d58729ece6e20211ed97ef56b8baea52df39480808080a0b19b826b59a7db662e9af57a595710163588c476f642b97df805705790dee4e680808080").to_vec(),
            hex!("f843a030ce6503f917cf7d4ecf54b344bf12226dc86adea09aeb7829c0bb8a1eae2c1aa1a03334000000000000000000000000000000000000000000000000000000000000").to_vec(),
        ]);

        let path = YuiIBCPath::from("clients/client1/clientState".as_bytes());

        let mut expected = [0_u8; 32];
        expected[0] = 51;
        expected[1] = 52;
        let client = ParliaClient::default();
        if let Err(e) = client.verify_commitment(
            &storage_root,
            &storage_proof,
            path,
            &Some(expected.to_vec()),
        ) {
            unreachable!("{:?}", e);
        }
    }

    struct MockValidatorReader {}
    impl ValidatorReader for MockValidatorReader {
        fn read(&self, height: ibc::Height) -> Result<Validators, Error> {
            let current_epoch = fill(create_epoch_block());
            let previous_epoch = fill(create_previous_epoch_block());
            if height.revision_height() == current_epoch.number {
                return Ok(current_epoch.new_validators);
            } else if height.revision_height() == previous_epoch.number {
                return Ok(previous_epoch.new_validators);
            }
            panic!("no validator {:?}", height);
        }
    }

    #[test]
    fn test_check_header_and_update_state() {
        let mainnet = header::testdata::mainnet();
        let header = header::testdata::create_after_checkpoint_headers();
        let trusting_period = 1_000_000_000;
        let now = new_ibc_timestamp(header.timestamp().nanoseconds()).unwrap();

        let ctx = MockValidatorReader {};

        let client_state = ClientState {
            chain_id: mainnet.clone(),
            ibc_store_address: hex!("a412becfedf8dccb2d56e5a88f5c1b87cc37ceef"),
            latest_height: new_ibc_height(
                header.height().revision_number(),
                header.height().revision_height() - 1,
            )
            .unwrap(),
            trust_level: Default::default(),
            trusting_period,
            frozen: false,
        };
        let trusted_consensus_state = ConsensusState {
            state_root: CommitmentRoot::from_bytes(&[0; 32]),
            timestamp: new_ibc_timestamp(header.timestamp().nanoseconds() - trusting_period)
                .unwrap(),
            validator_set: vec![],
        };

        struct MockAccountResolver;

        impl AccountResolver for MockAccountResolver {
            fn get_account(
                &self,
                _state_root: &Hash,
                _account_proof: &[Vec<u8>],
                _address: &Address,
            ) -> Result<Account, Error> {
                Ok(Account {
                    storage_root: hex!(
                        "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
                    )
                    .to_vec(),
                })
            }
        }

        let client = ParliaClient(alloc::boxed::Box::new(MockAccountResolver));
        let (new_client_state, new_consensus_state) = match client.check_header_and_update_state(
            ctx,
            now,
            &client_state,
            &trusted_consensus_state,
            &header,
        ) {
            Ok(data) => data,
            Err(e) => unreachable!("error {:?}", e),
        };
        assert_eq!(new_client_state.latest_height, header.height());
        assert_eq!(new_client_state.chain_id, mainnet);
        assert_eq!(
            new_client_state.ibc_store_address,
            client_state.ibc_store_address
        );
        assert_eq!(
            new_client_state.trusting_period,
            client_state.trusting_period
        );
        assert_eq!(new_client_state.frozen, client_state.frozen);

        assert_eq!(new_consensus_state.timestamp, header.timestamp());
        assert_eq!(
            new_consensus_state.state_root.as_bytes(),
            hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
        ); // test storage root
        assert!(new_consensus_state.validator_set.is_empty()); // not epoch block
    }
}
