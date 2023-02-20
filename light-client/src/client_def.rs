use crate::client_state::ClientState;
use crate::consensus_state::ConsensusState;
use crate::header::Header;

use alloc::vec::Vec;

use ibc::core::ics02_client::header::Header as _;

use patricia_merkle_trie::keccak;
use patricia_merkle_trie::EIP1186Layout;

use rlp::Rlp;
use trie_eip1186::{verify_proof, VerifyError};

use crate::errors::Error;
use crate::misc::{Account, Hash, ValidatorReader};

#[derive(Default, Clone, Debug)]
pub struct ParliaClient;

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
        let account = get_account(
            header.state_root(),
            header.account_proof(),
            &new_client_state.ibc_store_address,
        )?;
        let new_consensus_state = ConsensusState {
            state_root: account.storage_root.into(),
            timestamp: header.timestamp(),
            validator_set: header.validator_set().clone(),
        };

        Ok((new_client_state, new_consensus_state))
    }

    pub fn verify_proof(
        &self,
        root: &Hash,
        proof: &[u8],
        path: &[u8],
        // keccak256 hash
        expected_value: &Option<Vec<u8>>,
    ) -> Result<(), Error> {
        let proof = Rlp::new(proof).as_list().map_err(Error::RLPDecodeError)?;
        let expected_value = expected_value.as_ref().map(|e| rlp::encode(e).to_vec());
        verify_proof::<EIP1186Layout<keccak::KeccakHasher>>(
            &root.into(),
            &proof,
            path,
            expected_value.as_deref(),
        )
        .map_err(|_e| Error::UnexpectedStateRoot)
    }
}

fn get_account(state_root: &Hash, account_proof: &[u8], address: &[u8]) -> Result<Account, Error> {
    let account_proof = Rlp::new(account_proof)
        .as_list()
        .map_err(Error::RLPDecodeError)?;
    let account = match verify_proof::<EIP1186Layout<keccak::KeccakHasher>>(
        &state_root.into(),
        &account_proof,
        address,
        None,
    ) {
        Err(VerifyError::ExistingValue(value)) => value,
        _ => return Err(Error::AccountNotFound(account_proof.to_vec())),
    };
    Rlp::new(&account).try_into()
}
