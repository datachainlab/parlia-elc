use alloc::string::{String, ToString};
use alloc::vec::Vec;

use commitments::{
    gen_state_id_from_any, CommitmentPrefix, StateCommitment, StateID, UpdateClientCommitment,
};
use lcp_types::{Any, ClientId, Height};
use light_client::{
    CreateClientResult, Error as LightClientError, HostClientReader, LightClient,
    StateVerificationResult, UpdateClientResult,
};
use validation_context::ValidationParams;

use crate::client_state::ClientState;
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::path::YuiIBCPath;

#[derive(Default)]
pub struct ParliaLightClient;

impl LightClient for ParliaLightClient {
    fn client_type(&self) -> String {
        "99-parlia".to_string()
    }

    fn latest_height(
        &self,
        ctx: &dyn HostClientReader,
        client_id: &ClientId,
    ) -> Result<Height, LightClientError> {
        let any_client_state = ctx.client_state(client_id)?;
        let client_state = ClientState::try_from(any_client_state)?;
        Ok(client_state.latest_height)
    }

    fn create_client(
        &self,
        _ctx: &dyn HostClientReader,
        any_client_state: Any,
        any_consensus_state: Any,
    ) -> Result<CreateClientResult, LightClientError> {
        let new_state_id = state_id(&any_client_state, &any_consensus_state)?;
        let client_state = ClientState::try_from(any_client_state.clone())?;
        let consensus_state = ConsensusState::try_from(any_consensus_state)?;

        let height = client_state.latest_height;
        let timestamp = consensus_state.timestamp;

        Ok(CreateClientResult {
            height,
            commitment: UpdateClientCommitment {
                prev_state_id: None,
                new_state_id,
                new_state: Some(any_client_state),
                prev_height: None,
                new_height: height,
                timestamp,
                validation_params: ValidationParams::Empty,
            },
            prove: false,
        })
    }

    fn update_client(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        any_header: Any,
    ) -> Result<UpdateClientResult, LightClientError> {
        //Ensure header can be verified.
        let header = Header::try_from(any_header)?;
        let height = header.height();
        let timestamp = header.timestamp()?;
        let trusted_height = header.trusted_height();
        let any_client_state = ctx.client_state(&client_id)?;
        let any_consensus_state = ctx.consensus_state(&client_id, &trusted_height)?;
        let prev_state_id = state_id(&any_client_state, &any_consensus_state)?;

        //Ensure client is not frozen
        let client_state = ClientState::try_from(any_client_state)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id).into());
        }

        let trusted_consensus_state = ConsensusState::try_from(any_consensus_state)?;

        // Create new state and ensure header is valid
        let (new_client_state, new_consensus_state) = client_state.check_header_and_update_state(
            ctx,
            &trusted_consensus_state,
            client_id,
            header,
        )?;

        let new_height = new_client_state.latest_height;
        let new_any_client_state = Any::from(new_client_state);
        let new_any_consensus_state = Any::from(new_consensus_state);
        let new_state_id = state_id(&new_any_client_state, &new_any_consensus_state)?;

        Ok(UpdateClientResult {
            new_any_client_state,
            new_any_consensus_state,
            height,
            commitment: UpdateClientCommitment {
                prev_state_id: Some(prev_state_id),
                new_state_id,
                new_state: None,
                prev_height: Some(trusted_height),
                new_height,
                timestamp,
                validation_params: ValidationParams::Empty,
            },
            prove: true,
        })
    }

    fn verify_membership(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<StateVerificationResult, LightClientError> {
        let state_id = self.verify_commitment(
            ctx,
            client_id,
            &prefix,
            &path,
            Some(value.clone()),
            &proof_height,
            proof,
        )?;

        let value = Some(value.try_into().map_err(Error::UnexpectedCommitmentValue)?);
        Ok(StateVerificationResult {
            state_commitment: StateCommitment::new(prefix, path, value, proof_height, state_id),
        })
    }

    fn verify_non_membership(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        prefix: CommitmentPrefix,
        path: String,
        proof_height: Height,
        proof: Vec<u8>,
    ) -> Result<StateVerificationResult, LightClientError> {
        let state_id =
            self.verify_commitment(ctx, client_id, &prefix, &path, None, &proof_height, proof)?;
        Ok(StateVerificationResult {
            state_commitment: StateCommitment::new(prefix, path, None, proof_height, state_id),
        })
    }
}

impl ParliaLightClient {
    #[allow(clippy::too_many_arguments)]
    fn verify_commitment(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        _prefix: &CommitmentPrefix,
        path: &str,
        value: Option<Vec<u8>>,
        proof_height: &Height,
        storage_proof_rlp: Vec<u8>,
    ) -> Result<StateID, LightClientError> {
        let any_client_state = ctx.client_state(&client_id)?;
        let client_state = ClientState::try_from(any_client_state.clone())?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id).into());
        }
        let proof_height = *proof_height;
        if client_state.latest_height != proof_height {
            return Err(
                Error::UnexpectedLatestHeight(proof_height, client_state.latest_height).into(),
            );
        }

        let any_consensus_state = ctx.consensus_state(&client_id, &proof_height)?;
        let state_id = state_id(&any_client_state, &any_consensus_state)?;

        let consensus_state = ConsensusState::try_from(any_consensus_state)?;
        let storage_root = consensus_state.state_root;
        ClientState::verify_commitment(
            &storage_root,
            &storage_proof_rlp,
            YuiIBCPath::from(path.as_bytes()),
            &value,
        )?;

        Ok(state_id)
    }
}

fn state_id(client_state: &Any, consensus_state: &Any) -> Result<StateID, LightClientError> {
    gen_state_id_from_any(client_state, consensus_state).map_err(LightClientError::commitment)
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::str::FromStr;

    use hex_literal::hex;
    use lcp_types::{Any, ClientId, Height, Time};
    use light_client::{ClientReader, HostClientReader, HostContext, LightClient};

    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Fraction;

    use crate::client::ParliaLightClient;
    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;
    use crate::header::testdata::{
        create_after_checkpoint_headers, create_epoch_block, create_previous_epoch_block, fill,
        to_rlp,
    };
    use crate::misc::{new_height, new_timestamp, ChainId, Hash};

    struct MockClientReader;

    impl HostContext for MockClientReader {
        fn host_timestamp(&self) -> Time {
            create_after_checkpoint_headers().timestamp().unwrap()
        }
    }

    impl store::KVStore for MockClientReader {
        fn set(&mut self, _key: Vec<u8>, _value: Vec<u8>) {
            todo!()
        }

        fn get(&self, _key: &[u8]) -> Option<Vec<u8>> {
            todo!()
        }

        fn remove(&mut self, _key: &[u8]) {
            todo!()
        }
    }

    impl HostClientReader for MockClientReader {}

    impl ClientReader for MockClientReader {
        fn client_state(&self, client_id: &ClientId) -> Result<Any, light_client::Error> {
            let mainnet = ChainId::new(56);
            let cs = if client_id.as_str() == "99-parlia-0" {
                ClientState {
                    chain_id: mainnet,
                    ibc_store_address: hex!("a412becfedf8dccb2d56e5a88f5c1b87cc37ceef"),
                    latest_height: Height::new(1, 2),
                    trust_level: Fraction {
                        numerator: 1,
                        denominator: 3,
                    },
                    trusting_period: core::time::Duration::new(1, 0),
                    frozen: false,
                }
            } else {
                ClientState {
                    chain_id: mainnet,
                    ibc_store_address: hex!("a412becfedf8dccb2d56e5a88f5c1b87cc37ceef"),
                    latest_height: Height::new(1, 1),
                    trust_level: Fraction {
                        numerator: 1,
                        denominator: 3,
                    },
                    trusting_period: core::time::Duration::new(1, 0),
                    frozen: false,
                }
            };
            Ok(Any::from(cs))
        }

        fn consensus_state(
            &self,
            _client_id: &ClientId,
            height: &Height,
        ) -> Result<Any, light_client::Error> {
            let current_epoch = fill(create_epoch_block());
            let previous_epoch = fill(create_previous_epoch_block());
            if height.revision_height() == 1 {
                Ok(Any::from(ConsensusState {
                    state_root: [0_u8; 32],
                    timestamp: self.host_timestamp(),
                    validator_set: vec![],
                }))
            } else if height.revision_height() == 2 {
                Ok(Any::from(ConsensusState {
                    state_root: hex!(
                        "c7c2351e84411a86c7165856578a0668fddfe77e30d63965184af89dfb192f18"
                    ) as Hash,
                    timestamp: self.host_timestamp(),
                    validator_set: vec![],
                }))
            } else if height.revision_height() == current_epoch.number {
                Ok(Any::from(ConsensusState {
                    state_root: current_epoch.root,
                    timestamp: new_timestamp(current_epoch.timestamp).unwrap(),
                    validator_set: current_epoch.new_validators,
                }))
            } else if height.revision_height() == previous_epoch.number {
                Ok(Any::from(ConsensusState {
                    state_root: previous_epoch.root,
                    timestamp: new_timestamp(previous_epoch.timestamp).unwrap(),
                    validator_set: previous_epoch.new_validators,
                }))
            } else {
                panic!("no consensus state found {:?}", height);
            }
        }
    }

    #[test]
    fn test_create_client() {
        let client = ParliaLightClient::default();
        let ctx = MockClientReader {};

        let mainnet = ChainId::new(56);
        let client_state = ClientState {
            chain_id: mainnet.clone(),
            ibc_store_address: [0; 20],
            latest_height: new_height(mainnet.version(), 1),
            trust_level: Fraction {
                numerator: 1,
                denominator: 3,
            },
            trusting_period: core::time::Duration::new(0, 0),
            frozen: false,
        };
        let consensus_state = ConsensusState {
            state_root: [0_u8; 32],
            timestamp: new_timestamp(1677130449).unwrap(),
            validator_set: vec![],
        };
        let any_client_state = Any::from(client_state.clone());
        let any_consensus_state = Any::from(consensus_state.clone());
        match client.create_client(&ctx, any_client_state.clone(), any_consensus_state) {
            Ok(result) => {
                assert_eq!(result.height, client_state.latest_height);
                assert_eq!(result.commitment.timestamp, consensus_state.timestamp);
                assert_eq!(result.commitment.prev_height, None);
                assert_eq!(result.commitment.prev_state_id, None);
                assert_eq!(result.commitment.new_height, client_state.latest_height);
                assert_eq!(result.commitment.new_state.unwrap(), any_client_state);
                assert!(!result.commitment.new_state_id.to_vec().is_empty());
            }
            Err(e) => unreachable!("{:?}", e),
        }
    }

    #[test]
    fn test_update_client() {
        let ctx = MockClientReader;
        let client = ParliaLightClient::default();

        let header = create_after_checkpoint_headers();
        match client.update_client(
            &ctx,
            ClientId::new("99-parlia", 0).unwrap(),
            Any::from(header.clone()),
        ) {
            Ok(data) => {
                let new_client_state = ClientState::try_from(data.new_any_client_state).unwrap();
                let new_consensus_state =
                    ConsensusState::try_from(data.new_any_consensus_state).unwrap();
                assert_eq!(data.height, header.height());
                assert_eq!(new_client_state.latest_height, header.height());
                assert_eq!(
                    new_consensus_state.state_root,
                    hex!("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")
                );
                assert_eq!(new_consensus_state.timestamp, header.timestamp().unwrap());
                assert!(new_consensus_state.validator_set.is_empty());
                assert_eq!(data.commitment.new_height, header.height());
                assert_eq!(data.commitment.new_state, None);
                assert!(!data.commitment.new_state_id.to_vec().is_empty());
                assert_eq!(data.commitment.prev_height, Some(new_height(1, 1)));
                assert!(data.commitment.prev_state_id.is_some());
                assert_eq!(data.commitment.timestamp, header.timestamp().unwrap());
            }
            Err(e) => unreachable!("error {:?}", e),
        };
    }

    #[test]
    fn test_verify_commitment() {
        let ctx = MockClientReader;
        let client = ParliaLightClient::default();
        let prefix = vec![0];
        let path = "commitments/ports/port-1/channels/channel-1/sequences/1";
        let proof_height = new_height(1, 2);
        let client_id = ClientId::from_str("99-parlia-0").unwrap();
        let mut expected = [0_u8; 32];
        expected[0] = 51;
        expected[1] = 52;
        let storage_proof_rlp = to_rlp(vec![
            hex!("f8918080a048477c6f9a27dd3b09ba3140d73536c56f2d038c2d1f0156450b5cdd75fec740808080a0044f9d4608bdd7ff7943cee62a73ac4daeff3c495907afd494dce25436b0c534a0dd774c97b7b9a5ff4ba0073aa76d58729ece6e20211ed97ef56b8baea52df394808080808080a0f8cf7dfa7a8c74ff54bf6717a6520081d72e7ec9076a9bacb263be17cf24cfdd8080").to_vec(),
            hex!("f843a030e8c8f21e1b1f55c0464131968b01fa0a534609e5ca17ab6d3dfae0fcbe0fcaa1a03334000000000000000000000000000000000000000000000000000000000000").to_vec()
        ]);

        match client.verify_membership(
            &ctx,
            client_id.clone(),
            prefix.clone(),
            path.to_string(),
            expected.to_vec(),
            proof_height,
            storage_proof_rlp.to_vec(),
        ) {
            Ok(data) => {
                assert_eq!(data.state_commitment.path, path);
                assert_eq!(data.state_commitment.height, proof_height);
                assert_eq!(data.state_commitment.value, Some(expected));
            }
            Err(e) => unreachable!("error {:?}", e),
        };

        let path = "commitments/ports/port-1/channels/channel-1/sequences/2";
        match client.verify_non_membership(
            &ctx,
            client_id,
            prefix,
            path.to_string(),
            proof_height,
            storage_proof_rlp.to_vec(),
        ) {
            Ok(data) => {
                assert_eq!(data.state_commitment.path, path.to_string());
                assert_eq!(data.state_commitment.height, proof_height);
                assert_eq!(data.state_commitment.value, None);
            }
            Err(e) => unreachable!("error {:?}", e),
        };
    }
}
