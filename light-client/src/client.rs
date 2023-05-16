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
    use crate::header::Header;
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
            let cs = if client_id.as_str() == "99-parlia-0" {
                let mainnet = ChainId::new(56);
                ClientState {
                    chain_id: mainnet,
                    ibc_store_address: hex!("a412becfedf8dccb2d56e5a88f5c1b87cc37ceef"),
                    latest_height: Height::new(0, 2),
                    trust_level: Fraction {
                        numerator: 1,
                        denominator: 3,
                    },
                    trusting_period: core::time::Duration::new(1, 0),
                    frozen: false,
                }
            } else if client_id.as_str() == "99-parlia-1" {
                let relayernet = ChainId::new(9999);
                ClientState {
                    chain_id: relayernet,
                    ibc_store_address: hex!("702E40245797c5a2108A566b3CE2Bf14Bc6aF841"),
                    latest_height: Height::new(0, 400),
                    trust_level: Fraction {
                        numerator: 1,
                        denominator: 3,
                    },
                    trusting_period: core::time::Duration::new(86400 * 365 * 100, 0),
                    frozen: false,
                }
            } else {
                let mainnet = ChainId::new(56);
                ClientState {
                    chain_id: mainnet,
                    ibc_store_address: hex!("a412becfedf8dccb2d56e5a88f5c1b87cc37ceef"),
                    latest_height: Height::new(0, 1),
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
            client_id: &ClientId,
            height: &Height,
        ) -> Result<Any, light_client::Error> {
            // relayer testing consensus
            if client_id.as_str() == "99-parlia-1" {
                return Ok(Any::from(ConsensusState {
                    state_root: [0_u8; 32],
                    timestamp: self.host_timestamp(),
                    validator_set: vec![vec![
                        185, 13, 158, 11, 243, 253, 38, 122, 99, 113, 215, 108, 127, 137, 33, 136,
                        133, 3, 78, 91,
                    ]],
                }));
            }

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
        let _ctx = MockClientReader;
        let _client = ParliaLightClient::default();

        let relayer_protobuf_any = vec![
            10, 34, 47, 105, 98, 99, 46, 108, 105, 103, 104, 116, 99, 108, 105, 101, 110, 116, 115,
            46, 112, 97, 114, 108, 105, 97, 46, 118, 49, 46, 72, 101, 97, 100, 101, 114, 18, 194,
            10, 10, 226, 4, 10, 223, 4, 249, 2, 92, 160, 69, 100, 96, 9, 92, 91, 89, 93, 187, 132,
            246, 219, 247, 124, 227, 36, 0, 222, 245, 154, 49, 120, 234, 101, 57, 43, 249, 232,
            182, 251, 56, 30, 160, 29, 204, 77, 232, 222, 199, 93, 122, 171, 133, 181, 103, 182,
            204, 212, 26, 211, 18, 69, 27, 148, 138, 116, 19, 240, 161, 66, 253, 64, 212, 147, 71,
            148, 185, 13, 158, 11, 243, 253, 38, 122, 99, 113, 215, 108, 127, 137, 33, 136, 133, 3,
            78, 91, 160, 53, 254, 1, 149, 186, 50, 45, 115, 33, 111, 249, 239, 165, 149, 218, 15,
            30, 202, 122, 191, 57, 244, 168, 165, 62, 122, 30, 97, 130, 35, 91, 199, 160, 226, 125,
            160, 123, 89, 247, 25, 77, 251, 173, 80, 120, 56, 225, 176, 172, 84, 142, 61, 210, 221,
            195, 234, 127, 254, 181, 114, 22, 246, 146, 228, 243, 160, 75, 92, 11, 44, 186, 22,
            182, 153, 53, 239, 43, 54, 128, 125, 169, 101, 143, 214, 39, 209, 234, 158, 155, 166,
            19, 98, 25, 142, 126, 240, 148, 18, 185, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 32, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8,
            0, 32, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0,
            0, 0, 0, 0, 128, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 16, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1,
            0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 130, 2, 56, 132, 2, 98, 90, 0,
            131, 3, 34, 223, 132, 100, 59, 250, 254, 184, 97, 217, 131, 1, 1, 17, 132, 103, 101,
            116, 104, 137, 103, 111, 49, 46, 49, 54, 46, 49, 53, 133, 108, 105, 110, 117, 120, 0,
            0, 235, 106, 105, 84, 93, 26, 127, 169, 99, 107, 68, 254, 2, 191, 224, 176, 197, 237,
            117, 170, 57, 81, 200, 25, 247, 223, 143, 139, 245, 232, 186, 72, 105, 167, 246, 170,
            95, 225, 0, 80, 237, 12, 226, 3, 127, 54, 118, 76, 10, 44, 64, 131, 205, 172, 178, 215,
            111, 68, 177, 31, 139, 52, 201, 91, 173, 191, 1, 22, 1, 160, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 136, 0, 0, 0, 0,
            0, 0, 0, 0, 18, 3, 16, 174, 4, 26, 213, 5, 249, 2, 210, 249, 1, 209, 160, 234, 94, 56,
            76, 134, 99, 255, 52, 250, 39, 110, 79, 213, 196, 63, 252, 87, 87, 191, 209, 108, 114,
            60, 116, 114, 167, 185, 107, 234, 118, 254, 127, 160, 63, 12, 120, 108, 119, 49, 18,
            186, 151, 172, 24, 100, 44, 104, 26, 156, 82, 40, 195, 31, 103, 188, 120, 25, 139, 146,
            231, 95, 31, 142, 45, 241, 160, 71, 142, 109, 238, 82, 173, 122, 207, 36, 235, 38, 111,
            220, 44, 63, 33, 254, 113, 82, 62, 125, 175, 12, 144, 185, 196, 122, 173, 6, 105, 74,
            151, 128, 128, 160, 206, 87, 79, 196, 82, 184, 227, 84, 49, 145, 64, 103, 88, 216, 241,
            71, 68, 241, 195, 35, 152, 130, 255, 54, 222, 101, 195, 17, 163, 16, 50, 200, 160, 34,
            121, 223, 210, 81, 223, 193, 186, 226, 245, 65, 101, 70, 237, 45, 189, 176, 64, 164,
            146, 237, 218, 202, 64, 233, 109, 189, 120, 191, 68, 187, 127, 160, 153, 234, 95, 3,
            51, 102, 120, 221, 98, 76, 218, 77, 174, 75, 209, 78, 250, 255, 158, 66, 80, 103, 8,
            213, 183, 21, 245, 169, 39, 128, 202, 247, 160, 114, 125, 214, 218, 65, 47, 178, 193,
            225, 188, 43, 190, 217, 23, 213, 2, 22, 75, 30, 35, 132, 91, 236, 79, 178, 179, 137,
            20, 123, 32, 61, 0, 160, 95, 73, 61, 178, 46, 40, 102, 248, 32, 30, 37, 113, 195, 33,
            213, 203, 198, 144, 34, 17, 158, 186, 213, 150, 250, 10, 147, 60, 246, 84, 75, 69, 160,
            60, 164, 238, 4, 7, 155, 92, 84, 227, 96, 140, 72, 98, 105, 21, 124, 214, 49, 174, 123,
            123, 38, 104, 137, 173, 103, 2, 49, 177, 28, 48, 73, 160, 16, 17, 192, 82, 68, 23, 128,
            202, 112, 180, 106, 27, 138, 255, 190, 140, 214, 184, 166, 80, 247, 240, 99, 243, 148,
            58, 82, 71, 66, 208, 180, 104, 160, 121, 103, 48, 212, 18, 179, 73, 203, 93, 238, 118,
            194, 174, 148, 197, 104, 183, 215, 38, 127, 124, 97, 241, 103, 124, 161, 177, 127, 120,
            117, 71, 132, 160, 156, 33, 165, 11, 32, 99, 121, 237, 43, 145, 33, 241, 68, 122, 173,
            129, 64, 60, 17, 225, 68, 77, 52, 245, 181, 45, 152, 86, 229, 215, 200, 25, 160, 74,
            179, 210, 254, 22, 132, 148, 110, 25, 40, 122, 144, 182, 161, 108, 66, 170, 37, 139,
            252, 61, 133, 254, 204, 46, 6, 201, 18, 53, 73, 140, 43, 160, 51, 242, 214, 174, 87,
            203, 149, 192, 94, 81, 234, 124, 59, 89, 69, 65, 123, 4, 240, 243, 147, 53, 101, 87,
            85, 102, 224, 37, 153, 136, 150, 224, 128, 248, 145, 128, 128, 128, 128, 128, 128, 128,
            128, 160, 98, 83, 21, 101, 201, 254, 118, 167, 28, 161, 113, 154, 235, 159, 83, 123,
            61, 223, 8, 45, 193, 103, 196, 255, 165, 123, 60, 184, 233, 80, 202, 32, 128, 160, 154,
            8, 32, 167, 207, 15, 23, 56, 149, 151, 168, 151, 115, 139, 202, 159, 32, 182, 72, 58,
            51, 132, 47, 117, 150, 210, 123, 210, 191, 146, 28, 247, 128, 160, 226, 236, 91, 250,
            8, 116, 215, 78, 192, 253, 255, 192, 118, 2, 218, 180, 90, 165, 164, 38, 237, 140, 229,
            195, 241, 28, 149, 126, 245, 204, 236, 202, 160, 99, 187, 218, 1, 124, 204, 165, 156,
            9, 241, 27, 239, 206, 74, 131, 38, 90, 162, 66, 45, 129, 130, 48, 195, 211, 123, 108,
            239, 185, 0, 143, 66, 128, 128, 128, 248, 105, 160, 32, 156, 194, 102, 146, 39, 197,
            99, 147, 155, 61, 178, 16, 154, 96, 128, 30, 226, 115, 245, 13, 234, 105, 41, 210, 100,
            111, 172, 183, 10, 210, 52, 184, 70, 248, 68, 1, 128, 160, 13, 251, 204, 9, 214, 82,
            129, 250, 68, 158, 58, 129, 153, 171, 216, 252, 227, 134, 245, 37, 63, 130, 102, 124,
            23, 248, 15, 57, 39, 229, 249, 246, 160, 6, 21, 236, 38, 131, 128, 77, 181, 83, 7, 54,
            3, 200, 108, 196, 158, 131, 214, 45, 104, 205, 52, 149, 193, 212, 94, 70, 76, 69, 28,
            250, 253,
        ];
        let any: Any = relayer_protobuf_any.try_into().unwrap();
        let ctx = MockClientReader;
        let client = ParliaLightClient::default();
        let header = Header::try_from(any.clone()).unwrap();

        match client.update_client(&ctx, ClientId::new(&client.client_type(), 1).unwrap(), any) {
            Ok(data) => {
                let new_client_state = ClientState::try_from(data.new_any_client_state).unwrap();
                let new_consensus_state =
                    ConsensusState::try_from(data.new_any_consensus_state).unwrap();
                assert_eq!(data.height, header.height());
                assert_eq!(new_client_state.latest_height, header.height());
                assert_eq!(
                    new_consensus_state.state_root,
                    [
                        13, 251, 204, 9, 214, 82, 129, 250, 68, 158, 58, 129, 153, 171, 216, 252,
                        227, 134, 245, 37, 63, 130, 102, 124, 23, 248, 15, 57, 39, 229, 249, 246
                    ],
                );
                assert_eq!(new_consensus_state.timestamp, header.timestamp().unwrap());
                assert!(new_consensus_state.validator_set.is_empty());
                assert_eq!(data.commitment.new_height, header.height());
                assert_eq!(data.commitment.new_state, None);
                assert!(!data.commitment.new_state_id.to_vec().is_empty());
                assert_eq!(
                    data.commitment.prev_height,
                    Some(new_height(0, header.trusted_height().revision_height()))
                );
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
        let proof_height = new_height(0, 2);
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
