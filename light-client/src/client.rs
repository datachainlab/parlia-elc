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
use patricia_merkle_trie::keccak::keccak_256;
use validation_context::ValidationParams;

use crate::client_state::ClientState;
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;
use crate::proof::{calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof, verify_proof};

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
        let client_state = ClientState::try_from(any_client_state.clone())?;
        let consensus_state = ConsensusState::try_from(any_consensus_state)?;

        let new_state_id = gen_state_id(client_state.clone(), consensus_state.clone())?;

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

        let prev_state_id = gen_state_id(client_state, trusted_consensus_state)?;
        let new_state_id = gen_state_id(new_client_state.clone(), new_consensus_state.clone())?;

        Ok(UpdateClientResult {
            new_any_client_state: new_client_state.into(),
            new_any_consensus_state: new_consensus_state.into(),
            height,
            commitment: UpdateClientCommitment {
                prev_state_id: Some(prev_state_id),
                new_state_id,
                new_state: None,
                prev_height: Some(trusted_height),
                new_height: height,
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
        let value = keccak_256(&value);
        let state_id = self.verify_commitment(
            ctx,
            client_id,
            &prefix,
            &path,
            Some(value.to_vec()),
            &proof_height,
            proof,
        )?;

        Ok(StateVerificationResult {
            state_commitment: StateCommitment::new(
                prefix,
                path,
                Some(value),
                proof_height,
                state_id,
            ),
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
        let client_state = ClientState::try_from(ctx.client_state(&client_id)?)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id).into());
        }
        let proof_height = *proof_height;
        if client_state.latest_height != proof_height {
            return Err(
                Error::UnexpectedLatestHeight(proof_height, client_state.latest_height).into(),
            );
        }

        let consensus_state =
            ConsensusState::try_from(ctx.consensus_state(&client_id, &proof_height)?)?;
        let storage_root = consensus_state.state_root;
        let storage_proof = decode_eip1184_rlp_proof(&storage_proof_rlp)?;
        verify_proof(
            &storage_root,
            &storage_proof,
            calculate_ibc_commitment_storage_key(path).as_slice(),
            &value,
        )?;

        gen_state_id(client_state, consensus_state)
    }
}

fn gen_state_id(
    client_state: ClientState,
    consensus_state: ConsensusState,
) -> Result<StateID, LightClientError> {
    let client_state = Any::from(client_state.canonicalize());
    let consensus_state = Any::from(consensus_state.canonicalize());
    gen_state_id_from_any(&client_state, &consensus_state).map_err(LightClientError::commitment)
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use hex_literal::hex;
    use lcp_types::{Any, ClientId, Height, Time};
    use light_client::{ClientReader, HostClientReader, HostContext, LightClient};
    use patricia_merkle_trie::keccak::keccak_256;

    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Fraction;

    use crate::client::ParliaLightClient;
    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;

    use crate::header::Header;
    use crate::misc::{new_height, new_timestamp, ChainId};

    impl Default for ClientState {
        fn default() -> Self {
            ClientState {
                chain_id: ChainId::new(9999),
                ibc_store_address: [0; 20],
                trust_level: Fraction {
                    numerator: 1,
                    denominator: 3,
                },
                trusting_period: core::time::Duration::new(86400 * 365 * 100, 0),
                latest_height: Default::default(),
                frozen: false,
            }
        }
    }

    impl Default for ConsensusState {
        fn default() -> Self {
            ConsensusState {
                state_root: [0_u8; 32],
                timestamp: new_timestamp(1677130449).unwrap(),
                validator_set: vec![],
            }
        }
    }

    struct MockClientReader {
        client_state: Option<ClientState>,
        consensus_state: Option<ConsensusState>,
    }

    impl HostContext for MockClientReader {
        fn host_timestamp(&self) -> Time {
            new_timestamp(1677130449).unwrap()
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
        fn client_state(&self, _client_id: &ClientId) -> Result<Any, light_client::Error> {
            Ok(Any::from(self.client_state.clone().unwrap()))
        }

        fn consensus_state(
            &self,
            _client_id: &ClientId,
            _height: &Height,
        ) -> Result<Any, light_client::Error> {
            Ok(Any::from(self.consensus_state.clone().unwrap()))
        }
    }

    #[test]
    fn test_create_client() {
        let client = ParliaLightClient::default();
        let chain_id = ChainId::new(56);
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: None,
        };

        let client_state = ClientState {
            chain_id: chain_id.clone(),
            latest_height: new_height(chain_id.version(), 1),
            ..Default::default()
        };
        let consensus_state = ConsensusState::default();
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
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                ibc_store_address: hex!("702E40245797c5a2108A566b3CE2Bf14Bc6aF841"),
                latest_height: Height::new(0, 400),
                ..Default::default()
            }),
            consensus_state: Some(ConsensusState {
                validator_set: vec![vec![
                    185, 13, 158, 11, 243, 253, 38, 122, 99, 113, 215, 108, 127, 137, 33, 136, 133,
                    3, 78, 91,
                ]],
                ..Default::default()
            }),
        };
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
    fn test_update_client_with_mainnet() {
        // height = 27739354
        let mainnet_header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e486561646572128e520ae4040ae104f9025ea00c42d235a0c52bab022142c06743029426748172a0404aeb311850bc3b5b71b1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b4dd66d7c2c7e57f628210187192fb89d4b99dd4a08446967bd2a00c0282b0baceed18a8c469f5a10ca9ac807a5fd7dfacab2fac8da08b64ab1021af53826b6684a99130169b83cee42c275cdee28e1a5900649e550aa07d1eb9dcda27d768ed6dcfb7ecb4069785df0a8cc06cbc272fc48a75e574a7d0b901000220f2688010271ae01809419404803ac18642502886041720da4c2b82c83810b0884f224100044360600108185a02270b12101080006a40c042048500f826816560c9130b4088409142215f120102383e9440000812c102a14dc511988007200405012707072d0d144a71e04e008c2e1c0701740009700c0274c05179014500500a0325a0a08384f080184b06cc4bb9b0349d85680e4e39140080c254020630a2100950400a834460260254b3080dc0d02d4040040e2052020200e9d0291014a16910e600000d2b1a00800b6004f0a02038c8c641086050451ddc02223ab09b9090800852c2ac222135cdc0c9e0010bd10420310551485f1f60ac4ad8091b52028401a744da84083f4315838936ec84644b913eb861d883010115846765746888676f312e31392e37856c696e7578000000f98d107223d74627e42fd5350f0a8e25adbbbbd1bd60927be65a23d7f9164025a9ec3f1a1494e0c76e41e91665d59664d4c1cc91ed5f842c0a870871f1a8fc62c98c212801a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea031fcc6c83e326519b2f790df9cc7195786802b0566de7ffa55f35d044505e9bea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794be807dddb074639cd9fa61b47676c064fc50d62ca0c562b40142d4e41e38b982e38bc12aa3b59f74c9e83baafaac6a8e2972977c3ea0fe2791b7694bd7d3bf9e0c30d59f21904662fa6b3c4b8289e504a0faaaf7ba53a0d1dea762e04c9f8511042da6191207010074b02b5dfd6d2772d0bafd7a1f6120b9010049b9a64976543f566818b1f3b01c4c068a464e601580afaad3f30c90a642ccb6c68ad5d746c1b062c33190311a564038df1198d134fabb9bf9684929a8240cb8ced484374171492ac53b344b262007abf016a0a523cdef05e49c0c21d46009007a7ed8361f03034cb55f3aea948aca5bcfa8da77c28d66400c240a139f49b72094507d36401b58ce8ddb3c56c609dee521bc05a53f241bd9b185c040af00d8a22613a6115c259ac396466d4e1f0e0511563d442b04a4d141813963e3409232e9ad339486868c4b36949257dd42a611a1f04123e282e084396512050e2d38f547b030ae0e7281d28d071d3718c1348820cc4607264f48c959862131eba2dd8151028401a744db840847825783bf7f3184644b9141b861d883010117846765746888676f312e31392e38856c696e7578000000f98d1072a7a7ad0ffd7f06d30f7e2813420679e3b2070b8602ac5b7fcccb255f8bf9b90b4c780ca641ced6c2aff656f212d5961c8c7c05327dacce9fbb9baa1f332a185e00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa0b0b503834b6c74d5319183cb4e1d6969d6f2801c0bbe3b8c05e10a5de6514a1fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d1d6bf74282782b0b3eb1413c901d6ecf02e8e28a014eb79ebfc802246dda854721311c349b66fd9faba0307c43e12f787f83857e9a032359b2a557b3f66639029d514d06318ababad950eca0117613de1f278cd63caa0361716021c2037f7776b84370c5417618733d2cee7c8efa337d617683664e65ab90100bfbffffbac097d77ffafe3e49fec6feb3757ff5ffdbfafe9feffb37fdb35bf3b9ffbfefcf7db7dfa6ff7f3fb51bf78afff19bfbdf3bbfffefffdffffdfeeffffff5bffd7d37f6fb7fffffe7fff777bbafef9ff7bea5effb6fdf7d7e3d7baffc9db95cb2f3fffbb7f379bf3f7fdfbdf6fefdfefeffddbf7eff4ef6dbffa5bfffffefe6d9f8fafbe7f96fff7ef5fdebffb14ffce37ff13ffff6fefe7efffedf77f6ff7dd76efffb3397edeffffaf7fede97ef7fcbfe3ff3f3d7b73f6fb57a677eff9ef76ffff7b8de7ddcf348deb6f7fbbf99aff64edffa97befa76e5f3f3ff9fff6fdebecfdf1eb6f7b3dfeffedaffc7dfd7fffeff6fa7efb99777bfc7f4fadb9028401a744dc84083f3ad68402fdbadd84644b9144b861d883010115846765746888676f312e32302e31856c696e7578000000f98d1072b703ad0938b3b7b99fe4a2747897ed98ebb0d71fb7eb0ca5487f335d4e3ae29460be61c92c67039a071b5c88d643f7398358c1a2510bad7add2730f0a89030ce01a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea026485ea130e1fa7bc4cfca74d72eba6e1cf289a46aae3ebd38c066170a2b2d13a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d93dbfb27e027f5e9e6da52b9e1c413ce35adc11a09d3eaf106fb0d72f904ce861feeaa6481d3b60f9e9f9a4242387a9800e74cb93a018371b9d166ad9b5a5af7e99918dc84ae6b3213d49400886d0eb45f0d2b715bda0e1b8dc9757389cd8680ff69d665fdca643121434ec2d96de8e5d13c51940c964b901005560c7cc812414594108640b9200176e2654df8026e96468623240d3b4080538e60f0446458c1469a3903eee161e4243480198519418a20877b8d00c80b424024640449049c0882a817f502c4031262e23b420a1524759576634048b80083100200c422be2d7841b4ec3f093040089590e08846f010d44a002668c10fc0becc2b183f904840b15e5808c3cc116080a00503c95d57d280468013084c1add2066222901006648bab00ae0a4fe4d31ac8d02026891a604881654115a97570cb227df100349ed24d099e58a0090821865868a0f4da7639e80419c543dc024018e3b752f0a121a1042356095173a265220a09ca102428419c584980262ba41a990447028401a744dd8408477a0f838c374e84644b9147b861d883010115846765746888676f312e31382e32856c696e7578000000f98d107264d34b421c6a895b7c9559e62eb459dd437871aec6dfe06de6af54909d833111475faab43c089ff2232048ae443d6e037de063ec5eaaef58aec65db3ff9b15a601a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0bff7187ba5c364423e092e142cc3e38b34e55d08ba0e582f35dc458bd6eb5b34a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a011cf2e950b938f4cd41dba032dbf24ef559fcd6ced29e64305b789476b161527a01475a1917aa6263432d4df857ab26b6250e9a01e2acee3c6c8e90c0dcc978707a04829c0e1611973d4f6df694ca1ded18f524e1cd033ccd9ddd9e31be249cc0b7db90100832086d60dd8b6784c3b62489330140ac45a66cc0f5a16c3321a1c1b59208055ad110ccde04480a30381522d411e410a1fa2a154968571d9d062a44c27aebe8ac642a8462d548adbc1256ace61c803be6afa068691c746123454067a9401921cd89d0d6ec39e16b9e45d18d83ce088a849088365cb6b4c448a4428978a45a5631d82031c4dfdd953908874461e347cf4dc3686e16c5a5ebb61b652c04e584e33eed7b41359fd9350eb0e07fe53baced1d8be122a448d87d912a4a965d593421db5cd5ea6146849f395f4c4a544505330f596af63a135a059c751d7e6057fa4acf690871b3cd6c679033d29ac49824d835e3e9b2b4810e04c0f46478fdef75c50028401a744de84084fc18883ba5f5384644b914ab861d883010117846765746888676f312e31392e38856c696e7578000000f98d1072a40bb76fa0f34be846251c448b4ba062d70866bf3919f5c9b1c612ee7633e9635ab75a06873b10b84c811d1adff15c5264e7b3f041c651049a034dab89c89ede00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0e627710f8acacecf574b906c2d3e0b74721401d20c77c41e25d3829d32448414a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e9ae3261a475a27bb1028f140bc2a7c843318afda01403f6e763c0d1e8705872fc791c4c94c52a52e2f54cee28385c17de30b241c0a022c7e7465875b0c6ae90fdc40c96cb35890e1b0e7f579cd76cb18b7ab792c717a03f05f36320b52a0ac95ba2dee0a6a89bfc4a994d58774e567660c94cb4b260a2b9010000269ade1e8a041c400cf00dd82498b29014f2820c92840b643223033f32091d837a551348805082530010a2301a0b62452790b08bab66984450648e9436268b5465f402094048520512889900a0302f7c1846ae43f65882a04414128013b886c00e946a9e0b050954d470812f12088b9acc8065888b459541244211dd812a81206e3b860d551150d082514702194bf0d43d0d85fdf22029b91544c10793283b831984545402a3b8e3828366b71f8502142b05a910a00381402102e850d34a46b1001386a0c11b82144d4c0908f2332e217cb2e6356807d18d4375ce0338e09d50f9886003d07d00312557a6e15282207100452a0904424919642e0a1c31085a028401a744df840858114883a46ef984644b914db861d883010115846765746888676f312e31392e37856c696e7578000000f98d107235246ea29c256e3652e08a0bf7c618a58d4abc3a935f6613576da1d5db4b676d688f16221b1b16289aa0c4a9d61e0a35c9b65baadbcdca8c7918f8a968f1b9a800a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0b8cccab592a91b53757835d97fde766fb8558557fa9c863cfcc3605a65d6de09a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea0a6e3c511bbd10f4519ece37dc24887e11b55da04f112eefe36a58eaa98f90435d51824fd811bb2702fae67d8349ea6e1510f155a011be8262569d21cb179da2dca4eb847e797e696e88f1b9ad9e79d6daeb0c607aa0743aa0d7d5bc70322d7283db961113af2f1e2a803bd1126b9daa9b1178afa797b90100c1e63e0fb21c01b87e6c7a44d89a45a465b84eee0131a64ae3941737bcca8dd5ea928c8a4c879963a3615baae6b69ac8218bd43cc4085a7865c8343a503aa4a98cc0ff380b5b0962fdf3085821186a3e3c5b1938a2c63c12e0a6ec55b4d478134ab73367deca3da0fccf2284040188cb2f43da639158479f0c371a50993529e2fdcb7761669c30448c991e8e0a84ddd4f0b61dd55d32de1971b1496adca15be902bb3555d1368b753e9e5efec72e8c826b3641b320e6162153410861e1693ac0a30581c248a0e34e5d944e83b692325163ab862781d4c95f055f3dfe873aa6d759b8cd54b401cf022d4519c8dd038b7158d6851cc15ac86d1d0d976bac9d90d8028401a744e08408583b0083e9b14b84644b9150b861d883010117846765746888676f312e31392e38856c696e7578000000f98d10720b05dfe25b64b67c46448b28ae568f64d8a861379681e74fbb2b320e9730bb7e452bd35ba5680c056ad0f65c22c55dbb8702d910dec2b5256f885b3792d6961c01a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0dfe2db6a3bd0c3a25341a37bcfa83410143620a4f0bc47eb85aaedf5cd556ba4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ef0274e31810c9df02f98fafde0f841f4e66a1cda08de5fe0a044160119826a0ebb086005140f15d8958dc217975ad0d3aac2adf16a0f572ba225ca273bf839c729b84b98b0749767f884ac5c3c379a1111eb3a4f824a0fe16ec5967bb4d9b961920da9853329f79a516e8accf8bab4ccef2e3c0b9b005b9010065208e248632149d040b600090c090a925852c4b4be1e4b619d6adafda452da2ca22151a52473e034e4004395e52bc432102d418a5994b8246ccf4055e2566115604c42459ce3090c1653c9cc841862e3896a8668e539d6aaa54244096572d710455d5763b0f050922d9cea1640ad82d3d0198e507d844883b74a376bd07041a9813a9458c466184498c14018e0e3fb5903e245d399c0bba7d34a86185aa3970dfd083140885194060d226cd07a14440102f4711b629232b0d008170832a3061a3c3cca64ca741e37d422475454259102357eb8c85ade8718d11de8e9e58a681529c841ba01b3c48430db380e75f48213020843a48584e618d842ec0c0130564028401a744e18408583b0083ae965184644b9153b861d883010115846765746888676f312e31382e32856c696e7578000000f98d107200f949d291708ea299b3d49f4d8eb50c5c2c90af7cbbde1ec279b44c0bcf02f0137815c04dcbd506d7e39f2365fdae620d81430952c204ffb3bb8e54a886888600a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa09ef4c35acd8cb703bedc461c3128bccb67247a8e8fd497fbb228239e02582fcba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940bac492386862ad3df4b666bc096b0505bb694daa00b16c7d329039455f03b00f48f040096abc7f1c7a79876545e7ed80fe0340d01a0a11ef1c33dbbf08cb9af1917abdb8d99f077d2ba429a87c587b63c7f72ffbac2a02ba78a7fa92da7d4deb31e549976f970f494106874412ab3c7e60e9360c75c10b90100eef4feefffbfbe7eeffcbb74fbffffa3fbdffefbffbf76a2f6fbfdffaffdbff5ff3ffd8fe9cfed93fbf9dfe9ffbff6bffffff7ddf3befffff7ffdafb7ffdfbe7ffdeffd6fffd2bbffbfddefdbeff666f7fff7ffdffffe69d579f9fcfdfdeffff3d4ffeffbbd7be5bb8f7feefbb6dbadb5fab9f7fd7ff7f6e7f9eee9fbfbbffeff8f7efeff2feb7fff2ff5cd7eff5bfff7cff65bf6ffc1adf3bfffeffffefd37fe77fff97d7e7e3fcfedd57f7dffbbfffffffff7efffffaf96fbdeaf9e9ab75bfbbafb7dffdcf3df7fff797ff93ff9f7deffedfefefffdfdff7f7f57ffff9ebdbbef9efaf7ff7ffbf7fb7bfaffd7bd78bff9b9fbddffaeeff6fafffef7bbbfcdd028401a744e284084fe2c6840307536a84644b9156b861d883010115846765746888676f312e32302e31856c696e7578000000f98d107243f3318c52c90993ff9bb6d4f2d8074e812964491d79321e418d1f2299f6acc4026db55dde1e854c75df86b40b7303b7d3b11e8459e9a14bc58a678c41b39ec701a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea08e31f1bd5dc5c0bec45b0d39728875ac63de03941f1f1167c6e15c38205677bfa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942465176c461afb316ebc773c61faee85a6515daaa0d39bb77277a13e36fa826f9edfadecd41c54dd3ba72cae6aaa29493bbdd26dd0a0715e20b292b1a2a5211adf687e1afc795ca700c42c72837bb638f193927a5c34a08a15a3f741b98fb84286b88a9e1aed48d25707d6dde4831d880b7d58e4e41f05b90100ef685a534414147af61b7945b678cc9310114e4239bcc7a877ba461332906150ebb09fa0c98e48eb032012a3169f9842ac65d3043216fe92cfb80f3a4abd2183047cf617c9d002f259bf6a7f9af1342af59c10710b577243ae346c80ba200bc4e8ad9dee871a9e41b54d2ac4a6c2c84c4809c376409d4c97d3f520342d1579e7d3a3c72443a8d440c09c76435a4ddbf9122e3f8ded6114a80c7952c5cd8fdf70aa9d554150845711608e47570f390cc4a5a3729fa1af36b0a1b20ceda79053e4eb8f16f750780f17b4be849b23ce52f2235b036ccd69857994d3158aaf3bf0c2fcb3aa05d55342eb09595a5ce9f882a5c322e3a3d1f9c4e7380ebb8ddedd96d0028401a744e384085832a783ef119784644b9159b861d883010117846765746888676f312e31392e38856c696e7578000000f98d1072e85691219cb91879379743e9f6dcfd01e71edeb72caf7e721f4bfa8545d35a5b4f2b744434073f640f84bb403274ea6eaf054c1af78ee6ff0f22543b1d635ea101a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea07f731e76ca8641272fba7a1781065bb3e54424556f4178fe1fe999c5e94bd03ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794295e26495cef6f69dfa69911d9d8e4f3bbadb89ba03d4ff8f5e8d1c4f2633142146c2157bcb3a4ada23595f6cc0d5569002b3d3017a07b81e986c93111211655b11918fd9d68df99205b750a091bc535ae0e56c8148ba05e7d339200197a8b743c1560bdc0c11d58b101bb00aa601d72db5be5fb4b2876b90100443ca6441438371840c86241f9b4628280ed52449506c7403896c49722a18419f66195e3408f90834334d082707f9a5321001591883608a076282c5a5339b2b994d6721239daae17cdfd184da13043bb6cf400ebb74b7c07eb96142ab1926700459cbba2f302040118f93898496aaec88c8117cbbc4d44004265f49ca055de6a580ac525242b9a9324b9d6216e047de0192785bdfe608da95521e5c825301af3c3d1b667748b2302300d57f5538f244251a1ae310d58597f78e0ec7e674e482eeb4d165614091d67d6729c17d0a53161e05ee3fd816eb55b8d455e0ae23cea2c5498c80523b1dc3b07c512a1f1908d02f93a6724d95d6978d7160e5e5a7dd751028401a744e48408583b0083d87aa184644b915cb861d883010115846765746888676f312e32302e33856c696e7578000000f98d107208ca35c36b9afad92a16f0f2d0a6adefb1d8ac1a7585dbba7c201c1806345cbc1ebd09bb0de19b55ae08ad7470d72f641e9b642c0fa57760b1a7f5ec2c741f5601a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120510d9899d0d1a951df90e92f90211a024634f1331c447127a0682075dd45d23b3ce7eb2039686202d73a3f1c05a73d7a06ed7fd97f57badcd291f345c2b14c1e028cc9b361ea73dca9fe6e73613b8ac49a0b9501378ae71236097fbdf59e2da1deb823bc3b8e80dcbc1839044dd29968072a022cf1f796287a137c8d28f974d39cae4c38c22c6a927acd77bbda906ccb10926a0373fd36155b5df03a8a513b7272818cfb82d0a7158da3aee0849be4f629750cea0b725acbe55317a8364392cc8dba2131fac15d14b8fbdb88fcd816fb126ed13aea0a208442a031190a28f6522a09e3578704fcfeac8ebb5ff017af8302f7882ec33a0876b24b72ed9ce6a452d14aba50a9ec27bcc75a6d613e85f7b268b8ea0a683a2a02a4442f547b43d3d053c1006c17991276ec787f63c55dbba8e721d96cd2a11a4a080d11b9ce17cafeecb308ca0dee28254d1d7cc325da4ff9c8d5902067c635720a009852ea2f2e720105f9170af1161e166d1a4de6d0535288a6f6d13262b667daaa035bcf5c02400bf53b18658c56c557f45e10196f2073ed8214036d19deb287728a0d2b66c767650d02a1c9dc0bbb5a3ccd30d3ad3edf4422175b54ea10dbd8023f0a0bd47f77173dd78d3c0b1104214331b5a70b6ddc369e1701d6e2aa56e6784e6e5a015903c161b1dc9cef8d867646c90087d245697c00619b46a8375331b4dd1d841a0f2d7b505f7c24a4c89c2c9abb585adea696e185da7e3bc5fea64b1a86ce91fae80f90211a0eddc5b19dc1a07120fbec32ff5c19385ea804c13bfc4ad1cf00ba68b13df1c3ba0036ef5effe1508e8679cd200f804d36f222785dac0786f1d77d1b0ebf0d1d827a0e46cd52c3476aebf16c446ddf42c2d0104638bf179f3147f5165089586623fefa08955b21b67d5ec4002ee3d2c91f4a9689a1634538e69c043c8bfe01dfba85e04a0caa98d13d6b4441ddd8a67171382f075ca8fd00c07140f21f53dd6c63d5ae654a0fc5a032a7f8a466d8f0b5bbf77f036f98565edcf9da30c40be445db298bda4d9a0b96113119dd13ffc860e0140f3a45f631f40a261d0d3ef04124f60f34014bd67a0f2e2956448eb0de409c22f24df718c17d5df791bf67ea9da593625c57de58268a00f30ebc30089b8c241510ae10ee7f77fbd19532f6d2a45e35d866216bdc5a168a0b5ced867f280ceff97d28a3cfc15a5596f713cdea8ce0ca4d4c4cdf943069c24a0793aae703dd1f946e79a0ecbf4ad163578985c5bcf35df1ceeb63fc1c93b2b4aa0da060523a0542e0aa0b3b62ad3662b4fee8e6d947dd912e3231a7578fb9b69bea0e33c02800c900add7e4846bf5ac6c2364032dce43e506b53fbb4b4e2bfaf912ea0a3db4019dfdff088efa085ea1e376260acc1867356afdbf7b75ce7e73481c0bea0fd31d2604e719f12e9a0c8e24135a2a9ca4d2134c11e608ab3c4cabe6d9948f7a03e277bde3c33382d33904a4d29de1f6345302c866cd8099a187a47bd071c387280f90211a0e71df802b8e5870c7d09777d07afa288e4f4841cee9d76813d28cd491c1bbef9a01b0d969f65533b0e8191af5d7aee1de90ad6150f8c10e1ea31de4a5a13189ad4a0064be8a9286b21ad96f91cab53eaa3723084b8054bb8d55b5629cff774028a60a0b944c791f04057661a38304b04e78ef37b8d70434d3cc24f6ff63e6ed1daa3a7a08b6f41b3678e1ed968b71a5b5449a9e53992b1ec4f7ce4cb47cdf330c79e6898a0f22cf7628d5ee7da4ff669ec55ff9573b879342d10dd40d1dd0e5b7dee6d56bba0d649d3642bd20f62da58456d1979ffeb1a5f989602420f90ffc41f115ef8b19ca0ac364a075f8b231d7fdf9cbfe1ef6235306dfed2c6cd2b56e0c4bb56690001bba0b5b8b76f2aff754e4c916711e005c967b6e196414d13ec0b0399c72a307d620da021525997f478b1598ca26a78e2612e93df8282b48f0b5d21bfdb5128c2c24cbda0b3fb7a540129c52d766ead103dda9135d92df69385f2467e5a5372e6adb1cd86a0d3d6d50fb83512e1cf2abb7408b0287a727e2a3f4263ff8313621f1563574376a09fe86e26e8cd135ede3ca18b3dc4fb865322ad3250a34eaa73a1b8f7928255cca032bc98dde84e0c69ce6189ea79c2801bde27e358d0d9a045ee5fbbf6cee8e640a03a9dfb503015a9661014a07e0e0a9ceeb15ad8fed7298ae55800075b1b5a25d8a05b7467bb9cc16cab67b1e002aad5099758885a15003425b22a12d40afebf558780f90211a0c8c397a7ee6ac045043c70b2679746f7561cee9a2f23b80ca828ab81870d0479a0bf0b844bb20a5dc1ee59835dc9724c756dd396aeb354dcbf470f65100c0fb88ca01d28aa9ffaba1a74f7a69ae1c43ffbafd0930bae18069ade1766594b60ec2f52a083245e5b4287afd4c82c070238031fbfa4e22fec2022f91c0499009168a890e7a0b60d8344fd1c43f93ba811908fd59e540a5fd6e332acacd37cd7e64890bb6305a04a387bf8b63585661b7bc68bc973ce7cdae29b3ea02a17ab5b1c74e176157b11a019f7647c401c2373eaa03dc5ac7ba8f364f847db43a0226cd1c0939d0c79d6a7a0efabfbd3dd3939eba79afb36c6b111ee74e5dd50ee4764b1784368d7fabc15f0a01361d496f6108e12eb19ae157ae3930fd493f540043f243ce967662bc7d0af38a0470ee5b65cda129e19a4a4e6ee8181efd198b8574fe183db349c87896e639870a0f60a3be2ccb442a69527404d3e6cb4f336fd4e4eb783ea018207d8ade3a83f9ba03753972d77c0fc536a5182ffea99ca5afea9418b72a60bdd43487f05fee7ccd6a03e602f42e1d710d793b1144d4c213b849d0f3742211917fbc55e0559f85f508fa03cd1d5032160c2d4b5b042aaf4033203472b5eae1db5931e2b59ec082a517b67a0b36fb08c434dc1a694faa3bf1c5630eef2dd84d4fcfa4b02f56a75e4177f01c1a06245524a1e2cc1e02a70247986aceb7ffd43e40e95b0270b33378b9de7e50f5480f90211a013c928ec4946dc7bc0f664de59c323f57e0f59928fa24b931e9d16e8ae45ee60a0084cca44083276e700cc8d4868ef3695b58cd4ac9a20d72188ee6d86eef2fcd4a06fe19d0dda5fb08f44585cff568144a6a9686e91202de340243f3da5240ee00da0db5d5d1f8c078f2faed88175889d2dedbaba1db522670e0193d6b8741e6071eaa0c35d512236695a157ffa38b3215cfd085079392f7a78db5dcf17524116872a7ea09d3ebc2257eef629bdb0aab457746182e965652da3ca79fac122350ad661106ba0bbd365a84dba62c3e98ac31a0612936fc2bb8939ac927855d714cc0d681f964ba0482209fcc01fa375586d75a14837c9b0904b3981efb337cb543c5236d5a1cb36a0ec5b863b58f588d19746d7714d49b65085a0b19905f5d86886a02ce4e23c3d11a0b6a7b78b22b0c86657203b991346e1321f26e8a12dad91e4420f7562285ab280a073f0e4a566d75b967bc04d19619277b8626f88e2e563467a7b52b51768ca6937a04f13cadf496813dd07a7a5490b89d3a9acdceb6293b8532d2ff1fa0d2e761801a0171ae3abef7d85e34875542a1774eda7fac74d007cca0475048405cc530fa882a085c3a78036c0e9561d75864857da26a24575ad2506a4962cc224198127558fd4a0c9eecbfa37088516a5ed7ff6d6aa3402f0ff689c20b614208415c7b74e5dd45da027f806e985d491e921353f521a3b286c4f1c85e12f2d3be001b53e273a6633b680f90211a0ffcd8cf122c5b89b75f81a8df22d1cab9a6c8900f4deefe947bda17ab18097f8a0ad4d1a0e2af8d98be72960ef6645dc68472f82fa0546957e97dd571487dd3a1aa0e41524e500d6245e0fe091a6be8ddbea41ea9ae84ed92251409f93ad953022e5a011fa91a647a311ac0fb59d2b5fd3d1c61eb55d6cf72cef117c1cd554256238f5a0f6cf47c9c11158333a458beab01305c1aa9a36fc56474a1041fae47ab7a52b8da055abc5642a8381ea8d5ca2a3932c640da62fc282267bb7b32b571b08e58b5d58a0c147be76c0ec348a1e554c945a766e7ef01a00ce0b17ee749e971c7ee1ec6ae4a0a33abf2e1b189ab9b029f0fbbeaf538e53f396473204097e4e0c3665a89c6aa9a0332073d2912755e3a07f8af115990967a46ef3d1435666e504f0b601768c22c4a0f89bc877328f278d40b1e9bf42e73d560b130dd2bd59b1921d178a60597ea87ea09f61af9df8048fb11ab3e91a70fef0f256a0524d75c0d322f0187b71354e6af7a039fdc693688af21361600c041b3aca553c90e661f1259db89a5254e47789998da07e8f76e1db784ba419e1ce94993f8010cec1707206816d89a16098dcfadc2cc7a07df7b72d7b5230927fee52e5af3636c9928f9a6e0cffb8f27c5929ec2e077f6fa04481fc238171bfece98f318d6533832c1c604ca70b9cea0062525790a9825311a00a5822d49f18572ec060fe07522a79582287ca0e453ea36c8f27c3bda88dfc8080f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df808080a0c5251c3c07ae259b1880cf572e5cd373e389930822fdc15ceb35c1cad972d40ea04758dec46d9a94ceacf2d3f2cc3987b78153c7d56ed2f93061e460b33c58cb22a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0218187c78f28eac9e59d826f1fd9fb8b924c69cfdb0d9ac1214f94186307a684808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470").to_vec();
        let any: Any = mainnet_header.try_into().unwrap();
        let header = Header::try_from(any.clone()).unwrap();

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(56),
                ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
                latest_height: Height::new(0, 27739200),
                ..Default::default()
            }),
            // validator of 27739200
            consensus_state: Some(ConsensusState {
                validator_set: vec![
                    hex!("0bac492386862ad3df4b666bc096b0505bb694da").to_vec(),
                    hex!("2465176c461afb316ebc773c61faee85a6515daa").to_vec(),
                    hex!("295e26495cef6f69dfa69911d9d8e4f3bbadb89b").to_vec(),
                    hex!("2d4c407bbe49438ed859fe965b140dcf1aab71a9").to_vec(),
                    hex!("35ebb5849518aff370ca25e19e1072cc1a9fabca").to_vec(),
                    hex!("3f349bbafec1551819b8be1efea2fc46ca749aa1").to_vec(),
                    hex!("61dd481a114a2e761c554b641742c973867899d3").to_vec(),
                    hex!("685b1ded8013785d6623cc18d214320b6bb64759").to_vec(),
                    hex!("70f657164e5b75689b64b7fd1fa275f334f28e18").to_vec(),
                    hex!("72b61c6014342d914470ec7ac2975be345796c2b").to_vec(),
                    hex!("9f8ccdafcc39f3c7d6ebf637c9151673cbc36b88").to_vec(),
                    hex!("a6f79b60359f141df90a0c745125b131caaffd12").to_vec(),
                    hex!("b218c5d6af1f979ac42bc68d98a5a0d796c6ab01").to_vec(),
                    hex!("b4dd66d7c2c7e57f628210187192fb89d4b99dd4").to_vec(),
                    hex!("be807dddb074639cd9fa61b47676c064fc50d62c").to_vec(),
                    hex!("d1d6bf74282782b0b3eb1413c901d6ecf02e8e28").to_vec(),
                    hex!("d93dbfb27e027f5e9e6da52b9e1c413ce35adc11").to_vec(),
                    hex!("e2d3a739effcd3a99387d015e260eefac72ebea1").to_vec(),
                    hex!("e9ae3261a475a27bb1028f140bc2a7c843318afd").to_vec(),
                    hex!("ea0a6e3c511bbd10f4519ece37dc24887e11b55d").to_vec(),
                    hex!("ef0274e31810c9df02f98fafde0f841f4e66a1cd").to_vec(),
                ],
                ..Default::default()
            }),
        };
        match client.update_client(&ctx, client_id, any) {
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
                assert_eq!(
                    data.commitment.prev_height,
                    Some(new_height(0, header.trusted_height().revision_height()))
                );
                assert!(data.commitment.prev_state_id.is_some());
                assert_eq!(data.commitment.timestamp, header.timestamp().unwrap());
            }
            Err(e) => unreachable!("error {:?}", e),
        }
    }

    #[test]
    fn test_verify_membership_with_lcp() {
        let storage_proof_rlp = vec![
            249, 2, 108, 249, 1, 145, 160, 243, 2, 132, 113, 118, 63, 160, 241, 161, 149, 174, 195,
            18, 210, 53, 140, 244, 55, 106, 61, 135, 92, 126, 3, 174, 227, 145, 76, 246, 158, 163,
            237, 128, 128, 160, 161, 243, 110, 96, 138, 107, 213, 87, 172, 13, 123, 131, 19, 176,
            84, 242, 32, 18, 219, 20, 61, 136, 234, 214, 229, 63, 3, 59, 48, 2, 150, 137, 160, 175,
            166, 191, 1, 133, 187, 201, 138, 8, 129, 81, 61, 81, 86, 33, 87, 198, 100, 189, 6, 230,
            101, 136, 66, 66, 242, 24, 147, 184, 24, 61, 33, 160, 23, 83, 180, 210, 64, 112, 1,
            189, 122, 120, 147, 18, 45, 252, 211, 143, 177, 16, 93, 219, 135, 216, 71, 156, 65,
            241, 141, 38, 171, 247, 237, 182, 160, 210, 143, 238, 182, 140, 97, 22, 255, 66, 68,
            225, 250, 55, 56, 89, 201, 28, 147, 181, 102, 138, 47, 37, 0, 189, 189, 203, 212, 152,
            186, 241, 212, 160, 93, 33, 126, 80, 5, 168, 58, 116, 140, 187, 49, 219, 74, 219, 118,
            193, 62, 119, 121, 235, 231, 13, 122, 189, 163, 187, 122, 145, 6, 196, 148, 3, 160, 9,
            226, 194, 151, 8, 9, 20, 134, 217, 158, 89, 5, 196, 34, 23, 235, 234, 182, 193, 155,
            131, 238, 116, 100, 192, 196, 214, 102, 88, 180, 15, 239, 160, 114, 77, 73, 24, 57, 36,
            101, 1, 166, 27, 246, 128, 196, 20, 105, 243, 251, 51, 205, 247, 112, 2, 4, 109, 93, 1,
            104, 71, 100, 138, 24, 237, 160, 209, 8, 0, 140, 126, 171, 172, 12, 93, 82, 67, 64,
            234, 3, 152, 165, 245, 137, 166, 131, 218, 2, 177, 29, 84, 166, 186, 8, 42, 245, 54,
            145, 160, 214, 233, 118, 109, 210, 194, 72, 219, 143, 9, 216, 125, 95, 190, 129, 254,
            160, 111, 112, 122, 146, 103, 213, 223, 119, 10, 156, 212, 4, 60, 116, 180, 160, 90,
            98, 164, 183, 88, 177, 161, 231, 114, 25, 237, 70, 112, 69, 253, 90, 125, 202, 100,
            255, 155, 200, 174, 225, 111, 199, 221, 194, 180, 124, 109, 50, 160, 39, 152, 155, 234,
            177, 15, 57, 47, 67, 85, 70, 121, 225, 22, 86, 184, 135, 250, 224, 143, 245, 81, 251,
            117, 185, 11, 128, 32, 154, 54, 102, 126, 128, 128, 128, 248, 145, 128, 128, 128, 128,
            128, 160, 103, 18, 133, 119, 55, 115, 130, 213, 70, 76, 86, 39, 144, 246, 223, 29, 254,
            134, 177, 180, 108, 75, 102, 200, 241, 205, 231, 206, 19, 221, 182, 244, 128, 128, 160,
            111, 93, 78, 118, 145, 122, 232, 53, 185, 114, 80, 95, 148, 212, 14, 218, 218, 253,
            220, 68, 46, 148, 77, 193, 87, 179, 71, 171, 145, 93, 173, 118, 128, 128, 128, 128,
            160, 192, 156, 224, 147, 42, 238, 11, 71, 160, 213, 233, 164, 59, 206, 68, 79, 86, 159,
            212, 42, 109, 164, 91, 77, 164, 86, 88, 8, 192, 152, 241, 183, 128, 160, 8, 21, 54,
            159, 64, 208, 81, 17, 118, 220, 29, 163, 73, 142, 1, 7, 9, 151, 63, 23, 186, 206, 165,
            2, 3, 144, 30, 15, 37, 48, 164, 148, 128, 248, 67, 160, 32, 63, 196, 45, 223, 108, 27,
            91, 178, 24, 206, 36, 225, 76, 64, 175, 158, 14, 177, 39, 165, 215, 96, 80, 211, 125,
            115, 105, 226, 252, 74, 71, 161, 160, 34, 171, 87, 106, 125, 243, 139, 180, 134, 15,
            251, 198, 95, 48, 213, 166, 101, 54, 251, 45, 142, 195, 213, 215, 212, 171, 154, 62,
            173, 14, 67, 18,
        ];
        let expected_value = vec![
            10, 12, 108, 99, 112, 45, 99, 108, 105, 101, 110, 116, 45, 48, 18, 35, 10, 1, 49, 18,
            13, 79, 82, 68, 69, 82, 95, 79, 82, 68, 69, 82, 69, 68, 18, 15, 79, 82, 68, 69, 82, 95,
            85, 78, 79, 82, 68, 69, 82, 69, 68, 24, 1, 34, 21, 10, 12, 108, 99, 112, 45, 99, 108,
            105, 101, 110, 116, 45, 48, 26, 5, 10, 3, 105, 98, 99,
        ];
        let path = "connections/connection-0";

        let client = ParliaLightClient::default();
        let proof_height = Height::new(0, 400);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                latest_height: proof_height,
                ..Default::default()
            }),
            consensus_state: Some(ConsensusState {
                state_root: [
                    51, 143, 168, 48, 229, 178, 255, 245, 35, 4, 82, 182, 21, 136, 15, 201, 229,
                    227, 54, 146, 158, 189, 229, 10, 242, 165, 205, 60, 170, 52, 212, 78,
                ],
                validator_set: vec![vec![
                    185, 13, 158, 11, 243, 253, 38, 122, 99, 113, 215, 108, 127, 137, 33, 136, 133,
                    3, 78, 91,
                ]],
                ..Default::default()
            }),
        };
        let prefix = vec![0];
        let client_id = ClientId::new(client.client_type().as_str(), 0).unwrap();

        match client.verify_membership(
            &ctx,
            client_id,
            prefix,
            path.to_string(),
            expected_value.clone(),
            proof_height,
            storage_proof_rlp.to_vec(),
        ) {
            Ok(data) => {
                assert_eq!(data.state_commitment.path, path);
                assert_eq!(data.state_commitment.height, proof_height);
                assert_eq!(
                    data.state_commitment.value,
                    Some(keccak_256(expected_value.as_slice()))
                );
            }
            Err(e) => unreachable!("error {:?}", e),
        };
    }
}
