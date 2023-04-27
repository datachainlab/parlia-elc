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
