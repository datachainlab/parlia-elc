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
use crate::commitment::{
    calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof, verify_proof,
};
use crate::consensus_state::ConsensusState;
use crate::errors::Error;
use crate::header::Header;

#[derive(Default)]
pub struct ParliaLightClient;

impl LightClient for ParliaLightClient {
    fn client_type(&self) -> String {
        "xx-parlia".to_string()
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

        // Ensure trusted validator set is valid.
        // If the submission target is epoch block, the validator set is included in the header and not in the consensus_state.
        if !header.is_target_epoch() {
            let (current_epoch_height, current_validators_hash) = header.current_epoch_validators();
            let current_trusted_validators_hash =
                ConsensusState::try_from(ctx.consensus_state(&client_id, &current_epoch_height)?)?
                    .validators_hash;
            if current_validators_hash != &current_trusted_validators_hash {
                return Err(Error::UnexpectedCurrentValidatorsHash(
                    current_epoch_height,
                    *current_validators_hash,
                    current_trusted_validators_hash,
                )
                .into());
            }
        }

        // Ensure previous trusted validator set is valid
        let (previous_epoch_height, previous_validators_hash) = header.previous_epoch_validators();
        let previous_trusted_validators_hash =
            ConsensusState::try_from(ctx.consensus_state(&client_id, &previous_epoch_height)?)?
                .validators_hash;
        if previous_validators_hash != &previous_trusted_validators_hash {
            return Err(Error::UnexpectedPreviousValidatorsHash(
                previous_epoch_height,
                *previous_validators_hash,
                previous_trusted_validators_hash,
            )
            .into());
        }

        // Create new state and ensure header is valid
        let latest_trusted_consensus_state = ConsensusState::try_from(any_consensus_state)?;
        let (new_client_state, new_consensus_state) = client_state.check_header_and_update_state(
            ctx.host_timestamp(),
            &latest_trusted_consensus_state,
            header,
        )?;

        let prev_state_id = gen_state_id(client_state, latest_trusted_consensus_state)?;
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
            calculate_ibc_commitment_storage_key(&client_state.ibc_commitments_slot, path)
                .as_slice(),
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
    use std::collections::BTreeMap;

    use hex_literal::hex;
    use lcp_types::{Any, ClientId, Height, Time};
    use light_client::{ClientReader, HostClientReader, HostContext, LightClient};
    use patricia_merkle_trie::keccak::keccak_256;

    use parlia_ibc_proto::ibc::lightclients::parlia::v1::Fraction;

    use crate::client::ParliaLightClient;
    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;
    use crate::header::Header;
    use crate::misc::{keccak_256_vec, new_height, new_timestamp, ChainId};

    impl Default for ClientState {
        fn default() -> Self {
            ClientState {
                chain_id: ChainId::new(9999),
                ibc_store_address: [0; 20],
                ibc_commitments_slot: hex!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ),
                trust_level: Fraction {
                    numerator: 1,
                    denominator: 2,
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
                validators_hash: [0_u8; 32],
            }
        }
    }

    struct MockClientReader {
        client_state: Option<ClientState>,
        consensus_state: BTreeMap<Height, ConsensusState>,
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
            client_id: &ClientId,
            height: &Height,
        ) -> Result<Any, light_client::Error> {
            let state = self.consensus_state.get(height).ok_or_else(|| {
                light_client::Error::consensus_state_not_found(client_id.clone(), *height)
            })?;
            Ok(Any::from(state.clone()))
        }
    }

    #[test]
    fn test_create_client() {
        let client = ParliaLightClient::default();
        let chain_id = ChainId::new(56);
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: BTreeMap::new(),
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
    fn test_update_client_localnet() {
        let relayer_protobuf_any = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212f3160ae1040ade04f9025ba0ad39d90cf544a5377341f7537dcf409b6635023cc68739d37d1dc3685f79f30da01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479442897d87959d07b83a924a34e93b613e7f4798c2a0155520ea232faca9f277716ad83a4cddbe9888a08c0ade0628c35869288fa881a058902d24c5afac87cf7bbd9293d14def7986beb31263e6b95a4a2d47b9713556a030b67974d0561004c98d062311c223f598b40a1823e397dc38fafb2b476d25d4b90100000000000000000000000040000000000000000000000000000000000000000000001000000000000000000000000000000002000000000000000000000000000000000000000000000000002000000020100000000000000000000000000000000800200002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000001040000000000000000000000000000100000000000100000000000000000000000000000000000282010f8402625a0082fc558464634642b861d983010111846765746889676f312e31362e3135856c696e75780000079a6cd896e3a014f933fb30dfc0d4bdb8ebb6a9ada2b26f048ced8f7f60ae171f408bf52e89ad40cbe54257599b99c1714b770fbda08ce8a200769b0c06f43abe34027a01a000000000000000000000000000000000000000000000000000000000000000008800000000000000000adf040adc04f90259a0b3a6446f2fe77b67c6db593d1ad47a30164cd7ffc92e46469f603da95aea0938a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479492a84b62acf90b6e82e1583da79fa9cb9e0fc0a7a0155520ea232faca9f277716ad83a4cddbe9888a08c0ade0628c35869288fa881a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201108402625a00808464634645b861d983010111846765746889676f312e31362e3135856c696e75780000079a6cd8e0273e8adca3efc31f8e7de987b07e4e1a6131da31188a0827c63ec61b7f3bb751257beca1da4cc7d55eadeff3113ca46a8a6013ae24ba129d3b41996b04883501a000000000000000000000000000000000000000000000000000000000000000008800000000000000000adf040adc04f90259a04d70bbb9a19764aaed0208a0cbaa5259d54b72a8161097e984faf9f413fa78e8a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347949cb4ec6fc8c53e33c67d91563a07dca0140efbf4a0155520ea232faca9f277716ad83a4cddbe9888a08c0ade0628c35869288fa881a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028201118402625a00808464634648b861d983010111846765746889676f312e31362e3135856c696e75780000079a6cd80f4d6d5e36b5ec69daa62cf6d7c10debe668b3c94fcd76460e3aa4d1217d61ed7baf154fb3d4c69082a33d52c4f0d5049080c710dc5203fa79c12d53c82f753101a0000000000000000000000000000000000000000000000000000000000000000088000000000000000012031084021ae706f90364f901f1a02c2de4813a32632dad91b1baa4b513e3d10af8ae06aa7670867689bc452eb95da0e05a445d1b8c563f92ecef3301dd161f7e2ef3b7c48d758c8e5f506f26f075b6a02f0cad2e76cd339fe048e45f1e3f2266cbe40a722285b42005028352f6de0699a0ccaff84a535bd0c22286f3312c2f2ceb9905bf9a800ed2d1e47a90077db733e280a0ce574fc452b8e3543191406758d8f14744f1c3239882ff36de65c311a31032c8a0ce3e90fd6a5751569e8c041a9fe514ee2349a0e28d1c32c73dbc69d4ea5280b6a099ea5f03336678dd624cda4dae4bd14efaff9e42506708d5b715f5a92780caf7a0b291b0ee67e763e1a235d0711a58f020e9cd55202a46fced9386a9d1a5d1e4e9a05f493db22e2866f8201e2571c321d5cbc69022119ebad596fa0a933cf6544b45a03ca4ee04079b5c54e3608c486269157cd631ae7b7b266889ad670231b11c3049a01011c052441780ca70b46a1b8affbe8cd6b8a650f7f063f3943a524742d0b468a0be372dc7c44c2984476dda4f3c1cde6f8882f28f060a5df55aa0b949284b019da041eee44d7cfd75235296a3a6805d64339166f35ea79419f5313fb975e4b51e9da04ab3d2fe1684946e19287a90b6a16c42aa258bfc3d85fecc2e06c91235498c2ba014aba434eb1d9c3fe9dc4a71d5d01591d2718b0b7ff9774e78650f832ad58ec980f8b1808080808080a0696a99bbd6d72c73cc84866012d5514b73aa84ae63333de185d97a9f340b1c7b80a062531565c9fe76a71ca1719aeb9f537b3ddf082dc167c4ffa57b3cb8e950ca2080a0a9d3d6060e6cd1de053a9551f884c586aff25abba5aa5c7fe43a65cd7f3c92e380a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5cceccaa063bbda017ccca59c09f11befce4a83265aa2422d818230c3d37b6cefb9008f42808080f85180a03548f0b11fbbfd4744ad6e80f11a1f82c9a36922089e3235bfc5214fbb92080380808080808080a002f045bf8eae63c33870f1a3a0274740ef6482f5a99c99880d228b534552944780808080808080f8689f3cc2669227c563939b3db2109a60801ee273f50dea6929d2646facb70ad234b846f8440180a0d3e112cf3ec3787baf56c019fba0d376637f288903017e96bae60495ed3701c7a00615ec2683804db553073603c86cc49e83d62d68cd3495c1d45e464c451cfafd22141a2bf881c9335e9aa1ce43a00894340bfa70dcda221442897d87959d07b83a924a34e93b613e7f4798c2221492a84b62acf90b6e82e1583da79fa9cb9e0fc0a722149cb4ec6fc8c53e33c67d91563a07dca0140efbf422149e1cb61bd90f224222f09b3e993edf73cceb0e4f2a141a2bf881c9335e9aa1ce43a00894340bfa70dcda2a1442897d87959d07b83a924a34e93b613e7f4798c22a1492a84b62acf90b6e82e1583da79fa9cb9e0fc0a72a149cb4ec6fc8c53e33c67d91563a07dca0140efbf42a149e1cb61bd90f224222f09b3e993edf73cceb0e4f").to_vec();
        let any: Any = relayer_protobuf_any.try_into().unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(
            Height::new(0, 200),
            ConsensusState {
                validators_hash: hex!(
                    "809f5c5d2d6fac3926bef0aa3329cf239fead3c4ab4b456353885231757d92ff"
                ),
                ..Default::default()
            },
        );
        mock_consensus_state.insert(
            Height::new(0, 0),
            ConsensusState {
                validators_hash: hex!(
                    "809f5c5d2d6fac3926bef0aa3329cf239fead3c4ab4b456353885231757d92ff"
                ),
                ..Default::default()
            },
        );
        mock_consensus_state.insert(Height::new(0, 260), ConsensusState::default());
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                ibc_store_address: hex!("702E40245797c5a2108A566b3CE2Bf14Bc6aF841"),
                latest_height: Height::new(0, 260),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
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
                assert_eq!(new_consensus_state.timestamp, header.timestamp().unwrap());
                assert_eq!(new_consensus_state.validators_hash, keccak_256_vec(&[]));
                assert_eq!(
                    new_consensus_state.state_root,
                    hex!("d3e112cf3ec3787baf56c019fba0d376637f288903017e96bae60495ed3701c7")
                );
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
    fn test_update_client_mainnet() {
        // height = 28255846
        let mainnet_header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212d0590ae5040ae204f9025fa008559754595037877ce359236a354eb1cb2229a01eb4f6397ea13628c80f153ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479473564052d8e469ed0721c4e53379dc3c91228930a06a4bb2d243b93deba5138cb8555899330b31394f2135e4a89226deb940281a18a0e2dd8b944f6456caf5109251896a20d8780627e4c2ee0da5b2f69fa97a90e779a08fb41eb2db26d71cd73cd53a667026ee9ff36be69cf2ac4350cf988e4e7e3d46b90100dcffe3315b76b7ffcebfd4ffdeb2d57fffdfeb5bbbfd13c82fdedff7beeffbb3fff6ddeaedfd7ffdf7f86ceebffdddeffefbdf63f37ff67f7c7979fdbf3f6eb6fe7cefbc6bbeefb1ffef6a6fe7fd3f7ff7ff4fb38df4ae7fffb7f7d6dbf77e44ba3efdbf9ed2dbff146deafb1d97cae9ffffd9fbde997dc7def7e5bf7bcff66bf07e79effff9fa51fcbdfd03d8ba2bf7fdffffff7dfabf7e69ac43fbdffeff7cf6e9d9edf7febff7efddfd6fab9fbfffff4bbf9bf2d9f7fbd6bf7affe5fbdfbdec7bfffebdd3bdd7f2cfbabbfffefbede8eeeab7f327bef3cbdb357e65fbf737fdf3fdbf6cbdd9773be7ee1bfdf9ffd7f9cac67953dafd4d9fdf633f1facffd1028401af266684084792e584019caf2c8464633f1eb861d883010117846765746888676f312e31392e38856c696e7578000000f98d1072a9fb1fec3fdaf1ae672cc154dbe72533a44b96d09c2551387af8df09450a9b1730102eb7baccb16bca40c3fccb1d76207eb9fd25e154cb9512f3ad1e15cf70e001a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0e90cb62ae49e694d12a99443ab83a35d1a9cf5b57b142ebdb4496ee89efc7ea2a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947ae2f5b9e386cd1b50a4550696d957cb4900f03aa03c57487c4132bfe661e0acd6b8b1ed758fdcc0230f2166bb7bed97b1a9aaea18a0b0f1c45c474d343fa1ecdd0258166ce2401ed56c554bfb5105a1caeee4a00c65a0b67d0f9e1322d80cbbfec8b503aee39a1717f55cf432055c0d01c3baaae40680b90100cb37064d502bb4790a4c6cbed537dc42fcb8ea3df59b57c8701ec55311331911edfa54c2508c354cf1769e05063e40360c03c858b67a1074406b3bd8fc7527a6177ee4d33d64f132f1db4c59aae82cbcff34a9bfd3e63d9fb03e5ee2f5396768dbb7b6a6abd35d3f354d8e980962ec6d5b52e873df2d7dc614b5df339fd72e8f5b7bf816f36bde6b8184fd9a89bd4cdbb63e7dbdffa4b319b9bd11cb9c8b3a26a29a80abf382b3205f5af3eeff69c7d3803f398997a2c05b882b7af7ab9b2a5042bc56ce384609c7f4c10ae9073530f125708b6abd0a00b42b42e64eb0dae5c2d9baabcb3914d199b1c1e28a05d8c5c3dde19f68d57cd65c373828439a308a42028401af266784084fda7683f432a58464633f21b861d883010117846765746888676f312e31392e38856c696e7578000000f98d1072d4040bf2f21df4f722f31cc8caaadc6306fd1ddd05b03388db0730459717651d4301092b14f1e9d3b94b101a22492915007413dcb7ad19eed9612116426bd4b800a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa0ca6513cd9087eea684475a5681b8d29834984669df0e32a335ff9a3abb5e39c6a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347949f8ccdafcc39f3c7d6ebf637c9151673cbc36b88a007dd1bbbf7025b0639c4e54d01e7511ae73cd5dd7d3b8615b1ac7090d02046e1a0cee2479f2c9e9484a083abf96309c3c3eeb96654dd4a67de6a9d95825cf8a92ca049769618f11273e16c8144e2a4af674388c90584b6c331e03d62b872e473e2cbb901008ff80a4df4683458fa9d0aefb3a6b4f7fb93ce688fcf94e98f7f87223495c5b1bb54c7da57d8c48fd6983ea25157aa36498efc502ded7d0dea9aee7db5bc70c256e6bff79f7bce9b9bc7694f96b927ef75b45dff25de1830263f4d34a73a94248ffccbff9ba35c79fa622d9d1130fbeffcae69e57d9fff88ceb4ffd3963f2a9f9a5eedcdbdb91cd59ff974299c1ee9a0bd27ed197d68aa7da5a1b8dadc8eaf7a47e9b23b32f6056769d1cd6eef4f46760f1d26894bf8e6de3aad8fef63bc2dde27fd5f3b9b526fd3f63cbc0f4dafb35bafefe57ec3e9cffd6bc4f67f622df30e12f8cfe11ac65b5aebfdfe92dd118126b511c72b4ddcdbdc9972b6ecda007568028401af26688408478a9d840107de658464633f24b861d883010115846765746888676f312e32302e34856c696e7578000000f98d10726a6431061de71bf78b5b4d8cc3436f7c3c366bba3a2fe6324aebdfe4a53fd37a303cb3f9b626eb2d1e32ddef84f3a881c8097d110f3531c1272a47f3c7fcb31400a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa0a0c5c55fa208dd02615862d7aa7c308760db7a69146f84cdcda7ac7b90874167a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a6f79b60359f141df90a0c745125b131caaffd12a02db8d6f5839e2e44f5d668d1b27e2c3dfd608579039e01b8b23e8bec69fd306da0bcd9945e5d39f7d126ea43421a05b5a8e6e0eff3482f404a965eb336b3daeb5ba07a716eb1febfc6ba834d423029725d0d54c352e752acc38b4facbd328744262db90100fcbffb3d6d7fddfb3e5fc7fddfdd2fe9fcfa9c46dcd6e7cffefad7ef3d9ee7b6ff9f7ef7e2bf8a5758b87fa5dfdb4732bf3ffd3cda7a70da266ab0e979f4bbde5667e6c7096aba7d77b3d15e167fbbba2f9bae3596ffd39bed7d5fd7cff44b8ad67ff7afff9774ffdfed7dc77d5fefffdf88cbfffefd77e6d68d7d1bfed3b5b6fbdf7f9cafd8cbc379fbb7c6fa1dedb7b7bffffbf4f3dedb2cbc19ff5eeea3fde6315d3bbfbf8d79ffb5777fdb7e3f4b7a4fce7f11bcf2fcbf7bbeb7f1fcdffbfdfecb5b7dfe0b9376fd6dfba3eefe776ffe33f2a3c2f7b555dfdc9e7f6de25735b1e9cb70ff630badfd970bb5fbfffdfc6fcf8e54fdf8788f6fafdb9e6e65cb028401af266984083f43148401080c9b8464633f27b861d883010115846765746888676f312e32302e31856c696e7578000000f98d10724d9e6ae2547bbe0c460e77f59ed7e1d5d3ffad095d273ec6f7b42a4648160b9864e95248c38947656931506e3e1bc0399a6a79337cc4f1fc9d5396a8da250e9301a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa0771fbf874d7e1c11386372a129ca06fb93714119950ff9aadfabb72b522a29aba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794b4dd66d7c2c7e57f628210187192fb89d4b99dd4a084bd4d0b4a2005e9495c861f58e40a06647aef4802a79285a98deac0c73a6416a017b9b0d6ab4e7660139966ceaf097ea1bb0f6325067dcf4d8debee57d36b792ca05e3a9f3a0d054bc787d5c84b81234e2c74d2f802e9e80348c75830d1e8579f9ab901008c6d3654614c9a5a4497a0edf2665452a370047b94c44502201345f628d09d0cf6a13f60d40e110592a1b02e129e906b5b30a0043e4ab600782c6020a97c23349443d64213dc4b2e73510569d23903796a743d3d29520e226977a40394585a7fec2e19261a564f089579aaef3b20aaac28d0f774f1695686042585db98db883a004da56a90dd965c609d64ac1c1c1cd6faa48c8739210bfc4b1e8a568486922cdbc19047b4ec286bce4c21553ad41680b40c389db5d4a81e0a55aa7711d462c4e9509ce2352209c686e219ad04e315c2f440eb27134dc890c5cf022ae53ff7426454a2c318a421512fc73f82670a5851b9e6cf0919c874c807ebcf0e0e111443028401af266a840847825684032609c08464633f2ab861d883010115846765746888676f312e31392e37856c696e7578000000f98d1072e7a3151ee850d9c9b3b103b5ce8c6e60716c333698092736b55c7896c3560690245834747cd9b178fd9b0532da74aa2733eeca7ca632a9b08cf745128638f16401a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa071d1d809684d1b9ca391d4665b931fc244dd7e2a3e9106bae0c9e861e4d63b48a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794be807dddb074639cd9fa61b47676c064fc50d62ca0aeaff735c526bc6b5bbbf48824595e88170e9312de71bc0d49d5712ab3a12bcea0ca5467a1700c58f7c9c3e2a2cf20c68dad941bf2f6b7ae8a9dabb974d8f48384a085bf2ffccc1d3f7e2741467d17fb8105198123a5d066283652c60a52b2194c52b90100ca3233d4bf3b17384a683d04b092715ea2390772b69ae703aebe71322f017d20e3705d4044101a909975152a8457a6e640048a6f44fa20ac581917583e336b6255f22552914c2a2e47d547cb016d0bb975b50833ffeebfe498365549e84a92e0dbea7f29ba6274b047e6e8c0a9519ced4f31b1ddd3eae484366733d088198fdaf138390e232b1ce34ef8259a1c789ccf32ac2ca73b208c5b03088cc554d02e696e839594929a47ef5ad164545b7e0f1e6f45c2972592ea9c54e4fbadd90a8c5dad211e1affbe2986c217108b27921c0e24fde3c5cdc3a99423c0221766ecacc5ba99fc652c7a477029dd0e2a3d738d32e4233e4a6bf9affc8784716d7e07271e028401af266b84084fc9d78401098f0a8464633f2db861d883010117846765746888676f312e31392e38856c696e7578000000f98d1072805f0e10e74d8a07a2f3dad652b77bbd75076ad181bb31c8581f1b668f5d9dfc4b5c244f92acd0ef92c6ab83fb9e703c709edcfe97760b3b353e53bc967d626800a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa0182d33ac8fd55465b2905e95e2f8eb491fd13ff9a70ca808cb78677f420b0b3aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d1d6bf74282782b0b3eb1413c901d6ecf02e8e28a006c585fec8e811062ed7c564d89fe499025775508d8991446c7ba669e62d5ac3a0ef96172b285bef6b1c4f478c1f827d4b960f56116227b080ee2fe4390a91ecd8a08cae6846c8ce8a613acb45378a4a6b7aed266f8d653e98f8f72f478321c419dcb901009b75fbefdeff9fddf9ff75ebbef91f7df3ef7e67bffae7d7dfff997ffaffdfb9efda7756faff967fffe63b7b6fff6eb7be7ecdb9dfff7bfdff5effb7efff7fdffffffdfe5fefeffeffdf73bfd8fb5f6ffff9c9f39fe6ff0dfffecf9dff6bfef5fe2ffdffe3fef7fb2fdbfbffefdfffffdf2efffbffe9bfd7e7eef9ffbbdf75ebe67fbb6f4b7ffd79d1fda7f7fbbbdfffffbf7f7db9ef6e6fadfdf7de5f8adffbffecdf3ffbdef79cfffefdefdff75effddad0dfbfffed7d7ff5daeffd5dfdfdef9fedffffcfeffcfb7dd3beffdf399fbffeadfffdfbfdeffefdfbfffbbbbf7ffefffffbff9d3cf47dfdff796fdff7ffbfdefbfff67fa35f9ff7fddbb6ff7b46f028401af266c8408477a0f8401b5ecd98464633f30b861d883010115846765746888676f312e32302e31856c696e7578000000f98d1072bf412915f9ffbd7442162580a6a1d7a1d8d59a5832eea48ea6be7a9e85cce760084b864a3ab815511be8952d341a4be1544b7bb0ac05d248746cac73dc02647601a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0ccfde042e93823beb5bac16696ad3703b2b35874b7fdb8068b2a255850a5e6e8a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a08edc080fb04377c2365a8b20349981dc402fb3bae1bd5e878bb5998e16eed134a0563e52ddedbe5a36f411337f029d3be05e3a97053eab2520cba81fa76717fd5ba07adcf395884dc8e7946f491d8f14174fb289a5fffcbc418970c7bcf341172eb9b90100e8ffbf450df8177c517836eb9a08c622f48dec48ced6ad08e89e71d63c515419f207dc6dc11a3098d36639a4511bc1024f498054544af210871c8a246634b8949d66df3e096f082ab17300dd8b20d8ed647108004b669f43f4b57f02cd01ab208a161fe602931e993d5020b910c7f8d97bab9e40ffbd65c4763d1753fe3d4c6bc8c27da769dc3947f0985686bd98caf59e7e3ca5fde6509fbfa914e4bcc5aa61a291055ff1dca3f50234dfeee21f2747d7ae8bed4592d4d2663b3e682991046e67501e4775c36983b43998a8708c3ca6355e5860f51148d37765141e225df24a783de1c353e4430015d78ea397902c21e7321e2c7b7bf6d9462638c0be2c3ac6028401af266d84084fc18883e0a8928464633f33b861d883010117846765746888676f312e31392e38856c696e7578000000f98d1072f3b781deb96ded0cf6a59809eb39f7640cc321768809d681c14e40c77f46ec2b2943a6e56d7254e5500dc077eb777f3eeea7e819b638f8732e69520dbd10f57d00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa093d61b8fd9544bc7231d07b0e0984a4079b10d5d211434e207b5d5d97e32d4daa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e9ae3261a475a27bb1028f140bc2a7c843318afda0f8eea40fc0374bf6e39a5a23b182043f153c296bb5338784ef3748c4563bd8aba0d63f461e8f1d8dfba62bcd188c347f1b7d05ccb8a0e212da7896a1f5f7a86650a0180d7b9b65668238cfdf5ce169fbcae1b82d1fc467e3041c26847fe2d9d92ccbb901000ca786580d3664996f1c1347d1c6719af0dace466a857090b35ecb1a006e39f0f22e1d12512e108f52b333ab6cdfa13ac08e91270fac3427265822bc247d239a244dad8719584b89b1d9525cd81c403f68bdcb211ae604eae82cfd06d94f5e08fb4541a742260411f54b72800c3d8a1f5f680bff7d6dfcb8e25d97f24d3da652c82e68cc6b1ecd0378abda2706cf39e6b575343b7d02a2bf3008ebeb14ca2afe2683003ad3f43773ec1583fc039f066326ad40a32f8ff27e8c777935e34a38c4a4785f0ec76a099694a94bef192752a234e4a3ea87ce8afbcdea74476158f1163694fc9993d2c3d319e11f6e271beededca27fba29947dee97453b081ac38400028401af266e840858114884010d4ab08464633f36b861d883010115846765746888676f312e31392e37856c696e7578000000f98d10723702b1911bfbc81e2b3cacc25a7e79f80c2c177a54fc703e893715509bef990e55fb6e20e8ac09b62e84246cf3c481919528e76a8c42ba9e41ddec06ab4acadd00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa0cc628f285a79032596ef5b67e59f6db40ece197e17506d126c17be2382249027a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ea0a6e3c511bbd10f4519ece37dc24887e11b55da012e29a9fca7a96f08e10c464d12b247f19e25b54d1dde4cff8d6c0ac39293dfda0ba8ebc0756d82e3a418d8d39d308da457d3a648e2736e3b813a3e8e87bd29a3ca0abff4bbc44d9dabb53176ef05233397f281c5d980300786bee8e44000f85445ab9010039f426d1f5d21e58cd3cc0eeabed5c0ef4966d6cb1d7bf9f3b1f09a27da1dd5ec712c4436c0f5c5916343bf5373fd0f15f810d9886fe683e72f84e5c7829328715e4e6d63de0c82fdbb1164ff7a821fe67d3a3ef8ee79e23ce357624c43a246898b72f6f6bf69d4b7e596ea2a736a82b181c00f9d38b6de636850bbe1f9f2df3f85af98c95991efbd5ac6e599e161c9cfabe65a5f9bb749a25823bc0eda7f436bfba8de47baab3f73f5e63e65e1e6bfbfcb5d2bf41feed3d416421fdf7aeaf5bb9fb7fffb7e619b3feddf65d73f23b71a84e1be697c3fd552da374ab6a3af667b1f9c8a762eadd484d957646157fea43f5ecde3927f2cccfad7aa2dbfbc49d4b028401af266f8408583b0084012ce4688464633f39b861d883010117846765746888676f312e31392e38856c696e7578000000f98d1072403c0451345f11adc0baec249aca2358e5a1b204794fba3075fc322b2ce2bb03416412e357e8b0d157d23c763f40452db61d5950e1cef81cdb8d9f04ac42a2d400a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea03adafa27335c93087797360fe0947d9b6f78d6fcdf0aebfd9d3f057067beb258a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ef0274e31810c9df02f98fafde0f841f4e66a1cda0fd1d9c224a9a1070aee9f1db11d07f930ba0a0249c32161cd33024c6a58d38c1a0ae5274d4e35bd19acc16d207838f4a565c2349577e4e19d956ca2b178e73f10aa06eb8e18bcc9a69fa08ae7ce29b0aff677a7558c348d1fe05750ab4ba5710dcc3b901008377c35d453814115ec0a06d95cffb32522ae448101ee0ca6717833298902017e5d08e42eb825ca1d2a49aabae78993c54619ba894b970d27408a0584bbf6f9c08d0f6375f4a8a49b1f06d0d84d884aa69d108e104748b38e9e474e1e83a0d442e5e8e26abb260310320eec0a350dda14944cc47d079ee10e70f8f7ac2193ccfd8df217c07fb1c356cea262a289c18dc4ba4240f7da0dc68551ebeca14424a210a98ccfad61db7616694c7770b2e1686eeb2a276258fbf86aa612cb4891a2a4febb65f62e7c1098e91d896b366663fbef70ee870a0e498957df9147e7a49f1b27992f585962279440fa1de1a891b1401e5850ea5c0f874eea706034cdf0c171f028401af26708408583b0083ce94288464633f3cb861d883010115846765746888676f312e31382e32856c696e7578000000f98d1072f3c3d7ce6ee74d2b071efa3c63ed3f8051b4e430195a0858958963d80fba7d163bb64eb78953004e23fa81c875f535da3623532382f63c06b46e18b7a339e09101a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120510e5ccbc0d1ab51df90eb2f90211a0fbb64a6a14f895063e2496c43b56540b70b5c09413d0d7823b18923dccc0f1d7a0ea6c658696a9dd77e42dea042509b193dc1f0dc20b90af8cd7f40de94a34df86a0e1eeb4123bcf28280c6d8e23968650dd3693b08184b199314d37b9af6df9b621a09c504b31b9453e1521364da6c73f0769fe6ae0ffaa3bc807aaa2a3054be45edea0c710b524398823bed309aacd8ad00a05da22a040826072aa5615d249988f24a0a0fa9a6e562c749dc3bfe90be6ec99c0df6020bcc8efb9b2566b0086e5e21b726da0a47d796a1305b2500ec6e964050f8ca66d1fc86b648bb8dfe9ca005fb300856ea0d50ba5976f51f2f745febaf27d6482c029daf25f7f016a0ee59d5384c31e45f1a0d3656c29215b38dd87626913efe66593261a28c570e15da5de4ac0c4c9dc4c8ca0724db99ee9b5bc611442b00c640275475b743dad1faee7b09a94b79785c45351a0d2c6e40b1f4fcde13bda422f54b952015269a8a0feb470bd045c767dfae13bc8a030bf3e341af97fa089f6cc058b2d55990f2eeca22490654f74cff8ef6fc1ba74a08ae95a6dbfb9e37477b7cb9bbeda0b73fde759eaf48887fd60482dfbddc36087a066de5735b79cdcc278dd915854c04e4f8309b6fa6ac572a525f050f1971895b8a0025348133896547d5253d38e954bb375206c0aa7cdc656d61b257cbbd85b8895a0368f140a211be72e07fdecfb47ae681eae09df08b6cac3ec936be5d2f87f812480f90211a0a9a36d8c6f0148ba4307990fb03a25a1c216b448e17397ca2ae1917cde7840aba0b3139fb4c01baf2005dbcc6026f0b9332bc091f9942089207990252b89ebb29ca07a1306fec69d3ef7784a922291d36eec72d9aac253e2729bd4e34b615544acc4a0daf0253f46d0c0fa12fcb976fcb3cc93e0eb97461b5a7b8a7a0c73f3830826b8a0639eea6dc9cf07790b85a2fe6fddbc245f393f437b0f60e78627dc2866d0d80aa02e17ddec512c95301fabf2cf4007ff28e0c6c62654258c4b0751f0089e9437fda08177639792488d8b7713fd1de54892d0ad85a8dac48a8c22dde352b787f3f7f2a090bd4d1ae1dbbfead5b880c027b8641f9d8ff1fa7cca9e240d72d89a08b2af52a0a969dd45afa1c9ed1edcaf0f9aa40bcc3e4bdead7e996201f7ff9c984d90cde0a0e4ab38febbb96deb2bae6d57aadbc76449173bb3b37219435dc73a8d2bda745aa08e5bd1066cdff7826350fdb9ab230a740e1d87055d1f88208e7f1b9852b44a6da0913a384906daf79cbcb3368b5ad115fb104973e0151ea0d8e89fbeacdb61e8d5a084018a6e1b27b79dc8abd3b9dc4c973b922c065eb66910934dac6f7ac883013ba03d134feeb7b6d325b89229a689dc46c3d1fb13edb5a66eec9186c8e6923ff797a053f9bcc0f9b3033803306ba5d99422fce9f8224537415b6b2d94d637e0005973a0e999f657a938e9ffaeb3e3873ff04cd207657e874f2df7c5b3a0dd68f126acf180f90211a078b041dd05298c5f4ff869f63af63f7dc94f63dced8505cdabd91ae922cab124a084fdd6f1bbd97128df0c0e53e33bcfbd82abc104ca6960cbee1cc48901f6389aa0141bc397cadb2df409aa4c6be65530e436d3d42b28f3b14660000f6725b56205a06d94f8e462eecbcba4dc275e142b2f922f85df32a62609c90dcfe38ee88cc08aa0686b3c26c916b970674369bc0b544b7ec87f6177c8cd4275fa545dba7f9beaeea09f3b8a74118b5d84a25023b17f2aaabb5bc2ba91592268369da63831801897aea0096582a358fdf05b8a40f6585401fd0799e6d88d21056942acb7c5eabc18cd83a08a1ab8e4fe43de8cea12e3eb5fed78d26538300d084c482c2cd37196f36f54d6a063afd460f241ed4b6ce8f37e535480bb820de9999fff5b13b504bba259a096e6a09bd73451c28ca1b37bf8ecff96871b8ef8b9052b8aef6d30853bc5f363c5540da06192595ead8d36c13892465772a4de3045be317919af8448962025fc8bde19a3a0fbc9cc7d98910121cfc17509588cff02ade4d29cb4a5c6d47f0d61386d74f5cca001dd0affdc0b35ab87db5286767ab23379f8873f50da5eb968d849843ea4a25ba00373597de3a0056409fcc4f6319e9286a5fb8ec6a441b0535527a4fb367096e9a04aea7808b9e4c2aa02f93183fba82ebfdc5851b54c351143403f3cb3b17946eca0787c05a17968ff953879df14163e683fe05b95af7aaf6d6cb948a9f09368eed180f90211a0cbef720bea6b3c95748568382b4dc0612e8e9ac3dee7e798e8b248864d34cdfaa03018a79e0feff0952d3f5cd2ea46ea7cb2448d26520e6ec1836bb23905017ae7a0554b360ccad3849dc96ede9ca17b92a918dc84cbfbe871099fe9a96cae7828c9a0bedcafd6f588c0c3062651d2c2b3df15ed7b8fee4b45ce0967926ce7e1a728b0a06373c7a1a5f581bd697719b9e21e07480e5bc91f923eeab0307e5ef329cfa25ea0d231559aeb6c454bf4c705a9a3285e66f84f1f26d393e325cdfc54178619b845a0b60448f171c13e927b76e2c944091ae0f4b76b01a1783b97ac339efbb1550de0a0bdb770c328a1f55d21e15d9f25bdfc9b698d4ac3c3730997f9f87641e9a6870fa07ce72b4b0f9060bd907092f02bc0c5e97a0eed03b3cb3bb48b1ec3a150b91e23a03770f3ffd5bed8df0fb0303e6325c44347327276c16b524ce685f9e312fb0084a0d9424ae5c51831ccedc20ab52d3ef8e51e4f1de7b9a527bcb5d3554ce10936bea08576a018628ccc716885105afe9c508256b842e8a902e516d7e55ff4e05938a5a0178b09938ca5774a03445465bc9c869eeca749482ce39dd4e179de18055b6b26a05f021186811ec9736a7d0735ece06b4cc9fb8f483d47abb1fcd5861e60fea18ba03905874c0588127cdaa213593377455a6eee3a5ce6f1dd0a65fd42d740a7d75ba0c0bfee7b507f1d47388dc4d617a54e842911e772ff5ff3c98674c671c0acd8ac80f90211a0e80f012b8522803348fb72d9bf4b03e70df3a0e8680f579465783122b51ce0f7a065c4c3f9307313b3caa98bb23ae6f9dc13f523e2e062c23ab471e09508f72c1ca0361e83601184a8d10b07751889edeb3cb81dcd2a1a480ccc0a11bd50b22aeceba06d940d5b16829e2cb68828dfc979efa26a0f1991e8f9f1f715d77dead11c19a6a07f250991b67444afe21d2bac2cbfff9d30d328d2bf914ff1f26851d0278f2cd4a080e4c7ef7e277d83117bb66979e054f99327ccfc2b7fd6d1d239a80e834e6517a093903ce8992fa45177eb6d1b610ea9b45f02605ead42a18a113a73510f67375ca0e3788c9649c395dd8355dcd1e9006660df767dcef3830be0a8221c8431483e66a0f38766dc6381a5cd51c378da27f80f64d9e0bcfaf6f46f177f32e78e1939eebda05e225bed2969bb35591479b1b3053bf588235a4b4379cab27cc4f6f34a8f118ba05b8dd1e791866d88e0e1c544bf504dcf3c7cbc6d974d05a627087fd05670a518a057119bf9dbf4455713b7b113116ec0604dd6bdf9bdaf09f1508b2739e8c9252aa01c12ead4484c00094c771884a0a650a9dcd30211f88d4ae10a52f14c7d02afe9a05e8567b95433c1b46d4e491aedc0f836da36b221731bb903cd8fb5eb91e21953a02da10905d6c485ead1ec09cadaed443c77d853f57cd1beeda5e088a7954b3102a08ba2525c77ddc3ab8ec79c3a4e3edbba0c1eefdf557cda9f4d326e34f1ef0e3280f90211a0ffcd8cf122c5b89b75f81a8df22d1cab9a6c8900f4deefe947bda17ab18097f8a036b45913ac0c1b14bcc4ae95b1974657cdccf7ea1336400ce45ff84a8bf72bf4a0e41524e500d6245e0fe091a6be8ddbea41ea9ae84ed92251409f93ad953022e5a011fa91a647a311ac0fb59d2b5fd3d1c61eb55d6cf72cef117c1cd554256238f5a0a95146aff5b838dc1f16af232b99a0c7d707f71bd7f461151406d3af990d9aaca0911cb58c6551cd7d010babaf67c5c2d9e23928c5dacbef73d5f93a7fd8e02cfea0c147be76c0ec348a1e554c945a766e7ef01a00ce0b17ee749e971c7ee1ec6ae4a0a33abf2e1b189ab9b029f0fbbeaf538e53f396473204097e4e0c3665a89c6aa9a0332073d2912755e3a07f8af115990967a46ef3d1435666e504f0b601768c22c4a0f89bc877328f278d40b1e9bf42e73d560b130dd2bd59b1921d178a60597ea87ea0aaf5a864549de129b78b97915f366f6d43af9681c5dfd432d867ecf96e7bc75ba0eb92f299631911a75fd978fbccd4c9cc8c7fce20d17a7e7d34d0a77fe83b6321a0669afbdec695fe440f5528e984fda0ac28021c51d52fd4a50cca7f475eb6ab40a0b05ab82c2b8fd34834571088eca09959e6dafd4c83b717352f0a6b5f5a9c123aa01623c1d910bcf5129b4362c0d255e15e3b5128d7f2e4171a5a885d32f8d298b1a062ac58ff8d3cfbe87b798cf42214a6608ab03fc888b150f9626ea9407b0b55b780f9015180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b78380a0c5251c3c07ae259b1880cf572e5cd373e389930822fdc15ceb35c1cad972d40ea04758dec46d9a94ceacf2d3f2cc3987b78153c7d56ed2f93061e460b33c58cb22a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a01011898e0e550d9b3799310a4848d65366ce0c98b969edb6322d24977dd7d826808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022142465176c461afb316ebc773c61faee85a6515daa2214295e26495cef6f69dfa69911d9d8e4f3bbadb89b22142d4c407bbe49438ed859fe965b140dcf1aab71a9221435ebb5849518aff370ca25e19e1072cc1a9fabca22143f349bbafec1551819b8be1efea2fc46ca749aa1221461dd481a114a2e761c554b641742c973867899d32214685b1ded8013785d6623cc18d214320b6bb64759221472b61c6014342d914470ec7ac2975be345796c2b2214733fda7714a05960b7536330be4dbb135bef0ed622147ae2f5b9e386cd1b50a4550696d957cb4900f03a22148b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec7322149f8ccdafcc39f3c7d6ebf637c9151673cbc36b882214a6f79b60359f141df90a0c745125b131caaffd122214b218c5d6af1f979ac42bc68d98a5a0d796c6ab012214b4dd66d7c2c7e57f628210187192fb89d4b99dd42214be807dddb074639cd9fa61b47676c064fc50d62c2214cc8e6d00c17eb431350c6c50d8b8f05176b90b112214d1d6bf74282782b0b3eb1413c901d6ecf02e8e282214e2d3a739effcd3a99387d015e260eefac72ebea12214e9ae3261a475a27bb1028f140bc2a7c843318afd2214ef0274e31810c9df02f98fafde0f841f4e66a1cd2a140bac492386862ad3df4b666bc096b0505bb694da2a142465176c461afb316ebc773c61faee85a6515daa2a14295e26495cef6f69dfa69911d9d8e4f3bbadb89b2a142d4c407bbe49438ed859fe965b140dcf1aab71a92a143f349bbafec1551819b8be1efea2fc46ca749aa12a144ee63a09170c3f2207aeca56134fc2bee1b28e3c2a14685b1ded8013785d6623cc18d214320b6bb647592a1469c77a677c40c7fbea129d4b171a39b7a8ddabfa2a1470f657164e5b75689b64b7fd1fa275f334f28e182a1472b61c6014342d914470ec7ac2975be345796c2b2a1473564052d8e469ed0721c4e53379dc3c912289302a147ae2f5b9e386cd1b50a4550696d957cb4900f03a2a149f8ccdafcc39f3c7d6ebf637c9151673cbc36b882a14a6f79b60359f141df90a0c745125b131caaffd122a14b4dd66d7c2c7e57f628210187192fb89d4b99dd42a14be807dddb074639cd9fa61b47676c064fc50d62c2a14d1d6bf74282782b0b3eb1413c901d6ecf02e8e282a14e2d3a739effcd3a99387d015e260eefac72ebea12a14e9ae3261a475a27bb1028f140bc2a7c843318afd2a14ea0a6e3c511bbd10f4519ece37dc24887e11b55d2a14ef0274e31810c9df02f98fafde0f841f4e66a1cd").to_vec();
        let any: Any = mainnet_header.try_into().unwrap();
        let header = Header::try_from(any.clone()).unwrap();

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        // trusted
        mock_consensus_state.insert(Height::new(0, 28255845), ConsensusState::default());
        // current epoch
        mock_consensus_state.insert(
            Height::new(0, 28255800),
            ConsensusState {
                validators_hash: keccak_256_vec(&vec![
                    hex!("0bac492386862ad3df4b666bc096b0505bb694da").to_vec(),
                    hex!("2465176c461afb316ebc773c61faee85a6515daa").to_vec(),
                    hex!("295e26495cef6f69dfa69911d9d8e4f3bbadb89b").to_vec(),
                    hex!("2d4c407bbe49438ed859fe965b140dcf1aab71a9").to_vec(),
                    hex!("3f349bbafec1551819b8be1efea2fc46ca749aa1").to_vec(),
                    hex!("4ee63a09170c3f2207aeca56134fc2bee1b28e3c").to_vec(),
                    hex!("685b1ded8013785d6623cc18d214320b6bb64759").to_vec(),
                    hex!("69c77a677c40c7fbea129d4b171a39b7a8ddabfa").to_vec(),
                    hex!("70f657164e5b75689b64b7fd1fa275f334f28e18").to_vec(),
                    hex!("72b61c6014342d914470ec7ac2975be345796c2b").to_vec(),
                    hex!("73564052d8e469ed0721c4e53379dc3c91228930").to_vec(),
                    hex!("7ae2f5b9e386cd1b50a4550696d957cb4900f03a").to_vec(),
                    hex!("9f8ccdafcc39f3c7d6ebf637c9151673cbc36b88").to_vec(),
                    hex!("a6f79b60359f141df90a0c745125b131caaffd12").to_vec(),
                    hex!("b4dd66d7c2c7e57f628210187192fb89d4b99dd4").to_vec(),
                    hex!("be807dddb074639cd9fa61b47676c064fc50d62c").to_vec(),
                    hex!("d1d6bf74282782b0b3eb1413c901d6ecf02e8e28").to_vec(),
                    hex!("e2d3a739effcd3a99387d015e260eefac72ebea1").to_vec(),
                    hex!("e9ae3261a475a27bb1028f140bc2a7c843318afd").to_vec(),
                    hex!("ea0a6e3c511bbd10f4519ece37dc24887e11b55d").to_vec(),
                    hex!("ef0274e31810c9df02f98fafde0f841f4e66a1cd").to_vec(),
                ]),
                ..Default::default()
            },
        );
        // previous epoch
        mock_consensus_state.insert(
            Height::new(0, 28255600),
            ConsensusState {
                validators_hash: keccak_256_vec(&vec![
                    hex!("2465176c461afb316ebc773c61faee85a6515daa").to_vec(),
                    hex!("295e26495cef6f69dfa69911d9d8e4f3bbadb89b").to_vec(),
                    hex!("2d4c407bbe49438ed859fe965b140dcf1aab71a9").to_vec(),
                    hex!("35ebb5849518aff370ca25e19e1072cc1a9fabca").to_vec(),
                    hex!("3f349bbafec1551819b8be1efea2fc46ca749aa1").to_vec(),
                    hex!("61dd481a114a2e761c554b641742c973867899d3").to_vec(),
                    hex!("685b1ded8013785d6623cc18d214320b6bb64759").to_vec(),
                    hex!("72b61c6014342d914470ec7ac2975be345796c2b").to_vec(),
                    hex!("733fda7714a05960b7536330be4dbb135bef0ed6").to_vec(),
                    hex!("7ae2f5b9e386cd1b50a4550696d957cb4900f03a").to_vec(),
                    hex!("8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73").to_vec(),
                    hex!("9f8ccdafcc39f3c7d6ebf637c9151673cbc36b88").to_vec(),
                    hex!("a6f79b60359f141df90a0c745125b131caaffd12").to_vec(),
                    hex!("b218c5d6af1f979ac42bc68d98a5a0d796c6ab01").to_vec(),
                    hex!("b4dd66d7c2c7e57f628210187192fb89d4b99dd4").to_vec(),
                    hex!("be807dddb074639cd9fa61b47676c064fc50d62c").to_vec(),
                    hex!("cc8e6d00c17eb431350c6c50d8b8f05176b90b11").to_vec(),
                    hex!("d1d6bf74282782b0b3eb1413c901d6ecf02e8e28").to_vec(),
                    hex!("e2d3a739effcd3a99387d015e260eefac72ebea1").to_vec(),
                    hex!("e9ae3261a475a27bb1028f140bc2a7c843318afd").to_vec(),
                    hex!("ef0274e31810c9df02f98fafde0f841f4e66a1cd").to_vec(),
                ]),
                ..Default::default()
            },
        );
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(56),
                ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
                latest_height: Height::new(0, 28255845),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
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
                assert_eq!(new_consensus_state.validators_hash, keccak_256_vec(&[]));
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
    fn test_verify_membership_lcp_localnet() {
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
        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(
            proof_height,
            ConsensusState {
                state_root: [
                    51, 143, 168, 48, 229, 178, 255, 245, 35, 4, 82, 182, 21, 136, 15, 201, 229,
                    227, 54, 146, 158, 189, 229, 10, 242, 165, 205, 60, 170, 52, 212, 78,
                ],
                validators_hash: keccak_256_vec(&[vec![
                    185, 13, 158, 11, 243, 253, 38, 122, 99, 113, 215, 108, 127, 137, 33, 136, 133,
                    3, 78, 91,
                ]]),
                ..Default::default()
            },
        );
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                latest_height: proof_height,
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
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
