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

        // Ensure trusted validator set is valid.
        // If the submission target is epoch block, the validator set is included in the header and not in the consensus_state.
        if !header.is_target_epoch() {
            let (current_epoch_height, current_validators_hash) = header.current_validator_hash();
            let current_trusted_validators_hash =
                ConsensusState::try_from(ctx.consensus_state(&client_id, current_epoch_height)?)?
                    .validators_hash;
            if current_validators_hash != &current_trusted_validators_hash {
                return Err(Error::UnexpectedCurrentValidatorsHash(
                    *current_epoch_height,
                    *current_validators_hash,
                    current_trusted_validators_hash,
                )
                .into());
            }
        }

        // Ensure previous trusted validator set is valid
        let (previous_epoch_height, previous_validators_hash) = header.previous_validator_hash();
        let previous_trusted_validators_hash =
            ConsensusState::try_from(ctx.consensus_state(&client_id, previous_epoch_height)?)?
                .validators_hash;
        if previous_validators_hash != &previous_trusted_validators_hash {
            return Err(Error::UnexpectedPreviousValidatorsHash(
                *previous_epoch_height,
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
            let state = self.consensus_state.get(height).ok_or(
                light_client::Error::consensus_state_not_found(client_id.clone(), *height),
            )?;
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
        let relayer_protobuf_any = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212ed150adf040adc04f90259a0be2e2be652d2fab005526d730d842431fe0a62511552f68a17ccdd3efac5fcfba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794c1b53c6bf112a572f3059e2ec156fd24667a2b9fa06283fa44addd18c8c757f1136f732b48a2ef1e8c5eded318c460e4ad2610d6aaa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282027a8402625a0080846460b1a8b861d983010111846765746889676f312e31362e3135856c696e757800008956373651dd48eba1bb11b8f9bd12aac2778bf74e0c4df2d98286bb10c09d6572f4ea433aff1c88731281f7ed8e571d5eb28086a6b413fe50f48632146d3aa259511b7f00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000adf040adc04f90259a0c0a529cb2f705c7cc4ff7fc4703b9e2bb49c34234bfd1768a621b80dd3783e2ea01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479410515e82bc63b61f072e3b4f2b64d0c70f275e7ca06283fa44addd18c8c757f1136f732b48a2ef1e8c5eded318c460e4ad2610d6aaa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282027b8402625a0080846460b1abb861d983010111846765746889676f312e31362e3135856c696e75780000895637368adfdf7a32bcf5b47ccba1d22860b8f8d5dedb639c2bf9bf2af9b080134b2e785a5d9c345fd27de395c0fce515cb8d8389c7213f22715eba8778baa26cf7339a00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000adf040adc04f90259a0b6476d63cb5ac37bd939f66c36facc2f4a6fe881e7cbe6ea7b1d1560bdf3a0d3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347943cbeba7180b31b37a253c42b69aa40df3e2d51eba06283fa44addd18c8c757f1136f732b48a2ef1e8c5eded318c460e4ad2610d6aaa056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b90100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000282027c8402625a0080846460b1aeb861d983010111846765746889676f312e31362e3135856c696e7578000089563736769383600e87d9dd933304b4c09de4d7dea13f560813001f9abe969fb6eeed605be0afbcdbab2caabe40b9906666c343a71e843202ce96a238054dc7628a1be000a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120310f1041ad505f902d2f901d1a0720a09fc803cc6c8935813289e0934d5dbb3dcdaee735f9a343a93b851ba8de7a088bbc97920b6c8e02b2e306623b41b5256445fe59a408c000f8ba4d18725f9b7a0dcf0908675c7b75cfb42c358d48bb594a10c0c689c1eaee95e119235a949acdc8080a0ce574fc452b8e3543191406758d8f14744f1c3239882ff36de65c311a31032c8a0e72573919bd9e9a5ae04b5ceca9d823ddc66ec9c535a4dd2ca8505fc8b51d4eca099ea5f03336678dd624cda4dae4bd14efaff9e42506708d5b715f5a92780caf7a0ea5d9b712a33f5eae8426276eb8d22c325276a8936111c45b3489db4f166d32aa0e83c004ac957487c6838c3b73bc7b52981e91f94952127c58b1156d18dcd01dba0eb2c6da4f74980351ee9612496af26b6b4152c254a2c0f9245c5f4814fbe33aca01011c052441780ca70b46a1b8affbe8cd6b8a650f7f063f3943a524742d0b468a02a53b86c1c583f89d0894cc0e0d2e321f4e2bac4f08d2f477980f9dad1828d58a041eee44d7cfd75235296a3a6805d64339166f35ea79419f5313fb975e4b51e9da04ab3d2fe1684946e19287a90b6a16c42aa258bfc3d85fecc2e06c91235498c2ba014aba434eb1d9c3fe9dc4a71d5d01591d2718b0b7ff9774e78650f832ad58ec980f8918080808080808080a0d0bb13caaa0b3753a32816bb2af8e832e7f70e782c287a757f820a7a996d9b4780a08aca4b4250df553243de7b7eb4315161178efe38e3f523235e9323681fa44a3280a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5cceccaa063bbda017ccca59c09f11befce4a83265aa2422d818230c3d37b6cefb9008f42808080f869a0209cc2669227c563939b3db2109a60801ee273f50dea6929d2646facb70ad234b846f8440180a0d7cb130faec40201a8c1656faee693ca0902f6220c9b67649f0a306daa85d113a00615ec2683804db553073603c86cc49e83d62d68cd3495c1d45e464c451cfafd22730a03109003121410515e82bc63b61f072e3b4f2b64d0c70f275e7c12143cbeba7180b31b37a253c42b69aa40df3e2d51eb1214475284ee3de01899b76ee28ac3d2b2e3d5f5dc681214a5d3a2383997efc142bedf703c143b37b39306ac1214c1b53c6bf112a572f3059e2ec156fd24667a2b9f2a730a0310d804121410515e82bc63b61f072e3b4f2b64d0c70f275e7c12143cbeba7180b31b37a253c42b69aa40df3e2d51eb1214475284ee3de01899b76ee28ac3d2b2e3d5f5dc681214a5d3a2383997efc142bedf703c143b37b39306ac1214c1b53c6bf112a572f3059e2ec156fd24667a2b9f").to_vec();
        let any: Any = relayer_protobuf_any.try_into().unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(
            Height::new(0, 400),
            ConsensusState {
                validators_hash: hex!(
                    "4698f363764c0e2bbb128634bd4807dc46083950de351da9b053f189210820ff"
                )
                .try_into()
                .unwrap(),
                ..Default::default()
            },
        );
        mock_consensus_state.insert(
            Height::new(0, 600),
            ConsensusState {
                validators_hash: hex!(
                    "4698f363764c0e2bbb128634bd4807dc46083950de351da9b053f189210820ff"
                )
                .try_into()
                .unwrap(),
                ..Default::default()
            },
        );
        mock_consensus_state.insert(Height::new(0, 625), ConsensusState::default());
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                ibc_store_address: hex!("702E40245797c5a2108A566b3CE2Bf14Bc6aF841"),
                latest_height: Height::new(0, 625),
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
                assert_eq!(new_consensus_state.validators_hash, keccak_256_vec(&vec![]));
                assert_eq!(
                    new_consensus_state.state_root,
                    hex!("d7cb130faec40201a8c1656faee693ca0902f6220c9b67649f0a306daa85d113")
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
        // height = 28196089
        let mainnet_header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212bf590ae4040ae104f9025ea07ae60621635dcf3585f87bbb06c1899ec923a952f3347a932740a3312e3b3fe1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ee226379db83cffc681495730c11fdde79ba4c0ca011b82c7c97bd376f8853ac46194272737bd74e41837413b8e48b9c627a3d1501a034cd08816fbef96f3e1e765128df91b67bbf74dd34691f7d5d7016a5a2132370a03ccad3bc969004d260c13a77fd289773e037d932d9dcb8089672671abfd2db33b901005ca11318153cb590eb50b26ad31088fe8d2148c28302cc29b392c5312260c030e5581177413c12094b081159ab5a012a661304481a022181d0480d3022354a002550480a994889aa6132411db02582ba28b30958d1658dc3142f9f24943907bb5ed75a624b5211b2b421ea82a058dcd00cc0884319a815a25201ac10807e5cd2dc360fed861b1349e985265acb46901e042405a7e8e0381f0d0842caff2a0aa80722020afa8a237ab24a6156abea05d204084402519f1d0914c179a521129acc31223e52012869c71ab02043b6b813eba1d5a5fb0d50a8350340522a0a2af0a9fa95d1043014875903618c1611404ac6743dc720519ac368f5bb33700aab5a4f028401ae3cf984084fc9d883bea6c6846460816fb861d883010115846765746888676f312e31382e32856c696e7578000000f98d10723dca2f2dd534a1179809f9bec4093243b02cd0b27401852aba08a6100b96c2d138aeaaeffa3ac635ee5cc8a0121166b8ab7ba6455f91b69164718fdb23b5be8e00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea07f0e07c7203daf4932d47b54a714137e65787affbec5062a14f3aa0dbe52cb7fa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794ef0274e31810c9df02f98fafde0f841f4e66a1cda0c974f0b4bda963b0dc409871d28489ad24323e839b7e00c7224dab41836456cea01bed1d60340756825ebb2f6add361c7727897e47e7faca23a3f362fb66074d69a057f855b0d36e57426a22a47d0b027b098d5a48b54c5404fdc2543773b98412fab9010080b06262c031055102401082b6148c4e2c00614488d10808261329919a009915c1140140400000486a801800203841014fa3589c28009283408c040d163002059060c0138b30880101214049e00230a8e0504840018800625616652898010080e804d427a6120419380322d98040ae105ca7880001c94084004300105a804c8412010004002930090090000810485800a524050178008009088004ca0d0054200ab03120f4d8027899183264528a0001602515ac2024058b21f03165a5970248aa241046526a19c2d01188a04148d03a22c060c280a0043f0121720a220ba0201e148185008880a1c1411102878405c0409840a8900a5a58a802220438e05a06028401ae3cfa84085819a083750fbd8464608172b861d883010115846765746888676f312e31382e32856c696e7578000000f98d10723e7696eabff49308e6de0a3f3a1846942ab0f59341d8d81d56080713bad5e0c021d33d36b4714c8a9b2a3368f81b07d190a6daac2865efc1cde1de45d8facb0900a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa0022e92a9a70688686c8156f23cd40dd248562e95f0442df012828b7c80e279d3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940bac492386862ad3df4b666bc096b0505bb694daa051d985f721dc6d0f5cabc2b3ec5aada97ddcc926aca019dc3e25311833366d96a07cf3b264175c0bc64523c801e0e27f7b812058689f1d491c7e39999d9f02ec6ca04b12eb4bde19e29d0dd931ff36b07169ecc4dae28e10b91f3bea93b347bdf170b90100de33e7c1a7f55e7bd9fae77feef8f5b6b7abe7e516f1eebf7f77b92f7987fff7bf564ffb7a04571b5bb77fb7b7dec77fcf77ab7b8fae3747ec6a7d5fdc6ffff71ffff736adf9dffbdd7ff3e8f7fb9ebfebb527fedae67b6e7e77cf368695e7ecda9f4d3daf879dbe0ed7eda78efbec7bdb4cbcf3cbcbfde6dcb3af579b7b9e1ffde479adfefbfcf5d5b93f67bf70fbdffda71eeffd6ebcffc72ce7da1fd77ff1faf2f27ff6bebb1fbf73f35cafffc62ffffe56bc95abf7837eff3f6fffb3fef9b729feefff1dbfcef4b44a7b76ef72eb34fdffa3bc7f747d7cf776fbb964fdf7fefdfffb675fee799fed62f3bf17ffc67f13dfef6cba3effedbfef2dbbb57ddf028401ae3cfb84084fc18884011802bc8464608175b861d883010115846765746888676f312e32302e31856c696e7578000000f98d10720353cd617c1a63b7199d5a5adf185ef250c92c5926ed5835ae2383a3b346aea1427d6bdb16f034a947cbbc3f8771fd612a8b4b386031ede8ae66f975c73a994b00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0b00fc640e2026a72b33ebc526e220eed5a7af0c81fee778a2b80d43bde295d5ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942465176c461afb316ebc773c61faee85a6515daaa0763e38ada41c060569290f41dc9a73df87d31e88d9c9bc8782388c4e3db7d5f1a001349f5cc2444ffcfd9119c15c6b770f726e375bd94b044e709cdbb7b12a4bcca00a32f45e5ed5d4f5a8da13fad4764495a727459a8c7bcf61aa6732d006a9ca41b901002430070093182a1800c840f48098027a240442e0e0608220a180e1220a478930e822d6b943360811403ad874009f315018140819248b50c1182c255896346c00d6636005054a00224bc0810992b248bc20120c68e947281621a45409c8520608849705242a225d920040508c23208c48bca06a1dc109f49d4700843122b406028008242402184c4317a230001e58f2d47c6c168fbc94232a28b805d09c671e3886802200f1c003741030a95c02a08c84850f01400d0046311a01ba2c2b0409c4816f1c12105a5bc2170002414402952225e02c62a20488b50951020a10a0e01890b3cc5b110180888369a00a051c8a007609814a50ac4148e31962608860084e028401ae3cfc84085811488375ed2d8464608178b861d883010117846765746888676f312e31392e38856c696e7578000000f98d10721d964bbb8ad8c49a62f4f203ea373d1be3f845b147376732030935e8416b138a35bc5278d71c08bbfd1476ce90ceb6c1bd6477c723aebd628cdc676e1815c07f01a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa0183eb2fb9857d35bc7f0e576764dd163eeaa9c2dece22df27cabc3beaa297effa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794295e26495cef6f69dfa69911d9d8e4f3bbadb89ba0f7924d63c5364c9b12ca29fecc5fd49b8b2f0e87114705f00d98fa4a4cbba0cda09d81c3e102c2a2f53499036d027855087fe44fb325b92310190209fe7d19321ba046e8c7520e0a3ae1f393893935aa3dabeeb596424d2259a3fafac96193f3cc93b90100fee0bed33c853f7ead907c68dd11b43affc6ee38bd89a5f975b30129730aa1dcbee19ee641b8371747feec9d74fe4b197d325a99089bf3307c7d597d1fff378d87d26d1eb948da2b09addd3ab21712fcbe9b3ee2535eaa5ba7176e379fea6c21cb7c09779ba720ef65a16c80b2c9ac654a4ecc742b79f6df693dc632b7ef865158b8fdf62f677add99e9378c367bdaba5db78e17ef268819694940ecbfd63879ba11db3a62d88b437ed30b5e0f9e8ed4ad25c6f89e6dc5394bf429e0ade3a6d9e1e1bf3693da99f610c7bb11c50ffa2b3344337fb681a2f7bfac55ca8c6afd37f973bf9bb588cdafb315fadfe8400340eca594a5e2e3cc6b9f82b64e3f7400c7028401ae3cfd8408583b0084013f9001846460817bb861d883010115846765746888676f312e32302e33856c696e7578000000f98d107235081819992a4f29303ef3d8ca12b5af5fdd659ea7ee1c9ae1ef5575c372c3172f9992ad60c59e0023538daf3fea5059ecdab600209ccd4049f34787266f645d00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea07631ab5d13d01ff9851240adeb9ad22cd1725734bddba50ae2f6cb920e925e9aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942d4c407bbe49438ed859fe965b140dcf1aab71a9a0caf716f68e6b2b4b35c44df19a5b2c989eea5a0751f70a3c61f998ae9bd7bf2fa0cc1ebdeb719e75f3a0c65f880a3d8b3205184e50b9e617d28b6c904f3b3be8f3a00b97c9f269cb0c57be942c7093c62f3dde936bf5ce0beff257df6d0ce2c3c5a7b9010008a8169c045115dae02c30008810006240504e8803e04f89053218823006815aa0de9cc6d400040bdb90c20823922018c211939828522914c80844828860a020064880021d41c1200170564db26094a820f0004011aaa62104556500c210020420d63272260f4638444073a024808e5b0a00c269199b14004a0088149e5a0dca9a061804846bae4ca28906a304c88a08753504a5ac80010d042814c0c4816220c35092a2d20c83132311824c02aa52082450802004cdf149a1522a25624a38387d0014be290a2d421d102959603b332322c5a58680440c97136850420920e22b5a90a4d308c4c830010d360205248d02708cc281705a5059813b006d1b640941028401ae3cfe8408583b0083a9c1b9846460817eb861d883010117846765746888676f312e31392e38856c696e7578000000f98d1072ed8fef68fc793d030c58806b4ef01f23317da4a073119694e052e247cc704df30c76da6d684448011f5f8832bd190895e6352b3c849508456b5f3671e48998b000a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0344224d47d99edc6f9a13b99e4fdf0f25768b11383d7229a5ee6c1b511ee6483a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347943f349bbafec1551819b8be1efea2fc46ca749aa1a0cca229e6d98236a22a3b49e750b68c3ff4bdbd37dca1f6b98f87f60376838c08a093bf4388d5e663aebeb48e352803a7e21f8b051fba5bc374a46640462ef70e33a0ab81d5aceaa38a52e56793c774fb4bfbf86edbff760c2790e9d64eb69e96280ab901000e2106f01034de727c19ac45b2d11546b84cd172a796e7a13193c775a4c1c3d4ad8387c077993e35078080f879fae32aa85a09101c5071035b2be19294bf2cab5c4662948dd27ee2412f819cfbc892ba67b471bc14f58ac7ee1d4e2c86332528c8760426ca42900b209a7895c5659f1c4e7426f5a579ccc75b96c6389e22d753f80ea6ee65a92101a0e1259715669b9e642d95cd78364b8b2b1b91d3cda83a61abda4200f7da874877dd775587ce47da283491aa05a9f5f5547b382d758328ece6f1559256421dd79580aa6921a7b6f8b3ee4956a940c8bf1359fb8ac130f2251492b5502bb0d3d1954f2197bd4c8ca85cedaf7a439a4468e02282405aaa487c028401ae3cff8408583b0083e543058464608181b861d883010115846765746888676f312e32302e33856c696e7578000000f98d10729f981fb4cfb07a910b0439f655bad72168b5679e1516e3513f82073744ccc31e62e8743ec1e30401a960dbd6c8b11d7cf126bcceb254d43bead98ad0df46102201a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae5040ae204f9025fa0d77fd0bc22ac943762fdc11ee48cd4c72db11337a14992dc698ad083202496a1a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347944ee63a09170c3f2207aeca56134fc2bee1b28e3ca0e93be92bafc527a4c9c8c793c49e34c7894487d98c9369cdc0672ab86a0228e4a080d6b63a886a08e8f23bf241b8c0474526a970d0b2ab34bea43750e5d3857a3ea07f9ab456fdca6c0ee3cbe2369fd023188bb49756a75d4d8c9225b08c78212276b901006fb0127040d095fc27041040b410014684a05a642a9210383066bd217e488070e6141802638016002a6839a85a9e222d5b124889800ad123420c645c09be04440752d4501d782340959093199b39e0fae0960d2d4374f90609067c2983b8c6d83af509a74f273d775c4324d0da44ce43bac880f9802b44060115e614c200c0e79aa22c444b9b66c10588771227f55cad552487876d674588e54842e00c9c06218bc42285d20a663806d8074d1fb44a202ef8809a45b52a15797c9cf12544e8d726a91d12301939d611629123644254a029c693f604202c970fc15c439070e08d3b95f90900fa9340c957222a630028c215048574929a5ce82db506099a305c94028401ae3d008408583b00840108c5fb8464608184b861d883010117846765746888676f312e31392e38856c696e7578000000f98d10727abe5eb629a099e186db6e3465c786d542a6d20d47814b345b167152d8bbdac46de1218bb926f257047c2cac3e743aa9321614fd8b69409377ecceb8ef8246b601a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea070928d5aaef93e113b2912a06b96ebebeaea8f8bd798f056d05a0b97a2b58daba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479461dd481a114a2e761c554b641742c973867899d3a09f25f4a5602537ed7e404211cd84ba3ea34d74186ada1f8913c2012ad8797205a0fafc7a958b223d36bae97d56a4106badfe26dbd3924f38e307ac4a5f42a28ecda0a742b09fd469b32c57f86f831ae17c35497b0e7faa70d59c4091198933572179b901002aa03674bd18473fc860fa80d81cd2620401584872d16e813a264c233a7b9133e654188850945001c298c86180da2006fa4080c328a26800371c08c4acac21e0547b0230414b880b3113110bb1a850a9201101214967c80e20845cc4a009a4a54d5499238302462308c1bacd8084ccda3860686b8be9c4240225c4140af880a3ce00c9c4094f100a1e98e300a4d4da851c241585f824638fb17006c106898220e7904007d4b623321231ea4e07b04403f429a10e240d522104d0e87121109034a5e811b6ae4809c2b1571bcda1867064a1608979c54f949b2dcade263035e30bfc988201119088084145920bb305a7a64524f42d1150506834c0a24c1d228e14028401ae3d018408583b0083bf93258464608187b861d883010117846765746888676f312e31392e38856c696e7578000000f98d10728f53d81afe6cb7e60b34bb7bdf2138cfcef84897f9ad81dc3cece3c29bac8dfb3933d05970d14ec4fbdf3cec45bfdfa5c2e91c116c3d67f6463c4589629febbf01a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0a7f9362938b4c1ae91440aebb13157d7ea6ee4c47da95b9e25c892cde9f1c2f3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794685b1ded8013785d6623cc18d214320b6bb64759a048e3e2b298372981303bc5b048d48ff7f520cad30c58905cbe6eeb72fafc5071a045abaac2c36772f9d2d7528d278c75aa76e6659dcf37570096df383640591273a0fd241c52884cf266d5f89c872fc4963a27e647882bff5fd428a8fb9ba2fcd2fdb901000864163404111c50480a200889111407a0048b4609f18d0b5b931d1124119714841450420a0a10851b201c0d00dea1892151817002dc63105028045a64a460c5854a8c0249400c2a8ba7480f808400b028daa4e75267ee43ac147b0080889c859c60cf378212a03fc4006c10e4e28c614840a853491905aa03826d14822c04609043200d0e050a519580574062720cd9063e56853ca81439c13af2408cb09820caf8d85290ac413aa61440c403ba0c914205800c018dc961056c323ea693ca4bb0015412160201e7c782c08ce28614403c84806bc01c29b9850192ea18a1e42b44f1c1203240d2a1593403829d7910de5a8c04c05950606c89c29b1c03b80d48028401ae3d028408583b0083921dc6846460818ab861d883010117846765746888676f312e31392e38856c696e7578000000f98d10723ca41992e88896e999e666af1ccedbea6c5d1c2eb611c14d2b90e215cd7b04687a3cffeb40b3442676471e4307e15e6fc1ceb88e346dd1ec74d05110a0865b8100a000000000000000000000000000000000000000000000000000000000000000008800000000000000000ae4040ae104f9025ea0347ee0db984397cd9252db1c2ac382ac30f0e5d5881248344f4ce291d9c7ac7ca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479469c77a677c40c7fbea129d4b171a39b7a8ddabfaa0e9b18f56f0c0fc634320c29b12dff40d257d3e2df80a26fb2f30a419e1c47db4a0dcee50a7ad58c175d7adf3f22169dd2636d1d1ceb5dfa497c964edd78678659ba0dba9471154bafbc53cc526136c90c5968af2b7ebd0a9fa0b3071bb0af2cae0b4b90100c025a36186dc0970715c60cdd8d1140391844758c4c08f4af7634335bbc4b891e4c499c1cec84c114900db7a2952189b0b11c05e092b615032386c2508b725ad9449f024176a5a3745c30159a620a2a8331614e04356f90aad144785d417270668164d31df96e07da4c03cf6e560bcd249328001681a548211a43c33e3ca98d31acdf1962d1e70c0848893518cce2c526cb5b4c5ece1d98b322804531cb8aee0ab9585c2d5149a805f19725592c184c04609690a3ff854070f2548a229b10b4003019932c10139c750a42b478284972435d71080a18a80508342f0422520fc5630f4dd2934b0a009dbe5228da5150da05c450169b3e8604825006aca4f234bcc028401ae3d038408583b0083ae551f846460818db861d883010117846765746888676f312e31392e38856c696e7578000000f98d10725191932030b605219862975755dd55f0a56c02ebe1ec8ee30805eab62f7f881c548e66319ab510997ec78a06cddb35cadadef93f83dc50c4552af103963f68c600a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120510f8f9b80d1a951df90e92f90211a0bf2c09711418fd755d9d67788922d71596af5ec6d4f04fc6c377cbe1e9d1e334a0458d6b7e89de89ffe571ef6874802be0832b2dc4a5d7b9f478e395328c102e78a0d9ad8a427490c19787a3c680478455b6cef104b1321fa136ef5e96e55273179ca05547ac045553fd67cca3cea008ccaf9c915ad823a1e1e37279a62636fd0337d4a08c3332a3ac065e139a7d4d085959b4aa8ccbdcc2d4b6fc809677c9931ce50d1da03f4b19bfc13fa312cb761a9ca252fb8835cdd927b0487da43c7dca9c2bd2a2d1a071c0d64b36b404991a7c28e6ff4ea1e70aa9f830901e92212e720fa1ff966a07a06a3d758b6526847d54717a16e80c21bd0e099becc331fa490e550c2adb1ebc07a0b76160d54006e17374ab3caf21f66d14d90098ba4150f79327121d5240250a3ca0c7b6885f604bd4c40e01413531c59197c06c25e0f542e168bb8a3df1fb2e0da8a0377e2c6312e7b002050f250593625567d24d7314e748f69667078099bc9f5e41a0ae994e7bb5177efe3951e77e735fb1e9eef3ca7dfdb565de54990fe056cb99d0a003e2de9f64ad54384ef0dffba58ed2bbae4db98e7467d32d54dfc1d270629df4a0ec0a9295ff2f1082cd6c9709efa7984cbcc46719c8f8aeabaab654eaf8a8c485a0a16075e2e0fb061edf770c25c61c61bcf33c8dc01c24048ccd6c592c5cd694a1a041ac0b5c26aab0fa14be025f25475564f948f2875b0a3ed66f434805c8032bc380f90211a087d5fe877cb1d1177e5eeb02564ec5ba146d79d9d699a7ed4b00a35be8f58bc9a046b410df6d5d56afbcdf61fbc646ab5720d050cf88cccb51b9d440fb8be6611ea0c1e37109daab40ba03b68af134e24659caf0cce63feece2ce930155cb3a7ba33a0c1b289bbb55375fba2323bfd41729c4801f786cadeb936d21e3fb2508a42a2d5a08d156ca0af1266b63a4c73b53ac3b12f49cd581110f048914c61e8e0aa3c700aa0560a2ed03bdd558cb1231c17c8669c17afcf40a911abad45f544ca34d7a544c5a066bf083e9154977a9345ae7195b5907609f8212fa6ddd0589b8a72d09a09969aa0134b18bfe7f1b1ae1003a65ff2e5355767b6618cc03b60da8f6c70376d30b89ba00b2b912c6f1971c8bc24f0034a972c2d079d8983ee65d7232909e5601d225c01a0a2dc9ef3c8dee50c08d7ae649833a8f9313420383b24e3d85abb2e84f916b085a0736080ed0c1b6d2e9d7c904cf58c2c39beb6a93814129f5b312022af76818286a01352f9fa4fe3d395d668a5a25e65668beff6b6f7b75fb01b15488d096d5824cba0885000bafc84566ad28dd9081145a38724be5eebff7a8d8c85b040cfe11074faa05152505faa177d1cdcd702fbc16182c077e4abffa33d697094865617b6cbc9b4a08f6a3428c6c6502ab7122c31dc49f9b738117a20b30968e658463eb86587f1e4a001f0881e0ae6ee570d8ca0f0b577e042962f44bd6172a74f3f4050274825426680f90211a0e802a9b82469063dc49312deda492320a3ba8001966969901b1494b89fa14ce5a013f1dbbc113367c74ecfbb6bc7d7f126c9ee082adb2c48d66808ea67475de326a064aeb3b164c72bf01adb45db351ff081ee8387ddc971b9935debbd3ee6dbb265a0e764c1344731851af2eb0e531289ef40943d00ed526ec4d29fdb9b01884c68c4a0b69382b45246c477979840b7b42de46e7bdd464eefa9d8e97eab88a0c0bc5de4a0a210453cfd51f9fd0abdedd9fe5bd1ee9deb08e222642aaea9e0020fa275a1d1a03982a363faba92f19f522e2d6488e524d902044695c9c5dc44feec2bf64b9d16a07c22b6bec46ec525222cc94d49cf7a725e720631872aff087cb3dd3867f80804a030ad735e01f5646c0e995c285ecdf414f850b79af724a2992f1c7036da5fe895a08fd1cda1b5801d45761aa4ed9d8ff1aeb5252e7fd64eac1f88fb4b1dc201b1cfa06bba4ac17b34bf4675f3685737dffbee2b92eb68ebcb362de0448ad7de329866a0fe29dd10331f7098b9d38de13f5653fcbeada436ac72ffefcc90f0cc180bcaf1a00c5de0d0283e7b46f5cbae40d8ba6d4e789488820feede954577be0a7cce0ce9a066db43d104955ec15dcaac64d4507fb9fa8e03e740ec56264057cda56915c9e0a0077c8f604ad745defe4fee9179e2ec62f68ea7e11cab92985928b18f7a50cdaba0eda12a0d5abb1d9ed0a3a37e1a5d767728732d715e38aa07ecc4315a6850524f80f90211a054e374e39626eab92851f8538a4c44a8e1076d5e32104c29af6aca4304e23664a0474f451afe70e2d10c51f7804932343166753a9261c477ec7111fe93812b4fbda05e8013356cddd7f0e3f1bb1936c4e6fa920bd114d7f4b45a89c45500bfafed47a0bf2511985fe57f8aa6d637e0648a00fb1ee1e16d9abbaa645a1fa5bfa1d8771aa0145df7df893f46216fd8b9bb2f3cc3b8b59825cf84f9753aedea6a8438553ef6a03b4e2c6d31c437e420ac1c1c6200f7b4a74d431a656ab7bd1476b8493fa760fba02e409e3c7b2547b9e3d319beec35c07f38670faea727f06cda2e463bdea323b7a0fe915bf973cde26d34bbee9ae81ceca3059b7d53560e8f22a861d4f9c7d9fd22a09cc639e374368f7c3c1434ebf97741ff8972eceb6882fc89bea9fbe85bbfbc2ea07c08cbb6120ef5ac5c0ad9a2de703274fdbf6160bd352383563b8f22e48a270ca088de3dcfd9b0fdf2c5e0f03bfbefc65e8b6a2a4363a872c053b51221cbc6d7dda0b412a8f422bf41b28e38af348831331ab9355ec5d2674d64a1ba97fb1b3d4273a01c0c0220442c72671f483ae197f146b949b9bee92fc1b5eba1a42b0d9d95eea4a0ba55b4c71d1c977651127573075168e8eed3c6f99e1840d909943392b4f05539a0d51da395cf22019d7c1657b2d0215643dc9deb2d7903e3427db6ddcf575b582fa08183256c1a844fe398c9e094b8e666d969e7ce1f779b2866c8e4cf3ccacf4cb080f90211a0703898fe8ddec83011d3a80e1589475f4e0a83503116951e00176e8cc0e36bdba0072a13dacd67744ce6ad5241dc9d86b1f8e6a7c4c5c055113e4f14fde3c42c54a09c18c5fc8eed72502254105518019772fdf5dcf8c0fc7a3fbd115afaa9f79f5ca08620aae2b3ff20390a95b5832310331c1abb2f9c71cc2e4d744246ab0748c40aa0ee91031e983caa09227f2508de317898650dd6c180c6c549243cd53f688797ada05e952d06d04e09546f9d475c6b7cd4ac9995fa6adfdebe43e82d19f1539bc5d0a0ee4ceb23921e334b4ca37d27bf173a1b2ab38b9b65510fb5e86235771ca6221da0dba52d75f327f1f98d266cb0f71bd1cfbca42a01b0388ac99d5c4ff9ceff6e56a025b8ea692c55d183afeddececd1faaa9b6619c0010f1e0e4e7874cfd32ef604ea0e63025a81fb4115413530f1f62ea18ae0e4dbbc75585b22c4b9a7152d93b16dca06cc586f60d537764bf90612174bfddf2146fe3e6642db240c68d182d702a09b6a0105878367722948ce9918d5fe1032cf432208ac084b0a1ae8b155e26e0fb2798a018f175f7841d8782f1dac1d99c30dbd6930793cf9e5344fe81f62dad08785249a024e0e8cbd66f52d4ae6e14bccd6f7f3a359d5ca137507fca570d32a016be9897a089778b85e62ed09832707bbdf1f3a24aac213fc469bcc4a9bf99c5efbccc7557a0ec31637ed551a8875462b96a13045e965f1cc848a3c1003b3c1353967bf7d48980f90211a0ffcd8cf122c5b89b75f81a8df22d1cab9a6c8900f4deefe947bda17ab18097f8a036b45913ac0c1b14bcc4ae95b1974657cdccf7ea1336400ce45ff84a8bf72bf4a0e41524e500d6245e0fe091a6be8ddbea41ea9ae84ed92251409f93ad953022e5a011fa91a647a311ac0fb59d2b5fd3d1c61eb55d6cf72cef117c1cd554256238f5a0a95146aff5b838dc1f16af232b99a0c7d707f71bd7f461151406d3af990d9aaca0911cb58c6551cd7d010babaf67c5c2d9e23928c5dacbef73d5f93a7fd8e02cfea0c147be76c0ec348a1e554c945a766e7ef01a00ce0b17ee749e971c7ee1ec6ae4a0a33abf2e1b189ab9b029f0fbbeaf538e53f396473204097e4e0c3665a89c6aa9a0332073d2912755e3a07f8af115990967a46ef3d1435666e504f0b601768c22c4a0f89bc877328f278d40b1e9bf42e73d560b130dd2bd59b1921d178a60597ea87ea0e3ccdf51b6daf16ba563ae5b3bea3b87585af2fa64e944d0d74ba5d7810d1bd6a0eb92f299631911a75fd978fbccd4c9cc8c7fce20d17a7e7d34d0a77fe83b6321a0669afbdec695fe440f5528e984fda0ac28021c51d52fd4a50cca7f475eb6ab40a0b05ab82c2b8fd34834571088eca09959e6dafd4c83b717352f0a6b5f5a9c123aa01623c1d910bcf5129b4362c0d255e15e3b5128d7f2e4171a5a885d32f8d298b1a04050d4918e9eccae4dbf113b6197e1308bd53a268f21342e9a183bda371df98a80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df808080a0c5251c3c07ae259b1880cf572e5cd373e389930822fdc15ceb35c1cad972d40ea04758dec46d9a94ceacf2d3f2cc3987b78153c7d56ed2f93061e460b33c58cb22a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a01011898e0e550d9b3799310a4848d65366ce0c98b969edb6322d24977dd7d826808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022d5030a0510d8f7b80d12140bac492386862ad3df4b666bc096b0505bb694da12142465176c461afb316ebc773c61faee85a6515daa1214295e26495cef6f69dfa69911d9d8e4f3bbadb89b12142d4c407bbe49438ed859fe965b140dcf1aab71a912143f349bbafec1551819b8be1efea2fc46ca749aa1121461dd481a114a2e761c554b641742c973867899d31214685b1ded8013785d6623cc18d214320b6bb64759121470f657164e5b75689b64b7fd1fa275f334f28e181214733fda7714a05960b7536330be4dbb135bef0ed6121473564052d8e469ed0721c4e53379dc3c9122893012148b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec7312149f8ccdafcc39f3c7d6ebf637c9151673cbc36b881214a6f79b60359f141df90a0c745125b131caaffd121214b218c5d6af1f979ac42bc68d98a5a0d796c6ab011214b4dd66d7c2c7e57f628210187192fb89d4b99dd41214be807dddb074639cd9fa61b47676c064fc50d62c1214d1d6bf74282782b0b3eb1413c901d6ecf02e8e281214e2d3a739effcd3a99387d015e260eefac72ebea11214e9ae3261a475a27bb1028f140bc2a7c843318afd1214ea0a6e3c511bbd10f4519ece37dc24887e11b55d1214ef0274e31810c9df02f98fafde0f841f4e66a1cd2ad5030a0510a0f9b80d12140bac492386862ad3df4b666bc096b0505bb694da12142465176c461afb316ebc773c61faee85a6515daa1214295e26495cef6f69dfa69911d9d8e4f3bbadb89b12142d4c407bbe49438ed859fe965b140dcf1aab71a912143f349bbafec1551819b8be1efea2fc46ca749aa112144ee63a09170c3f2207aeca56134fc2bee1b28e3c121461dd481a114a2e761c554b641742c973867899d31214685b1ded8013785d6623cc18d214320b6bb64759121469c77a677c40c7fbea129d4b171a39b7a8ddabfa121470f657164e5b75689b64b7fd1fa275f334f28e18121472b61c6014342d914470ec7ac2975be345796c2b12147ae2f5b9e386cd1b50a4550696d957cb4900f03a12148b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec7312149f8ccdafcc39f3c7d6ebf637c9151673cbc36b881214a6f79b60359f141df90a0c745125b131caaffd121214b218c5d6af1f979ac42bc68d98a5a0d796c6ab011214d1d6bf74282782b0b3eb1413c901d6ecf02e8e281214e9ae3261a475a27bb1028f140bc2a7c843318afd1214ea0a6e3c511bbd10f4519ece37dc24887e11b55d1214ee226379db83cffc681495730c11fdde79ba4c0c1214ef0274e31810c9df02f98fafde0f841f4e66a1cd").to_vec();
        let any: Any = mainnet_header.try_into().unwrap();
        let header = Header::try_from(any.clone()).unwrap();

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        // trusted
        mock_consensus_state.insert(Height::new(0, 28196088), ConsensusState::default());
        // current epoch
        mock_consensus_state.insert(
            Height::new(0, 28196000),
            ConsensusState {
                validators_hash: keccak_256_vec(&vec![
                    hex!("0bac492386862ad3df4b666bc096b0505bb694da").to_vec(),
                    hex!("2465176c461afb316ebc773c61faee85a6515daa").to_vec(),
                    hex!("295e26495cef6f69dfa69911d9d8e4f3bbadb89b").to_vec(),
                    hex!("2d4c407bbe49438ed859fe965b140dcf1aab71a9").to_vec(),
                    hex!("3f349bbafec1551819b8be1efea2fc46ca749aa1").to_vec(),
                    hex!("4ee63a09170c3f2207aeca56134fc2bee1b28e3c").to_vec(),
                    hex!("61dd481a114a2e761c554b641742c973867899d3").to_vec(),
                    hex!("685b1ded8013785d6623cc18d214320b6bb64759").to_vec(),
                    hex!("69c77a677c40c7fbea129d4b171a39b7a8ddabfa").to_vec(),
                    hex!("70f657164e5b75689b64b7fd1fa275f334f28e18").to_vec(),
                    hex!("72b61c6014342d914470ec7ac2975be345796c2b").to_vec(),
                    hex!("7ae2f5b9e386cd1b50a4550696d957cb4900f03a").to_vec(),
                    hex!("8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73").to_vec(),
                    hex!("9f8ccdafcc39f3c7d6ebf637c9151673cbc36b88").to_vec(),
                    hex!("a6f79b60359f141df90a0c745125b131caaffd12").to_vec(),
                    hex!("b218c5d6af1f979ac42bc68d98a5a0d796c6ab01").to_vec(),
                    hex!("d1d6bf74282782b0b3eb1413c901d6ecf02e8e28").to_vec(),
                    hex!("e9ae3261a475a27bb1028f140bc2a7c843318afd").to_vec(),
                    hex!("ea0a6e3c511bbd10f4519ece37dc24887e11b55d").to_vec(),
                    hex!("ee226379db83cffc681495730c11fdde79ba4c0c").to_vec(),
                    hex!("ef0274e31810c9df02f98fafde0f841f4e66a1cd").to_vec(),
                ]),
                ..Default::default()
            },
        );
        // previous epoch
        mock_consensus_state.insert(
            Height::new(0, 28195800),
            ConsensusState {
                validators_hash: keccak_256_vec(&vec![
                    hex!("0bac492386862ad3df4b666bc096b0505bb694da").to_vec(),
                    hex!("2465176c461afb316ebc773c61faee85a6515daa").to_vec(),
                    hex!("295e26495cef6f69dfa69911d9d8e4f3bbadb89b").to_vec(),
                    hex!("2d4c407bbe49438ed859fe965b140dcf1aab71a9").to_vec(),
                    hex!("3f349bbafec1551819b8be1efea2fc46ca749aa1").to_vec(),
                    hex!("61dd481a114a2e761c554b641742c973867899d3").to_vec(),
                    hex!("685b1ded8013785d6623cc18d214320b6bb64759").to_vec(),
                    hex!("70f657164e5b75689b64b7fd1fa275f334f28e18").to_vec(),
                    hex!("733fda7714a05960b7536330be4dbb135bef0ed6").to_vec(),
                    hex!("73564052d8e469ed0721c4e53379dc3c91228930").to_vec(),
                    hex!("8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73").to_vec(),
                    hex!("9f8ccdafcc39f3c7d6ebf637c9151673cbc36b88").to_vec(),
                    hex!("a6f79b60359f141df90a0c745125b131caaffd12").to_vec(),
                    hex!("b218c5d6af1f979ac42bc68d98a5a0d796c6ab01").to_vec(),
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
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(56),
                ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
                latest_height: Height::new(0, 28196000),
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
                assert_eq!(new_consensus_state.validators_hash, keccak_256_vec(&vec![]));
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
                validators_hash: keccak_256_vec(&vec![vec![
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
