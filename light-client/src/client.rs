use alloc::string::{String, ToString};
use alloc::vec::Vec;

use light_client::commitments::{
    EmittedState, TrustingPeriodContext, UpdateClientMessage, VerifyMembershipMessage,
};
use light_client::{
    commitments::{gen_state_id_from_any, CommitmentPrefix, StateID, ValidationContext},
    types::{Any, ClientId, Height},
    CreateClientResult, Error as LightClientError, HostClientReader, LightClient,
    UpdateClientResult, VerifyMembershipResult, VerifyNonMembershipResult,
};
use patricia_merkle_trie::keccak::keccak_256;

use crate::client_state::ClientState;
use crate::commitment::{
    calculate_ibc_commitment_storage_key, decode_eip1184_rlp_proof, verify_proof,
};
use crate::consensus_state::ConsensusState;
use crate::errors::Error;

use crate::header::Header;
use crate::misbehaviour::Misbehaviour;

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

        let post_state_id = gen_state_id(client_state.clone(), consensus_state.clone())?;

        let height = client_state.latest_height;
        let timestamp = consensus_state.timestamp;

        Ok(CreateClientResult {
            height,
            message: UpdateClientMessage {
                prev_state_id: None,
                post_state_id,
                emitted_states: vec![EmittedState(height, any_client_state)],
                prev_height: None,
                post_height: height,
                timestamp,
                context: ValidationContext::Empty,
            }
            .into(),
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

        // Create new state and ensure header is valid
        let trusted_consensus_state = ConsensusState::try_from(any_consensus_state)?;

        let (new_client_state, new_consensus_state) = client_state.check_header_and_update_state(
            ctx.host_timestamp(),
            &trusted_consensus_state,
            header,
        )?;

        let trusted_state_timestamp = trusted_consensus_state.timestamp;
        let trusting_period = client_state.trusting_period;
        let max_clock_drift = client_state.max_clock_drift;
        let prev_state_id = gen_state_id(client_state, trusted_consensus_state)?;
        let post_state_id = gen_state_id(new_client_state.clone(), new_consensus_state.clone())?;

        Ok(UpdateClientResult {
            new_any_client_state: new_client_state.try_into()?,
            new_any_consensus_state: new_consensus_state.try_into()?,
            height,
            message: UpdateClientMessage {
                prev_state_id: Some(prev_state_id),
                post_state_id,
                emitted_states: Default::default(),
                prev_height: Some(trusted_height),
                post_height: height,
                timestamp,
                context: ValidationContext::TrustingPeriod(TrustingPeriodContext::new(
                    trusting_period,
                    max_clock_drift,
                    timestamp,
                    trusted_state_timestamp,
                )),
            }
            .into(),
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
    ) -> Result<VerifyMembershipResult, LightClientError> {
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

        Ok(VerifyMembershipResult {
            message: VerifyMembershipMessage::new(
                prefix,
                path,
                Some(value),
                proof_height,
                state_id,
            )
            .into(),
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
    ) -> Result<VerifyNonMembershipResult, LightClientError> {
        let state_id =
            self.verify_commitment(ctx, client_id, &prefix, &path, None, &proof_height, proof)?;
        Ok(VerifyNonMembershipResult {
            message: VerifyMembershipMessage::new(prefix, path, None, proof_height, state_id)
                .into(),
        })
    }
}

impl ParliaLightClient {
    //TODO impl LightClient
    pub fn submit_misbehaviour(
        &self,
        ctx: &dyn HostClientReader,
        client_id: ClientId,
        any_misbehaviour: Any,
    ) -> Result<ClientState, LightClientError> {
        let misbehaviour = Misbehaviour::try_from(any_misbehaviour)?;
        let any_client_state = ctx.client_state(&client_id)?;
        let any_consensus_state1 =
            ctx.consensus_state(&client_id, &misbehaviour.header_1.trusted_height())?;
        let any_consensus_state2 =
            ctx.consensus_state(&client_id, &misbehaviour.header_2.trusted_height())?;

        let client_state = ClientState::try_from(any_client_state)?;
        if client_state.frozen {
            return Err(Error::ClientFrozen(client_id).into());
        }

        let trusted_consensus_state1 = ConsensusState::try_from(any_consensus_state1)?;
        let trusted_consensus_state2 = ConsensusState::try_from(any_consensus_state2)?;
        let new_client_state = client_state.check_misbehaviour_and_update_state(
            ctx.host_timestamp(),
            &trusted_consensus_state1,
            &trusted_consensus_state2,
            misbehaviour,
        )?;
        Ok(new_client_state)
    }

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
        if client_state.latest_height < proof_height {
            return Err(
                Error::UnexpectedProofHeight(proof_height, client_state.latest_height).into(),
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
    let client_state = Any::try_from(client_state.canonicalize())?;
    let consensus_state = Any::try_from(consensus_state.canonicalize())?;
    gen_state_id_from_any(&client_state, &consensus_state).map_err(LightClientError::commitment)
}

#[cfg(test)]
mod test {
    use alloc::string::ToString;

    use alloc::vec::Vec;
    use std::collections::BTreeMap;

    use hex_literal::hex;
    use light_client::types::{Any, ClientId, Height, Time};

    use light_client::commitments::{Message, TrustingPeriodContext, ValidationContext};
    use light_client::{
        ClientReader, HostClientReader, HostContext, LightClient, VerifyMembershipResult,
    };

    use patricia_merkle_trie::keccak::keccak_256;
    use time::macros::datetime;

    use crate::client::ParliaLightClient;
    use crate::client_state::ClientState;
    use crate::consensus_state::ConsensusState;

    use crate::header::Header;
    use crate::misbehaviour::Misbehaviour;
    use crate::misc::{new_height, ChainId, Hash};

    impl Default for ClientState {
        fn default() -> Self {
            ClientState {
                chain_id: ChainId::new(9999),
                ibc_store_address: [0; 20],
                ibc_commitments_slot: hex!(
                    "0000000000000000000000000000000000000000000000000000000000000000"
                ),
                trusting_period: core::time::Duration::new(86400 * 365 * 100, 0),
                max_clock_drift: core::time::Duration::new(1, 0),
                latest_height: Default::default(),
                frozen: false,
            }
        }
    }

    impl Default for ConsensusState {
        fn default() -> Self {
            ConsensusState {
                state_root: [0_u8; 32],
                timestamp: Time::from_unix_timestamp_nanos(
                    datetime!(2023-09-05 9:00 UTC).unix_timestamp_nanos() as u128,
                )
                .unwrap(),
                previous_validators_hash: [0_u8; 32],
                current_validators_hash: [0_u8; 32],
            }
        }
    }

    struct MockClientReader {
        client_state: Option<ClientState>,
        consensus_state: BTreeMap<Height, ConsensusState>,
    }

    impl HostContext for MockClientReader {
        fn host_timestamp(&self) -> Time {
            Time::now()
        }
    }

    impl HostClientReader for MockClientReader {}

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

    impl ClientReader for MockClientReader {
        fn client_state(&self, client_id: &ClientId) -> Result<Any, light_client::Error> {
            let cs = self
                .client_state
                .clone()
                .ok_or_else(|| light_client::Error::client_state_not_found(client_id.clone()))?;
            Ok(Any::try_from(cs)?)
        }

        fn consensus_state(
            &self,
            client_id: &ClientId,
            height: &Height,
        ) -> Result<Any, light_client::Error> {
            let state = self
                .consensus_state
                .get(height)
                .ok_or_else(|| {
                    light_client::Error::consensus_state_not_found(client_id.clone(), *height)
                })?
                .clone();
            Ok(Any::try_from(state)?)
        }
    }

    fn mainnet() -> ChainId {
        ChainId::new(56)
    }

    #[test]
    fn test_success_create_client() {
        let client_state = hex!("0a272f6962632e6c69676874636c69656e74732e7061726c69612e76312e436c69656e745374617465124d08381214151f3951fa218cac426edfe078fa9e5c6dcea5001a2000000000000000000000000000000000000000000000000000000000000000002205109b9ea90f2a040880a305320410c0843d").to_vec();
        let consensus_state = hex!("0a2a2f6962632e6c69676874636c69656e74732e7061726c69612e76312e436f6e73656e7375735374617465126c0a2056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b42110de82d5a8061a209c59cf0b5717cb6e2bd8620b7f3481605c8abcd45636bdf45c86db06338f0c5e22207a1dede35f5c835fecdc768324928cd0d9d9161e8529e1ba1e60451f3a9d088a").to_vec();
        let client = ParliaLightClient::default();
        let mock_consensus_state = BTreeMap::new();
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: mock_consensus_state,
        };
        let any_client_state: Any = client_state.try_into().unwrap();
        let any_consensus_state: Any = consensus_state.try_into().unwrap();
        let result = client
            .create_client(&ctx, any_client_state.clone(), any_consensus_state.clone())
            .unwrap();
        assert_eq!(result.height.revision_height(), 32132891);
        match result.message {
            Message::UpdateClient(data) => {
                assert_eq!(data.post_height, result.height);

                let cs = ConsensusState::try_from(any_consensus_state).unwrap();
                assert_eq!(data.timestamp.as_unix_timestamp_secs(), 1695891806);
                assert_eq!(
                    data.timestamp.as_unix_timestamp_secs(),
                    cs.timestamp.as_unix_timestamp_secs()
                );
                assert_eq!(data.emitted_states[0].0, result.height);
                assert_eq!(data.emitted_states[0].1, any_client_state);
                assert!(!data.post_state_id.to_vec().is_empty());
                assert!(data.prev_height.is_none());
                assert!(data.prev_state_id.is_none());
            }
            _ => unreachable!("invalid commitment"),
        }
    }

    #[test]
    fn test_success_update_client_epoch() {
        let header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212d3460ab2110aaf11f908aca0dfd0c915ed6e3bf10aab0e202dfb47a446eec66bd209be1254deea2551cf94d4a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942465176c461afb316ebc773c61faee85a6515daaa0d673cb388003076ea9d177df010d633f8a781d8a07a2d39abf4dee7f4f66560ca09310e9d727791dd64c1b9a82137fcd84d30d72db5cb9612954c4e4aaac371bb6a0b2014756b40d764f128315cd9d884f74cc09e4338266edd2a7b59877abff8a6fb9010006a002cae2c09472216150d68116104e2258428914810601284a01001a6d558ea2511130184c8005cd211bf8001a6678c8190258d082221221802412142dea20464859422b420c208144c08ab64024b57170032142164a502094100682400402ccec90338b2331e344418a8003104db1baeeb63b002bf4241648b43aeb090ca26d7ed90181033b49a89934004a528a081ca406c96d211c9e885101c017c21624171048200e458b12135607cc028004f1486a82501000d643816148233880383cb4a254e22025484252d04083911272696eb064609168001441135137bb48f2589438ca8b91e48c002b7602c606018385730480e060b4e04815aa2755d9b37448028401eab9c88408583b0083e5723e846516824cb906add88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2150bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c816295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e912d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab03f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a61dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d2569c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca72b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a517ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e8b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d78869485a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b741b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de7b4dd66d7c2c7e57f628210187192fb89d4b99dd4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cdcc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a419d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce739e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d21e9ae3261a475a27bb1028f140bc2a7c843318afd000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c192183ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5bef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0f8b5831df7ffb86082f8e61d76df2c3ef83424fa67ec8876d449b2fd44df70c68424f2fda1b5a577fd90d189e4b4c9c5d9c81d99fd9fb074081f89eb6c6c3a624af63e6ab774a39be3f91c2bf914687a185671f331820de9ac6cb6b1739b1d13c1374a5f020959c6f84c8401eab9c6a03a2a7732ae0dc866b2d586a161d8d4558fd4f1f0069c8e1d8cc54c2f6cab57648401eab9c7a0dfd0c915ed6e3bf10aab0e202dfb47a446eec66bd209be1254deea2551cf94d48094a0f11205eb4f01d1998f9ce7392e3043fb81cc84eb261457a71cd31ceb85307e27d5e12e7da1bacaf574ed1090636046b47d74916b049a60700f488c2751f701a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0389ad325ba54c2b20796e7ef348c0cfd043d0e47dc5d36f493cc6ff15551a5cfa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942d4c407bbe49438ed859fe965b140dcf1aab71a9a08cd020e09c663281b9ae955b0687ae330aae132fad7ccc3c19b1e783f9852b62a058179c401509bc10ac5dfb63292d5f0dddf83f62ecbace571381e5eba88a20cfa0b55ae3ad5ed5842f99c9872cb5fa9a63f66c541489ca91620010eb54d35af568b901005e64027388ded758a9406cedc31cdd7a8ed041c1fcd83c707cbfb51a4468ab16a6863b506121f18b83b300b6e75e9b10ef0f1e3908732ae4f0480056c02c5ac547d028dc8b71306a9979f4c8eda035bc659d33a5c8c43ac62115045fc0cbbc31d3beadf70e2703d5d527c114cb6ead19abea85cda8abe56030f8b67bda080d35b25c7ee432b1484bced5b4435779a88c44a5c7df78663c0ab3d032ca45ef1876b23b811252f7af4882550fcf9b8e9839c4798c39b3829d83da2d61212b8e4228efe29fcaac2ed8561ba05484aae3d7a52c577f45d58b1d351fbc54e6f750efb353d2d41cd1d9cb9c653338b2430861437a2094b1f5fa4e483eb841ddfa294858028401eab9c98408583b0083e69429846516824fb90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831df7ffb860ae76b8e45de3d46d3e3f1adc47057430c7d71df79f2e554772f68776c0b6e85eb786ddde8c731e3c7b46a63fca05507c00b482e0f67b0bf5361c840ec33c54a90fc290051dcdb4feb242c56787dd1184412980c029859a36ebefd639a026954ff84c8401eab9c7a0dfd0c915ed6e3bf10aab0e202dfb47a446eec66bd209be1254deea2551cf94d48401eab9c8a0389ad325ba54c2b20796e7ef348c0cfd043d0e47dc5d36f493cc6ff15551a5cf80a7bac79aa62ed6b91415c9400db3fa59d4528af80ac203de536f20e5c2f9fc7143bee31e43d0d46ef49d4f99dffa6dd34254ca88f9cc60c1a3a50891614daef601a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9e060a9b06f90318a022c32b836e14bb6b733e91900715e7268b23efbe462314fbc500d36b425ba104a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347943f349bbafec1551819b8be1efea2fc46ca749aa1a06ecdc699ec13310359ca3d1bd7e507020bc4063490ec16f1881dd5cc81ea6da9a0e739535837bc8c327cb65e0aa1a3d8c9a1a1844cbdfb2c60fb6ff861995606f6a07034ff88e282a64345d3e1b654a94504a6225063b61fb014807f1cd82e6610b5b90100c63676c23fc2565ad4d90272974d1c0e92da75e191390e2ced5ec91234c8f917c77c9a35614051886b6379a0041f13938ec75df905aa3664ca687b56f52c27c27c42c68e2d7c2db9f75bb4bbe666ac3e64b67b2a475636b7a775943f837f4d04840cbe2e0a2e298541cf98c03ca55bfb7c5908ffa929c4a6f77bfe5d034e50e58efbb16502f538a69fce26ba3516c88dc6b647e16deb053bb715bec43fd09873a7f34c9b72a79feb14240eefbf86759c4cebdff98ca1be8d1ed951b72de52363e697577b3d453fd693d607abca67f03860f7034415a8981d9f97dc76f350fe96b3f8d45577be6f9231372fa2e33ac5837024b4fb3b6ecfdad6e80d811bebdd79028401eab9ca8408583b0084013b95b08465168252b90118d883010209846765746888676f312e32302e36856c696e7578000000b19df4a2f8b5831df7ffb860973510b65d5f1f134b71d4e204275e5229d31646c0c63051b7e7cbf7b2a37e3634cab526336cc6da768a2e14fd8d5db613def7689f1b7c74b12a8794e836c74b1bfbc0e138bdd6dcc3de1d3f0313203fed1c97032b3c110c976e3cba4683ea8ff84c8401eab9c8a0389ad325ba54c2b20796e7ef348c0cfd043d0e47dc5d36f493cc6ff15551a5cf8401eab9c9a022c32b836e14bb6b733e91900715e7268b23efbe462314fbc500d36b425ba1048053391cf629f049537a52461a20a370c48fedc2e74d9269baf7a3877ee808c9da0c580de4ac77495d864920da762169ea1f92e7cf52e889103cb0a8405a6850ec01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080120510c7f3aa0f1a951df90e92f90211a06dd75d98e90634b3bb5291f8c14498a0d772e62a78e82de5097a4da0d4060e41a08f088073f331f27c28eda5cbd298eaa12f2f2d4d529dd31402cb4febaeb88478a04b46786e5a83fde3763bceee958e672a4d182850b5a91f38226e9385ae69d3eba06ff3cb8143314fe846a546abbee661a73f4eeefc0b9d56cda7cd2637ed57ca42a0393bc2437ba742be234d313c29fcfd3de0c798f816cef35988217f9c985397daa0626b3d47b7c1519007cca079ea93c2dcaba6c2a4ba4e5b650588a0d6f845a7d4a0f5eb17977ba1709050d9c6c808c37df2296c4a766b8d09c6ed3be1355878f8c1a0ae60112553477fb4eb97a61f3ca2d7988c2fd5af1dc6056a1c9fd1975124e27aa059a015a82f1ba917ea2c847a791f1ffe45db6bf8ec12be0e7558544f190a71bfa0c0652ad14aa94acdf3a58f8090debe5ab11d6619e1a58d7c37a5f9c91839b171a024e93d32d68f50ab4ce9201db50ee803ec748bcfd0f0926fc1e6792e998cdd98a0612438ff57632a7cedad3b77e17584ed293d08433793bbe76ea5879f38ff6b70a06a64f953601cff261b74892d3db2f19e8832fee7ed2051a9d36e80d4aa163d97a0d9db99411ebc74c356f1385f867a8ebb79693e8910d4ab81a26b53a6999961b5a0514d3230b3d239fc1f9243c03bb1f6c75cae112605118479e46994a7a3a32140a02d71605c614c583284d7aee4e6f123c2e7db894fc5b655076114f588a1f2aa2280f90211a07f9d3901b46ee6b732d2aaaf84d40b47ebc831ed47adb8a2c1c43613de4605dba0877a5df00fd7b24640adba5bba8d39aa3da551cd9aa7ef6268d133f966ee3853a056389b7c71cf708a9f104ab69ea97c8f8561c94fd3cdf1c69026c552c624d826a0af67e75eb2f83ef984dad98b2e2d05a1b9e0d18175e7882e9ceb847c994f89a9a038eae492cbea3819225dc47e9e674ae67152a4a622434aca0f511048bd4e2882a0545ca391120d092d590f710ce97d747b4b10efc5fe71304890bb78d83ad971cda0867c657413b8318047ea92cbb77cf3deacfc656c1f5169121c28f794e5af26bba09bb21e93ca6bbfe9a956aa45cb206c1ba30b9238bae608d9e61a85c3a1484698a01b39a4dd4376819599fd8a99a5844233e92747ab47d03af7c7428151d78140f7a08418b9718f62e572bb0ef05748a66dba2017dc4ccc947712e40c58e05ca7ee0da083afe7ac216b0a694e59d64d4b674fa496d9145f4426510308c3afbabc6e6390a031cdb81e4d4e346ba20be533add17ae14f020e3c75b1d942ceb831b4463d5429a06458dc8f9eec70fe541af826f608ec29f196568904a98159f4082ad0b194e864a0939d9a2627cde2638d815e8dab37856e2769741e130a96d5fe6dd02932a8394da089f290235af65e72b8976c726c070c2923c650f74344699f3b34658a6630d199a0299c63b050cf559312ff256ab0466948d67230e719ee2bc3189c5bc89c28d84580f90211a0e6d6c23fa1734c2f5d243a3cfb0f39cd02cfbfdb4bc3c8f431aed32fcd2854dda0bd9e04a6c8916365dec12c4d12f14e63d680afc5db3316bb69f6d3ffff20d52aa0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa091e6a46980bb716301891e6d65c420b2c25481f5f1fc0ec3e921fa1ec0b33e65a07ea284e90799149edd33ace9e67e83806405f98028558b45a5dcf6e411ac1d7ba070c2688533f8337332f5c7c11b1bd46704b7f2937d4683e509ca40cfb97502eda04b03a777f36dc9be61cca125223359ebb167562b64715f8aada6ee9f0219df0da093993ee43f49f3e33f6cb6541c6393dca4ac240893f1c0a250490f784d138814a0f47f2f96f3597ce60ca3370a8fbcbbac7d5b55bab33c29eb1fd3b386bcb6a2fba099de7a7a033931dc6ac0f61b83fdf182aa296cb2a8239a0cc6dbb313c47157a8a0e56b7c7c4656dd0b9f0919e09d6da771d38c453af4c0f0d6544f390fd2a543f7a081cca9739d3140249d6ae461371ff7b465883352d81bc757ca982f52d524c1dba0d3dbf7dcc484d241e77ee2be684b262f614f871a8c9d6598430a2134973782e0a09917ddd6820b6c66429eba999f5030141508a439dea8393b098035dbd283c287a0e053ba6f7c0865df751aa1b868b6dab4f49bba166c64e86762abb1e6556e5bdfa0c8af8672c865cd5af89c4a6b9e55b87f1dcf1ee0f76560a7d1f3c04daab60e4e80f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a4702a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        let height = 32160200;
        let trusted_height = 32160199;
        let trusted_current_validator_hash =
            hex!("dc895253030c1833d95cfaa05c9aac223222099bc4b86ab99eeab6021ba64a71"); // empty validator set
        let trusted_previous_validator_hash =
            hex!("607d7394b225d4fdd5daa65ca82df3c2e01149269f77d11d55aad656f0095b09");
        let new_current_validator_hash =
            hex!("abe3670d5b312d3dd78123a31673e12413573eac5cada972eefb608edae91cac"); // empty validator set
        let new_previous_validator_hash =
            hex!("dc895253030c1833d95cfaa05c9aac223222099bc4b86ab99eeab6021ba64a71");
        do_test_success_update_client(
            header,
            height,
            trusted_height,
            trusted_current_validator_hash,
            trusted_previous_validator_hash,
            new_current_validator_hash,
            new_previous_validator_hash,
        )
    }

    #[test]
    fn test_success_update_client_non_epoch() {
        let header = hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212fb460a9d060a9a06f90317a0feb3dca8515ba663608be132579cc4be830849c364fccc90d3e46b5f0c23fc41a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479461dd481a114a2e761c554b641742c973867899d3a023de09bdc6958b6144faa67c37966f2c1a8fb0697fb99b9e6a2340bb5be1dd05a0c834461f3fb915a33c55976be1bea82c54f7ff96ee284554346daa86d89d9806a0c61679f1e18d68a25b8598d05ae895768c0d6017198393f4c07d66b99221d6a4b90100812bae02ce1014d8885402d4ac1c150f9309418024012028ca0e4b3002c21800c01132417004ce41008139a008123203940e301980880004a00204d28d2420c2a42044820fe40060279d9f3cb14022f621d0126107668247210414058f206360b0fce6238a17002445cb199001c04d490a208041e24044aa2a00e710a4085101c51ae300021aa0718288a410e4408ad84c246c0528238048b510c044082940230b9a20008e22cda1260040042a8a0310040042023e88018583a235b068531469e30f045e04ac49c6809404a033105080200160809122403c6913704ea705f0aa2398a101b0c4d12253200ac32a0d099de93ae02da97223c811042a600c3914d0028401eab9cb8408583b00837a7f0d8465168255b90118d88301020a846765746888676f312e32302e36856c696e7578000000b19df4a2f8b5831df7ffb86097df3baf86afba3c26f7f97e49223d62fd9c09d728fe214d2d06ef9f7c3416fdc310be297444b7f4b0ff2835a02858e407d574343436f249ebf617c094c80bbc5d19341fb4ea8c7d9024480f16c4856edb087c3b7a06b10c38920a43c8753fccf84c8401eab9c9a022c32b836e14bb6b733e91900715e7268b23efbe462314fbc500d36b425ba1048401eab9caa0feb3dca8515ba663608be132579cc4be830849c364fccc90d3e46b5f0c23fc4180d25d99399c6b8c0339bcfd6b516fb1f3d2413efd792cf3c87a7c34ae80ca147934267791f4635c5d3840c11b240696e9c889ba0ec411388251026105fa7e5eb201a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a004155d7b8c18f2d69800c8f9444b4a25027c23eb7514ea0d3c646693d4673d99a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479470f657164e5b75689b64b7fd1fa275f334f28e18a0dd5169230dd630e4891f1356f1b96707176e5922adf7d1607d6235eaddd50cb7a001c548e269165c55330607dcaa0a13c7508ff56922757219a9050366b5833115a0224fc94974291205e108fdf540928481aa6ff640ad1ed67db7ea087dbd557bc9b901002a708b2a016850920a010e649218000223074a82c918008039019b851244021ca14931207014d88000404308001e20048a00581b10075420834024022928a2802c5042018540040041489808e0a2583c25182376014e0a4124c74210388301b1466ca5219e121828408108888b03c90308086440a84c04b93200c09c031425074709ca85a248c44e908b160088404898602e840438420868015080410009c460c69000006b66aa80806844440e42900370b2022098820a18100341e0c41286080881944a04480a871c2044418210d22020742940b808ca140d12548a0312a0001030ab0d016c2d2801318ad0080009680c2804f40468280899616f010a010140028401eab9cc8408583b008367bf768465168258b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831df7ffb860abf70f41702762f51619c42bdf6b9c3ba383175632b6db3cc238bc17364bf21562a51f228f68534e7b4aaaff35f8c5ce08fd5e8dfeaa328a76b0e6ebb85b5e99099b660ed69b759f014fafa7eecb3098292d75f82d0c471ef6f9511b4ef3f8d4f84c8401eab9caa0feb3dca8515ba663608be132579cc4be830849c364fccc90d3e46b5f0c23fc418401eab9cba004155d7b8c18f2d69800c8f9444b4a25027c23eb7514ea0d3c646693d4673d99800b315cd2d4e3162f9ccfb0a1c3bfbf57368525086dd5c0b18bad6833e2bfca3e1fbad1657e623968d777fec26778fd846e6664bbf5eac859dd09eae74d96bee200a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0dc9fb461ecd0a1bf6349e94d61f78c783a511d0e773154f6593f2530dc8c5cc3a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0b4486492538ac1aba093c1b5f303d47fdfc5be01cd5c67380e5e9760779139d3a037c90501705e0938b684c912c4bc8a2ebbbc46f477abf481e600262c733451d1a09219073211ceb3d89b20b19264464a28229a069c832e751f5452e7fb8b5efb60b9010052a0a28f26cff3f5004e00e4a39a044e8b084a42b48914c87a398316d3482614a6d2125560fbc0015063baf2041e401abd4bd410581be876371c29bb043e0a48864f669223440e39897b28298560542d7218016b437cc3aa28b6519482202e20c96cb4a98edb1d8f6d078b90c32c2b65ae80c41d0ee0c4ae9051de93c508e65082fcba04803651c7d3bc3482590a081c2c3c45c1ab33105930ac83405d02c530aa11d10553c30a14129042e4638214b96609149c6ace47e294644462e18acab0990b165ab81418225420106d0e34d160747963e4b182515451185e87a74be270b331ca0531290e2889276f12b400090a7900008d932867ce1b6fad1118bb520b028401eab9cd84084fe2c683b2b318846516825bb90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831df7ffb86099ff0d5d682bbb7d7a82a3e81c09b9fb4c3b3c2cfcc0f1b1d68ae90a678bbba5430aa814fb2102d6893c39de2e86c96f19d8d1e8cd93a5f86dd87c7639adf3f661e3ae238daa85243e03e8dee02e45d64556263c7b9d38a9fd250fc47791dc56f84c8401eab9cba004155d7b8c18f2d69800c8f9444b4a25027c23eb7514ea0d3c646693d4673d998401eab9cca0dc9fb461ecd0a1bf6349e94d61f78c783a511d0e773154f6593f2530dc8c5cc38040c23bea0a66f1eb621da3fd7184780591887e9a85a0b075a1df3e0cd6e14d522f9b3245bac947cfcc959770a65f63115fc2891b2043f675ca4e9e4aa6f2baf501a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080120510caf3aa0f1a951df90e92f90211a0879fbf1597c6a4a5c19795c1962370cc6de1ff693534c7bee22df95842990dcda0b22fc1e58162520af9a6bf4326027e307cec4342c9c3a6a9d6a32564363b0a2ca0f1654bf9e5e926a80711aff2934e073cf4b103765f9df3b069f24aef4d16cdf1a087c5469547200128d2c98237b629189f162e786bde24b500029235ec2ca89281a0e498ce1143f8c074010db7643780a87780f7578a41ec4a0f3bb2251369d68d46a0d3c655057035d5002eedc89b56f66bcf2d1b6fa8be67bc41d3c89be1f7722c4aa0284d823ebb6f34818f14ecc532b770540712f3aa1ca4df74e334bc253e6b32aca0f28ab40b0509b25fe9f3dd65f626f42729f52ccb9685b61b867469a321f21716a00f76ce464832957ad288c150ba1cadb0e590f316076a52a3344a37e70123c51ca0f02904295ad311f10ba192a1049f4816b40f7c81c651c88b110136d02e638f7ea021b037ac53fc4ea00c1da756df5fcd5f73fedb991cb716bfb9f946e07979833ba03144039e8987b82900e059f5780412506b75769f3b68609775a46112091297dda02641eb6e6277e93c4288f92338d04e51b4ef75a709852f73419d9da61c618cd0a01b65d747629e22c321c27bf3a3be57e9ee06e9f51193e8fbebfac66ad0e3abcba01cf92f3196475026a7c231bbf0f12cfc1f08b47fbcedc2a7c57b64e3b3832dc7a018767613ec3bea5597898b1dd2601c931ffcf0115547e23f84c06f320719db6980f90211a07f9d3901b46ee6b732d2aaaf84d40b47ebc831ed47adb8a2c1c43613de4605dba027cb7f21a746a9c6e76b3d4d0cc1da32111ca20b0d3f1cb64afd1d0462e8e211a0052f5245ea659debd6f38fc4789cbeb0fd2235aff77537e808e0e767196e8b7da0af67e75eb2f83ef984dad98b2e2d05a1b9e0d18175e7882e9ceb847c994f89a9a01af6bc0e3ec6cc384dd68218ed53f2799024d57d2c3a53523dfa227128699ceda040971b58d91a4e17e12065b5ee59134aa12173a581716893358ddb80ccd76486a0c68ac43d0dbaa844b812b91c527f70595d1c9fb33e49e373993078a9b6506f4fa0542841b0417994c8e689d15cf3d895a09d1e485ab9b3bf0b782b112792f459dfa09c410eeb054c0cd4bdcebab79f3dcd445ef33994e03b4f8336b1a3842c879261a0317498b85f2e60d0144557a9daa665b04858f6d67afa4692f6e40b518becc5e3a03e15531394d36f2cebabf69de2823a5a17994e85f6d4bc663947157c007edee2a091c0de5ac4131c6e9a625000d994dffb70f87eaa0dddb27544e731e2e04a066fa023ce1490b59b94bd8840af9c1a12f2f98f9537ddddee037209dd7881a114052ea0c7e8afeea81b08c7b07ab41e191b8c054baad1231db7585084ac90907211fc2ba068e094995972c8da18e345180551c04af0696b5b756d3f414dea3b41a15b575da0e22741ba7909396a84d3dbef5aeba6e6614638253a7319ec2fa6409cbde44b5180f90211a0e6d6c23fa1734c2f5d243a3cfb0f39cd02cfbfdb4bc3c8f431aed32fcd2854dda06bcf17926dad58b8c5118d5a6174fd085d03d92a9d4a5ed56efdd36f45975ea4a0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa091e6a46980bb716301891e6d65c420b2c25481f5f1fc0ec3e921fa1ec0b33e65a07ea284e90799149edd33ace9e67e83806405f98028558b45a5dcf6e411ac1d7ba070c2688533f8337332f5c7c11b1bd46704b7f2937d4683e509ca40cfb97502eda04b03a777f36dc9be61cca125223359ebb167562b64715f8aada6ee9f0219df0da093993ee43f49f3e33f6cb6541c6393dca4ac240893f1c0a250490f784d138814a085ae2d7b32dc0f0da002ea5033910b035e01f5ae12ff3105010e13a5a33c0ad4a00c39c1e39b90b4afab7648dd547f77b8f9d4c6d9e0c63e34ebf4c149c948edafa0e56b7c7c4656dd0b9f0919e09d6da771d38c453af4c0f0d6544f390fd2a543f7a081cca9739d3140249d6ae461371ff7b465883352d81bc757ca982f52d524c1dba0d3dbf7dcc484d241e77ee2be684b262f614f871a8c9d6598430a2134973782e0a09917ddd6820b6c66429eba999f5030141508a439dea8393b098035dbd283c287a0690b4d39eff7648da540434688e23bed68fe43f3711a9bc7dac7c15626fe1b7ba0c8af8672c865cd5af89c4a6b9e55b87f1dcf1ee0f76560a7d1f3c04daab60e4e80f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        let height = 32160203;
        let trusted_height = 32160202;
        let trusted_current_validator_hash =
            hex!("abe3670d5b312d3dd78123a31673e12413573eac5cada972eefb608edae91cac");
        let trusted_previous_validator_hash =
            hex!("dc895253030c1833d95cfaa05c9aac223222099bc4b86ab99eeab6021ba64a71");
        let new_current_validator_hash = trusted_current_validator_hash;
        let new_previous_validator_hash = trusted_previous_validator_hash;
        do_test_success_update_client(
            header,
            height,
            trusted_height,
            trusted_current_validator_hash,
            trusted_previous_validator_hash,
            new_current_validator_hash,
            new_previous_validator_hash,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn do_test_success_update_client(
        header: Vec<u8>,
        height: u64,
        trusted_height: u64,
        trusted_current_validator_hash: Hash,
        trusted_previous_validator_hash: Hash,
        new_current_validator_hash: Hash,
        new_previous_validator_hash: Hash,
    ) {
        let any: Any = header.try_into().unwrap();
        let header = Header::try_from(any.clone()).unwrap();

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: trusted_current_validator_hash,
            previous_validators_hash: trusted_previous_validator_hash,
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, trusted_height), trusted_cs.clone());
        let cs = ClientState {
            chain_id: ChainId::new(56),
            ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
            latest_height: Height::new(0, height),
            ..Default::default()
        };
        let ctx = MockClientReader {
            client_state: Some(cs.clone()),
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
                assert_eq!(
                    new_consensus_state.current_validators_hash,
                    new_current_validator_hash
                );
                assert_eq!(
                    new_consensus_state.previous_validators_hash,
                    new_previous_validator_hash
                );
                match &data.message {
                    Message::UpdateClient(data) => {
                        assert_eq!(data.post_height, header.height());
                        assert_eq!(data.emitted_states, vec![]);
                        assert!(!data.post_state_id.to_vec().is_empty());
                        assert_eq!(
                            data.prev_height,
                            Some(new_height(0, header.trusted_height().revision_height()))
                        );
                        assert!(data.prev_state_id.is_some());
                        assert_eq!(data.timestamp, header.timestamp().unwrap());
                        match &data.context {
                            ValidationContext::TrustingPeriod(actual) => {
                                let expected = TrustingPeriodContext::new(
                                    cs.trusting_period,
                                    cs.max_clock_drift,
                                    header.timestamp().unwrap(),
                                    trusted_cs.timestamp,
                                );
                                assert_eq!(format!("{}", actual), format!("{}", expected));
                            }
                            _ => unreachable!("invalid commitment context {:?}", data.context),
                        }
                    }
                    _ => unreachable!("invalid commitment {:?}", data.message),
                }
            }
            Err(e) => unreachable!("error {:?}", e),
        };
    }

    #[test]
    fn test_error_update_client() {
        let header= hex!("0a222f6962632e6c69676874636c69656e74732e7061726c69612e76312e48656164657212fd460a9e060a9b06f90318a0aeb34c70bba2db766857340f3b9a391b5332c5be7dfc6fd45117d95cf32bda85a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba00000000000000000000000000000000000000000000000000000000000000000a09327a61481b2408f2a2d3cd4c1956259215eedd9f5f4cfe53ef0df89e80f335da0b35856be0503b120103115c6bf48ffd750e2e83880676f70dc34d9a50e64c247b9010086260674d1c0d73c1d5439558051687683845288bc1a18743c2f814631882c40ee4cb9a2e88cc19c00d0ffba0a9e52229b8ec1199402712450c0e129dd2e34e1e76229f4ff416ca91999c02be1244ebe72319828856ee26620067491c7350a60c8ec82234aeeada54d47cbb2d56cad888acace4fa8ad4d781a086a10834a41c1ced08b15a31d0fd6d49a74ac4c9859de90678ec168b1447b2ad14aca95820d302bdf881553828a51931897e70e823cdb756ad6a59e860337202804322910cae3e53a565e4a00acd75e272289417757352275514595e7b09de390550f72b0fca83118a79791f57909630507827a144d4015e48d3be9ba43ca3b6684307a210ded028401eab9f784084fe2c68401193c0f84651682deb90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb860ae89c1a42abb17a167fd49be92d22898e1a449743966cc36a8813508a5e5f8c180e0a2713d5cc8d748acd0fdb95c3a9d0134fec56824b3b1901378823ffd3e98d36bd1574329805cdd96499704ce21dfee1c3b35e744a4dd5f2e8c811a939143f84c8401eab9f5a04faca5268b7a0425eccecac9a27a75e9e4e6abeaf018eed562ef01a8ff8f6cd78401eab9f6a0aeb34c70bba2db766857340f3b9a391b5332c5be7dfc6fd45117d95cf32bda85804ef67727f6a4a908a26a1229538a5b7f90bec3e2e6b8fc5420045b8c5520343932847f59933c3a400d088d5fe9f5fde2ae5809ac8b3a11de33e7818c8fec422b00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0c2bb1d712ce142a2ef22b975ed83416ea31f4545b297765e7456d0c0ebeb9f28a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347947ae2f5b9e386cd1b50a4550696d957cb4900f03aa06afbbdd36cb61f3d2a651bc6218ef4b7fb7ad2367195105a67e952189dbc3188a03709615ddca48112289d87be4f8083e7067d4d0898f983132558e12a897c1d87a08227455c29c40f1bbbe4792e2b9814d98cb622d862f5aeca8373dfae7969e8deb90100527986d63768151ac9100068b058b15181120286f3710c10315231ea512011068a40b85371d9920143217125061e0022a922251aa54b564851d018b5322e06e84e0284800b610c5011b4488daa630abc30d8092409742d4185661a5480143d20483ab8b35a2b61e64c53181051490f3b18818f5d814c05a453e7ac982a08455010e2e4213709480d8ac067480a4c09b8066c8cc5310e01084b99ce6078f20c6fb3d100f256e88197218058454b8ec711314200612a0a4325b022a66824eb28cee540cd62006443c712205a0d423fd94d23d1af94d00215dd6512d4d60064e57408d5a043c0e8c3ca231402ee4820e524710004104738446ebd5b151e4c614844028401eab9f884085832a783cfa37b84651682e1b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860a1f5946901ac7f9e875f2fdcb906700be782d4720fda4bf4c5e9680b62608c09c051723f6eb08edca330815bf3836987093575166c87a59e64cc7798737d2c4d3eee7b080d888a5454e689a3df1a6e1d2b655dec52ae3f8c444b90a93ea478b6f84c8401eab9f6a0aeb34c70bba2db766857340f3b9a391b5332c5be7dfc6fd45117d95cf32bda858401eab9f7a0c2bb1d712ce142a2ef22b975ed83416ea31f4545b297765e7456d0c0ebeb9f28804f1bcd3484aea92f5ab7772ec713cb6f94b092c251b5ae134bd178111aaf5ce95b23b86e4965e9578cfd6240ec8b7a6effa75aecaa6326cfa42aceec2b69a59200a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9e060a9b06f90318a05c1a4ac59fa493c7add0898f753bd3b6eca7717d0424cc3660d9908233989079a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a0f82ea8b35f53773563a8ecb3287113bbbd5efaedcd09834667e32212ff288fbea0689b79ba82934bb61ee8f64af6f980d9bf164419dc9329f9d62a33b621e1a5eea06f8a552cbb9e52bff118baa395c75251a3b582c0b6dcc93bfc4fa0a15cca1dd5b90100cfa64722a69e3dbe2e9978dcb71e5cff8f31e4f436e949285fa0ab4f3b89ad5fa7b1d411f036b680cd1a337a4512e71b9f1f1eff1192aa4066cd5a1e743c2a82bc41ead1af65dc218d7ec42ca585c7bf699f91a4f354da97efacb534e051bc91dc3ddb35cf07d9cc544f9daf23632d192c3fdf498a81ed387a70b615fe8728d7d5ead0ae3a2100759197b4115f766988213e2607ff25195b2d5526c68b684cf5bf910071e2afab080fbc1dce2f9e9c9a45e3035d3ddbfc2962543e22eaeb3c60d0acfe2667a46d6e10d398b91c33d4e06671fb9a959f8f3d4511d5febdecbef813f2c752f3f3ddb8893758fa30ab83f972b24c1843b34ec81e4fcf5ef8ad6c4a028401eab9f98408583b00840129f24984651682e4b90118d883010209846765746888676f312e32302e36856c696e7578000000b19df4a2f8b5831defffb860b0f58980edb50dd10c56c83443f5ebd140d430a422bfa1168da234e15187977283647b7ec30a3443a2d5bc5c705ea19d193782aca1a29a5adf2e8378e2c86498185700253f885dbf3c58d05a785f9bb3dcc914fbbbcd4addae9aaf8a3eea0575f84c8401eab9f7a0c2bb1d712ce142a2ef22b975ed83416ea31f4545b297765e7456d0c0ebeb9f288401eab9f8a05c1a4ac59fa493c7add0898f753bd3b6eca7717d0424cc3660d9908233989079809d9d51ff8ea924fcbb62f90bd0a6185457a3a5c6e7d074acb2d35373e02ab466039d3d23c795be05eca2773251b0bb4ac7dc25e247d3f295ffb6421e6b65fd5b01a0000000000000000000000000000000000000000000000000000000000000000088000000000000000080120510f6f3aa0f1a951df90e92f90211a05760c478b528201548b880f9df75f669b35285dfe4bce3a2245b6fdace23806ea06702ed5328fc88ae32788582fdce6087c3772e9f2872be07dddfd72bce23e6e6a076fecf1768f2efca0493b32434dc758cb1804a9eba8479ecc244490d02016850a05fc46706b33918b46e21e0552215669313eb6fee038e8662a364d450f20b765ea02162336e1f97ea3aaaf26e5482e752e3bc335f146b08a4ec067bb2f6b66ad4eba0f9c52bc52d2bff446b57580612ff3d5e5ce63fe38ae9a6c286068fe6d8dd69e1a0f2ffb55c6c86989060e530e9300716eb81b402ee6e54d6845e40f256cc5a30a8a040307a80bb9b2672c1ddf9e009377bf6f792ccb6471975a7efbae167310f32dda0ed0a7cf42511cdf4c79e1cf995074202e10b148e9d8cc9ff459ea63bd456c292a0d8642102cd0c903c286313b4da9fc2d576f819d24c5dc9decf7a72d6c5f3a6f5a0a72af8ac881122fe9e28643d845ec0bdb82e7c6844c4e90d1375b3b6d00b2e83a027e16ad7e44adc72b9f25459e50d59ebdfc2df5210a317e9af7e6953001b06d4a0e2c69d81c457b2499b10a65b4764ea149ce06c38e20a1b81034c86c1072ed008a000f2f7a39a9572c5eaf08e46f20a46f2b3b9f0dba44940cbb3b717e8cb72cd0ea053da4d2d3e34749b27aa7867bc4eaa05c33e5ebb914eb7a2eda4337b302fa43aa094da8ed2b23a83012b966d1361235fc24cb33a0886be41d9ee19862cb313094580f90211a0a2128874d2823da6bd7cdf67438effc0e407274501327d2405e25687585eb70ba05b0986965e23b96ad60c8af08434733c40efe29db0c993d7ba9bc4ffa1483ba8a0f43d30c11169496786df08702b0080269f67dec4afc589a629f481b16d19832ba04a12b6f2493e006b66605e1d00af7f6eb3f6c733dd84cf40ddf5f89267e8e7aba064e170ac6680f6cdf1e42faba258367fcf0393b6b2ccdc896d90acbd23ab5465a070771a010394851774d88d286b57bdf9faf9d9356a2240128eb9de145ec2edfba02dc8752dafe069b464c36b8509826d726c1f131f205a49fe8788659122203620a0f63f4e9a984f664b13b67dfe922fc3a560efce6720b9172614e11965dfa3b711a05afa9694c979c6904d88cf2f248a755f41b78a44ecfd7861bbf11ab617528723a0b5d0e96e1a30c464bcbadf2fb1e6587f30c26e611912bc71298309869803e01ba0bb30f6dd3be410db17d680911856ad5068698256462beda07b6fa0ecb2c795d6a016d61ebc2df2ae26c81a9e42e21e690835a3855cd5fb8b080914b29e61b0cba9a07f3f00a25937d9fa7f5fab4e72c39e7c61e2744c3a7f98489ab4d1b2e7caedf3a0cb308105ad0e53f8295d98d64926f0e932459a9690b5a54bcf5557985cf4e401a0e5fd124381dc44dcd9fc74bdc6d9e73eed51c739aad2270730c146a80ae4f1f2a02bdd929c52fb5bbcb95162cce765015a272ef934c1c0c7ed38c8ca2c0bef5ad280f90211a0e6d6c23fa1734c2f5d243a3cfb0f39cd02cfbfdb4bc3c8f431aed32fcd2854dda03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa087492846af03fde43add538ba9a0cd3a58dda4f92af41fa5ec85c724b3569952a0251aab0f729960016c67c4450afcea003fe27516ae12a4aacbba88c2218d609aa00773c02f14993b861c986adb86c48e2b964b04fc93b7c14e0adf236ba48fc3c3a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa098e233266cb2949de7efbc5249a002cd0e347ee19307a53498a6d46ae5dd5e5ea0668cead9c0b63d7ebcb34a1a5864a894baac5fc4a85fae89ff6301645b1a2c5aa0001d500e083c7b36f84d6d19af62df79986281f6c826e47f44d7b97c3d106af4a0607867cd831b1cac0eb801706ed0a6c762746c07b8ee12870445c526da6058a3a0c82d3b93fbfab9bb7d75a7eae35fb9ab46558857867d24d65de62e93befd63bda0a39ffe983c540e96c66156dc256c27ab556267c1169629ebecf09c11dca8ad7fa09917ddd6820b6c66429eba999f5030141508a439dea8393b098035dbd283c287a04d959bbbe8ea6b950a3c865aca329123dac37debff5ea2531c8a25af9e09b1eea03d184ecdda0c942db6d34a492675d82093b1bdea5eb088d69e6502fff16bc71980f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        let any: Any = header.try_into().unwrap();

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(&client.client_type(), 1).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: hex!(
                "abe3670d5b312d3dd78123a31673e12413573eac5cada972eefb608edae91cac"
            ),
            previous_validators_hash: hex!(
                "dc895253030c1833d95cfaa05c9aac223222099bc4b86ab99eeab6021ba64a71"
            ),
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, 32160246), trusted_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(56),
                ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
                latest_height: Height::new(0, 32160247),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };

        // fail: check_header_and_update_state
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("UnexpectedHeaderRelation: 32160247 32160248"),
            "{}",
            err
        );
        // assert testdata validity
        let de_header: Header = any.clone().try_into().unwrap();
        assert_ne!(
            de_header.eth_header().target.hash,
            de_header.eth_header().all[1].parent_hash.as_slice()
        );

        // fail: client_frozen
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                frozen: true,
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("ClientFrozen: xx-parlia-1"),
            "{}",
            err
        );

        // fail: client state not found
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: mock_consensus_state,
        };
        let err = client
            .update_client(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("client_state not found: client_id=xx-parlia-1"),
            "{}",
            err
        );

        // fail: consensus state not found
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: ChainId::new(56),
                ibc_store_address: hex!("151f3951FA218cac426edFe078fA9e5C6dceA500"),
                latest_height: Height::new(0, 32160247),
                ..Default::default()
            }),
            consensus_state: BTreeMap::new(),
        };
        let err = client.update_client(&ctx, client_id, any).unwrap_err();
        assert!(
            format!("{:?}", err)
                .contains("consensus_state not found: client_id=xx-parlia-1 height=0-32160246"),
            "{}",
            err
        );
    }

    #[test]
    fn test_success_verify_membership() {
        let proof_height = new_height(0, 232);
        let proof = hex!("f902ccf90211a06868e3a43071c06084145e2546b14ab7b49b4a073213228fd2fe5b9ad6978723a032238795ce6d015be83c499b744c7108308321b5c52b424bdfe851819470572ca0db54777eae7ba641adeb842ebae3b86206443a817af6211162cb7b8f54685722a094b114ebfe63288bd344dc06b50a25982f93b38ae7deb1c4f0085a80b76692fda087385f44c834ce1d100176adb7dabf314d3d3799e83cecbdbae8bf0047bbeb8da0afa75930fdc8b5bbcc7de9653a126bbd5e7480ba180117ac8f6448ac620fe881a0c9970b5bcfc0a37c601a907ab40e0d73fe4a19b00564ebfaa2962bc4659937e8a07c6b19783013eefd4b7362ea987dda4509b7a6f6b9fa765f4be79817023c9fefa0c928ae51650933cbdc43721f48a8d96b1ff49326b6afc59fe4441a6ab4ec6391a0c60665890ed3028fb4cc13ffe5b37f9eaf93886aa0920ea7aab00e5f36a58cb9a0341de64564e1cde279f15a152a41fc07b955ed8fb331e8fbb70b6ada2f4533c1a0eb2cfd02210dd040808b05b9fcb94d99fb459a04cbaae816a87b30224962b82fa0dbd758e0c3164e578837b817584efafc5582fa3ad872bc59ba20a0ff29d84438a0ad31c527b35a0c5a0f50c15bcba55b473de5ced9ab8c22736bc71ca7ff5f9e4fa03d448120e46b82861ae5eccd3a72e3c12f8cd350b466dc27586a1d6d58791212a08a70cfd0b8005d9c457f0d83b1a7b29244963fadf71fb1ce35764fe7141bc90080f8718080808080a0ce42aec576e424376d1bfec5089611170bedc488327075ec1c37905b2eb04a7b80808080a0e8c783a5d1417b9c3c59e642b630d1fb818a3ca870068c33a8d3b3114d1a31278080a05868dd463ca96a009a6bbf76fe9a9d904ca04e30b83a3759619f191367ce5b26808080f843a0203fc42ddf6c1b5bb218ce24e14c40af9e0eb127a5d76050d37d7369e2fc4a47a1a038841326d6f11b905566840b11a81201594ec536da63c44f38c1681ddad3eee4");
        let state_root = hex!("4050c398b206f467b6d88cfd3d877a11f65701c37aabaa48d77466a63dfda9b7");
        let value = hex!("0a0b78782d7061726c69612d3012230a0131120d4f524445525f4f524445524544120f4f524445525f554e4f524445524544180322220a0b78782d7061726c69612d30120c636f6e6e656374696f6e2d301a050a03696263").to_vec();
        let path = "connections/connection-0";
        let result = do_test_verify_membership(
            path,
            value.to_vec(),
            proof_height,
            proof.to_vec(),
            state_root,
            proof_height,
            false,
        )
        .unwrap();
        match result.message {
            Message::VerifyMembership(data) => {
                assert_eq!(data.path, path);
                assert_eq!(data.height, proof_height);
                assert_eq!(data.value, Some(keccak_256(value.as_slice())));
            }
            _ => unreachable!("invalid state commitment {:?}", result.message),
        };
    }

    #[test]
    fn test_error_verify_membership() {
        let proof_height = new_height(0, 232);
        let proof = hex!("f902ccf90211a06868e3a43071c06084145e2546b14ab7b49b4a073213228fd2fe5b9ad6978723a032238795ce6d015be83c499b744c7108308321b5c52b424bdfe851819470572ca0db54777eae7ba641adeb842ebae3b86206443a817af6211162cb7b8f54685722a094b114ebfe63288bd344dc06b50a25982f93b38ae7deb1c4f0085a80b76692fda087385f44c834ce1d100176adb7dabf314d3d3799e83cecbdbae8bf0047bbeb8da0afa75930fdc8b5bbcc7de9653a126bbd5e7480ba180117ac8f6448ac620fe881a0c9970b5bcfc0a37c601a907ab40e0d73fe4a19b00564ebfaa2962bc4659937e8a07c6b19783013eefd4b7362ea987dda4509b7a6f6b9fa765f4be79817023c9fefa0c928ae51650933cbdc43721f48a8d96b1ff49326b6afc59fe4441a6ab4ec6391a0c60665890ed3028fb4cc13ffe5b37f9eaf93886aa0920ea7aab00e5f36a58cb9a0341de64564e1cde279f15a152a41fc07b955ed8fb331e8fbb70b6ada2f4533c1a0eb2cfd02210dd040808b05b9fcb94d99fb459a04cbaae816a87b30224962b82fa0dbd758e0c3164e578837b817584efafc5582fa3ad872bc59ba20a0ff29d84438a0ad31c527b35a0c5a0f50c15bcba55b473de5ced9ab8c22736bc71ca7ff5f9e4fa03d448120e46b82861ae5eccd3a72e3c12f8cd350b466dc27586a1d6d58791212a08a70cfd0b8005d9c457f0d83b1a7b29244963fadf71fb1ce35764fe7141bc90080f8718080808080a0ce42aec576e424376d1bfec5089611170bedc488327075ec1c37905b2eb04a7b80808080a0e8c783a5d1417b9c3c59e642b630d1fb818a3ca870068c33a8d3b3114d1a31278080a05868dd463ca96a009a6bbf76fe9a9d904ca04e30b83a3759619f191367ce5b26808080f843a0203fc42ddf6c1b5bb218ce24e14c40af9e0eb127a5d76050d37d7369e2fc4a47a1a038841326d6f11b905566840b11a81201594ec536da63c44f38c1681ddad3eee4");
        let state_root = hex!("4050c398b206f467b6d88cfd3d877a11f65701c37aabaa48d77466a63dfda9b7");
        let value = hex!("0a0b78782d7061726c69612d3012230a0131120d4f524445525f4f524445524544120f4f524445525f554e4f524445524544180322220a0b78782d7061726c69612d30120c636f6e6e656374696f6e2d301a050a03696263").to_vec();
        let path = "connections/connection-0";

        let err = do_test_verify_membership(
            path,
            value[0..1].to_vec(),
            proof_height,
            proof.to_vec(),
            state_root,
            proof_height,
            false,
        )
        .unwrap_err();
        let expected = format!("{:?}", err).contains("UnexpectedStateValue");
        assert!(expected, "{}", err);

        let latest_height = new_height(
            proof_height.revision_number(),
            proof_height.revision_height() - 1,
        );
        let err = do_test_verify_membership(
            path,
            value.clone(),
            proof_height,
            proof.to_vec(),
            state_root,
            latest_height,
            false,
        )
        .unwrap_err();
        let expected = format!("{:?}", err).contains("UnexpectedProofHeight");
        assert!(expected, "{}", err);

        let err = do_test_verify_membership(
            path,
            value,
            proof_height,
            proof.to_vec(),
            state_root,
            latest_height,
            true,
        )
        .unwrap_err();
        let expected = format!("{:?}", err).contains(" ClientFrozen: xx-parlia-0");
        assert!(expected, "{}", err);
    }

    fn do_test_verify_membership(
        path: &str,
        value: Vec<u8>,
        proof_height: Height,
        proof: Vec<u8>,
        state_root: Hash,
        latest_height: Height,
        frozen: bool,
    ) -> Result<VerifyMembershipResult, light_client::Error> {
        let client = ParliaLightClient::default();
        let client_id = ClientId::new(client.client_type().as_str(), 0).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        mock_consensus_state.insert(
            proof_height,
            ConsensusState {
                state_root,
                ..Default::default()
            },
        );
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                latest_height,
                frozen,
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
        };
        client.verify_membership(
            &ctx,
            client_id,
            "ibc".into(),
            path.to_string(),
            value,
            proof_height,
            proof,
        )
    }

    #[test]
    fn test_success_submit_misbehavior() {
        let client = ParliaLightClient::default();
        let client_id = ClientId::new(client.client_type().as_str(), 1).unwrap();

        // Detect misbehavior
        // Use blocks of two local nets with the same ChainID(=9999) and validator set.
        let any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212b1340a0b78782d7061726c69612d31128f1a0a90060a8d06f9030aa025ffb3920008fd0591adc665132f7296d4d3da213f27ad5f13c29bae6b53b150a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a03feedbe444fcdaeea389d10588435b9657b71aea384266ac09e15c0772ea6bc9a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a58402625a00808465122d33b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b8608ce4e95f382e2d06eb6c98641c574069f7c8cfdb482a4c58290f9f2ee86f6d4ce520d7bb6a6be1acd082c07a9d65b45f1334def3c66fc793003cf06f3fcea7ce055b34aa911f6ff7b9bf2eb083f3e7010a34e8c61aa70edd8ad630c82f3d4a8bf8488204a3a02d59fc7d664ae17504839bf6c49ca0e21fa794fe661c86e929a522bd4872d3458204a4a025ffb3920008fd0591adc665132f7296d4d3da213f27ad5f13c29bae6b53b1508022216e66d52050e392e6a6b86f677363e01be8deb6611cab76cada1bfd6c0b7048798c2376f52d8357d8aeb6e6c0109dd802675c849dff145dc3dd470fc7bce400a000000000000000000000000000000000000000000000000000000000000000008800000000000000000a90060a8d06f9030aa09432b9b136e91a12cea5e9cc363bc821e90da6c7b2d7f369533afa746ac21508a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a03feedbe444fcdaeea389d10588435b9657b71aea384266ac09e15c0772ea6bc9a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a68402625a00808465122d36b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b8608f21cd736cba2bf8c4af32f237f4851282c77b602f3e5ef48c48e16b36fae2f8a80bdb501d48c235b3409ec53340742919fbab1a54cde9da53886da4e7280a7c450714fbdd1dd5907a9f4990fb99e1badebba671d521d47f1cdd23ce3eec2e90f8488204a4a025ffb3920008fd0591adc665132f7296d4d3da213f27ad5f13c29bae6b53b1508204a5a09432b9b136e91a12cea5e9cc363bc821e90da6c7b2d7f369533afa746ac21508804b8debfb8d55a7f71547fd88e1c40eb0efe960d32d08601589e22a62bb0ebeb26b984bba8f736484ae789567e5d9563104126e78181a293d6ee504e9ad35725801a000000000000000000000000000000000000000000000000000000000000000008800000000000000000a90060a8d06f9030aa086efaa0d95f31de170d88687b07806f3bf271bf842b65f6dd76b326e1575e609a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a03feedbe444fcdaeea389d10588435b9657b71aea384266ac09e15c0772ea6bc9a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a78402625a00808465122d39b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b86094c8bc4a6ed9b43a592f7c7a035e27b119ff45ea9e7e6ab149136ab18f268499c6d6d920aab86608315093fffaa354cf0077173664aebe97ca185285e739559a01c96d04a30df92c23ce051b1700c8fabd41e1ac8db8229a3c08a067a60a4ee7f8488204a5a09432b9b136e91a12cea5e9cc363bc821e90da6c7b2d7f369533afa746ac215088204a6a086efaa0d95f31de170d88687b07806f3bf271bf842b65f6dd76b326e1575e6098085641457482587c8687b5e40069f915f48961cad6069305c278fb117d4661cd80c92987afd0b4e44e794945580feeedece4b1b68098b6134de8be2ed2245aa8b01a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120310a0091aaa04f90227f901d1a06ed7d26d8a14a9cd8aeb3f01960cae49b7e95dbd549fff6556694ea3ee3dc173a0c445c1e18313a154c9cfd1a1bdbf2fb6d7513227c59c5cfe4ed6b2f1585ea74ea06c664a574aeaa739d85b114d13a20a15330b02565910dfb142b6715b5742a562a0726016a81a8017e5825a30ad9481c2ea45a35601f9e17a25ef74fb2fcc093ecb80a019977eb86a7f4c991220db91b3be76de8c43b5f5ea5414ad2ae17d27226ff633a075d1dffd2abda435b74cfaccf176f5e0938c60d66068a44727add2ef2df1f3eea0c993119ba273a56742e6fa6f92bb58a0120a3b3d27200340be21bc37ae8fdce2a04f3e6cb5f42f4cfe12e8e586e820edf8460ca87b27b4823c129d986c127e4898a07def82f69a90079ffaeaa69f6fda2b28363547c376948939c06aa8206c51c022a0b84308f4cb54366a086a4fdd936c40ab7ba0429ca9b7a624a6db6c5ac35c0b9ca041feda5565ebddc0a30be2e0fef75fe61729344ec36395f2f1e60865cd434a58a01223a2c45e23b4266f6b786bb346c31ea0c18ac94135d2f5138cc2851f7bf44a80a00d690f6252aa5118f41dce0eb3fdd420419d6d73ef7d51559385cab56a0308e2a054529b9b4e918ca60d7d2c1f1c9104a1442f9dcee09012b637ec7bd7ec46702680f8518080808080808080a00f079d6471365442c66c0559bffebac0b429bc330e636338e9c5dac3bd3fbaf7808080a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5ccecca8080808022448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072244a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512244d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff2a448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072a44a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512a44d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff1a8f1a0a90060a8d06f9030aa0312846a6b051a39d1ac8afa16dd707c278c2590b5b5399dd5dbaa2c87e9c6d04a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794a7876ea32e7a748c697d01345145485561305b24a049b529cd1d9b70dc216289fe9519c319964f0f7bd9458056da2defcf42743335a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a58402625a00808465122d36b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b860a0be31d422b4b017cc814dedd756cafcaff3c871779a6321284cebe91e5e1c2c0cb49b65be2a9bb41eabfc5480c8c75f0906339f62235d0b4352b3af1e38c79986cc1eb16880f26dd9c8f40bd8020890985d59f01bba4dd46df62be6a0c05414f8488204a3a0263c6cea09d25bb460401680cc3142f116c5a377f8ef11060e80f0f612f1c3168204a4a0312846a6b051a39d1ac8afa16dd707c278c2590b5b5399dd5dbaa2c87e9c6d0480f7464a0e50746e1283e82b6ea17ec53c71c61ed86665a300756b53d37dd3991346774d2ac3c242d8f0371f0ebe08f5af80757c6cd3e239212106d05d067064a300a000000000000000000000000000000000000000000000000000000000000000008800000000000000000a90060a8d06f9030aa04f09e6f36be8d56f196ab819ceab4de899dd91ea84d1a579c59cfe8d41f74269a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794d9a13701eafb76870cb220843b8c6476824bfa15a049b529cd1d9b70dc216289fe9519c319964f0f7bd9458056da2defcf42743335a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a68402625a00808465122d39b90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b8608ae8e9f3eeb44fc2ace50cb82e7922ccfad7571f507e89282474c970cd87f2f90cb7e3e22ef872e48cc904015c4792290b172b0e9aef2090a9ee653c0f258c215314c810b42b1a4399378cfeb7e8130082d7048bbc25c56373e4167b25feb51ff8488204a4a0312846a6b051a39d1ac8afa16dd707c278c2590b5b5399dd5dbaa2c87e9c6d048204a5a04f09e6f36be8d56f196ab819ceab4de899dd91ea84d1a579c59cfe8d41f742698048e891fd5b3f1eed759866fe722882c746dab531d47e972732640e42f49365b1348eb77bdc7425486f16a59b5080dd87b9406f1d532c37b8589e4b666cfd855b00a000000000000000000000000000000000000000000000000000000000000000008800000000000000000a90060a8d06f9030aa0ccdadba9c31c3462045f7552ec31591fc033d53cc02f66efe74a7a11527dd886a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347948fdaaa7e6631e438625ca25c857a3727ea28e565a049b529cd1d9b70dc216289fe9519c319964f0f7bd9458056da2defcf42743335a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000028204a78402625a00808465122d3cb90111d98301020b846765746889676f312e31392e3133856c696e75780000e904d98cf8ae07b860b5564a5fdce667a739c336d6b07beec17f8afcbc72da74f98e690327c32893b81ff51a6badcb7dfc0af7de042dc3b90e0467fef125d666956f3179b5330fc7a47624858eee5cb9edc93b45677417b742d213d97205770fcd0a36d6c409f551aff8488204a5a04f09e6f36be8d56f196ab819ceab4de899dd91ea84d1a579c59cfe8d41f742698204a6a0ccdadba9c31c3462045f7552ec31591fc033d53cc02f66efe74a7a11527dd88680299e2c8ee9446f79b09078581adec0382f5f0a5f49986493802bc10349e535d71b7e2d734818374617361443398ac0a3e3a343b7ca920586db67a7dcae60018101a00000000000000000000000000000000000000000000000000000000000000000880000000000000000120310a0091aaa04f90227f901d1a06ed7d26d8a14a9cd8aeb3f01960cae49b7e95dbd549fff6556694ea3ee3dc173a010790f90204b51f76a67de8b4bd23f62ea75f921641ff583a3ec5e8d681df975a06c664a574aeaa739d85b114d13a20a15330b02565910dfb142b6715b5742a562a051b92742fd280c4a2285b18197d40134dfe7d903b7d707cea1bd5f442a78a63580a019977eb86a7f4c991220db91b3be76de8c43b5f5ea5414ad2ae17d27226ff633a022a617263a20b5549555a9424a99ea156c9337b4b2009f9274febe93638918aaa0c993119ba273a56742e6fa6f92bb58a0120a3b3d27200340be21bc37ae8fdce2a04f3e6cb5f42f4cfe12e8e586e820edf8460ca87b27b4823c129d986c127e4898a07def82f69a90079ffaeaa69f6fda2b28363547c376948939c06aa8206c51c022a0b84308f4cb54366a086a4fdd936c40ab7ba0429ca9b7a624a6db6c5ac35c0b9ca041feda5565ebddc0a30be2e0fef75fe61729344ec36395f2f1e60865cd434a58a01223a2c45e23b4266f6b786bb346c31ea0c18ac94135d2f5138cc2851f7bf44a80a00d690f6252aa5118f41dce0eb3fdd420419d6d73ef7d51559385cab56a0308e2a09ab965be5ca3cbb09432f80709f918076cbad663afd466131fd184c8bda104c480f8518080808080808080a00f079d6471365442c66c0559bffebac0b429bc330e636338e9c5dac3bd3fbaf7808080a0e2ec5bfa0874d74ec0fdffc07602dab45aa5a426ed8ce5c3f11c957ef5ccecca8080808022448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072244a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512244d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff2a448fdaaa7e6631e438625ca25c857a3727ea28e5658bb6a87761d9668637faacae15f907dd813ea1df4f85062fa5535765c198bb9d55293684a75d3a12e65215a8b410f2072a44a7876ea32e7a748c697d01345145485561305b24a4f05ea3dd58373394ba3a7ca3cabec78b69e044b2b09e82171d82e6e3998a9ed1f82226cd4540bcc8c3bafa8c9c72512a44d9a13701eafb76870cb220843b8c6476824bfa15ab63700b5d3f58338176990c8488a7c319480310b5ec39d23453839ff26116b29a91e20f834835c5e6f670961d7df8ff").to_vec();
        let any: Any = any.try_into().unwrap();
        let misbehavior = Misbehaviour::try_from(any.clone()).unwrap();
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: misbehavior.header_1.current_validators_hash(),
            previous_validators_hash: misbehavior.header_1.previous_validators_hash(),
            ..Default::default()
        };
        mock_consensus_state.insert(misbehavior.header_1.trusted_height(), trusted_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: mock_consensus_state,
        };

        let result = client.submit_misbehaviour(&ctx, client_id.clone(), any);
        match result {
            Ok(cs) => assert!(cs.frozen),
            Err(e) => unreachable!("err={:?}", e),
        };

        // assert testdata validity
        assert_eq!(misbehavior.client_id, client_id);
        assert_eq!(misbehavior.header_1.height(), new_height(0, 1189));
        assert_eq!(
            misbehavior.header_1.block_hash(),
            &hex!("9432b9b136e91a12cea5e9cc363bc821e90da6c7b2d7f369533afa746ac21508")
        );
        assert_eq!(misbehavior.header_2.height(), misbehavior.header_1.height());
        assert_eq!(
            misbehavior.header_2.trusted_height(),
            misbehavior.header_1.trusted_height()
        );
        assert_ne!(
            misbehavior.header_2.block_hash(),
            misbehavior.header_1.block_hash()
        );
    }

    #[test]
    fn test_error_submit_misbehavior() {
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: BTreeMap::new(),
        };

        let client = ParliaLightClient::default();
        let client_id = ClientId::new(client.client_type().as_str(), 1).unwrap();

        // fail: exactly same block
        let mut any= hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212898e010a0b78782d7061726c69612d3112fb460a9d060a9a06f90317a0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479469c77a677c40c7fbea129d4b171a39b7a8ddabfaa0367319f8df31ff4b616b09c5d0877147904002cbeb93701e2bc2291d3f85e373a0a36d378b3813df6d2cfb735f98b9f1c2ad274767d70d2b83f01df65bd7060c7da0c07110486e8eb7be3528220485458e1904554e77a709835bcdf102de08b61445b901004222e610319851925ec8a154c538000d1618a08003578c18285805003b321c97a7345044c970940be2052cba00125380a2085c53144f23627c415c3349272ee714926a41234418b9af7c04bda5080931a51709a3547d9f82a30db42080012c05016881359b46c3820001bc98e1428bdb2c590c6f88418c3d70c47a1048c8a48934bdb1342c0b5c54808ca48044270ceb88a536f54270754b07051c489bc4f02586c0841997d889a8243816842b8b2498200a90d518a8c78213412a2c515b446c2584150775092b9286a6202b8846f2812415a35019ee011433114cfea021f67e431a0305206470020364a623a020894870960ea0c2764e4b95ca4e10238b10a9028401eaba0b8408583b0083ad346e846516831eb90118d98301020b846765746889676f312e31392e3132856c696e75780000b19df4a2f8b5831defffb86081828df4756db11e725568e085da9ea4f1db63f97645e76c91f77d22ffef7200e0a8f06d9f2f2698f62d99c972c488ba009b507f36b346254e782534110e04a20772e2dd6a2ba12f482b478cfada1981fb46fe33d31a08ebef4abaa4ac2b83fcf84c8401eaba09a03009339cf4323f2c5efd3ec22eeb696e0b0a4e6ab60ed9f9d4c8f23bf227ac7a8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8083ad988504ae27211e4a676510c51568f555d6b95545410b209b6761282cd3e679e277a8969b5f5d97101ae220174d69e960ce9f13bf7fdf0661c368b1df347400a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0d4d38d061e7a8eaa7beaf72bfda8e61ab5bf52aea4315b273e29a7bdccef7cb8a0087324763ee1c00c9ad8d09121f2d2f56d80d593342bcd998e4fca26f0e03153a05eea513d92cac961941b786a8827e4d1375885b0cbb90af62fca8e0fd9285ed3b901008d6b62622b1c923e0b335b6584226a3b955878d0deba0ec87a78e16a316a2034876953d9d2a6e610c7b1faa45f9e6f6381e1c118207bbaa650282513dd3c2edc0cd7c42ebf6acc6e21ad284b7724473d2675b0224fd6e2bcb1b64eb490b0cf294f3fb9755b072fad587b8b7881341f08fc157c55c23a543e2f65949e4fbba4c5f5daa92c0eaf839b9d8ae4888d026c1eb46cd4edb96a619a1a1584f8f4ac0f2402d2b9857249930c8528f166ee9e4e59c18210453d06b1874d31a82a05f678abe04a1e9a98811d5fd6a848ed024c78b0a6fba25c9a42e6361513510e79aaeea810d1d805d4e0db90c90b2a92530081e349946b6893bc8079f17746207c3d1158028401eaba0c84084fe2c683efb91f8465168321b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb86083265457e59114983f1076e6afe3914e8f6c68afcb50c434f49e3d4f3e380208adde4d348c10d83a4caa577dc8f875050aace673b180818bc9c53c44be471a089d2773a9088356409b7668f24e0221f5dc0e12d121552cf2554a54710fde149df84c8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc80fea86520fb3bdd71a0744ae6311c632107f640536f647f352c4d76cdefc0fe3f334095862d3f08362d50104caa4dcae5f15cb24a25a6e7c413ad04b20e7d6d1901a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904dba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a0711c94607e53ea254337a19dfe928741d406c0217becb0b51034fc91a4b2e88ea0e540e2e257a6edbb482543f15e1690410b70cddc7b8111f48de4c688a35caca1a0ded39245b638233ed2ac16389abb608f6329d48557888cd16de33d6b510873f6b901000e220e06afc4d15833201a459150012f1a51400005088c06383961403a2c0c00a42c3111001898020123ecf3081a00838e000418000b60a00490a002003f2a014458d8408570580b0148802b24a00428a132222861f47b86248404b4c02316210b2c802b0aa209d500c98d000145090d38c84409084cc420b944593410ca38a2c83c80a40b38108af0d84420240404fa2a740e812ca604ba38819241410b9070060182011f801211019aa03c0b8004a31c8b47204a0e450812f803a206402260a40b971220084c065500489b50315423a0402510d52900144513444e1421ed5d1511a45d1822275801b522040090017126448c05132a04e85608991043990849018401eaba0d84085832a78389fc6a8465168324b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860accd42f5a790b23a42c750634bd4c632b68b4a13d9e67a23fc88e634c1f5be8b8824355e90f5e6bcb23af9f0ecdb041c011c645770184427d940f1078c0f20aa6f70aa3e68944f9e588ec0726febd32ab6519295e3eefdfd66ca3ff0a57e6e3af84c8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc8401eaba0ca0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904db80c68c3a1187742f4228a35df126397c068f0d529182962a834f230031471c12bc6d4cc917d21556160579a782e799fdbce7d5bae9c67027ac6f9860f540f768db00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801205108af4aa0f1a951df90e92f90211a02bff590463eb4f2fb98586805a6591c49ad02eb38211ce40238beef315d2b1a3a03f20d9b30890c082262b4ebcb9c089af0b95a18873fd3c0b1a13e0d0c71137eba0c0649e9f0a6040129bcd329483228eba044da097d400621ab85b5351d2980b40a0304852b72a4c75c7d71e3946ef983cf4c1f3c2b478c8997870a1d4454ae04dbfa0432d943bbfe2b6d9f62df84439769f8ea76f9213c6fcfdcf2052d5c31dcdf16fa00c4d39f0619caa3ae86e99de2395b94ba29a52ab6e4966a5bb4b138ae39e0c70a0384ee242954ec95a8f3372527b557488894506ab1a9fe80fc8381ff15216e103a022bb93d7f4851836b855b2570e2e01270585595c9792cc4e93a437a4e474bb5fa0d02fec5b104fcc8919ab37aff38a323fb06bb05663078b901c7dd54306d3caeda0f18f265a00fedc81f65cde8e79d8909c9eaf01cb1badafac441193c3911a50cfa0a475a4d413336a0497c6c412db1f4a0b75339d8ebaa318ead92b01926f904668a08b350addc0ac0af1c475f6ea8c89f9e7bfd2f08db1496d88a4b9b8d7e68b775ca0a93aa453df1f6fea8e6586b761752c988bebc9d8919fce66a2dc07b13b516317a0e88647c53c3837076340c8af5dd6e7d6eae1e979748907cc77735a2fa61fe3b5a03558b2e214bbd1e4f1066b9444fd27491b8cd594727b4df2c6c40a66ee092e48a04b8dd919d1cd6c0dc1c868e8b17383212a9291ee4c6129b74927822c836d96f580f90211a082dfa0895f58c8ab219b1a3495c930a91ced1024bb93d17db00e25b951a6c619a07daeef642e3fafcd93260f2c8486ee75803c32795ea83152752c7f298ba98481a0416d5ba0562c59a16a92991b267cdb40b25734856902f5599db0ebf64ce4ea40a006a001e9a09963a91a4e2fdea6a238d4b540699e8828085b460dab39744547c7a01dc72e0048890365d8fbfb7c5b1c8ef52d49e41e089d99f52fadffe3efde1303a0942505b8e8a3ec1f16bee602466ef6605139cce2b5802355aecd2de1def8363ba0096a2585a6d4d2912c5387d5998f22455a1baf48894c5f89621d22721202f238a0c798b5904ca51608776665eb627ba3a32ecb75eaf20cea825ece8f9b8a7a44f3a076f5e9f1ff4e8b68028f8dbf07711a9e5235887749da2db07d8c7ca23d1c06dba0019d4d8661b0e52876e58c1cb072c5c2aef8db86d35288be6ddbf6cd782eb5f6a01c418f5263baafdae54580467f5e50ec141611331f53db37d838c1671bc6a25ba0a0fb254b54da6444d91d0b6585c4a2fcdf9e19b10357377fd5699b4bad8adab6a00b841477da486c5819fd12285e8f097c92b317c9e239954f5cbba1c70f679b4ba0612b371378ad1d8cc5e0954a111df8e0c8ea0da63300ca1126fb1a54338b32f4a072a4f633843d50afdb0d3a76464892f1c392579ec74f6df6cf1df231ba4ab42ea07734e834476c826ab88df35eb30599174a9f863d17d18ce04f87f34526cb6fc480f90211a02fedb0b9b16e327962ff519dfc137fb4e25408054dc09c6cf8d97fcc8c58f1fca03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa005613369534c7d926a4b06e352e6d17532bc802c0fcedd13073e68c41b99901da0c5daa0a98986bab70d997d7faa4b55ddbcb75bcf7cd71d7950d145222cb3e21fa02718fac0f09350134ea331146441ad6005f8a8c20b9673f5b4bb1d9cac9f2163a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa0b4cf1ad7a7b3f08bc8842186fcd78ff7d746763fcae212432d0f20a50be4fb65a07396b72a68947b922b056495abe200f446a5fa9b01fd098d17a76a2672b9515ca09a877e342351f9e10dea0fbf7478ee67c215bfd821da88208b9fcf63bea39bfba0b5ead9f9ba5a3ac8c888cb19af13e8a3d279474818054d335b28e81c431cc72ea04e66c0882953c62e542817724480b4f8d7a7944b3dee7455b249be68b5b9990da03a1aca9f115f2d3d71ee1cc202c2129d6f72c4f80b7b85128d54f9be9cda8c2fa01c1a35b8aa431b2a845c34b464542a83220b17e4dd1a4d4774b1807f1f9c9e23a03b2492dac5c5619f8c84fc0969ff24f5695bb4363c22c4120c86d2bc128aabfaa0c30d11204878acb9ce6a7931150e9ec10f1a659076ec3c1528c663f1897f85e180f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd075").to_vec();
        let any2= hex!("6e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd01afb460a9d060a9a06f90317a0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479469c77a677c40c7fbea129d4b171a39b7a8ddabfaa0367319f8df31ff4b616b09c5d0877147904002cbeb93701e2bc2291d3f85e373a0a36d378b3813df6d2cfb735f98b9f1c2ad274767d70d2b83f01df65bd7060c7da0c07110486e8eb7be3528220485458e1904554e77a709835bcdf102de08b61445b901004222e610319851925ec8a154c538000d1618a08003578c18285805003b321c97a7345044c970940be2052cba00125380a2085c53144f23627c415c3349272ee714926a41234418b9af7c04bda5080931a51709a3547d9f82a30db42080012c05016881359b46c3820001bc98e1428bdb2c590c6f88418c3d70c47a1048c8a48934bdb1342c0b5c54808ca48044270ceb88a536f54270754b07051c489bc4f02586c0841997d889a8243816842b8b2498200a90d518a8c78213412a2c515b446c2584150775092b9286a6202b8846f2812415a35019ee011433114cfea021f67e431a0305206470020364a623a020894870960ea0c2764e4b95ca4e10238b10a9028401eaba0b8408583b0083ad346e846516831eb90118d98301020b846765746889676f312e31392e3132856c696e75780000b19df4a2f8b5831defffb86081828df4756db11e725568e085da9ea4f1db63f97645e76c91f77d22ffef7200e0a8f06d9f2f2698f62d99c972c488ba009b507f36b346254e782534110e04a20772e2dd6a2ba12f482b478cfada1981fb46fe33d31a08ebef4abaa4ac2b83fcf84c8401eaba09a03009339cf4323f2c5efd3ec22eeb696e0b0a4e6ab60ed9f9d4c8f23bf227ac7a8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8083ad988504ae27211e4a676510c51568f555d6b95545410b209b6761282cd3e679e277a8969b5f5d97101ae220174d69e960ce9f13bf7fdf0661c368b1df347400a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0d4d38d061e7a8eaa7beaf72bfda8e61ab5bf52aea4315b273e29a7bdccef7cb8a0087324763ee1c00c9ad8d09121f2d2f56d80d593342bcd998e4fca26f0e03153a05eea513d92cac961941b786a8827e4d1375885b0cbb90af62fca8e0fd9285ed3b901008d6b62622b1c923e0b335b6584226a3b955878d0deba0ec87a78e16a316a2034876953d9d2a6e610c7b1faa45f9e6f6381e1c118207bbaa650282513dd3c2edc0cd7c42ebf6acc6e21ad284b7724473d2675b0224fd6e2bcb1b64eb490b0cf294f3fb9755b072fad587b8b7881341f08fc157c55c23a543e2f65949e4fbba4c5f5daa92c0eaf839b9d8ae4888d026c1eb46cd4edb96a619a1a1584f8f4ac0f2402d2b9857249930c8528f166ee9e4e59c18210453d06b1874d31a82a05f678abe04a1e9a98811d5fd6a848ed024c78b0a6fba25c9a42e6361513510e79aaeea810d1d805d4e0db90c90b2a92530081e349946b6893bc8079f17746207c3d1158028401eaba0c84084fe2c683efb91f8465168321b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb86083265457e59114983f1076e6afe3914e8f6c68afcb50c434f49e3d4f3e380208adde4d348c10d83a4caa577dc8f875050aace673b180818bc9c53c44be471a089d2773a9088356409b7668f24e0221f5dc0e12d121552cf2554a54710fde149df84c8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc80fea86520fb3bdd71a0744ae6311c632107f640536f647f352c4d76cdefc0fe3f334095862d3f08362d50104caa4dcae5f15cb24a25a6e7c413ad04b20e7d6d1901a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904dba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a0711c94607e53ea254337a19dfe928741d406c0217becb0b51034fc91a4b2e88ea0e540e2e257a6edbb482543f15e1690410b70cddc7b8111f48de4c688a35caca1a0ded39245b638233ed2ac16389abb608f6329d48557888cd16de33d6b510873f6b901000e220e06afc4d15833201a459150012f1a51400005088c06383961403a2c0c00a42c3111001898020123ecf3081a00838e000418000b60a00490a002003f2a014458d8408570580b0148802b24a00428a132222861f47b86248404b4c02316210b2c802b0aa209d500c98d000145090d38c84409084cc420b944593410ca38a2c83c80a40b38108af0d84420240404fa2a740e812ca604ba38819241410b9070060182011f801211019aa03c0b8004a31c8b47204a0e450812f803a206402260a40b971220084c065500489b50315423a0402510d52900144513444e1421ed5d1511a45d1822275801b522040090017126448c05132a04e85608991043990849018401eaba0d84085832a78389fc6a8465168324b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860accd42f5a790b23a42c750634bd4c632b68b4a13d9e67a23fc88e634c1f5be8b8824355e90f5e6bcb23af9f0ecdb041c011c645770184427d940f1078c0f20aa6f70aa3e68944f9e588ec0726febd32ab6519295e3eefdfd66ca3ff0a57e6e3af84c8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc8401eaba0ca0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904db80c68c3a1187742f4228a35df126397c068f0d529182962a834f230031471c12bc6d4cc917d21556160579a782e799fdbce7d5bae9c67027ac6f9860f540f768db00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801205108af4aa0f1a951df90e92f90211a02bff590463eb4f2fb98586805a6591c49ad02eb38211ce40238beef315d2b1a3a03f20d9b30890c082262b4ebcb9c089af0b95a18873fd3c0b1a13e0d0c71137eba0c0649e9f0a6040129bcd329483228eba044da097d400621ab85b5351d2980b40a0304852b72a4c75c7d71e3946ef983cf4c1f3c2b478c8997870a1d4454ae04dbfa0432d943bbfe2b6d9f62df84439769f8ea76f9213c6fcfdcf2052d5c31dcdf16fa00c4d39f0619caa3ae86e99de2395b94ba29a52ab6e4966a5bb4b138ae39e0c70a0384ee242954ec95a8f3372527b557488894506ab1a9fe80fc8381ff15216e103a022bb93d7f4851836b855b2570e2e01270585595c9792cc4e93a437a4e474bb5fa0d02fec5b104fcc8919ab37aff38a323fb06bb05663078b901c7dd54306d3caeda0f18f265a00fedc81f65cde8e79d8909c9eaf01cb1badafac441193c3911a50cfa0a475a4d413336a0497c6c412db1f4a0b75339d8ebaa318ead92b01926f904668a08b350addc0ac0af1c475f6ea8c89f9e7bfd2f08db1496d88a4b9b8d7e68b775ca0a93aa453df1f6fea8e6586b761752c988bebc9d8919fce66a2dc07b13b516317a0e88647c53c3837076340c8af5dd6e7d6eae1e979748907cc77735a2fa61fe3b5a03558b2e214bbd1e4f1066b9444fd27491b8cd594727b4df2c6c40a66ee092e48a04b8dd919d1cd6c0dc1c868e8b17383212a9291ee4c6129b74927822c836d96f580f90211a082dfa0895f58c8ab219b1a3495c930a91ced1024bb93d17db00e25b951a6c619a07daeef642e3fafcd93260f2c8486ee75803c32795ea83152752c7f298ba98481a0416d5ba0562c59a16a92991b267cdb40b25734856902f5599db0ebf64ce4ea40a006a001e9a09963a91a4e2fdea6a238d4b540699e8828085b460dab39744547c7a01dc72e0048890365d8fbfb7c5b1c8ef52d49e41e089d99f52fadffe3efde1303a0942505b8e8a3ec1f16bee602466ef6605139cce2b5802355aecd2de1def8363ba0096a2585a6d4d2912c5387d5998f22455a1baf48894c5f89621d22721202f238a0c798b5904ca51608776665eb627ba3a32ecb75eaf20cea825ece8f9b8a7a44f3a076f5e9f1ff4e8b68028f8dbf07711a9e5235887749da2db07d8c7ca23d1c06dba0019d4d8661b0e52876e58c1cb072c5c2aef8db86d35288be6ddbf6cd782eb5f6a01c418f5263baafdae54580467f5e50ec141611331f53db37d838c1671bc6a25ba0a0fb254b54da6444d91d0b6585c4a2fcdf9e19b10357377fd5699b4bad8adab6a00b841477da486c5819fd12285e8f097c92b317c9e239954f5cbba1c70f679b4ba0612b371378ad1d8cc5e0954a111df8e0c8ea0da63300ca1126fb1a54338b32f4a072a4f633843d50afdb0d3a76464892f1c392579ec74f6df6cf1df231ba4ab42ea07734e834476c826ab88df35eb30599174a9f863d17d18ce04f87f34526cb6fc480f90211a02fedb0b9b16e327962ff519dfc137fb4e25408054dc09c6cf8d97fcc8c58f1fca03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa005613369534c7d926a4b06e352e6d17532bc802c0fcedd13073e68c41b99901da0c5daa0a98986bab70d997d7faa4b55ddbcb75bcf7cd71d7950d145222cb3e21fa02718fac0f09350134ea331146441ad6005f8a8c20b9673f5b4bb1d9cac9f2163a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa0b4cf1ad7a7b3f08bc8842186fcd78ff7d746763fcae212432d0f20a50be4fb65a07396b72a68947b922b056495abe200f446a5fa9b01fd098d17a76a2672b9515ca09a877e342351f9e10dea0fbf7478ee67c215bfd821da88208b9fcf63bea39bfba0b5ead9f9ba5a3ac8c888cb19af13e8a3d279474818054d335b28e81c431cc72ea04e66c0882953c62e542817724480b4f8d7a7944b3dee7455b249be68b5b9990da03a1aca9f115f2d3d71ee1cc202c2129d6f72c4f80b7b85128d54f9be9cda8c2fa01c1a35b8aa431b2a845c34b464542a83220b17e4dd1a4d4774b1807f1f9c9e23a03b2492dac5c5619f8c84fc0969ff24f5695bb4363c22c4120c86d2bc128aabfaa0c30d11204878acb9ce6a7931150e9ec10f1a659076ec3c1528c663f1897f85e180f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        any.extend(any2);
        let any: Any = any.try_into().unwrap();
        let err = client
            .submit_misbehaviour(&ctx, client_id.clone(), any)
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("UnexpectedSameBlockHash : 0-32160267"),
            "{}",
            err
        );

        // fail: invalid block
        let mut mock_consensus_state = BTreeMap::new();
        let trusted_cs = ConsensusState {
            current_validators_hash: hex!(
                "abe3670d5b312d3dd78123a31673e12413573eac5cada972eefb608edae91cac"
            ),
            previous_validators_hash: hex!(
                "dc895253030c1833d95cfaa05c9aac223222099bc4b86ab99eeab6021ba64a71"
            ),
            ..Default::default()
        };
        mock_consensus_state.insert(Height::new(0, 32160266), trusted_cs);
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                chain_id: mainnet(),
                ..Default::default()
            }),
            consensus_state: mock_consensus_state.clone(),
        };

        let mut any = hex!("0a282f6962632e6c69676874636c69656e74732e7061726c69612e76312e4d69736265686176696f757212898e010a0b78782d7061726c69612d3112fb460a9d060a9a06f90317a0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479469c77a677c40c7fbea129d4b171a39b7a8ddabfaa0367319f8df31ff4b616b09c5d0877147904002cbeb93701e2bc2291d3f85e373a0a36d378b3813df6d2cfb735f98b9f1c2ad274767d70d2b83f01df65bd7060c7da0c07110486e8eb7be3528220485458e1904554e77a709835bcdf102de08b61445b901004222e610319851925ec8a154c538000d1618a08003578c18285805003b321c97a7345044c970940be2052cba00125380a2085c53144f23627c415c3349272ee714926a41234418b9af7c04bda5080931a51709a3547d9f82a30db42080012c05016881359b46c3820001bc98e1428bdb2c590c6f88418c3d70c47a1048c8a48934bdb1342c0b5c54808ca48044270ceb88a536f54270754b07051c489bc4f02586c0841997d889a8243816842b8b2498200a90d518a8c78213412a2c515b446c2584150775092b9286a6202b8846f2812415a35019ee011433114cfea021f67e431a0305206470020364a623a020894870960ea0c2764e4b95ca4e10238b10a9028401eaba0b8408583b0083ad346e846516831eb90118d98301020b846765746889676f312e31392e3132856c696e75780000b19df4a2f8b5831defffb86081828df4756db11e725568e085da9ea4f1db63f97645e76c91f77d22ffef7200e0a8f06d9f2f2698f62d99c972c488ba009b507f36b346254e782534110e04a20772e2dd6a2ba12f482b478cfada1981fb46fe33d31a08ebef4abaa4ac2b83fcf84c8401eaba09a03009339cf4323f2c5efd3ec22eeb696e0b0a4e6ab60ed9f9d4c8f23bf227ac7a8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8083ad988504ae27211e4a676510c51568f555d6b95545410b209b6761282cd3e679e277a8969b5f5d97101ae220174d69e960ce9f13bf7fdf0661c368b1df347400a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0d4d38d061e7a8eaa7beaf72bfda8e61ab5bf52aea4315b273e29a7bdccef7cb8a0087324763ee1c00c9ad8d09121f2d2f56d80d593342bcd998e4fca26f0e03153a05eea513d92cac961941b786a8827e4d1375885b0cbb90af62fca8e0fd9285ed3b901008d6b62622b1c923e0b335b6584226a3b955878d0deba0ec87a78e16a316a2034876953d9d2a6e610c7b1faa45f9e6f6381e1c118207bbaa650282513dd3c2edc0cd7c42ebf6acc6e21ad284b7724473d2675b0224fd6e2bcb1b64eb490b0cf294f3fb9755b072fad587b8b7881341f08fc157c55c23a543e2f65949e4fbba4c5f5daa92c0eaf839b9d8ae4888d026c1eb46cd4edb96a619a1a1584f8f4ac0f2402d2b9857249930c8528f166ee9e4e59c18210453d06b1874d31a82a05f678abe04a1e9a98811d5fd6a848ed024c78b0a6fba25c9a42e6361513510e79aaeea810d1d805d4e0db90c90b2a92530081e349946b6893bc8079f17746207c3d1158028401eaba0c84084fe2c683efb91f8465168321b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb86083265457e59114983f1076e6afe3914e8f6c68afcb50c434f49e3d4f3e380208adde4d348c10d83a4caa577dc8f875050aace673b180818bc9c53c44be471a089d2773a9088356409b7668f24e0221f5dc0e12d121552cf2554a54710fde149df84c8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc80fea86520fb3bdd71a0744ae6311c632107f640536f647f352c4d76cdefc0fe3f334095862d3f08362d50104caa4dcae5f15cb24a25a6e7c413ad04b20e7d6d1901a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904dba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a0711c94607e53ea254337a19dfe928741d406c0217becb0b51034fc91a4b2e88ea0e540e2e257a6edbb482543f15e1690410b70cddc7b8111f48de4c688a35caca1a0ded39245b638233ed2ac16389abb608f6329d48557888cd16de33d6b510873f6b901000e220e06afc4d15833201a459150012f1a51400005088c06383961403a2c0c00a42c3111001898020123ecf3081a00838e000418000b60a00490a002003f2a014458d8408570580b0148802b24a00428a132222861f47b86248404b4c02316210b2c802b0aa209d500c98d000145090d38c84409084cc420b944593410ca38a2c83c80a40b38108af0d84420240404fa2a740e812ca604ba38819241410b9070060182011f801211019aa03c0b8004a31c8b47204a0e450812f803a206402260a40b971220084c065500489b50315423a0402510d52900144513444e1421ed5d1511a45d1822275801b522040090017126448c05132a04e85608991043990849018401eaba0d84085832a78389fc6a8465168324b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860accd42f5a790b23a42c750634bd4c632b68b4a13d9e67a23fc88e634c1f5be8b8824355e90f5e6bcb23af9f0ecdb041c011c645770184427d940f1078c0f20aa6f70aa3e68944f9e588ec0726febd32ab6519295e3eefdfd66ca3ff0a57e6e3af84c8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc8401eaba0ca0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904db80c68c3a1187742f4228a35df126397c068f0d529182962a834f230031471c12bc6d4cc917d21556160579a782e799fdbce7d5bae9c67027ac6f9860f540f768db00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801205108af4aa0f1a951df90e92f90211a02bff590463eb4f2fb98586805a6591c49ad02eb38211ce40238beef315d2b1a3a03f20d9b30890c082262b4ebcb9c089af0b95a18873fd3c0b1a13e0d0c71137eba0c0649e9f0a6040129bcd329483228eba044da097d400621ab85b5351d2980b40a0304852b72a4c75c7d71e3946ef983cf4c1f3c2b478c8997870a1d4454ae04dbfa0432d943bbfe2b6d9f62df84439769f8ea76f9213c6fcfdcf2052d5c31dcdf16fa00c4d39f0619caa3ae86e99de2395b94ba29a52ab6e4966a5bb4b138ae39e0c70a0384ee242954ec95a8f3372527b557488894506ab1a9fe80fc8381ff15216e103a022bb93d7f4851836b855b2570e2e01270585595c9792cc4e93a437a4e474bb5fa0d02fec5b104fcc8919ab37aff38a323fb06bb05663078b901c7dd54306d3caeda0f18f265a00fedc81f65cde8e79d8909c9eaf01cb1badafac441193c3911a50cfa0a475a4d413336a0497c6c412db1f4a0b75339d8ebaa318ead92b01926f904668a08b350addc0ac0af1c475f6ea8c89f9e7bfd2f08db1496d88a4b9b8d7e68b775ca0a93aa453df1f6fea8e6586b761752c988bebc9d8919fce66a2dc07b13b516317a0e88647c53c3837076340c8af5dd6e7d6eae1e979748907cc77735a2fa61fe3b5a03558b2e214bbd1e4f1066b9444fd27491b8cd594727b4df2c6c40a66ee092e48a04b8dd919d1cd6c0dc1c868e8b17383212a9291ee4c6129b74927822c836d96f580f90211a082dfa0895f58c8ab219b1a3495c930a91ced1024bb93d17db00e25b951a6c619a07daeef642e3fafcd93260f2c8486ee75803c32795ea83152752c7f298ba98481a0416d5ba0562c59a16a92991b267cdb40b25734856902f5599db0ebf64ce4ea40a006a001e9a09963a91a4e2fdea6a238d4b540699e8828085b460dab39744547c7a01dc72e0048890365d8fbfb7c5b1c8ef52d49e41e089d99f52fadffe3efde1303a0942505b8e8a3ec1f16bee602466ef6605139cce2b5802355aecd2de1def8363ba0096a2585a6d4d2912c5387d5998f22455a1baf48894c5f89621d22721202f238a0c798b5904ca51608776665eb627ba3a32ecb75eaf20cea825ece8f9b8a7a44f3a076f5e9f1ff4e8b68028f8dbf07711a9e5235887749da2db07d8c7ca23d1c06dba0019d4d8661b0e52876e58c1cb072c5c2aef8db86d35288be6ddbf6cd782eb5f6a01c418f5263baafdae54580467f5e50ec141611331f53db37d838c1671bc6a25ba0a0fb254b54da6444d91d0b6585c4a2fcdf9e19b10357377fd5699b4bad8adab6a00b841477da486c5819fd12285e8f097c92b317c9e239954f5cbba1c70f679b4ba0612b371378ad1d8cc5e0954a111df8e0c8ea0da63300ca1126fb1a54338b32f4a072a4f633843d50afdb0d3a76464892f1c392579ec74f6df6cf1df231ba4ab42ea07734e834476c826ab88df35eb30599174a9f863d17d18ce04f87f34526cb6fc480f90211a02fedb0b9b16e327962ff519dfc137fb4e25408054dc09c6cf8d97fcc8c58f1fca03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa005613369534c7d926a4b06e352e6d17532bc802c0fcedd13073e68c41b99901da0c5daa0a98986bab70d997d7faa4b55ddbcb75bcf7cd71d7950d145222cb3e21fa02718fac0f09350134ea331146441ad6005f8a8c20b9673f5b4bb1d9cac9f2163a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa0b4cf1ad7a7b3f08bc8842186fcd78ff7d746763fcae212432d0f20a50be4fb65a07396b72a68947b922b056495abe200f446a5fa9b01fd098d17a76a2672b9515ca09a877e342351f9e10dea0fbf7478ee67c215bfd821da88208b9fcf63bea39bfba0b5ead9f9ba5a3ac8c888cb19af13e8a3d279474818054d335b28e81c431cc72ea04e66c0882953c62e542817724480b4f8d7a7944b3dee7455b249be68b5b9990da03a1aca9f115f2d3d71ee1cc202c2129d6f72c4f80b7b85128d54f9be9cda8c2fa01c1a35b8aa431b2a845c34b464542a83220b17e4dd1a4d4774b1807f1f9c9e23a03b2492dac5c5619f8c84fc0969ff24f5695bb4363c22c4120c86d2bc128aabfaa0c30d11204878acb9ce6a7931150e9ec10f1a659076ec3c1528c663f1897f85e180f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd075").to_vec();
        let any2 = hex!("6e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd01afb460a9d060a9a06f90317a0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1aa01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479469c77a677c40c7fbea129d4b171a39b7a8ddabfaa00000000000000000000000000000000000000000000000000000000000000000a0a36d378b3813df6d2cfb735f98b9f1c2ad274767d70d2b83f01df65bd7060c7da0c07110486e8eb7be3528220485458e1904554e77a709835bcdf102de08b61445b901004222e610319851925ec8a154c538000d1618a08003578c18285805003b321c97a7345044c970940be2052cba00125380a2085c53144f23627c415c3349272ee714926a41234418b9af7c04bda5080931a51709a3547d9f82a30db42080012c05016881359b46c3820001bc98e1428bdb2c590c6f88418c3d70c47a1048c8a48934bdb1342c0b5c54808ca48044270ceb88a536f54270754b07051c489bc4f02586c0841997d889a8243816842b8b2498200a90d518a8c78213412a2c515b446c2584150775092b9286a6202b8846f2812415a35019ee011433114cfea021f67e431a0305206470020364a623a020894870960ea0c2764e4b95ca4e10238b10a9028401eaba0b8408583b0083ad346e846516831eb90118d98301020b846765746889676f312e31392e3132856c696e75780000b19df4a2f8b5831defffb86081828df4756db11e725568e085da9ea4f1db63f97645e76c91f77d22ffef7200e0a8f06d9f2f2698f62d99c972c488ba009b507f36b346254e782534110e04a20772e2dd6a2ba12f482b478cfada1981fb46fe33d31a08ebef4abaa4ac2b83fcf84c8401eaba09a03009339cf4323f2c5efd3ec22eeb696e0b0a4e6ab60ed9f9d4c8f23bf227ac7a8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8083ad988504ae27211e4a676510c51568f555d6b95545410b209b6761282cd3e679e277a8969b5f5d97101ae220174d69e960ce9f13bf7fdf0661c368b1df347400a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cca01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479472b61c6014342d914470ec7ac2975be345796c2ba0d4d38d061e7a8eaa7beaf72bfda8e61ab5bf52aea4315b273e29a7bdccef7cb8a0087324763ee1c00c9ad8d09121f2d2f56d80d593342bcd998e4fca26f0e03153a05eea513d92cac961941b786a8827e4d1375885b0cbb90af62fca8e0fd9285ed3b901008d6b62622b1c923e0b335b6584226a3b955878d0deba0ec87a78e16a316a2034876953d9d2a6e610c7b1faa45f9e6f6381e1c118207bbaa650282513dd3c2edc0cd7c42ebf6acc6e21ad284b7724473d2675b0224fd6e2bcb1b64eb490b0cf294f3fb9755b072fad587b8b7881341f08fc157c55c23a543e2f65949e4fbba4c5f5daa92c0eaf839b9d8ae4888d026c1eb46cd4edb96a619a1a1584f8f4ac0f2402d2b9857249930c8528f166ee9e4e59c18210453d06b1874d31a82a05f678abe04a1e9a98811d5fd6a848ed024c78b0a6fba25c9a42e6361513510e79aaeea810d1d805d4e0db90c90b2a92530081e349946b6893bc8079f17746207c3d1158028401eaba0c84084fe2c683efb91f8465168321b90118d88301020b846765746888676f312e32302e35856c696e7578000000b19df4a2f8b5831defffb86083265457e59114983f1076e6afe3914e8f6c68afcb50c434f49e3d4f3e380208adde4d348c10d83a4caa577dc8f875050aace673b180818bc9c53c44be471a089d2773a9088356409b7668f24e0221f5dc0e12d121552cf2554a54710fde149df84c8401eaba0aa0a253fa96c80a63c58a92c2169edc61d58f53912fbecf0a3d23d95ddd7d375b1a8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc80fea86520fb3bdd71a0744ae6311c632107f640536f647f352c4d76cdefc0fe3f334095862d3f08362d50104caa4dcae5f15cb24a25a6e7c413ad04b20e7d6d1901a00000000000000000000000000000000000000000000000000000000000000000880000000000000000800a9d060a9a06f90317a0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904dba01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794e2d3a739effcd3a99387d015e260eefac72ebea1a0711c94607e53ea254337a19dfe928741d406c0217becb0b51034fc91a4b2e88ea0e540e2e257a6edbb482543f15e1690410b70cddc7b8111f48de4c688a35caca1a0ded39245b638233ed2ac16389abb608f6329d48557888cd16de33d6b510873f6b901000e220e06afc4d15833201a459150012f1a51400005088c06383961403a2c0c00a42c3111001898020123ecf3081a00838e000418000b60a00490a002003f2a014458d8408570580b0148802b24a00428a132222861f47b86248404b4c02316210b2c802b0aa209d500c98d000145090d38c84409084cc420b944593410ca38a2c83c80a40b38108af0d84420240404fa2a740e812ca604ba38819241410b9070060182011f801211019aa03c0b8004a31c8b47204a0e450812f803a206402260a40b971220084c065500489b50315423a0402510d52900144513444e1421ed5d1511a45d1822275801b522040090017126448c05132a04e85608991043990849018401eaba0d84085832a78389fc6a8465168324b90118d88301020b846765746888676f312e31392e38856c696e7578000000b19df4a2f8b5831defffb860accd42f5a790b23a42c750634bd4c632b68b4a13d9e67a23fc88e634c1f5be8b8824355e90f5e6bcb23af9f0ecdb041c011c645770184427d940f1078c0f20aa6f70aa3e68944f9e588ec0726febd32ab6519295e3eefdfd66ca3ff0a57e6e3af84c8401eaba0ba0ec996d8163dd118f6fa5e2a83a7d19fe665a2317facaa7ae9fbc95e6aca7e7cc8401eaba0ca0937afa96827a173a5ab83721cc146cb8f10dc87ba31ceff7e2395d2589a904db80c68c3a1187742f4228a35df126397c068f0d529182962a834f230031471c12bc6d4cc917d21556160579a782e799fdbce7d5bae9c67027ac6f9860f540f768db00a00000000000000000000000000000000000000000000000000000000000000000880000000000000000801205108af4aa0f1a951df90e92f90211a02bff590463eb4f2fb98586805a6591c49ad02eb38211ce40238beef315d2b1a3a03f20d9b30890c082262b4ebcb9c089af0b95a18873fd3c0b1a13e0d0c71137eba0c0649e9f0a6040129bcd329483228eba044da097d400621ab85b5351d2980b40a0304852b72a4c75c7d71e3946ef983cf4c1f3c2b478c8997870a1d4454ae04dbfa0432d943bbfe2b6d9f62df84439769f8ea76f9213c6fcfdcf2052d5c31dcdf16fa00c4d39f0619caa3ae86e99de2395b94ba29a52ab6e4966a5bb4b138ae39e0c70a0384ee242954ec95a8f3372527b557488894506ab1a9fe80fc8381ff15216e103a022bb93d7f4851836b855b2570e2e01270585595c9792cc4e93a437a4e474bb5fa0d02fec5b104fcc8919ab37aff38a323fb06bb05663078b901c7dd54306d3caeda0f18f265a00fedc81f65cde8e79d8909c9eaf01cb1badafac441193c3911a50cfa0a475a4d413336a0497c6c412db1f4a0b75339d8ebaa318ead92b01926f904668a08b350addc0ac0af1c475f6ea8c89f9e7bfd2f08db1496d88a4b9b8d7e68b775ca0a93aa453df1f6fea8e6586b761752c988bebc9d8919fce66a2dc07b13b516317a0e88647c53c3837076340c8af5dd6e7d6eae1e979748907cc77735a2fa61fe3b5a03558b2e214bbd1e4f1066b9444fd27491b8cd594727b4df2c6c40a66ee092e48a04b8dd919d1cd6c0dc1c868e8b17383212a9291ee4c6129b74927822c836d96f580f90211a082dfa0895f58c8ab219b1a3495c930a91ced1024bb93d17db00e25b951a6c619a07daeef642e3fafcd93260f2c8486ee75803c32795ea83152752c7f298ba98481a0416d5ba0562c59a16a92991b267cdb40b25734856902f5599db0ebf64ce4ea40a006a001e9a09963a91a4e2fdea6a238d4b540699e8828085b460dab39744547c7a01dc72e0048890365d8fbfb7c5b1c8ef52d49e41e089d99f52fadffe3efde1303a0942505b8e8a3ec1f16bee602466ef6605139cce2b5802355aecd2de1def8363ba0096a2585a6d4d2912c5387d5998f22455a1baf48894c5f89621d22721202f238a0c798b5904ca51608776665eb627ba3a32ecb75eaf20cea825ece8f9b8a7a44f3a076f5e9f1ff4e8b68028f8dbf07711a9e5235887749da2db07d8c7ca23d1c06dba0019d4d8661b0e52876e58c1cb072c5c2aef8db86d35288be6ddbf6cd782eb5f6a01c418f5263baafdae54580467f5e50ec141611331f53db37d838c1671bc6a25ba0a0fb254b54da6444d91d0b6585c4a2fcdf9e19b10357377fd5699b4bad8adab6a00b841477da486c5819fd12285e8f097c92b317c9e239954f5cbba1c70f679b4ba0612b371378ad1d8cc5e0954a111df8e0c8ea0da63300ca1126fb1a54338b32f4a072a4f633843d50afdb0d3a76464892f1c392579ec74f6df6cf1df231ba4ab42ea07734e834476c826ab88df35eb30599174a9f863d17d18ce04f87f34526cb6fc480f90211a02fedb0b9b16e327962ff519dfc137fb4e25408054dc09c6cf8d97fcc8c58f1fca03869abaa6f82c34c1aba13cfe0b7ad104312b8ca918060c181dd406c8a99260ca0f753573922dd3666bd8c5dbd5b4ce6de8a8f0800188c034d383d8916a53ce3efa005613369534c7d926a4b06e352e6d17532bc802c0fcedd13073e68c41b99901da0c5daa0a98986bab70d997d7faa4b55ddbcb75bcf7cd71d7950d145222cb3e21fa02718fac0f09350134ea331146441ad6005f8a8c20b9673f5b4bb1d9cac9f2163a0895fe437ecebfb9a688f7de6f3e9ef5118168fc60d9eee552eb504d64d301f6fa0b4cf1ad7a7b3f08bc8842186fcd78ff7d746763fcae212432d0f20a50be4fb65a07396b72a68947b922b056495abe200f446a5fa9b01fd098d17a76a2672b9515ca09a877e342351f9e10dea0fbf7478ee67c215bfd821da88208b9fcf63bea39bfba0b5ead9f9ba5a3ac8c888cb19af13e8a3d279474818054d335b28e81c431cc72ea04e66c0882953c62e542817724480b4f8d7a7944b3dee7455b249be68b5b9990da03a1aca9f115f2d3d71ee1cc202c2129d6f72c4f80b7b85128d54f9be9cda8c2fa01c1a35b8aa431b2a845c34b464542a83220b17e4dd1a4d4774b1807f1f9c9e23a03b2492dac5c5619f8c84fc0969ff24f5695bb4363c22c4120c86d2bc128aabfaa0c30d11204878acb9ce6a7931150e9ec10f1a659076ec3c1528c663f1897f85e180f90211a043beb9ae278028ab0e6ae1dd97bfc1adc7da5d5b35418cde1372ed15dc60d844a0969897f77040974812fdc243499998d5a2f808b010e3e743fff5bb1cf06701b7a072a62f95c81d3849bc02102bcb66b5be775ad3b68cae7967451e6a13c48b6c43a0488199752a3a18aaaaa52b07d5a306826c4ccb2afe3cb30058de3e361dee74cfa0a63fb5ff17b1ca7f9c095cd9a888f4fd493a3379cdc2a0cfb49353c854923fc7a0ce7a2593ac4b8c89ad4c5fde8940d9695e969cfe6eb6a614954a48bcfd715843a0cb8b4d0264778a2ab04b96777ffe78a5ee62483a87446fceccb37813cda25b60a008fac15554b1c384ad91aa696e7e5e5454dc0c0fa343bb26b48a4f34ec95f785a0f1811154dd01ffd9f43443acd407e0beee53bbd03f40f63b7d993681182f0289a0a620126c5db0919a29b4b27c728dc42d2d63015849527be64acd0062b575c0eea088d3cde1a49a0ac95f076d1e15b3fde9cefd0f7e308f53b3aa466eb0385aec50a07f99a989d621bd1b59fa51d109f6413c9cb7f8ccd704dbf13cfb27bebec8f1b1a04321111d914057fe87d18e8c6f4128c6c7778fa2b73d435f0b2562c5910361a2a07ee88a697a560dc7023a840f16df54c599dc345e787927bf6628963e782a6847a078d58eb776d8d9dd6dbdbdd830b0350bd0427b15678ef457da5d41ec2cca708ca050e0c4585785b9c800e24c4c4e00599d7e5c4e6d8f3363979ab6c49ed514f12680f90211a011ff0a2d404fd7ed97509ebaa806f2a5ba09c5cde5ff596903c4313783487509a014931c578b05f5948939281aa31d2bc8b05b01c6932c45bf7a70972a430575c2a07272592f567daa667135799961e9eef529a6cd754395e39694d9452ae24a8797a092b17ad714173ec4787f0b3b9d2dfa96680861e093b5121441ffcde64183d074a06db41a6efb6f94c7d185f76deb8bb00468715bf6828fb63db31b880a6050c54da07ce695737ab0d4bf9003a06ce83b11e75d81fbeb47c013b41f9c2e00a97cb87aa0dfe63771f833e98a5aeff54d9dd5a8dcfd89ca43c23644b18ec8e29ab8ccc287a0a327c817dc8a8ea3a5d3ca3cb55169777a1bfa30fe9f0df842eb3978dbd6737ba053683114bdaed7819b30ab8baec1fb9a2a96fee4dabc72f319cec9869da3b0b0a04d98297a896312d18da40240ed9a527f4c01c73edd3ea1f7c28338d1d863d97ca070451b5f2a402b497659eb18e648ac46f39c0068cc91436eb0b082b1d06dd63da066e866f800200512b0d3e534c547f4d2012429152cc9693bf1553cc22361627ba003fc4e648aafdadd7a9fa7cb534103f08dc699413ecda22bda46898bfb792429a0b46a167c66b50c74227d03a68971e124fdd011d6c90f5a08f6fe30ae34de603ca0a7ced66271235bc27b154f37bee6d9a1366cd253176c96de707d124fcc593c35a0f4f09b104a86cefc5c282d393b415e6c224eb8a463386448ebebfad9f9f53c9680f90211a05f93540f4317a4c6d8b73556a7ffdab6fcf0aa36af84b8c4bd2a3e7114e2da4ea05dd8c13b1b83485911f5e1185669f7d5559c260193a72e52597a3e80736c248ca03d50a67e8ec93696c35865d9f03814e95406c8d04e5decc320b9a24e5beee1baa0a928e2ea8773ba69dde5344d69069b237667dbaaa69e86133d4e444e432799b1a0ebb2cbf0c3314ddf681f21a29fa17b320094684ba35e725bc36bbc407821cfa3a0762aeb8161d2b1b8a5ee51d1ede36f51cc2dad7e0c4d0ff097b89c831aff8c35a0957a8eaaac924688482d21a95b7a7f01889ab39a7a50d58efaaffa9e486ae071a046c10b0c15aa83973ea4b108f50bad2638941550fce7c9308c8b968abee271f8a08a831384faa68f9caa047a6200464e11cfe5f9f700a5ed9435e5241d9d2a501ca020630d0f41d1f38c61fc8d3fc6170f6f11fc52ade454930a3b5e4f4491b47467a04539a99793f29484fdbd39b606f27265499acb3c24461f48858655f07166f0dfa05fd40548cfae17d12e103db98572f22cdc8dd3ec670be570727a7ff68f6bce9fa032efe866f058f79ef06de75f682e10773576eb9fca3f950fda96ea9926784685a05c170d685d29417781f678b746174c7500e7c228b4bd71bcfe9f5421742a0b67a0c3fb71b77522f06c4a4e4cb7029e7faeb747b8e446460586ea0d5e9abae68cd9a03f2294bf8bea287c7afafde4b39aaa56716230ef425ece688f6a78fcadf5f49e80f9013180a0c2cb770a3d18eb1214a782cc81b79a7fd772716c2d050ef66011095c3774e8f7a08fc7d7da06fba7ffa69b095aae41147e3a55b89644682057cedab705ba7aefd5a05975b434f69398107a4d1729f8f56e75247df09c65b1a750797818607bf118df80a026cea4c13260b2a1dd74bb6fcc7cc36162d2856ce691a36165c633ba68f7b783a0f7b0c667509a4ce937c487b45bc53c0700543daf4f8c127fbe475b4e1084d2328080a0454eca3fcc32afd4c4000ccbb47732bbce342b1a9d374fb5872162f2c873625fa0b3e6c44579a731cc730a5472e83c6098fa2943e5b2c72f4475f0afea76848a87a03b8c951788b8c93366aedbf88f6c1ca6085cd0249025ce542f19294b40bb92f180a0a10cfa51ae290afebd64a5b530db7088fa0b02f22ce9b0838135b422b885dee5808080e482000ea07b2632b8b97e159d88f112a8dd9d44df2f3c4502e0c79a29297ea7f61f41f311f851a030590b16841225b9590cdc95b19176201d442ca0b931c6e4314d20a1c772ea9ba052e8f9f247cd159c65b304863d444087f6a60d7dbec3a0e4fa09f007b5a1c64f808080808080808080808080808080f86c9c20120c458c4c09a9448628f84e81161b308d5c4041a3d3a1ea329d0eb84df84b0487400e8b4f1c9c00a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a0c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a47022440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e22442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162244295e26495cef6f69dfa69911d9d8e4f3bbadb89b977cf58294f7239d515e15b24cfeb82494056cf691eaf729b165f32c9757c429dba5051155903067e56ebe3698678e9122442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab022443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a224461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d25224469c77a677c40c7fbea129d4b171a39b7a8ddabfab2317f59d86abfaf690850223d90e9e7593d91a29331dfc2f84d5adecc75fc39ecab4632c1b4400a3dd1e1298835bcca224472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a5122447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e22448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852244a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412244b218c5d6af1f979ac42bc68d98a5a0d796c6ab01b659ad0fbd9f515893fdd740b29ba0772dbde9b4635921dd91bd2963a0fc855e31f6338f45b211c4e9dedb7f2eb09de72244b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2244cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192244d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392244e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212244e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002244ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832244ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2244ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd02a440bac492386862ad3df4b666bc096b0505bb694dab0bec348681af766751cb839576e9c515a09c8bffa30a46296ccc56612490eb480d03bf948e10005bbcc0421f90b3d4e2a4412d810c13e42811e9907c02e02d1fad46cfa18bab679cbab0276ac30ff5f198e5e1dedf6b84959129f70fe7a07fcdf13444ba45b5dbaa7b1f650adf8b0acbecd04e2675b2a442465176c461afb316ebc773c61faee85a6515daa8a923564c6ffd37fb2fe9f118ef88092e8762c7addb526ab7eb1e772baef85181f892c731be0c1891a50e6b06262c8162a442d4c407bbe49438ed859fe965b140dcf1aab71a993c1f7f6929d1fe2a17b4e14614ef9fc5bdc713d6631d675403fbeefac55611bf612700b1b65f4744861b80b0f7d6ab02a443f349bbafec1551819b8be1efea2fc46ca749aa184248a459464eec1a21e7fc7b71a053d9644e9bb8da4853b8f872cd7c1d6b324bf1922829830646ceadfb658d3de009a2a4461dd481a114a2e761c554b641742c973867899d38a80967d39e406a0a9642d41e9007a27fc1150a267d143a9f786cd2b5eecbdcc4036273705225b956d5e2f8f5eb95d252a4470f657164e5b75689b64b7fd1fa275f334f28e1896a26afa1295da81418593bd12814463d9f6e45c36a0e47eb4cd3e5b6af29c41e2a3a5636430155a466e216585af3ba72a4472b61c6014342d914470ec7ac2975be345796c2b81db0422a5fd08e40db1fc2368d2245e4b18b1d0b85c921aaaafd2e341760e29fc613edd39f71254614e2055c3287a512a447ae2f5b9e386cd1b50a4550696d957cb4900f03ab84f83ff2df44193496793b847f64e9d6db1b3953682bb95edd096eb1e69bbd357c200992ca78050d0cbe180cfaa018e2a448b6c8fd93d6f4cea42bbb345dbc6f0dfdb5bec73a8a257074e82b881cfa06ef3eb4efeca060c2531359abd0eab8af1e3edfa2025fca464ac9c3fd123f6c24a0d788694852a44a6f79b60359f141df90a0c745125b131caaffd12b772e180fbf38a051c97dabc8aaa0126a233a9e828cdafcc7422c4bb1f4030a56ba364c54103f26bad91508b5220b7412a44b4dd66d7c2c7e57f628210187192fb89d4b99dd40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44be807dddb074639cd9fa61b47676c064fc50d62cb1f2c71577def3144fabeb75a8a1c8cb5b51d1d1b4a05eec67988b8685008baa17459ec425dbaebc852f496dc92196cd2a44cc8e6d00c17eb431350c6c50d8b8f05176b90b11b3a3d4feb825ae9702711566df5dbf38e82add4dd1b573b95d2466fa6501ccb81e9d26a352b96150ccbf7b697fd0a4192a44d1d6bf74282782b0b3eb1413c901d6ecf02e8e28939e8fb41b682372335be8070199ad3e8621d1743bcac4cc9d8f0f6e10f41e56461385c8eb5daac804fe3f2bca6ce7392a44d93dbfb27e027f5e9e6da52b9e1c413ce35adc11b313f9cba57c63a84edb4079140e6dbd7829e5023c9532fce57e9fe602400a2953f4bf7dab66cca16e97be95d4de70442a44e2d3a739effcd3a99387d015e260eefac72ebea1956c470ddff48cb49300200b5f83497f3a3ccb3aeb83c5edd9818569038e61d197184f4aa6939ea5e9911e3e98ac6d212a44e9ae3261a475a27bb1028f140bc2a7c843318afd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002a44ea0a6e3c511bbd10f4519ece37dc24887e11b55db2d4c6283c44a1c7bd503aaba7666e9f0c830e0ff016c1c750a5e48757a713d0836b1cabfd5c281b1de3b77d1c1921832a44ee226379db83cffc681495730c11fdde79ba4c0cae7bc6faa3f0cc3e6093b633fd7ee4f86970926958d0b7ec80437f936acf212b78f0cd095f4565fff144fd458d233a5b2a44ef0274e31810c9df02f98fafde0f841f4e66a1cd98cbf822e4bc29f1701ac0350a3d042cd0756e9f74822c6481773ceb000641c51b870a996fe0f6a844510b1061f38cd0").to_vec();
        any.extend(any2);
        let any: Any = any.try_into().unwrap();
        let err = client
            .submit_misbehaviour(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("UnexpectedHeaderRelation: 32160267 32160268"),
            "{}",
            err
        );

        // fail: client state is frozen
        let ctx = MockClientReader {
            client_state: Some(ClientState {
                frozen: true,
                ..Default::default()
            }),
            consensus_state: mock_consensus_state,
        };
        let err = client
            .submit_misbehaviour(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("ClientFrozen: xx-parlia-1"),
            "{}",
            err
        );

        // fail: consensus state not found
        let ctx = MockClientReader {
            client_state: Some(ClientState::default()),
            consensus_state: BTreeMap::new(),
        };
        let err = client
            .submit_misbehaviour(&ctx, client_id.clone(), any.clone())
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("consensus_state not found: client_id=xx-parlia-1"),
            "{}",
            err
        );

        // fail: client state not found
        let ctx = MockClientReader {
            client_state: None,
            consensus_state: BTreeMap::new(),
        };
        let err = client
            .submit_misbehaviour(&ctx, client_id, any)
            .unwrap_err();
        assert!(
            format!("{:?}", err).contains("client_state not found: client_id=xx-parlia-1"),
            "{}",
            err
        );
    }
}
