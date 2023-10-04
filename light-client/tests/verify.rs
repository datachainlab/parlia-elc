#[cfg(test)]
mod test {
    use std::collections::BTreeMap;
    use std::num::ParseIntError;

    use light_client::commitments::Commitment;
    use light_client::types::{Any, ClientId, Height, Time};
    use light_client::{ClientReader, HostClientReader, HostContext, LightClient};
    use parlia_elc::client::ParliaLightClient;

    struct MockClientReader {
        client_state: Option<Any>,
        consensus_state: BTreeMap<Height, Any>,
    }

    impl HostContext for MockClientReader {
        fn host_timestamp(&self) -> Time {
            Time::now()
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
            self.client_state
                .clone()
                .ok_or_else(|| light_client::Error::client_state_not_found(client_id.clone()))
        }

        fn consensus_state(
            &self,
            client_id: &ClientId,
            height: &Height,
        ) -> Result<Any, light_client::Error> {
            let v = self.consensus_state.get(height).ok_or_else(|| {
                light_client::Error::consensus_state_not_found(client_id.clone(), *height)
            })?;
            Ok(v.clone())
        }
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MsgCreateClient {
        pub client_state: String,
        pub consensus_state: String,
    }

    impl MsgCreateClient {
        pub fn any_client_state(&self) -> Any {
            let hex = decode_hex(&self.client_state);
            Any::try_from(hex).unwrap()
        }
        pub fn any_consensus_state(&self) -> Any {
            let hex = decode_hex(&self.consensus_state);
            Any::try_from(hex).unwrap()
        }
    }

    #[derive(serde::Deserialize)]
    struct MsgUpdateClient {
        pub header: String,
    }

    #[derive(serde::Deserialize)]
    struct MsgUpdateClients {
        pub data: Vec<MsgUpdateClient>,
    }

    #[test]
    #[ignore]
    fn test_verify_mainnet() {
        verify("mainnet");
    }

    #[test]
    #[ignore]
    fn test_verify_testnet() {
        verify("testnet");
    }

    fn verify(net_id: &'static str) {
        let root = "./tests/ibc-parlia-relay/tool/testdata";
        let create_path = format!("{}/create_{}.json", root, net_id);
        let update_path = format!("{}/update_{}.json", root, net_id);
        let msg_create_client = std::fs::read(create_path).unwrap();
        let msg_create_client: MsgCreateClient =
            serde_json::from_slice(&msg_create_client).unwrap();
        let msg_update_client = std::fs::read(update_path).unwrap();
        let msg_update_client: MsgUpdateClients =
            serde_json::from_slice(&msg_update_client).unwrap();

        assert!(!msg_update_client.data.is_empty());

        let mut ctx = MockClientReader {
            client_state: None,
            consensus_state: BTreeMap::default(),
        };
        let client = ParliaLightClient::default();
        let any_client_state = msg_create_client.any_client_state();
        let any_cons_state = msg_create_client.any_consensus_state();
        let result = client
            .create_client(&ctx, any_client_state, any_cons_state.clone())
            .unwrap();
        match result.commitment {
            Commitment::UpdateClient(upd) => {
                println!("height = {}", upd.new_height);
                ctx.client_state = upd.new_state;
                ctx.consensus_state.insert(upd.new_height, any_cons_state);
            }
            _ => unreachable!("invalid commitment"),
        }

        let client_id = ClientId::new(client.client_type().as_str(), 0).unwrap();
        for update in msg_update_client.data {
            let any: Any = decode_hex(&update.header).try_into().unwrap();
            let result = client.update_client(&ctx, client_id.clone(), any);
            match result {
                Err(err) => {
                    unreachable!("error {:?}", err)
                }
                Ok(result) => {
                    println!("update height = {}", result.height);
                    ctx.client_state = Some(result.new_any_client_state);
                    ctx.consensus_state
                        .insert(result.height, result.new_any_consensus_state);
                }
            }
        }
    }

    fn decode_hex(s: &str) -> Vec<u8> {
        let v: Result<Vec<u8>, ParseIntError> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect();
        v.unwrap()
    }
}
