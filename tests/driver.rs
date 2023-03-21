use execution_layer::engine_api::{
    auth::{Auth, JwtKey},
    http::HttpJsonRpc,
    BlockByNumberQuery, PayloadAttributes, PayloadAttributesV1, LATEST_TAG,
};

use execution_layer::ForkchoiceState;

use sensitive_url::SensitiveUrl;
use types::{Address, ExecutionBlockHash, Hash256, MainnetEthSpec};

pub const JWT_SECRET: [u8; 32] = [0u8; 32];

enum API {
    original,
    new
}

fn driver(api_type: API) {
    let rpc_url = SensitiveUrl::parse("http://localhost:8551").unwrap();
    let rpc_auth = Auth::new(JwtKey::from_slice(&JWT_SECRET).unwrap(), None, None);
    let rpc_client = HttpJsonRpc::new_with_auth(rpc_url, rpc_auth, None).unwrap();
    //let rpc_client = HttpJsonRpc::new(rpc_url, None).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        loop {
            rpc_client.upcheck().await.unwrap();
            let capabilities = rpc_client.exchange_capabilities().await.unwrap();
            println!("Caps: {capabilities:?}");

            let block = rpc_client
                .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                .await
                .unwrap()
                .unwrap();
            println!("Latest Block: {block:?}");
            let f = ForkchoiceState {
                head_block_hash: block.block_hash,
                safe_block_hash: block.block_hash,
                finalized_block_hash: ExecutionBlockHash::zero(),
            };
            let attr = Some(PayloadAttributes::V1(PayloadAttributesV1 {
                timestamp: block.timestamp + 1,
                prev_randao: Hash256::zero(),
                suggested_fee_recipient: Address::repeat_byte(0),
            }));
            let fchoice_result = rpc_client.forkchoice_updated_v1(f, attr).await.unwrap();
            println!("Fork choice {fchoice_result:?}");


            let payload = match api_type {
                API::original =>
                    rpc_client
                    .get_payload_v1::<MainnetEthSpec>(fchoice_result.payload_id.unwrap())
                    .await
                    .unwrap()
                    .into(),
                API::new =>
                     rpc_client
                    .get_json_payload_v1::<MainnetEthSpec>(fchoice_result.payload_id.unwrap())
                    .await
                    .unwrap()
                    .into()
            };

            println!("New payload {payload:?}");
            let payload_result = rpc_client.new_payload_v1(payload).await.unwrap();
            println!("New payload result {payload_result:?}");

            // next state
            let next_fork_choice = ForkchoiceState {
                head_block_hash: payload_result.latest_valid_hash.unwrap(),
                safe_block_hash: payload_result.latest_valid_hash.unwrap(),
                finalized_block_hash: ExecutionBlockHash::zero(),
            };
            let attr = Some(PayloadAttributes::V1(PayloadAttributesV1 {
                timestamp: block.timestamp + 2,
                prev_randao: Hash256::zero(),
                suggested_fee_recipient: Address::repeat_byte(0),
            }));
            let _fchoice_result = rpc_client
                .forkchoice_updated_v1(next_fork_choice, attr)
                .await
                .unwrap();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_layer_driver() {
        driver(API::new);
    }
}