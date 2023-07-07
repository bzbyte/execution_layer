use bzb_execution_layer::engine_api::{
    auth::{Auth, JwtKey},
    ethspec::MainnetEthSpec,
    execution_payload::Hash256,
    http::HttpJsonRpc,
    json_structures::ExecutionBlockHash,
    sensitive_url::SensitiveUrl,
    Address, BlockByNumberQuery, ForkchoiceState, PayloadAttributes, PayloadAttributesV1,
    LATEST_TAG,
};

use num_derive::FromPrimitive;
pub const JWT_SECRET: [u8; 32] = [0u8; 32];

// stat counters
#[derive(FromPrimitive, Debug)]
enum Ops {
    UpCheck = 0,
    ForkChoiceUpdate = 1,
    GetPayload = 2,
    NewPayload = 3,
    ForkChoiceUpdate2 = 4,
    MAX,
}

impl Into<usize> for Ops {
    fn into(self) -> usize {
    self as usize
    }
}

fn driver(exec_url: &str, num_blocks: u32, tag: &str) {
    let mut stats =  [std::time::Duration::default(); Ops::MAX as usize];
    let rpc_url = SensitiveUrl::parse(exec_url).unwrap();
    let rpc_auth = Auth::new(JwtKey::from_slice(&JWT_SECRET).unwrap(), None, None);
    let rpc_client = HttpJsonRpc::new_with_auth(rpc_url, rpc_auth, None).unwrap();
    //let rpc_client = HttpJsonRpc::new(rpc_url, None).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let capabilities = rpc_client.exchange_capabilities().await.unwrap();
        //println!("Caps: {capabilities:?}");

        for i in 0..num_blocks {
            rpc_client.upcheck().await.unwrap();

            let start = std::time::Instant::now();
            let block = rpc_client
                .get_block_by_number(BlockByNumberQuery::Tag(LATEST_TAG))
                .await
                .unwrap()
                .unwrap();
            stats[Ops::UpCheck as usize] += start.elapsed();

            //println!("Latest Block: {block:?}");
            let start = std::time::Instant::now();
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
            let fchoice_result = rpc_client.forkchoice_updated_v2(f, attr).await.unwrap();
            stats[Ops::ForkChoiceUpdate as usize] += start.elapsed();
            //println!("Fork choice {fchoice_result:?}");


            let start = std::time::Instant::now();
            let payload = rpc_client
                .get_json_payload_v1::<MainnetEthSpec>(fchoice_result.payload_id.unwrap())
                .await
                .unwrap()
                .into();
            stats[Ops::GetPayload as usize] += start.elapsed();

            //println!("New payload {payload:?}");
            let start = std::time::Instant::now();
            let payload_result = rpc_client.new_payload_v1(payload).await.unwrap();
            stats[Ops::NewPayload as usize] += start.elapsed();
            //println!("New payload result {payload_result:?}");

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


            let start = std::time::Instant::now();
            let _fchoice_result = rpc_client
                .forkchoice_updated_v2(next_fork_choice, attr)
                .await
                .unwrap();
            stats[Ops::ForkChoiceUpdate2 as usize] += start.elapsed();
        }

        println!("Created {num_blocks} empty blocks using engine api and {tag} client:");
        for i in 0..Ops::MAX as usize {
            let op: Ops = num::FromPrimitive::from_usize(i).unwrap();
            println!("{op:?}:\t\t {} micro", stats[i].as_micros());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_layer_driver_geth() {
        driver("http://localhost:8551", 100, "geth");
    }
    #[test]
    fn execution_layer_driver_reth() {
        driver("http://localhost:8552", 100, "reth");
    }
}
