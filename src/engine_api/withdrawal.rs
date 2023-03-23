use serde_derive::{Deserialize, Serialize};
use ssz_derive::{Decode, Encode};
use ethereum_types::Address;

#[derive(
    arbitrary::Arbitrary,
    Debug,
    PartialEq,
    Eq,
    Hash,
    Clone,
    Serialize,
    Deserialize,
    Encode,
    Decode,
)]
pub struct Withdrawal {
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub index: u64,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub validator_index: u64,
    pub address: Address,
    #[serde(with = "eth2_serde_utils::quoted_u64")]
    pub amount: u64,
}
