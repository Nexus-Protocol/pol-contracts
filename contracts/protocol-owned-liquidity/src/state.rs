use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::Addr;
use cw_storage_plus::Item;
use terraswap::asset::PairInfo;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub owner: Addr,
    pub governance_addr: Addr,
    pub pairs_info: Vec<PairInfo>,
    pub psi_token_addr: Addr,
    pub vesting_addr: Addr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GovernanceUpdateState {
    pub new_governance_addr: Addr,
    pub wait_approve_until: u64,
}

pub const CONFIG: Item<Config> = Item::new("config");
pub const GOVERNANCE_UPDATE: Item<GovernanceUpdateState> = Item::new("gov_update");
