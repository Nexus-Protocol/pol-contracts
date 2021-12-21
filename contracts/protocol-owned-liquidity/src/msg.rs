use cw20::Cw20ReceiveMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub governance_addr: String,
    pub pairs_addr: Vec<String>,
    pub psi_token_addr: String,
    pub vesting_addr: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    Receive(Cw20ReceiveMsg),
    Buy {},
    Governance { msg: GovernanceMsg },
    AcceptGovernance {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceMsg {
    UpdateConfig {
        pairs_addr: Option<Vec<String>>,
        psi_token_addr: Option<String>,
        vesting_addr: Option<String>,
    },
    AddPairsToConfig {
        pairs_addr: Vec<String>,
    },
    UpdateGovernanceContract {
        addr: String,
        tx_duration_sec: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Cw20HookMsg {
    Buy {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Config {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigResponse {
    pub owner: String,
    pub governance_addr: String,
    pub pairs_info: String,
    pub psi_token_addr: String,
    pub vesting_addr: String,
}
