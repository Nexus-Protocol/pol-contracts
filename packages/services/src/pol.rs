use astroport::asset::Asset;
use cosmwasm_std::{Decimal, Uint128};
use cw20::Cw20ReceiveMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub governance: String,
    pub psi_token: String,

    // All issued bonds have linear vesting.
    pub vesting: String,
    pub vesting_period: u64,

    // ASTRO & PSI rewards are transfered to.
    pub community_pool: String,

    // Whether to stake LP tokens to Astroport or not.
    pub autostake_lp_tokens: bool,

    pub astro_generator: String,
    pub astro_token: String,

    // Pairs are allowed to provide liquidity in.
    pub pairs: Vec<String>,

    // If set, user should use this token to be allowed to buy bonds.
    pub utility_token: Option<String>,
    pub bond_cost_in_utility_tokens: Decimal,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    // Send cw20 tokens and buy bonds.
    Receive(Cw20ReceiveMsg),

    // Buy no less than min_amount of bonds.
    Buy { min_amount: Uint128 },

    // Claim ASTRO & PSI rewards from staking LP tokens.
    // Transfer them to the community pool.
    ClaimRewards {},

    Governance { msg: GovernanceMsg },
    AcceptGovernance {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceMsg {
    // Start a new phase of bonding.
    Phase {
        max_discount: Decimal,
        psi_amount_total: Uint128,
        psi_amount_start: Uint128,
        start_time: u64,
        end_time: u64,
    },
    UpdateConfig {
        psi_token: Option<String>,
        vesting: Option<String>,
        vesting_period: Option<u64>,
        community_pool: Option<String>,
        autostake_lp_tokens: Option<bool>,
        astro_generator: Option<String>,
        astro_token: Option<String>,
        utility_token: Option<Option<String>>,
        bond_cost_in_utility_tokens: Option<Decimal>,
    },
    UpdatePairs {
        add: Vec<String>,
        remove: Vec<String>,
    },
    UpdateGovernanceContract {
        addr: String,
        seconds_to_wait_for_accept_gov_tx: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Cw20HookMsg {
    Buy { min_amount: Uint128 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    Config {},
    Phase {},
    BuySimulation { asset: Asset },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigResponse {
    pub owner: String,
    pub governance: String,
    pub psi_token: String,
    pub vesting: String,
    pub vesting_period: u64,
    pub pairs: Vec<String>,
    pub community_pool: String,
    pub autostake_lp_tokens: bool,
    pub astro_generator: String,
    pub astro_token: String,
    pub utility_token: Option<String>,
    pub bond_cost_in_utility_tokens: Decimal,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct PhaseResponse {
    pub max_discount: Decimal,
    pub psi_amount_total: Uint128,
    pub psi_amount_start: Uint128,
    pub start_time: u64,
    pub end_time: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BuySimulationResponse {
    pub bonds: Uint128,
    pub discount: Decimal,
    pub utility_tokens: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MigrateMsg {}
