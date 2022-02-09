use astroport::asset::Asset;
use cosmwasm_std::{Decimal, Uint128};
use cw20::Cw20ReceiveMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub governance: String,
    pub psi_token: String,

    // User can bond only if he is staking at least this amount of psi.
    pub min_staked_psi_amount: Uint128,

    // All issued bonds have linear vesting.
    pub vesting: String,
    pub vesting_period: u64,

    // BCV controls how fast bond`s price increases.
    pub bond_control_var: Decimal,

    // Tokens are out of circulation.
    pub excluded_psi: Vec<String>,

    // User cant buy more than this share of PSI token supply at a time.
    pub max_bonds_amount: Decimal,

    // ASTRO & PSI rewards are transfered to.
    pub community_pool: String,

    // Whether to stake LP tokens to Astroport or not.
    pub autostake_lp_tokens: bool,

    pub astro_generator: String,
    pub astro_token: String,

    // Pairs are allowed to provide liquidity in.
    pub pairs: Vec<String>,
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
    UpdateConfig {
        psi_token: Option<String>,
        min_staked_psi_amount: Option<Uint128>,
        vesting: Option<String>,
        vesting_period: Option<u64>,
        bond_control_var: Option<Decimal>,
        max_bonds_amount: Option<Decimal>,
        community_pool: Option<String>,
        autostake_lp_tokens: Option<bool>,
        astro_generator: Option<String>,
        astro_token: Option<String>,
    },
    UpdatePairs {
        add: Vec<String>,
        remove: Vec<String>,
    },
    UpdateExcludedPsi {
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
    Version {},
    BuySimulation { asset: Asset },
    PsiCirculatingSupply {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ConfigResponse {
    pub owner: String,
    pub governance: String,
    pub psi_token: String,
    pub min_staked_psi_amount: Uint128,
    pub vesting: String,
    pub vesting_period: u64,
    pub bond_control_var: Decimal,
    pub max_bonds_amount: Decimal,
    pub excluded_psi: Vec<String>,
    pub pairs: Vec<String>,
    pub community_pool: String,
    pub autostake_lp_tokens: bool,
    pub astro_generator: String,
    pub astro_token: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BuySimulationResponse {
    pub bonds: Uint128,
    pub bond_price: Decimal,
    pub psi_price: Decimal,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MigrateMsg {}
