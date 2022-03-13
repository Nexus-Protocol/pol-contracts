use astroport::asset::{AssetInfo, PairInfo};
use cosmwasm_std::{Addr, Attribute, Decimal, Env, Order, StdError, StdResult, Storage, Uint128};
use cw_storage_plus::{Item, Map};
use nexus_pol_services::pol::Phase as PolPhase;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub owner: Addr,
    pub governance: Addr,
    pub psi_token: Addr,

    // All issued bonds have linear vesting.
    pub vesting: Addr,
    pub vesting_period: u64,

    // Whether to stake LP tokens to Astroport or not.
    pub autostake_lp_tokens: bool,

    // ASTRO & PSI rewards are transfered to.
    pub community_pool: Addr,

    pub astro_generator: Addr,
    pub astro_token: Addr,

    // If set, user should use this token to be allowed to buy bonds.
    pub utility_token: Option<Addr>,
    pub bond_cost_in_utility_tokens: Decimal,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GovernanceUpdateState {
    pub new_governance: Addr,
    pub wait_approve_until: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Phase {
    pub max_discount: Decimal,
    pub psi_amount_total: Uint128,
    pub psi_amount_start: Uint128,
    pub start_time: u64,
    pub end_time: u64,
}

impl From<PolPhase> for Phase {
    fn from(value: PolPhase) -> Self {
        Self {
            max_discount: value.max_discount,
            psi_amount_total: value.psi_amount_total,
            psi_amount_start: value.psi_amount_start,
            start_time: value.start_time,
            end_time: value.end_time,
        }
    }
}

impl From<Phase> for PolPhase {
    fn from(value: Phase) -> Self {
        Self {
            max_discount: value.max_discount,
            psi_amount_total: value.psi_amount_total,
            psi_amount_start: value.psi_amount_start,
            start_time: value.start_time,
            end_time: value.end_time,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct State {
    pub psi_amount_sold: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct TokenBalance {
    pub token: Addr,
    pub token_name: String,
    pub amount: Uint128,
}

impl TokenBalance {
    pub fn new(token: Addr, token_name: String, amount: Uint128) -> Self {
        Self {
            token,
            token_name,
            amount,
        }
    }
}

impl From<(Addr, String, Uint128)> for TokenBalance {
    fn from(value: (Addr, String, Uint128)) -> Self {
        Self::new(value.0, value.1, value.2)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct ReplyContext {
    // Attributes have to be added to a response.
    pub attributes: Vec<Attribute>,
    // Balances of tokens before a rewards claim.
    pub balances: Vec<TokenBalance>,
}

pub const CONFIG: Item<Config> = Item::new("config");

pub const GOVERNANCE_UPDATE: Item<GovernanceUpdateState> = Item::new("gov_update");

pub const PHASE: Item<Phase> = Item::new("phase");

pub fn phase(store: &dyn Storage, env: Env) -> StdResult<Phase> {
    match PHASE.may_load(store)? {
        Some(phase) => {
            let cur_time = env.block.time.seconds();
            if cur_time < phase.start_time {
                Err(StdError::generic_err(format!(
                    "phase starts at {}, but {} now",
                    phase.start_time, cur_time
                )))
            } else if cur_time > phase.end_time {
                Err(StdError::generic_err(format!(
                    "phase finished at {}, but {} now",
                    phase.end_time, cur_time
                )))
            } else {
                Ok(phase)
            }
        }
        None => Err(StdError::generic_err("phase is not set")),
    }
}

pub const STATE: Item<State> = Item::new("state");

pub fn save_state(store: &mut dyn Storage, psi_amount_sold: Uint128) -> StdResult<()> {
    STATE.save(store, &State { psi_amount_sold })
}

// Pairs are allowed to provide liquidity in.
const PAIRS: Map<&[u8], PairInfo> = Map::new("pairs");

fn pair_key(assets_info: &[AssetInfo; 2]) -> Vec<u8> {
    let mut assets_info = assets_info.to_vec();
    assets_info.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    [assets_info[0].as_bytes(), assets_info[1].as_bytes()].concat()
}

pub fn save_pair(store: &mut dyn Storage, pi: &PairInfo) -> StdResult<()> {
    PAIRS.save(store, &pair_key(&pi.asset_infos), pi)
}

pub fn remove_pair(store: &mut dyn Storage, pi: &PairInfo) {
    PAIRS.remove(store, &pair_key(&pi.asset_infos));
}

pub fn pair(store: &dyn Storage, assets_info: &[AssetInfo; 2]) -> StdResult<PairInfo> {
    PAIRS.load(store, &pair_key(assets_info))
}

pub fn pairs(store: &dyn Storage) -> Vec<PairInfo> {
    PAIRS
        .range(store, None, None, Order::Ascending)
        .flatten()
        .map(|v| v.1)
        .collect()
}

pub const REPLY_CONTEXT: Item<ReplyContext> = Item::new("reply_context");
