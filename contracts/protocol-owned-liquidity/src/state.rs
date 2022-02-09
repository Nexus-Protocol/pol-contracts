use astroport::asset::{AssetInfo, PairInfo};
use cosmwasm_std::{Addr, Attribute, Decimal, Order, StdResult, Storage, Uint128};
use cw_storage_plus::{Item, Map};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Config {
    pub owner: Addr,
    pub governance: Addr,
    pub psi_token: Addr,

    // User can bond only if he is staking at least this amount of psi.
    pub min_staked_psi_amount: Uint128,

    // All issued bonds have linear vesting.
    pub vesting: Addr,
    pub vesting_period: u64,

    // BCV controls how fast bond`s price increases.
    pub bond_control_var: Decimal,

    // User cant buy more than this share of PSI token supply at a time.
    pub max_bonds_amount: Decimal,

    // Whether to stake LP tokens to Astroport or not.
    pub autostake_lp_tokens: bool,

    // ASTRO & PSI rewards are transfered to.
    pub community_pool: Addr,

    pub astro_generator: Addr,
    pub astro_token: Addr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct GovernanceUpdateState {
    pub new_governance: Addr,
    pub wait_approve_until: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct State {
    pub bonds_issued: Uint128,
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
        TokenBalance::new(value.0, value.1, value.2)
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

pub const STATE: Item<State> = Item::new("state");

pub fn save_state(store: &mut dyn Storage, bonds_issued: Uint128) -> StdResult<()> {
    STATE.save(store, &State { bonds_issued })
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

// Tokens are out of circulation.
const EXCLUDED_PSI: Map<&Addr, ()> = Map::new("excluded_psi");

pub fn save_excluded_psi(store: &mut dyn Storage, addr: &Addr) -> StdResult<()> {
    EXCLUDED_PSI.save(store, addr, &())
}

pub fn remove_excluded_psi(store: &mut dyn Storage, addr: &Addr) {
    EXCLUDED_PSI.remove(store, addr);
}

pub fn excluded_psi(store: &dyn Storage) -> Vec<Addr> {
    EXCLUDED_PSI
        .keys(store, None, None, Order::Ascending)
        .map(|addr| Addr::unchecked(String::from_utf8_lossy(&addr)))
        .collect()
}

pub const REPLY_CONTEXT: Item<ReplyContext> = Item::new("reply_context");
