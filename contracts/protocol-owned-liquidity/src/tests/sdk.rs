use astroport::asset::{AssetInfo, PairInfo};
use astroport::factory::PairType;
use cosmwasm_std::testing::{self, MockApi};
use cosmwasm_std::{to_binary, Addr, Decimal, Env, MemoryStorage, OwnedDeps, Uint128};
use services::pol::InstantiateMsg;
use std::str::FromStr;

use crate::contract::instantiate;
use crate::tests::mock_querier::*;

pub const GOVERNANCE: &str = "governance";
pub const PSI_TOKEN: &str = "psi_token";
pub const CW20_TOKEN: &str = "token";
pub const VESTING: &str = "vesting";
pub const COMMUNITY_POOL: &str = "community_pool";
pub const FACTORY: &str = "factory";
pub const GENERATOR: &str = "generator";
pub const ASTRO_TOKEN: &str = "astro_token";

pub const CREATOR: &str = "creator";
pub const INVESTOR: &str = "investor";

pub const VESTING_PERIOD: u64 = 5 * 24 * 3600;

pub fn bcv() -> Decimal {
    Decimal::from_ratio(Uint128::new(7), Uint128::new(2))
}

pub fn max_bonds_amount() -> Decimal {
    Decimal::from_str("0.0001").unwrap()
}

pub fn min_bonds_amount() -> Uint128 {
    Uint128::new(1_000)
}

pub fn init() -> (OwnedDeps<MemoryStorage, MockApi, WasmMockQuerier>, Env) {
    (mock_dependencies(&[]), testing::mock_env())
}

pub fn psi_ust_pair() -> PairInfo {
    PairInfo {
        asset_infos: [
            AssetInfo::Token {
                contract_addr: Addr::unchecked(PSI_TOKEN),
            },
            AssetInfo::NativeToken {
                denom: UST.to_owned(),
            },
        ],
        contract_addr: Addr::unchecked("psi_ust"),
        liquidity_token: Addr::unchecked("lp_psi_ust"),
        pair_type: PairType::Xyk {},
    }
}

pub fn psi_cw20token_pair() -> PairInfo {
    PairInfo {
        asset_infos: [
            AssetInfo::Token {
                contract_addr: Addr::unchecked(PSI_TOKEN),
            },
            AssetInfo::Token {
                contract_addr: Addr::unchecked(CW20_TOKEN),
            },
        ],
        contract_addr: Addr::unchecked("psi_cw20token"),
        liquidity_token: Addr::unchecked("lp_psi_cw20token"),
        pair_type: PairType::Xyk {},
    }
}

pub fn random_psi_pair(suffix: &str) -> PairInfo {
    PairInfo {
        asset_infos: [
            AssetInfo::Token {
                contract_addr: Addr::unchecked(PSI_TOKEN),
            },
            AssetInfo::NativeToken {
                denom: format!("denom{}", suffix),
            },
        ],
        contract_addr: Addr::unchecked(format!("addr{}", suffix)),
        liquidity_token: Addr::unchecked(format!("lpaddr{}", suffix)),
        pair_type: PairType::Xyk {},
    }
}

type Deps = OwnedDeps<MemoryStorage, MockApi, WasmMockQuerier>;

pub fn add_pairs(deps: &mut Deps, pairs_info: &[PairInfo]) {
    for pi in pairs_info {
        deps.querier
            .wasm_query_smart_responses
            .insert(pi.contract_addr.to_string(), to_binary(&pi).unwrap());
    }
}

pub fn instantiate_with_pairs(deps: &mut Deps, env: Env, pairs_info: Vec<PairInfo>) {
    let info = testing::mock_info(CREATOR, &[]);

    add_pairs(deps, &pairs_info);

    instantiate(
        deps.as_mut(),
        env,
        info,
        InstantiateMsg {
            governance: GOVERNANCE.to_owned(),
            pairs: pairs_info
                .into_iter()
                .map(|pi| pi.contract_addr.to_string())
                .collect(),
            psi_token: PSI_TOKEN.to_owned(),
            vesting: VESTING.to_owned(),
            vesting_period: VESTING_PERIOD,
            bond_control_var: bcv(),
            excluded_psi: vec![GOVERNANCE.to_owned(), VESTING.to_owned()],
            max_bonds_amount: max_bonds_amount(),
            community_pool: COMMUNITY_POOL.to_owned(),
            autostake_lp_tokens: true,
            factory: FACTORY.to_owned(),
        },
    )
    .unwrap();
}
