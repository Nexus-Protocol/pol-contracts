use cosmwasm_std::testing::{self, MockApi, MockQuerier, MockStorage, MOCK_CONTRACT_ADDR};
use cosmwasm_std::{
    coin, coins, from_slice, Api, BankQuery, Binary, Coin, ContractResult, CosmosMsg, Env,
    MemoryStorage, OwnedDeps, Querier, QuerierResult, QueryRequest, Response, StdError,
    SystemError, SystemResult, Uint128, WasmMsg, WasmQuery,
};
use cosmwasm_storage::to_length_prefixed;
use cw0::PaymentError;
use cw20::{Cw20ReceiveMsg, TokenInfoResponse};
use services::vesting::VestingSchedule;
use std::collections::HashMap;
use terra_cosmwasm::TerraQueryWrapper;
use terraswap::asset::{AssetInfo, PairInfo};

use crate::msg::{ExecuteMsg, GovernanceMsg, InstantiateMsg};
use crate::state::{Config, CONFIG, GOVERNANCE_UPDATE};
use crate::ContractError;

pub fn mock_dependencies(
    contract_balance: &[Coin],
) -> OwnedDeps<MockStorage, MockApi, WasmMockQuerier> {
    let custom_querier: WasmMockQuerier =
        WasmMockQuerier::new(MockQuerier::new(&[(MOCK_CONTRACT_ADDR, contract_balance)]));

    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: custom_querier,
    }
}

pub struct WasmMockQuerier {
    base: MockQuerier<TerraQueryWrapper>,
    pub wasm_query_smart_responses: HashMap<String, Binary>,
    uust_amount: Uint128,
    psi_tokens_amount: Uint128,
    total_supply: Uint128,
}

impl Querier for WasmMockQuerier {
    fn raw_query(&self, bin_request: &[u8]) -> QuerierResult {
        let request: QueryRequest<TerraQueryWrapper> = match from_slice(bin_request) {
            Ok(v) => v,
            Err(e) => {
                return SystemResult::Err(SystemError::InvalidRequest {
                    error: format!("Parsing query request: {}", e),
                    request: bin_request.into(),
                })
            }
        };
        self.handle_query(&request)
    }
}

impl WasmMockQuerier {
    pub fn handle_query(&self, request: &QueryRequest<TerraQueryWrapper>) -> QuerierResult {
        match &request {
            QueryRequest::Custom(_) => {
                unimplemented!("Custom request");
            }
            QueryRequest::Wasm(WasmQuery::Raw {
                contract_addr: _,
                key,
            }) => {
                let key: &[u8] = key.as_slice();
                if key.starts_with(&to_length_prefixed(b"balance")) {
                    SystemResult::Ok(ContractResult::from(cosmwasm_std::to_binary(
                        &self.psi_tokens_amount,
                    )))
                } else if key == b"token_info" {
                    SystemResult::Ok(ContractResult::from(cosmwasm_std::to_binary(
                        &TokenInfoResponse {
                            name: "rand_name".to_owned(),
                            symbol: "rand_symbol".to_owned(),
                            decimals: 6,
                            total_supply: self.total_supply,
                        },
                    )))
                } else {
                    panic!("DO NOT ENTER HERE")
                }
            }
            QueryRequest::Bank(BankQuery::Balance { address: _, denom }) => {
                if denom == UUST {
                    let bank_res = cosmwasm_std::BalanceResponse {
                        amount: Coin {
                            amount: self.uust_amount,
                            denom: denom.to_string(),
                        },
                    };
                    SystemResult::Ok(ContractResult::from(cosmwasm_std::to_binary(&bank_res)))
                } else {
                    let bank_res = cosmwasm_std::BalanceResponse {
                        amount: Coin {
                            amount: Uint128::new(11_000_000),
                            denom: denom.to_string(),
                        },
                    };
                    SystemResult::Ok(ContractResult::from(cosmwasm_std::to_binary(&bank_res)))
                }
            }
            QueryRequest::Wasm(WasmQuery::Smart { contract_addr, msg }) => {
                let response = match self.wasm_query_smart_responses.get(contract_addr) {
                    Some(response) => response,
                    None => {
                        return SystemResult::Err(SystemError::InvalidRequest {
                            error: format!(
                                "No WasmQuery::Smart responses exists for the contract {}",
                                contract_addr
                            ),
                            request: (*msg).clone(),
                        })
                    }
                };
                SystemResult::Ok(ContractResult::Ok(response.clone()))
            }
            _ => self.base.handle_query(request),
        }
    }
}

impl WasmMockQuerier {
    pub fn new(base: MockQuerier<TerraQueryWrapper>) -> Self {
        WasmMockQuerier {
            base,
            wasm_query_smart_responses: HashMap::new(),
            uust_amount: Uint128::default(),
            psi_tokens_amount: Uint128::default(),
            total_supply: Uint128::default(),
        }
    }

    pub fn set_uust_amount(&mut self, amount: Uint128) {
        self.uust_amount = amount;
    }

    pub fn set_psi_tokens_amount(&mut self, amount: Uint128) {
        self.psi_tokens_amount = amount;
    }

    pub fn set_total_supply(&mut self, amount: Uint128) {
        self.total_supply = amount;
    }
}

pub const GOVERNANCE_ADDR: &str = "addr0000";
pub const PSI_TOKEN_ADDR: &str = "addr0001";
pub const LP_TOKEN_ADDR: &str = "addr0002";
pub const VESTING_ADDR: &str = "addr0003";
pub const PAIR_ADDR: &str = "addr0004";

pub const UUST: &str = "uust";

pub const CREATOR: &str = "creator";
pub const INVESTOR: &str = "investor";

#[test]
fn proper_instantiation() {
    let mut deps = mock_dependencies(&[]);
    let info = testing::mock_info(CREATOR, &[]);
    let pair_info = PairInfo {
        asset_infos: [
            AssetInfo::Token {
                contract_addr: PSI_TOKEN_ADDR.to_owned(),
            },
            AssetInfo::NativeToken {
                denom: UUST.to_owned(),
            },
        ],
        contract_addr: PAIR_ADDR.to_owned(),
        liquidity_token: LP_TOKEN_ADDR.to_owned(),
    };
    deps.querier.wasm_query_smart_responses.insert(
        PAIR_ADDR.to_owned(),
        cosmwasm_std::to_binary(&pair_info).unwrap(),
    );

    let res = crate::contract::instantiate(
        deps.as_mut(),
        testing::mock_env(),
        info,
        InstantiateMsg {
            governance_addr: GOVERNANCE_ADDR.to_owned(),
            pairs_addr: vec![PAIR_ADDR.to_owned()],
            psi_token_addr: PSI_TOKEN_ADDR.to_owned(),
            vesting_addr: VESTING_ADDR.to_owned(),
        },
    )
    .unwrap();

    let config = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(0, res.messages.len());
    assert_eq!(CREATOR, config.owner);
    assert_eq!(vec![pair_info], config.pairs_info);
}

#[test]
fn instantiation_fails_when_no_pairs() {
    let mut deps = mock_dependencies(&[]);
    let info = testing::mock_info(CREATOR, &[]);

    let res = crate::contract::instantiate(
        deps.as_mut(),
        testing::mock_env(),
        info,
        InstantiateMsg {
            governance_addr: GOVERNANCE_ADDR.to_owned(),
            pairs_addr: vec![],
            psi_token_addr: PSI_TOKEN_ADDR.to_owned(),
            vesting_addr: VESTING_ADDR.to_owned(),
        },
    );

    assert_eq!(Err(ContractError::NoPairs {}), res);
}

fn init() -> (OwnedDeps<MemoryStorage, MockApi, WasmMockQuerier>, Env) {
    (mock_dependencies(&[]), testing::mock_env())
}

fn psi_ust_pair() -> PairInfo {
    PairInfo {
        asset_infos: [
            AssetInfo::Token {
                contract_addr: PSI_TOKEN_ADDR.to_owned(),
            },
            AssetInfo::NativeToken {
                denom: UUST.to_owned(),
            },
        ],
        contract_addr: PAIR_ADDR.to_owned(),
        liquidity_token: LP_TOKEN_ADDR.to_owned(),
    }
}

fn random_psi_pair() -> PairInfo {
    PairInfo {
        asset_infos: [
            AssetInfo::Token {
                contract_addr: PSI_TOKEN_ADDR.to_owned(),
            },
            AssetInfo::NativeToken {
                denom: "urand".to_owned(),
            },
        ],
        contract_addr: "rand_addr1".to_owned(),
        liquidity_token: "rand_addr2".to_owned(),
    }
}

fn random_ust_pair() -> PairInfo {
    PairInfo {
        asset_infos: [
            AssetInfo::Token {
                contract_addr: "rand_addr1".to_owned(),
            },
            AssetInfo::NativeToken {
                denom: UUST.to_owned(),
            },
        ],
        contract_addr: "rand_addr2".to_owned(),
        liquidity_token: "rand_addr3".to_owned(),
    }
}

type Deps = OwnedDeps<MemoryStorage, MockApi, WasmMockQuerier>;

fn add_pairs(deps: &mut Deps, pairs_info: Vec<PairInfo>) {
    for pi in &pairs_info {
        deps.querier.wasm_query_smart_responses.insert(
            pi.contract_addr.clone(),
            cosmwasm_std::to_binary(&pi).unwrap(),
        );
    }
}

fn instantiate_with_pairs(deps: &mut Deps, env: Env, pairs_info: Vec<PairInfo>) {
    let info = testing::mock_info(CREATOR, &[]);

    add_pairs(deps, pairs_info.clone());

    crate::contract::instantiate(
        deps.as_mut(),
        env,
        info,
        InstantiateMsg {
            governance_addr: GOVERNANCE_ADDR.to_owned(),
            pairs_addr: pairs_info.into_iter().map(|pi| pi.contract_addr).collect(),
            psi_token_addr: PSI_TOKEN_ADDR.to_owned(),
            vesting_addr: VESTING_ADDR.to_owned(),
        },
    )
    .unwrap();
}

#[test]
fn buy_with_no_coins_fails() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(INVESTOR, &[]);
    let resp = crate::contract::execute(deps.as_mut(), env, info, ExecuteMsg::Buy {});

    assert_eq!(Err(ContractError::Payment(PaymentError::NoFunds {})), resp);
}

#[test]
fn buy_with_two_coins_fails() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(INVESTOR, &[coin(1, "uusdt"), coin(1, UUST)]);
    let resp = crate::contract::execute(deps.as_mut(), env, info, ExecuteMsg::Buy {});

    assert_eq!(
        Err(ContractError::Payment(PaymentError::MultipleDenoms {})),
        resp
    );
}

#[test]
fn buy_with_zero_coins_fails() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(INVESTOR, &coins(0, UUST));
    let resp = crate::contract::execute(deps.as_mut(), env, info, ExecuteMsg::Buy {});

    assert_eq!(Err(ContractError::Payment(PaymentError::NoFunds {})), resp);
}

#[test]
fn buy_with_coins_fails_when_psi_native_token_pair_not_found() {
    let (mut deps, env) = init();
    instantiate_with_pairs(
        &mut deps,
        env.clone(),
        vec![random_psi_pair(), random_ust_pair()],
    );

    let info = testing::mock_info(INVESTOR, &coins(10_000_000, UUST));
    let resp = crate::contract::execute(deps.as_mut(), env, info, ExecuteMsg::Buy {});

    assert_eq!(Err(ContractError::PsiNativeTokenPairNotFound {}), resp);
}

#[test]
fn buy_with_coins_fails_when_zero_native_tokens_in_pair() {
    let (mut deps, env) = init();
    deps.querier.set_psi_tokens_amount(Uint128::new(5_000_000));
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(INVESTOR, &coins(10_000_000, UUST));
    let resp = crate::contract::execute(deps.as_mut(), env, info, ExecuteMsg::Buy {});

    assert_eq!(Err(ContractError::ZeroNativeTokensInPair {}), resp);
}

#[test]
fn buy_with_coins_fails_when_zero_psi_tokens_in_pair() {
    let (mut deps, env) = init();
    deps.querier.set_uust_amount(Uint128::new(1_000_000));
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(INVESTOR, &coins(10_000, UUST));
    let resp = crate::contract::execute(deps.as_mut(), env, info, ExecuteMsg::Buy {});

    assert_eq!(Err(ContractError::ZeroPsiTokensInPair {}), resp);
}

#[test]
fn buy_with_coins() {
    let (mut deps, env) = init();
    deps.querier.set_uust_amount(Uint128::new(1_000_000));
    deps.querier.set_psi_tokens_amount(Uint128::new(10_000_000));
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(INVESTOR, &coins(10_000, UUST));
    let resp = crate::contract::execute(deps.as_mut(), env.clone(), info, ExecuteMsg::Buy {});

    assert_eq!(
        Ok(Response::new()
            .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: VESTING_ADDR.to_string(),
                msg: cosmwasm_std::to_binary(&services::vesting::ExecuteMsg::AddVestingSchedule {
                    addr: INVESTOR.to_string(),
                    schedule: VestingSchedule {
                        start_time: env.block.time.seconds(),
                        end_time: env.block.time.plus_seconds(5 * 24 * 3600).seconds(),
                        cliff_end_time: env.block.time.plus_seconds(4 * 24 * 3600).seconds(),
                        amount: Uint128::new(100_000),
                    }
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_attribute("action", "buy")
            .add_attribute("native_token_denom", UUST)
            .add_attribute("lp_psi_tokens_amount", 10_000_000.to_string())
            .add_attribute("lp_native_token_amount", 1_000_000.to_string())
            .add_attribute("native_token_amount", 10_000.to_string())
            .add_attribute("psi_amount", 100_000.to_string())),
        resp
    );
}

#[test]
fn buy_with_zero_lp_tokens_fails() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(INVESTOR, &[]);
    let resp = crate::contract::execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: LP_TOKEN_ADDR.to_owned(),
            amount: Uint128::zero(),
            msg: cosmwasm_std::to_binary(&ExecuteMsg::Buy {}).unwrap(),
        }),
    );

    assert_eq!(Err(ContractError::Payment(PaymentError::NoFunds {})), resp);
}

#[test]
fn buy_with_lp_tokens_fails_when_their_pair_not_found() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(INVESTOR, &[]);
    let resp = crate::contract::execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: "unknown_lp_addr".to_owned(),
            amount: Uint128::new(10_000),
            msg: cosmwasm_std::to_binary(&ExecuteMsg::Buy {}).unwrap(),
        }),
    );

    assert_eq!(Err(ContractError::NotSupportedLpToken {}), resp);
}

#[test]
fn buy_with_lp_tokens_fails_when_zero_psi_tokens_in_pair() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(LP_TOKEN_ADDR, &[]);
    let resp = crate::contract::execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(10_000),
            msg: cosmwasm_std::to_binary(&ExecuteMsg::Buy {}).unwrap(),
        }),
    );

    assert_eq!(Err(ContractError::ZeroPsiTokensInPair {}), resp);
}

#[test]
fn buy_with_lp_tokens() {
    let (mut deps, env) = init();
    deps.querier.set_uust_amount(Uint128::new(1_000_000));
    deps.querier.set_psi_tokens_amount(Uint128::new(10_000_000));
    deps.querier.set_total_supply(Uint128::new(500_000));
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(LP_TOKEN_ADDR, &[]);
    let resp = crate::contract::execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(10_000),
            msg: cosmwasm_std::to_binary(&ExecuteMsg::Buy {}).unwrap(),
        }),
    );

    assert_eq!(
        Ok(Response::new()
            .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: VESTING_ADDR.to_string(),
                msg: cosmwasm_std::to_binary(&services::vesting::ExecuteMsg::AddVestingSchedule {
                    addr: INVESTOR.to_string(),
                    schedule: VestingSchedule {
                        start_time: env.block.time.seconds(),
                        end_time: env.block.time.plus_seconds(5 * 24 * 3600).seconds(),
                        cliff_end_time: env.block.time.plus_seconds(4 * 24 * 3600).seconds(),
                        amount: Uint128::new(400_000),
                    }
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_attribute("action", "buy")
            .add_attribute("lp_tokens_amount", 10_000.to_string())
            .add_attribute("lp_tokens_price", 400_000.to_string())),
        resp
    );
}

#[test]
fn do_not_accept_any_governance_msg_from_non_governance_contract() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);
    let info = testing::mock_info("nongovernance", &[]);

    let resp_update_config = crate::contract::execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateConfig {
                pairs_addr: None,
                psi_token_addr: None,
                vesting_addr: None,
            },
        },
    );
    let resp_add_pairs_to_config = crate::contract::execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::AddPairsToConfig { pairs_addr: vec![] },
        },
    );
    let resp_update_governance_contract = crate::contract::execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateGovernanceContract {
                addr: GOVERNANCE_ADDR.to_owned(),
                tx_duration_sec: 10,
            },
        },
    );

    assert_eq!(Err(ContractError::Unauthorized {}), resp_update_config);
    assert_eq!(
        Err(ContractError::Unauthorized {}),
        resp_add_pairs_to_config
    );
    assert_eq!(
        Err(ContractError::Unauthorized {}),
        resp_update_governance_contract
    );
}

#[test]
fn update_config() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);
    let config = CONFIG.load(&deps.storage).unwrap();
    let info = testing::mock_info(GOVERNANCE_ADDR, &[]);

    let pair1 = random_psi_pair();
    let pair2 = random_ust_pair();
    add_pairs(&mut deps, vec![pair1.clone(), pair2.clone()]);
    crate::contract::execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateConfig {
                pairs_addr: Some(vec![
                    pair1.contract_addr.clone(),
                    pair2.contract_addr.clone(),
                ]),
                psi_token_addr: Some("new_psi_token_addr".to_owned()),
                vesting_addr: Some("new_vesting_addr".to_owned()),
            },
        },
    )
    .unwrap();

    let config_new = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(
        Config {
            owner: config.owner,
            governance_addr: config.governance_addr,
            pairs_info: vec![pair1, pair2],
            psi_token_addr: deps.api.addr_validate("new_psi_token_addr").unwrap(),
            vesting_addr: deps.api.addr_validate("new_vesting_addr").unwrap(),
        },
        config_new
    );
}

#[test]
fn add_pairs_to_config() {
    let (mut deps, env) = init();
    let pair0 = random_psi_pair();
    instantiate_with_pairs(&mut deps, env.clone(), vec![pair0.clone()]);
    let config = CONFIG.load(&deps.storage).unwrap();
    let info = testing::mock_info(GOVERNANCE_ADDR, &[]);

    let pair1 = random_psi_pair();
    let pair2 = random_ust_pair();
    add_pairs(&mut deps, vec![pair1.clone(), pair2.clone()]);
    crate::contract::execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::AddPairsToConfig {
                pairs_addr: vec![pair1.contract_addr.clone(), pair2.contract_addr.clone()],
            },
        },
    )
    .unwrap();

    let config_new = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(
        Config {
            owner: config.owner,
            governance_addr: config.governance_addr,
            pairs_info: vec![pair0, pair1, pair2],
            psi_token_addr: config.psi_token_addr,
            vesting_addr: config.vesting_addr,
        },
        config_new
    );
}

#[test]
fn too_late_to_accept_governance_contract() {
    let (mut deps, mut env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(GOVERNANCE_ADDR, &[]);
    crate::contract::execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateGovernanceContract {
                addr: "new_governance_addr".to_owned(),
                tx_duration_sec: 10,
            },
        },
    )
    .unwrap();

    env.block.time = env.block.time.plus_seconds(15);
    let info = testing::mock_info("new_governance_addr", &[]);
    let resp = crate::contract::execute(deps.as_mut(), env, info, ExecuteMsg::AcceptGovernance {});

    assert_eq!(
        Err(StdError::generic_err("too late to accept governance owning").into()),
        resp
    );
}

#[test]
fn deny_accepting_governance_contract_from_not_new_governance_address() {
    let (mut deps, mut env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(GOVERNANCE_ADDR, &[]);
    crate::contract::execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateGovernanceContract {
                addr: "new_governance_addr".to_owned(),
                tx_duration_sec: 10,
            },
        },
    )
    .unwrap();

    env.block.time = env.block.time.plus_seconds(5);
    let info = testing::mock_info("unknown_addr", &[]);
    let resp = crate::contract::execute(deps.as_mut(), env, info, ExecuteMsg::AcceptGovernance {});

    assert_eq!(Err(ContractError::Unauthorized {}), resp);
}

#[test]
fn accept_new_governance_contract() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![psi_ust_pair()]);

    let info = testing::mock_info(GOVERNANCE_ADDR, &[]);
    crate::contract::execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateGovernanceContract {
                addr: "new_governance_addr".to_owned(),
                tx_duration_sec: 10,
            },
        },
    )
    .unwrap();

    let info = testing::mock_info("new_governance_addr", &[]);
    crate::contract::execute(deps.as_mut(), env, info, ExecuteMsg::AcceptGovernance {}).unwrap();

    let config = CONFIG.load(deps.as_ref().storage).unwrap();
    assert_eq!(
        "new_governance_addr".to_owned(),
        config.governance_addr.to_string()
    );
    assert!(GOVERNANCE_UPDATE.load(deps.as_ref().storage).is_err())
}
