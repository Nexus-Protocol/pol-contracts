use astroport::asset::{Asset, AssetInfo};
use cosmwasm_std::{
    coin, coins, from_binary, Addr, ContractResult, CosmosMsg, Decimal, Reply, Response, StdError,
    SubMsg, SubMsgExecutionResponse, Uint128, WasmMsg,
};
use cosmwasm_std::{testing, to_binary};
use cw0::{Expiration, PaymentError};
use cw20::{AllowanceResponse, Cw20ReceiveMsg};
use nexus_pol_services::pol::{
    BuySimulationResponse, ConfigResponse, ExecuteMsg, GovernanceMsg, InstantiateMsg,
    PhaseResponse, QueryMsg,
};
use nexus_pol_services::vesting::VestingSchedule;
use std::str::FromStr;

mod mock_querier;
mod sdk;

use crate::contract::{execute, instantiate, query, reply, BUY_REPLY_ID, CLAIM_REWARDS_REPLY_ID};
use crate::error::ContractError;
use crate::state::{pairs, Config, State, CONFIG, GOVERNANCE_UPDATE, STATE};
use mock_querier::*;
use sdk::*;

#[test]
fn proper_instantiation() {
    let mut deps = mock_dependencies(&[]);
    let info = testing::mock_info(CREATOR, &[]);
    let pair = psi_ust_pair();
    deps.querier
        .wasm_query_smart_responses
        .insert(pair.contract_addr.to_string(), to_binary(&pair).unwrap());

    let res = instantiate(
        deps.as_mut(),
        testing::mock_env(),
        info,
        InstantiateMsg {
            governance: GOVERNANCE.to_owned(),
            pairs: vec![pair.contract_addr.to_string()],
            psi_token: PSI_TOKEN.to_owned(),
            vesting: VESTING.to_owned(),
            vesting_period: VESTING_PERIOD,
            community_pool: COMMUNITY_POOL.to_owned(),
            autostake_lp_tokens: true,
            astro_generator: ASTRO_GENERATOR.to_owned(),
            astro_token: ASTRO_TOKEN.to_owned(),
            utility_token: Some(UTILITY_TOKEN.to_owned()),
            bond_cost_in_utility_tokens: bond_cost(),
        },
    );

    assert_eq!(
        Ok(Response::new().add_attribute("action", "instantiate")),
        res
    );
    let config = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(
        Config {
            owner: Addr::unchecked(CREATOR),
            governance: Addr::unchecked(GOVERNANCE),
            psi_token: Addr::unchecked(PSI_TOKEN),
            vesting: Addr::unchecked(VESTING),
            vesting_period: VESTING_PERIOD,
            community_pool: Addr::unchecked(COMMUNITY_POOL),
            autostake_lp_tokens: true,
            astro_generator: Addr::unchecked(ASTRO_GENERATOR),
            astro_token: Addr::unchecked(ASTRO_TOKEN),
            utility_token: Some(Addr::unchecked(UTILITY_TOKEN)),
            bond_cost_in_utility_tokens: bond_cost(),
        },
        config
    );
    assert_eq!(vec![pair], pairs(&deps.storage));
}

#[test]
fn instantiation_fails_when_wrong_case_address() {
    let mut deps = mock_dependencies(&[]);
    let info = testing::mock_info(CREATOR, &[]);
    let pair = psi_ust_pair();
    deps.querier
        .wasm_query_smart_responses
        .insert(pair.contract_addr.to_string(), to_binary(&pair).unwrap());
    let wrong_case_addr = "WrOnGcAsE".to_owned();

    let res = instantiate(
        deps.as_mut(),
        testing::mock_env(),
        info,
        InstantiateMsg {
            governance: GOVERNANCE.to_owned(),
            pairs: vec![pair.contract_addr.to_string(), wrong_case_addr.clone()],
            psi_token: PSI_TOKEN.to_owned(),
            vesting: VESTING.to_owned(),
            vesting_period: VESTING_PERIOD,
            community_pool: COMMUNITY_POOL.to_owned(),
            autostake_lp_tokens: true,
            astro_generator: ASTRO_GENERATOR.to_owned(),
            astro_token: ASTRO_TOKEN.to_owned(),
            utility_token: Some(UTILITY_TOKEN.to_owned()),
            bond_cost_in_utility_tokens: Decimal::from_str("0.5").unwrap(),
        },
    );

    assert_eq!(
        Err(ContractError::WrongCaseAddr {
            addr: wrong_case_addr
        }),
        res
    );
}

#[test]
fn buy_with_non_allowed_cw20_tokens_fails() {
    let (mut deps, env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], Some(default_phase(&env)));

    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(10_000_000),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );
    let query_resp = query(
        deps.as_ref(),
        env,
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::Token {
                    contract_addr: Addr::unchecked(CW20_TOKEN),
                },
                amount: Uint128::new(10_000_000),
            },
        },
    );

    assert_eq!(
        Err(ContractError::NotAllowedPair {
            assets_info: psi_cw20token_pair().asset_infos,
        }),
        resp
    );
    assert_eq!(
        Err(StdError::generic_err(format!(
            "pair {}-{} not allowed",
            PSI_TOKEN, CW20_TOKEN
        ))),
        query_resp
    );
}

#[test]
fn buy_with_cw20_tokens_fails_when_no_active_phase() {
    let (mut deps, mut env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], None);

    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(50),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );
    assert_eq!(Err(StdError::generic_err("phase is not set").into()), resp);

    let cur_time = env.block.time.seconds();
    let info = testing::mock_info(GOVERNANCE, &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::from_str("0.5").unwrap(),
                psi_amount_total: Uint128::new(1_000),
                psi_amount_start: Uint128::new(100),
                start_time: cur_time + 1,
                end_time: cur_time + 2,
            },
        },
    )
    .unwrap();
    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(50),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );
    assert_eq!(
        Err(StdError::generic_err(format!(
            "phase starts at {}, but {} now",
            cur_time + 1,
            cur_time
        ))
        .into()),
        resp
    );

    let info = testing::mock_info(GOVERNANCE, &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::from_str("0.5").unwrap(),
                psi_amount_total: Uint128::new(1_000),
                psi_amount_start: Uint128::new(100),
                start_time: cur_time + 1,
                end_time: cur_time + 2,
            },
        },
    )
    .unwrap();
    let info = testing::mock_info(CW20_TOKEN, &[]);
    env.block.time = env.block.time.plus_seconds(3);
    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(50),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );
    assert_eq!(
        Err(StdError::generic_err(format!(
            "phase finished at {}, but {} now",
            cur_time + 2,
            cur_time + 3,
        ))
        .into()),
        resp
    );
}

#[test]
fn tiny_buy_with_cw20_tokens_fails() {
    let (mut deps, env) = init();
    let pair = psi_cw20token_pair();
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![pair.clone()],
        Some(default_phase(&env)),
    );
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[(pair.contract_addr.as_str(), &Uint128::new(100_000_000_000))],
        ),
        (
            CW20_TOKEN,
            &[(
                pair.contract_addr.as_str(),
                &Uint128::new(10_000_000_000_000),
            )],
        ),
    ]);

    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(50),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );
    let query_resp = query(
        deps.as_ref(),
        env,
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::Token {
                    contract_addr: Addr::unchecked(CW20_TOKEN),
                },
                amount: Uint128::new(50),
            },
        },
    );

    assert_eq!(Err(ContractError::PaymentTooSmall {}), resp);
    assert_eq!(Err(StdError::generic_err("payment too small",)), query_resp);
}

#[test]
fn buy_with_cw20_tokens_fails_when_not_enough_psi_tokens_to_provide_liquidity() {
    let (mut deps, env) = init();
    let cw_pair = psi_cw20token_pair();
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (env.contract.address.as_str(), &Uint128::new(500_000_000)),
                (
                    cw_pair.contract_addr.as_str(),
                    &Uint128::new(30_000_000_000_000),
                ),
            ],
        ),
        (
            CW20_TOKEN,
            &[(
                cw_pair.contract_addr.as_str(),
                &Uint128::new(1_000_000_000_000),
            )],
        ),
    ]);
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![cw_pair.clone()],
        Some(default_phase(&env)),
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                psi_amount_sold: Uint128::new(4_000_000_000_000_000),
            },
        )
        .unwrap();

    let query_resp = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::Token {
                    contract_addr: Addr::unchecked(CW20_TOKEN),
                },
                amount: Uint128::new(2_000_000_000),
            },
        },
    );
    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(2_000_000_000),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );

    assert_eq!(
        Err(ContractError::NotEnoughTokens {
            name: "psi".to_owned(),
            value: Uint128::new(500_000_000),
            required: Uint128::new(60_000_000_000)
        }),
        resp
    );
    assert_eq!(
        Err(StdError::generic_err(
            "not enough psi tokens: 500000000, but 60000000000 required"
        )),
        query_resp
    );
}

#[test]
fn buy_with_cw20_tokens_fails_when_not_enough_psi_tokens_for_vesting() {
    let (mut deps, env) = init();
    let cw_pair = psi_cw20token_pair();
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (env.contract.address.as_str(), &Uint128::new(30_000)),
                (
                    cw_pair.contract_addr.as_str(),
                    &Uint128::new(30_000_000_000_000),
                ),
            ],
        ),
        (
            CW20_TOKEN,
            &[(
                cw_pair.contract_addr.as_str(),
                &Uint128::new(1_000_000_000_000),
            )],
        ),
    ]);
    deps.querier.wasm_query_smart_responses.insert(
        UTILITY_TOKEN.to_owned(),
        to_binary(&AllowanceResponse {
            allowance: Uint128::MAX,
            expires: Expiration::Never {},
        })
        .unwrap(),
    );
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![cw_pair.clone()],
        Some(default_phase(&env)),
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                psi_amount_sold: Uint128::new(4_000_000),
            },
        )
        .unwrap();

    let query_resp = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::Token {
                    contract_addr: Addr::unchecked(CW20_TOKEN),
                },
                amount: Uint128::new(2_000),
            },
        },
    );
    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(2_000),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );

    assert_eq!(
        Err(ContractError::NotEnoughTokens {
            name: "psi".to_owned(),
            value: Uint128::new(30_000),
            required: Uint128::new(60_000)
        }),
        resp
    );
    assert_eq!(
        Err(StdError::generic_err(
            "not enough psi tokens: 30000, but 60000 required"
        )),
        query_resp
    );
}

#[test]
fn buy_with_cw20_tokens_fails_when_not_enough_utility_tokens() {
    let (mut deps, env) = init();
    let cw_pair = psi_cw20token_pair();
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (env.contract.address.as_str(), &Uint128::new(300_000)),
                (
                    cw_pair.contract_addr.as_str(),
                    &Uint128::new(30_000_000_000_000),
                ),
            ],
        ),
        (
            CW20_TOKEN,
            &[(
                cw_pair.contract_addr.as_str(),
                &Uint128::new(1_000_000_000_000),
            )],
        ),
    ]);
    deps.querier.wasm_query_smart_responses.insert(
        UTILITY_TOKEN.to_owned(),
        to_binary(&AllowanceResponse {
            allowance: Uint128::new(10),
            expires: Expiration::Never {},
        })
        .unwrap(),
    );
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![cw_pair.clone()],
        Some(default_phase(&env)),
    );

    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(2_000),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );

    assert_eq!(
        Err(ContractError::NotEnoughTokens {
            name: "utility".to_owned(),
            value: Uint128::new(10),
            required: Uint128::new(30_003)
        }),
        resp
    );
}

#[test]
fn buy_with_cw20_tokens() {
    let (mut deps, env) = init();
    let cw_pair = psi_cw20token_pair();
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (
                    env.contract.address.as_str(),
                    &Uint128::new(500_000_000_000_000),
                ),
                (
                    cw_pair.contract_addr.as_str(),
                    &Uint128::new(30_000_000_000_000),
                ),
            ],
        ),
        (
            CW20_TOKEN,
            &[(
                cw_pair.contract_addr.as_str(),
                &Uint128::new(1_000_000_000_000),
            )],
        ),
        (
            ASTRO_TOKEN,
            &[(env.contract.address.as_str(), &Uint128::zero())],
        ),
    ]);
    deps.querier.wasm_query_smart_responses.insert(
        UTILITY_TOKEN.to_owned(),
        to_binary(&AllowanceResponse {
            allowance: Uint128::MAX,
            expires: Expiration::Never {},
        })
        .unwrap(),
    );
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![cw_pair.clone()],
        Some(default_phase(&env)),
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                psi_amount_sold: Uint128::new(4_000),
            },
        )
        .unwrap();

    let query_resp = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::Token {
                    contract_addr: Addr::unchecked(CW20_TOKEN),
                },
                amount: Uint128::new(2_000),
            },
        },
    );
    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(2_000),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );

    assert_eq!(
        Ok(Response::new()
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: UTILITY_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::BurnFrom {
                    owner: INVESTOR.to_owned(),
                    amount: Uint128::new(30_003),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: PSI_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                    recipient: VESTING.to_owned(),
                    amount: Uint128::new(60_006),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: VESTING.to_string(),
                msg: to_binary(
                    &nexus_pol_services::vesting::ExecuteMsg::AddVestingSchedule {
                        addr: INVESTOR.to_string(),
                        schedule: VestingSchedule {
                            start_time: env.block.time.seconds(),
                            end_time: env.block.time.plus_seconds(VESTING_PERIOD).seconds(),
                            cliff_end_time: env.block.time.seconds(),
                            amount: Uint128::new(60_006),
                        }
                    }
                )
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: PSI_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::IncreaseAllowance {
                    spender: cw_pair.contract_addr.to_string(),
                    amount: Uint128::new(60_000),
                    expires: Some(Expiration::AtHeight(env.block.height + 1)),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: CW20_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::IncreaseAllowance {
                    spender: cw_pair.contract_addr.to_string(),
                    amount: Uint128::new(2_000),
                    expires: Some(Expiration::AtHeight(env.block.height + 1)),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::reply_on_success(
                WasmMsg::Execute {
                    contract_addr: cw_pair.contract_addr.to_string(),
                    msg: to_binary(&astroport::pair::ExecuteMsg::ProvideLiquidity {
                        assets: [
                            Asset {
                                info: AssetInfo::Token {
                                    contract_addr: Addr::unchecked(PSI_TOKEN),
                                },
                                amount: Uint128::new(60_000),
                            },
                            Asset {
                                info: AssetInfo::Token {
                                    contract_addr: Addr::unchecked(CW20_TOKEN),
                                },
                                amount: Uint128::new(2_000),
                            },
                        ],
                        slippage_tolerance: None,
                        receiver: None,
                        auto_stake: Some(true),
                    })
                    .unwrap(),
                    funds: vec![],
                },
                BUY_REPLY_ID
            ))
            .add_attribute("utility_tokens_burned", "30003")
            .add_attribute("action", "buy")
            .add_attribute("asset", CW20_TOKEN)
            .add_attribute("discount", "0.000115740268472222")
            .add_attribute("bonds_issued", "60006")
            .add_attribute(
                "pair_with_provided_liquidity",
                cw_pair.contract_addr.clone()
            )
            .add_attribute("provided_liquidity_in_psi", "60000")
            .add_attribute("provided_liquidity_in_asset", "2000")),
        resp
    );
    assert_eq!(
        State {
            psi_amount_sold: Uint128::new(4_000) + Uint128::new(60006),
        },
        STATE.load(&deps.storage).unwrap(),
    );
    assert_eq!(
        BuySimulationResponse {
            bonds: Uint128::new(60006),
            discount: Decimal::from_str("0.000115740268472222").unwrap(),
            utility_tokens: Uint128::new(30003),
        },
        from_binary(&query_resp.unwrap()).unwrap(),
    );

    deps.querier
        .token_balances
        .get_mut(PSI_TOKEN)
        .unwrap()
        .insert(
            env.contract.address.to_string(),
            Uint128::new(500_000_000_000_000),
        );
    deps.querier
        .token_balances
        .get_mut(ASTRO_TOKEN)
        .unwrap()
        .insert(env.contract.address.to_string(), Uint128::new(10_000_000));
    let reply_resp = reply(
        deps.as_mut(),
        env,
        Reply {
            id: BUY_REPLY_ID,
            result: ContractResult::Ok(SubMsgExecutionResponse {
                events: vec![],
                data: None,
            }),
        },
    )
    .unwrap();
    assert_eq!(
        Response::new()
            .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: ASTRO_TOKEN.to_string(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                    recipient: COMMUNITY_POOL.to_string(),
                    amount: Uint128::new(10_000_000),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: PSI_TOKEN.to_string(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                    recipient: COMMUNITY_POOL.to_string(),
                    amount: Uint128::new(120_006),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_attribute("utility_tokens_burned", "30003")
            .add_attribute("action", "buy")
            .add_attribute("asset", CW20_TOKEN)
            .add_attribute("discount", "0.000115740268472222")
            .add_attribute("bonds_issued", "60006")
            .add_attribute("pair_with_provided_liquidity", cw_pair.contract_addr)
            .add_attribute("provided_liquidity_in_psi", "60000")
            .add_attribute("provided_liquidity_in_asset", "2000")
            .add_attribute("astro_tokens_claimed", "10000000")
            .add_attribute("psi_tokens_claimed", "120006"),
        reply_resp
    );
}

#[test]
fn buy_with_no_coins_fails() {
    let (mut deps, env) = init();
    let ust_pair = psi_ust_pair();
    instantiate_properly(&mut deps, env.clone(), vec![ust_pair], None);

    let info = testing::mock_info(INVESTOR, &[]);
    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );

    assert_eq!(Err(ContractError::Payment(PaymentError::NoFunds {})), resp);
}

#[test]
fn buy_with_two_coins_fails() {
    let (mut deps, env) = init();
    let ust_pair = psi_ust_pair();
    instantiate_properly(&mut deps, env.clone(), vec![ust_pair], None);

    let info = testing::mock_info(INVESTOR, &[coin(1, "uusdt"), coin(1, UST)]);
    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );

    assert_eq!(
        Err(ContractError::Payment(PaymentError::MultipleDenoms {})),
        resp
    );
}

#[test]
fn buy_with_not_allowed_denom_fails() {
    let (mut deps, env) = init();
    let ust_pair = psi_ust_pair();
    deps.querier.set_ust_balances(&[(
        ust_pair.contract_addr.as_str(),
        &Uint128::new(10_000_000_000),
    )]);
    deps.querier.set_token_balances(&[(
        PSI_TOKEN,
        &[
            (
                ust_pair.contract_addr.as_str(),
                &Uint128::new(10_000_000_000_000),
            ),
            (env.contract.address.as_str(), &Uint128::new(1_000_000_000)),
        ],
    )]);
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![ust_pair],
        Some(default_phase(&env)),
    );

    let not_allowed_denom = "blablabla";
    let info = testing::mock_info(INVESTOR, &coins(1_000, not_allowed_denom));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );
    let query_resp = query(
        deps.as_ref(),
        env,
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::NativeToken {
                    denom: not_allowed_denom.to_owned(),
                },
                amount: Uint128::new(10_000_000),
            },
        },
    );

    assert_eq!(
        Err(ContractError::NotAllowedPair {
            assets_info: [
                AssetInfo::Token {
                    contract_addr: Addr::unchecked(PSI_TOKEN)
                },
                AssetInfo::NativeToken {
                    denom: not_allowed_denom.to_owned()
                }
            ],
        }),
        resp
    );
    assert_eq!(
        Err(StdError::generic_err(format!(
            "pair {}-{} not allowed",
            PSI_TOKEN, not_allowed_denom,
        ),)),
        query_resp
    );
}

#[test]
fn buy_with_zero_coins_fails() {
    let (mut deps, env) = init();
    let ust_pair = psi_ust_pair();
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![ust_pair],
        Some(default_phase(&env)),
    );

    let info = testing::mock_info(INVESTOR, &coins(0, UST));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );
    let query_resp = query(
        deps.as_ref(),
        env,
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::NativeToken {
                    denom: UST.to_owned(),
                },
                amount: Uint128::zero(),
            },
        },
    );

    assert_eq!(Err(ContractError::Payment(PaymentError::NoFunds {})), resp);
    assert_eq!(Err(StdError::generic_err("no funds")), query_resp);
}

#[test]
fn buy_with_coins_fails_when_no_active_phase() {
    let (mut deps, mut env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], None);

    let info = testing::mock_info(INVESTOR, &coins(10_000_000, UST));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );
    assert_eq!(Err(StdError::generic_err("phase is not set").into()), resp);

    let cur_time = env.block.time.seconds();
    let info = testing::mock_info(GOVERNANCE, &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::from_str("0.5").unwrap(),
                psi_amount_total: Uint128::new(1_000),
                psi_amount_start: Uint128::new(100),
                start_time: cur_time + 1,
                end_time: cur_time + 2,
            },
        },
    )
    .unwrap();
    let info = testing::mock_info(INVESTOR, &coins(10_000_000, UST));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );
    assert_eq!(
        Err(StdError::generic_err(format!(
            "phase starts at {}, but {} now",
            cur_time + 1,
            cur_time
        ))
        .into()),
        resp
    );

    let info = testing::mock_info(GOVERNANCE, &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::from_str("0.5").unwrap(),
                psi_amount_total: Uint128::new(1_000),
                psi_amount_start: Uint128::new(100),
                start_time: cur_time + 1,
                end_time: cur_time + 2,
            },
        },
    )
    .unwrap();
    let info = testing::mock_info(INVESTOR, &coins(10_000_000, UST));
    env.block.time = env.block.time.plus_seconds(3);
    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );
    assert_eq!(
        Err(StdError::generic_err(format!(
            "phase finished at {}, but {} now",
            cur_time + 2,
            cur_time + 3,
        ))
        .into()),
        resp
    );
}

#[test]
fn buy_with_coins_fails_when_no_psi_ust_pair() {
    let (mut deps, env) = init();
    let cw_pair = psi_cw20token_pair();
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![cw_pair],
        Some(default_phase(&env)),
    );

    let info = testing::mock_info(INVESTOR, &coins(10_000_000, UST));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );
    let query_resp = query(
        deps.as_ref(),
        env,
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::NativeToken {
                    denom: UST.to_owned(),
                },
                amount: Uint128::new(10_000_000),
            },
        },
    );

    assert_eq!(
        Err(ContractError::NotAllowedPair {
            assets_info: psi_ust_pair().asset_infos,
        }),
        resp
    );
    assert_eq!(
        Err(StdError::generic_err(format!(
            "pair {}-{} not allowed",
            PSI_TOKEN, UST
        ))),
        query_resp
    );
}

#[test]
fn tiny_buy_with_coins_fails() {
    let (mut deps, env) = init();
    let pair = psi_ust_pair();
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![pair.clone()],
        Some(default_phase(&env)),
    );
    deps.querier
        .set_ust_balances(&[(pair.contract_addr.as_str(), &Uint128::new(400_000_000_000))]);
    deps.querier.set_token_balances(&[(
        PSI_TOKEN,
        &[(pair.contract_addr.as_str(), &Uint128::new(100_000_000_000))],
    )]);

    let info = testing::mock_info(INVESTOR, &coins(3, UST));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: Uint128::new(50),
        },
    );
    let query_resp = query(
        deps.as_ref(),
        env,
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::NativeToken {
                    denom: UST.to_owned(),
                },
                amount: Uint128::new(3),
            },
        },
    );

    assert_eq!(Err(ContractError::PaymentTooSmall {}), resp);
    assert_eq!(Err(StdError::generic_err("payment too small",)), query_resp);
}

#[test]
fn buy_with_coins_fails_when_not_enough_psi_tokens_to_provide_liquidity() {
    let (mut deps, env) = init();
    let pair = psi_ust_pair();
    deps.querier
        .set_ust_balances(&[(pair.contract_addr.as_str(), &Uint128::new(400_000_000_000))]);
    deps.querier.set_token_balances(&[(
        PSI_TOKEN,
        &[
            (env.contract.address.as_str(), &Uint128::new(500_000_000)),
            (
                pair.contract_addr.as_str(),
                &Uint128::new(10_000_000_000_000),
            ),
        ],
    )]);
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![pair.clone()],
        Some(default_phase(&env)),
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                psi_amount_sold: Uint128::new(4_000_000_000_000_000),
            },
        )
        .unwrap();

    let query_resp = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::NativeToken {
                    denom: UST.to_owned(),
                },
                amount: Uint128::new(2_000_000_000),
            },
        },
    );
    let info = testing::mock_info(INVESTOR, &coins(2_000_000_000, UST));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );

    assert_eq!(
        Err(ContractError::NotEnoughTokens {
            name: "psi".to_owned(),
            value: Uint128::new(500_000_000),
            required: Uint128::new(49_999_999_750)
        }),
        resp
    );
    assert_eq!(
        Err(StdError::generic_err(
            "not enough psi tokens: 500000000, but 49999999750 required"
        )),
        query_resp
    );
}

#[test]
fn buy_with_coins_fails_when_not_enough_psi_tokens_for_vesting() {
    let (mut deps, env) = init();
    let pair = psi_ust_pair();
    deps.querier
        .set_ust_balances(&[(pair.contract_addr.as_str(), &Uint128::new(400_000_000_000))]);
    deps.querier.set_token_balances(&[(
        PSI_TOKEN,
        &[
            (env.contract.address.as_str(), &Uint128::new(50_000)),
            (
                pair.contract_addr.as_str(),
                &Uint128::new(10_000_000_000_000),
            ),
        ],
    )]);
    deps.querier.wasm_query_smart_responses.insert(
        UTILITY_TOKEN.to_owned(),
        to_binary(&AllowanceResponse {
            allowance: Uint128::MAX,
            expires: Expiration::Never {},
        })
        .unwrap(),
    );
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![pair.clone()],
        Some(default_phase(&env)),
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                psi_amount_sold: Uint128::new(4_000),
            },
        )
        .unwrap();

    let query_resp = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::NativeToken {
                    denom: UST.to_owned(),
                },
                amount: Uint128::new(2_000),
            },
        },
    );
    let info = testing::mock_info(INVESTOR, &coins(2_000, UST));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );

    assert_eq!(
        Err(ContractError::NotEnoughTokens {
            name: "psi".to_owned(),
            value: Uint128::new(250),
            required: Uint128::new(49755)
        }),
        resp
    );
    assert_eq!(
        Err(StdError::generic_err(
            "not enough psi tokens: 250, but 49755 required"
        )),
        query_resp
    );
}

#[test]
fn buy_with_coins_fails_when_not_enough_utility_tokens() {
    let (mut deps, env) = init();
    let pair = psi_ust_pair();
    deps.querier
        .set_ust_balances(&[(pair.contract_addr.as_str(), &Uint128::new(400_000_000_000))]);
    deps.querier.set_token_balances(&[(
        PSI_TOKEN,
        &[
            (env.contract.address.as_str(), &Uint128::new(50_000)),
            (
                pair.contract_addr.as_str(),
                &Uint128::new(10_000_000_000_000),
            ),
        ],
    )]);
    deps.querier.wasm_query_smart_responses.insert(
        UTILITY_TOKEN.to_owned(),
        to_binary(&AllowanceResponse {
            allowance: Uint128::new(10),
            expires: Expiration::Never {},
        })
        .unwrap(),
    );
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![pair.clone()],
        Some(default_phase(&env)),
    );

    let info = testing::mock_info(INVESTOR, &coins(2_000, UST));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );

    assert_eq!(
        Err(ContractError::NotEnoughTokens {
            name: "utility".to_owned(),
            value: Uint128::new(10),
            required: Uint128::new(24877),
        }),
        resp
    );
}

#[test]
fn buy_with_coins() {
    let (mut deps, env) = init();
    let pair = psi_ust_pair();
    deps.querier
        .set_ust_balances(&[(pair.contract_addr.as_str(), &Uint128::new(400_000_000_000))]);
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (
                    env.contract.address.as_str(),
                    &Uint128::new(500_000_000_000_000),
                ),
                (
                    pair.contract_addr.as_str(),
                    &Uint128::new(10_000_000_000_000),
                ),
            ],
        ),
        (
            ASTRO_TOKEN,
            &[(env.contract.address.as_str(), &Uint128::zero())],
        ),
    ]);
    deps.querier.wasm_query_smart_responses.insert(
        UTILITY_TOKEN.to_owned(),
        to_binary(&AllowanceResponse {
            allowance: Uint128::MAX,
            expires: Expiration::Never {},
        })
        .unwrap(),
    );
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![pair.clone()],
        Some(default_phase(&env)),
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                psi_amount_sold: Uint128::new(4_000),
            },
        )
        .unwrap();

    let query_resp = query(
        deps.as_ref(),
        env.clone(),
        QueryMsg::BuySimulation {
            asset: Asset {
                info: AssetInfo::NativeToken {
                    denom: UST.to_owned(),
                },
                amount: Uint128::new(2_000),
            },
        },
    );
    assert_eq!(
        BuySimulationResponse {
            bonds: Uint128::new(49_755),
            discount: Decimal::from_str("0.000115740339659722").unwrap(),
            utility_tokens: Uint128::new(24877),
        },
        from_binary(&query_resp.unwrap()).unwrap(),
    );

    let info = testing::mock_info(INVESTOR, &coins(2_000, UST));
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );

    assert_eq!(
        Ok(Response::new()
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: UTILITY_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::BurnFrom {
                    owner: INVESTOR.to_owned(),
                    amount: Uint128::new(24_877),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: PSI_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                    recipient: VESTING.to_owned(),
                    amount: Uint128::new(49_755),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: VESTING.to_owned(),
                msg: to_binary(
                    &nexus_pol_services::vesting::ExecuteMsg::AddVestingSchedule {
                        addr: INVESTOR.to_owned(),
                        schedule: VestingSchedule {
                            start_time: env.block.time.seconds(),
                            end_time: env.block.time.plus_seconds(VESTING_PERIOD).seconds(),
                            cliff_end_time: env.block.time.seconds(),
                            amount: Uint128::new(49_755),
                        }
                    }
                )
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: PSI_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::IncreaseAllowance {
                    spender: pair.contract_addr.to_string(),
                    amount: Uint128::new(49_750),
                    expires: Some(Expiration::AtHeight(env.block.height + 1)),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::reply_on_success(
                WasmMsg::Execute {
                    contract_addr: pair.contract_addr.to_string(),
                    msg: to_binary(&astroport::pair::ExecuteMsg::ProvideLiquidity {
                        assets: [
                            Asset {
                                info: AssetInfo::Token {
                                    contract_addr: Addr::unchecked(PSI_TOKEN),
                                },
                                amount: Uint128::new(49_750),
                            },
                            Asset {
                                info: AssetInfo::NativeToken {
                                    denom: UST.to_owned(),
                                },
                                amount: Uint128::new(1_990),
                            },
                        ],
                        slippage_tolerance: None,
                        receiver: None,
                        auto_stake: Some(true),
                    })
                    .unwrap(),
                    funds: coins(1_990, UST),
                },
                BUY_REPLY_ID,
            ))
            .add_attribute("utility_tokens_burned", "24877")
            .add_attribute("action", "buy")
            .add_attribute("asset", UST)
            .add_attribute("psi_price", "0.04")
            .add_attribute("discount", "0.000115740339659722")
            .add_attribute("bonds_issued", "49755")
            .add_attribute("pair_with_provided_liquidity", pair.contract_addr.clone())
            .add_attribute("provided_liquidity_in_psi", "49750")
            .add_attribute("provided_liquidity_in_asset", "1990")),
        resp
    );
    assert_eq!(
        State {
            psi_amount_sold: Uint128::new(4_000) + Uint128::new(49_755),
        },
        STATE.load(&deps.storage).unwrap(),
    );

    deps.querier
        .token_balances
        .get_mut(PSI_TOKEN)
        .unwrap()
        .insert(
            env.contract.address.to_string(),
            Uint128::new(600_000_000_000_000),
        );
    deps.querier
        .token_balances
        .get_mut(ASTRO_TOKEN)
        .unwrap()
        .insert(env.contract.address.to_string(), Uint128::new(10_000_000));
    let reply_resp = reply(
        deps.as_mut(),
        env,
        Reply {
            id: BUY_REPLY_ID,
            result: ContractResult::Ok(SubMsgExecutionResponse {
                events: vec![],
                data: None,
            }),
        },
    );
    assert_eq!(
        Ok(Response::new()
            .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: ASTRO_TOKEN.to_string(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                    recipient: COMMUNITY_POOL.to_string(),
                    amount: Uint128::new(10_000_000),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: PSI_TOKEN.to_string(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                    recipient: COMMUNITY_POOL.to_string(),
                    amount: Uint128::new(100_000_000_099_505),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_attribute("utility_tokens_burned", "24877")
            .add_attribute("action", "buy")
            .add_attribute("asset", UST)
            .add_attribute("psi_price", "0.04")
            .add_attribute("discount", "0.000115740339659722")
            .add_attribute("bonds_issued", "49755")
            .add_attribute("pair_with_provided_liquidity", pair.contract_addr)
            .add_attribute("provided_liquidity_in_psi", "49750")
            .add_attribute("provided_liquidity_in_asset", "1990")
            .add_attribute("astro_tokens_claimed", "10000000")
            .add_attribute("psi_tokens_claimed", "100000000099505")),
        reply_resp
    );
}

#[test]
fn claim_rewards() {
    let (mut deps, env) = init();
    let ust_pair = psi_ust_pair();
    let cw_pair = psi_cw20token_pair();
    deps.querier.set_ust_balances(&[(
        ust_pair.contract_addr.as_str(),
        &Uint128::new(400_000_000_000),
    )]);
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (
                    env.contract.address.as_str(),
                    &Uint128::new(500_000_000_000_000),
                ),
                (
                    cw_pair.contract_addr.as_str(),
                    &Uint128::new(10_000_000_000_000),
                ),
            ],
        ),
        (
            ASTRO_TOKEN,
            &[(
                env.contract.address.as_str(),
                &Uint128::new(10_000_000_000_000),
            )],
        ),
    ]);
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![ust_pair.clone(), cw_pair.clone()],
        None,
    );

    let info = testing::mock_info(INVESTOR, &[]);
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::ClaimRewards {},
    );
    assert_eq!(
        Ok(Response::new()
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: ASTRO_GENERATOR.to_owned(),
                msg: to_binary(&astroport::generator::ExecuteMsg::Withdraw {
                    lp_token: cw_pair.liquidity_token,
                    amount: Uint128::zero(),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::reply_on_success(
                WasmMsg::Execute {
                    contract_addr: ASTRO_GENERATOR.to_owned(),
                    msg: to_binary(&astroport::generator::ExecuteMsg::Withdraw {
                        lp_token: ust_pair.liquidity_token,
                        amount: Uint128::zero(),
                    })
                    .unwrap(),
                    funds: vec![],
                },
                CLAIM_REWARDS_REPLY_ID
            ))),
        resp
    );

    deps.querier
        .token_balances
        .get_mut(PSI_TOKEN)
        .unwrap()
        .insert(
            env.contract.address.to_string(),
            Uint128::new(550_000_000_000_000),
        );
    deps.querier
        .token_balances
        .get_mut(ASTRO_TOKEN)
        .unwrap()
        .insert(
            env.contract.address.to_string(),
            Uint128::new(10_100_000_000_000),
        );
    let reply_resp = reply(
        deps.as_mut(),
        env,
        Reply {
            id: CLAIM_REWARDS_REPLY_ID,
            result: ContractResult::Ok(SubMsgExecutionResponse {
                events: vec![],
                data: None,
            }),
        },
    );
    assert_eq!(
        Ok(Response::new()
            .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: ASTRO_TOKEN.to_string(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                    recipient: COMMUNITY_POOL.to_string(),
                    amount: Uint128::new(100_000_000_000),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                contract_addr: PSI_TOKEN.to_string(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                    recipient: COMMUNITY_POOL.to_string(),
                    amount: Uint128::new(50_000_000_000_000),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_attribute("action", "claim_rewards")
            .add_attribute("astro_tokens_claimed", "100000000000")
            .add_attribute("psi_tokens_claimed", "50000000000000")),
        reply_resp
    );
}

#[test]
fn invalid_phase() {
    let (mut deps, env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], None);

    let info = testing::mock_info(GOVERNANCE, &[]);
    let end_time = env.block.time.plus_seconds(1).seconds();
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::zero(),
                psi_amount_total: Uint128::new(10),
                psi_amount_start: Uint128::new(100),
                start_time: 0,
                end_time,
            },
        },
    );
    assert_eq!(Err(ContractError::InvalidPhase {}), resp);

    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::one(),
                psi_amount_total: Uint128::new(1_000),
                psi_amount_start: Uint128::new(100),
                start_time: 0,
                end_time,
            },
        },
    );
    assert_eq!(Err(ContractError::InvalidPhase {}), resp);

    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::zero(),
                psi_amount_total: Uint128::new(1_000),
                psi_amount_start: Uint128::new(100),
                start_time: end_time,
                end_time: 0,
            },
        },
    );
    assert_eq!(Err(ContractError::InvalidPhase {}), resp);

    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::zero(),
                psi_amount_total: Uint128::new(1_000),
                psi_amount_start: Uint128::new(100),
                start_time: 0,
                end_time: end_time - 2,
            },
        },
    );
    assert_eq!(Err(ContractError::InvalidPhase {}), resp);
}

#[test]
fn phase() {
    let (mut deps, env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], None);

    let info = testing::mock_info(GOVERNANCE, &[]);
    let end_time = env.block.time.plus_seconds(1).seconds();
    let resp = execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::from_str("0.5").unwrap(),
                psi_amount_total: Uint128::new(1_000),
                psi_amount_start: Uint128::new(100),
                start_time: 0,
                end_time,
            },
        },
    );
    let query_resp = query(deps.as_ref(), env, QueryMsg::Phase {});

    assert_eq!(Ok(Response::new().add_attribute("action", "phase")), resp);
    assert_eq!(
        Uint128::zero(),
        STATE.load(&deps.storage).unwrap().psi_amount_sold
    );
    assert_eq!(
        PhaseResponse {
            max_discount: Decimal::from_str("0.5").unwrap(),
            psi_amount_total: Uint128::new(1_000),
            psi_amount_start: Uint128::new(100),
            start_time: 0,
            end_time,
        },
        from_binary(&query_resp.unwrap()).unwrap()
    );
}

#[test]
fn do_not_accept_any_governance_msg_from_non_governance_contract() {
    let (mut deps, env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], None);
    let info = testing::mock_info("nongovernance", &[]);

    let resp_phase = execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::Phase {
                max_discount: Decimal::one(),
                psi_amount_total: Uint128::zero(),
                psi_amount_start: Uint128::zero(),
                start_time: 0,
                end_time: 0,
            },
        },
    );
    let resp_update_config = execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateConfig {
                psi_token: None,
                vesting: None,
                vesting_period: None,
                community_pool: None,
                autostake_lp_tokens: None,
                astro_generator: None,
                astro_token: None,
                utility_token: None,
                bond_cost_in_utility_tokens: None,
            },
        },
    );
    let resp_update_pairs = execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdatePairs {
                add: vec![],
                remove: vec![],
            },
        },
    );
    let resp_update_governance_contract = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateGovernanceContract {
                addr: GOVERNANCE.to_owned(),
                seconds_to_wait_for_accept_gov_tx: 10,
            },
        },
    );

    assert_eq!(Err(ContractError::Unauthorized {}), resp_phase);
    assert_eq!(Err(ContractError::Unauthorized {}), resp_update_config);
    assert_eq!(Err(ContractError::Unauthorized {}), resp_update_pairs);
    assert_eq!(
        Err(ContractError::Unauthorized {}),
        resp_update_governance_contract
    );
}

#[test]
fn update_config() {
    let (mut deps, env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], None);
    let config = CONFIG.load(&deps.storage).unwrap();
    let info = testing::mock_info(GOVERNANCE, &[]);

    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateConfig {
                psi_token: Some("new_psi_token".to_owned()),
                vesting: Some("new_vesting".to_owned()),
                vesting_period: Some(100),
                community_pool: Some("new_community_pool".to_owned()),
                autostake_lp_tokens: Some(false),
                astro_generator: Some("new_astro_generator".to_owned()),
                astro_token: Some("new_astro_token".to_owned()),
                utility_token: Some("".to_owned()),
                bond_cost_in_utility_tokens: Some(Decimal::one()),
            },
        },
    );

    assert_eq!(
        Ok(Response::new().add_attribute("action", "update_config")),
        resp
    );
    let new_config = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(
        Config {
            owner: config.owner,
            governance: config.governance,
            psi_token: Addr::unchecked("new_psi_token"),
            vesting: Addr::unchecked("new_vesting"),
            vesting_period: 100,
            community_pool: Addr::unchecked("new_community_pool"),
            autostake_lp_tokens: false,
            astro_generator: Addr::unchecked("new_astro_generator"),
            astro_token: Addr::unchecked("new_astro_token"),
            utility_token: None,
            bond_cost_in_utility_tokens: Decimal::one(),
        },
        new_config
    );
}

#[test]
fn update_pairs() {
    let (mut deps, env) = init();
    let pair0 = random_psi_pair("0");
    instantiate_properly(&mut deps, env.clone(), vec![pair0.clone()], None);
    let info = testing::mock_info(GOVERNANCE, &[]);

    let pair1 = random_psi_pair("1");
    let pair2 = random_psi_pair("2");
    add_pairs(&mut deps, &[pair1.clone(), pair2.clone()]);
    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdatePairs {
                add: vec![
                    pair1.contract_addr.to_string(),
                    pair2.contract_addr.to_string(),
                ],
                remove: vec![pair0.contract_addr.to_string()],
            },
        },
    );

    assert_eq!(
        Ok(Response::new().add_attribute("action", "update_pairs")),
        resp
    );
    assert_eq!(vec![pair1, pair2], pairs(&deps.storage));
}

#[test]
fn too_late_to_accept_governance_contract() {
    let (mut deps, mut env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], None);

    let info = testing::mock_info(GOVERNANCE, &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateGovernanceContract {
                addr: "new_governance_addr".to_owned(),
                seconds_to_wait_for_accept_gov_tx: 10,
            },
        },
    )
    .unwrap();

    env.block.time = env.block.time.plus_seconds(15);
    let info = testing::mock_info("new_governance", &[]);
    let resp = execute(deps.as_mut(), env, info, ExecuteMsg::AcceptGovernance {});

    assert_eq!(
        Err(StdError::generic_err("too late to accept governance owning").into()),
        resp
    );
}

#[test]
fn deny_accepting_governance_contract_from_not_new_governance_address() {
    let (mut deps, mut env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], None);

    let info = testing::mock_info(GOVERNANCE, &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateGovernanceContract {
                addr: "new_governance".to_owned(),
                seconds_to_wait_for_accept_gov_tx: 10,
            },
        },
    )
    .unwrap();

    env.block.time = env.block.time.plus_seconds(5);
    let info = testing::mock_info("unknown", &[]);
    let resp = execute(deps.as_mut(), env, info, ExecuteMsg::AcceptGovernance {});

    assert_eq!(Err(ContractError::Unauthorized {}), resp);
}

#[test]
fn accept_new_governance_contract() {
    let (mut deps, env) = init();
    instantiate_properly(&mut deps, env.clone(), vec![], None);

    let info = testing::mock_info(GOVERNANCE, &[]);
    execute(
        deps.as_mut(),
        env.clone(),
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateGovernanceContract {
                addr: "new_governance".to_owned(),
                seconds_to_wait_for_accept_gov_tx: 10,
            },
        },
    )
    .unwrap();

    let info = testing::mock_info("new_governance", &[]);
    execute(deps.as_mut(), env, info, ExecuteMsg::AcceptGovernance {}).unwrap();

    let config = CONFIG.load(deps.as_ref().storage).unwrap();
    assert_eq!("new_governance".to_owned(), config.governance.to_string());
    assert!(GOVERNANCE_UPDATE.load(deps.as_ref().storage).is_err())
}

#[test]
fn query_config() {
    let (mut deps, env) = init();
    let ust_pair = psi_ust_pair();
    let pair1 = random_psi_pair("1");
    let pair2 = random_psi_pair("2");
    instantiate_properly(
        &mut deps,
        env.clone(),
        vec![ust_pair.clone(), pair1.clone(), pair2.clone()],
        None,
    );

    let resp = from_binary(&query(deps.as_ref(), env, QueryMsg::Config {}).unwrap());

    assert_eq!(
        Ok(ConfigResponse {
            owner: CREATOR.to_owned(),
            governance: GOVERNANCE.to_owned(),
            psi_token: PSI_TOKEN.to_owned(),
            vesting: VESTING.to_owned(),
            vesting_period: VESTING_PERIOD,
            pairs: vec![
                pair1.contract_addr.to_string(),
                pair2.contract_addr.to_string(),
                ust_pair.contract_addr.to_string(),
            ],
            community_pool: COMMUNITY_POOL.to_owned(),
            autostake_lp_tokens: true,
            astro_generator: ASTRO_GENERATOR.to_owned(),
            astro_token: ASTRO_TOKEN.to_owned(),
            utility_token: Some(UTILITY_TOKEN.to_owned()),
            bond_cost_in_utility_tokens: bond_cost(),
        }),
        resp,
    );
}
