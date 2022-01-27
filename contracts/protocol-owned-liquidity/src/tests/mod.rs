use astroport::asset::{Asset, AssetInfo};
use cosmwasm_std::{
    coin, coins, from_binary, Addr, ContractResult, CosmosMsg, Decimal, Reply, Response, StdError,
    SubMsg, SubMsgExecutionResponse, Uint128, WasmMsg,
};
use cosmwasm_std::{testing, to_binary};
use cw0::{Expiration, PaymentError};
use cw20::Cw20ReceiveMsg;
use services::pol::{
    BuySimulationResponse, ConfigResponse, ExecuteMsg, GovernanceMsg, InstantiateMsg, QueryMsg,
};
use services::vesting::VestingSchedule;
use std::str::FromStr;

mod mock_querier;
mod sdk;

use crate::contract::{execute, instantiate, query, reply, BUY_REPLY_ID, CLAIM_REWARDS_REPLY_ID};
use crate::error::ContractError;
use crate::state::{excluded_psi, pairs, Config, State, CONFIG, GOVERNANCE_UPDATE, STATE};
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
            bond_control_var: bcv(),
            excluded_psi: vec![
                GOVERNANCE.to_owned(),
                VESTING.to_owned(),
                GOVERNANCE.to_owned(),
            ],
            max_bonds_amount: max_bonds_amount(),
            community_pool: COMMUNITY_POOL.to_owned(),
            autostake_lp_tokens: true,
            astro_generator: ASTRO_GENERATOR.to_owned(),
            astro_token: ASTRO_TOKEN.to_owned(),
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
            bond_control_var: bcv(),
            max_bonds_amount: max_bonds_amount(),
            community_pool: Addr::unchecked(COMMUNITY_POOL),
            autostake_lp_tokens: true,
            astro_generator: Addr::unchecked(ASTRO_GENERATOR),
            astro_token: Addr::unchecked(ASTRO_TOKEN),
        },
        config
    );
    assert_eq!(vec![pair], pairs(&deps.storage));
    assert_eq!(
        vec![GOVERNANCE.to_owned(), VESTING.to_owned()],
        excluded_psi(&deps.storage),
    );
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
            bond_control_var: bcv(),
            excluded_psi: vec![GOVERNANCE.to_owned()],
            max_bonds_amount: max_bonds_amount(),
            community_pool: COMMUNITY_POOL.to_owned(),
            autostake_lp_tokens: true,
            astro_generator: ASTRO_GENERATOR.to_owned(),
            astro_token: ASTRO_TOKEN.to_owned(),
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
    let pair = psi_ust_pair();
    instantiate_with_pairs(&mut deps, env.clone(), vec![pair]);

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
fn tiny_buy_with_cw20_tokens_fails() {
    let (mut deps, env) = init();
    let pair = psi_cw20token_pair();
    instantiate_with_pairs(&mut deps, env.clone(), vec![pair.clone()]);
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
fn buy_with_cw20_tokens_fails_when_no_psi_ust_pair() {
    let (mut deps, env) = init();
    let pair = psi_cw20token_pair();
    instantiate_with_pairs(&mut deps, env.clone(), vec![pair.clone()]);
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (pair.contract_addr.as_str(), &Uint128::new(100_000_000_000)),
                (
                    env.contract.address.as_str(),
                    &Uint128::new(90_000_000_000_000_000),
                ),
            ],
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
            amount: Uint128::new(50_000),
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
                amount: Uint128::new(50_000),
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
fn buy_too_much_with_cw20_tokens_fails() {
    let (mut deps, env) = init();
    let cw_pair = psi_cw20token_pair();
    let ust_pair = psi_ust_pair();
    deps.querier.set_ust_balances(&[(
        ust_pair.contract_addr.as_str(),
        &Uint128::new(400_000_000_000),
    )]);
    deps.querier
        .set_total_supply(Uint128::new(10_000_000_000_000_000));
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (
                    env.contract.address.as_str(),
                    &Uint128::new(90_000_000_000_000_000),
                ),
                (
                    ust_pair.contract_addr.as_str(),
                    &Uint128::new(10_000_000_000_000),
                ),
                (
                    cw_pair.contract_addr.as_str(),
                    &Uint128::new(30_000_000_000_000),
                ),
                (VESTING, &Uint128::new(3_000_000_000_000_000)),
                (GOVERNANCE, &Uint128::new(1_000_000_000_000_000)),
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
    instantiate_with_pairs(
        &mut deps,
        env.clone(),
        vec![cw_pair.clone(), ust_pair.clone()],
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                bonds_issued: Uint128::new(4_000_000_000_000_000),
            },
        )
        .unwrap();

    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(2_000_000_000_000_000),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: min_bonds_amount(),
            })
            .unwrap(),
        }),
    );

    assert_eq!(
        Err(ContractError::BondsAmountTooLarge {
            value: Uint128::new(1_685_393_258_426_966),
            maximum: Uint128::new(1_000_000_000_000)
        }),
        resp
    );
}

#[test]
fn buy_with_cw20_tokens_fails_when_get_less_than_expect() {
    let (mut deps, env) = init();
    let cw20_pair = psi_cw20token_pair();
    let ust_pair = psi_ust_pair();
    deps.querier.set_ust_balances(&[(
        ust_pair.contract_addr.as_str(),
        &Uint128::new(400_000_000_000),
    )]);
    deps.querier
        .set_total_supply(Uint128::new(10_000_000_000_000_000));
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (
                    env.contract.address.as_str(),
                    &Uint128::new(500_000_000_000_000),
                ),
                (
                    ust_pair.contract_addr.as_str(),
                    &Uint128::new(10_000_000_000_000),
                ),
                (
                    cw20_pair.contract_addr.as_str(),
                    &Uint128::new(30_000_000_000_000),
                ),
                (VESTING, &Uint128::new(3_000_000_000_000_000)),
                (GOVERNANCE, &Uint128::new(1_000_000_000_000_000)),
            ],
        ),
        (
            CW20_TOKEN,
            &[(
                cw20_pair.contract_addr.as_str(),
                &Uint128::new(1_000_000_000_000),
            )],
        ),
    ]);
    instantiate_with_pairs(
        &mut deps,
        env.clone(),
        vec![cw20_pair.clone(), ust_pair.clone()],
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                bonds_issued: Uint128::new(4_000_000_000_000_000),
            },
        )
        .unwrap();

    let info = testing::mock_info(CW20_TOKEN, &[]);
    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Receive(Cw20ReceiveMsg {
            sender: INVESTOR.to_owned(),
            amount: Uint128::new(2_000_000_000),
            msg: to_binary(&ExecuteMsg::Buy {
                min_amount: Uint128::new(1_000_000_000_000),
            })
            .unwrap(),
        }),
    );

    assert_eq!(
        Err(ContractError::BondsAmountTooSmall {
            value: Uint128::new(1_685_393_258),
            minimum: Uint128::new(1_000_000_000_000)
        }),
        resp
    );
}

#[test]
fn buy_fails_when_not_enough_psi_tokens_to_provide_liquidity() {
    let (mut deps, env) = init();
    let cw_pair = psi_cw20token_pair();
    let ust_pair = psi_ust_pair();
    deps.querier.set_ust_balances(&[(
        ust_pair.contract_addr.as_str(),
        &Uint128::new(400_000_000_000),
    )]);
    deps.querier
        .set_total_supply(Uint128::new(10_000_000_000_000_000));
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (env.contract.address.as_str(), &Uint128::new(500_000_000)),
                (
                    ust_pair.contract_addr.as_str(),
                    &Uint128::new(10_000_000_000_000),
                ),
                (
                    cw_pair.contract_addr.as_str(),
                    &Uint128::new(30_000_000_000_000),
                ),
                (VESTING, &Uint128::new(3_000_000_000_000_000)),
                (GOVERNANCE, &Uint128::new(1_000_000_000_000_000)),
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
    instantiate_with_pairs(
        &mut deps,
        env.clone(),
        vec![cw_pair.clone(), ust_pair.clone()],
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                bonds_issued: Uint128::new(4_000_000_000_000_000),
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
        Err(ContractError::NotEnoughPsiTokens {
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
fn buy_with_cw20_tokens() {
    let (mut deps, env) = init();
    let cw_pair = psi_cw20token_pair();
    let ust_pair = psi_ust_pair();
    deps.querier.set_ust_balances(&[(
        ust_pair.contract_addr.as_str(),
        &Uint128::new(400_000_000_000),
    )]);
    deps.querier
        .set_total_supply(Uint128::new(10_000_000_000_000_000));
    deps.querier.set_token_balances(&[
        (
            PSI_TOKEN,
            &[
                (
                    env.contract.address.as_str(),
                    &Uint128::new(500_000_000_000_000),
                ),
                (
                    ust_pair.contract_addr.as_str(),
                    &Uint128::new(10_000_000_000_000),
                ),
                (
                    cw_pair.contract_addr.as_str(),
                    &Uint128::new(30_000_000_000_000),
                ),
                (VESTING, &Uint128::new(3_000_000_000_000_000)),
                (GOVERNANCE, &Uint128::new(1_000_000_000_000_000)),
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
    instantiate_with_pairs(
        &mut deps,
        env.clone(),
        vec![cw_pair.clone(), ust_pair.clone()],
    );
    STATE
        .save(
            &mut deps.storage,
            &State {
                bonds_issued: Uint128::new(4_000_000_000_000_000),
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
        Ok(Response::new()
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: VESTING.to_string(),
                msg: to_binary(&services::vesting::ExecuteMsg::AddVestingSchedule {
                    addr: INVESTOR.to_string(),
                    schedule: VestingSchedule {
                        start_time: env.block.time.seconds(),
                        end_time: env.block.time.plus_seconds(VESTING_PERIOD).seconds(),
                        cliff_end_time: env.block.time.seconds(),
                        amount: Uint128::new(1685393258),
                    }
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: PSI_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::IncreaseAllowance {
                    spender: cw_pair.contract_addr.to_string(),
                    amount: Uint128::new(60_000_000_000),
                    expires: Some(Expiration::AtHeight(env.block.height + 1)),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: CW20_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::IncreaseAllowance {
                    spender: cw_pair.contract_addr.to_string(),
                    amount: Uint128::new(2_000_000_000),
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
                                amount: Uint128::new(60_000_000_000),
                            },
                            Asset {
                                info: AssetInfo::Token {
                                    contract_addr: Addr::unchecked(CW20_TOKEN),
                                },
                                amount: Uint128::new(2_000_000_000),
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
            ))),
        resp
    );
    assert_eq!(
        State {
            bonds_issued: Uint128::new(4_000_000_000_000_000) + Uint128::new(1685393258),
        },
        STATE.load(&deps.storage).unwrap(),
    );
    assert_eq!(
        BuySimulationResponse {
            bonds: Uint128::new(1685393258),
            bond_price: Decimal::from_str("1.424").unwrap(),
            psi_price: Decimal::from_str("0.04").unwrap(),
        },
        from_binary(&query_resp.unwrap()).unwrap(),
    );

    deps.querier
        .token_balances
        .get_mut(PSI_TOKEN)
        .unwrap()
        .insert(
            env.contract.address.to_string(),
            Uint128::new(499_940_030_000_000),
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
                    amount: Uint128::new(30_000_000),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_attribute("action", "buy")
            .add_attribute("asset", CW20_TOKEN)
            .add_attribute("psi_price", "0.04")
            .add_attribute("bond_price", "1.424")
            .add_attribute("bonds_issued", "1685393258")
            .add_attribute("pair_with_provided_liquidity", cw_pair.contract_addr)
            .add_attribute("provided_liquidity_in_psi", "60000000000")
            .add_attribute("provided_liquidity_in_asset", "2000000000")
            .add_attribute("astro_tokens_claimed", "10000000")
            .add_attribute("psi_tokens_claimed", "30000000"),
        reply_resp
    );
}

#[test]
fn buy_with_no_coins_fails() {
    let (mut deps, env) = init();
    let ust_pair = psi_ust_pair();
    instantiate_with_pairs(&mut deps, env.clone(), vec![ust_pair]);

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
    instantiate_with_pairs(&mut deps, env.clone(), vec![ust_pair]);

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
fn buy_with_non_ust_fails() {
    let (mut deps, env) = init();
    let ust_pair = psi_ust_pair();
    instantiate_with_pairs(&mut deps, env.clone(), vec![ust_pair]);

    let info = testing::mock_info(INVESTOR, &coins(1, "blablabla"));
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
                    denom: "blabla".to_owned(),
                },
                amount: Uint128::new(10_000_000),
            },
        },
    );

    assert_eq!(
        Err(ContractError::Payment(PaymentError::MissingDenom(
            UST.to_owned()
        ))),
        resp
    );
    assert_eq!(
        Err(StdError::generic_err(format!(
            "invalid denom: only {} allowed",
            UST
        ),)),
        query_resp
    );
}

#[test]
fn buy_with_zero_coins_fails() {
    let (mut deps, env) = init();
    let ust_pair = psi_ust_pair();
    instantiate_with_pairs(&mut deps, env.clone(), vec![ust_pair]);

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
fn buy_with_coins_fails_when_no_psi_ust_pair() {
    let (mut deps, env) = init();
    let cw_pair = psi_cw20token_pair();
    instantiate_with_pairs(&mut deps, env.clone(), vec![cw_pair]);

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
    instantiate_with_pairs(&mut deps, env.clone(), vec![pair.clone()]);
    deps.querier
        .set_ust_balances(&[(pair.contract_addr.as_str(), &Uint128::new(400_000_000_000))]);
    deps.querier
        .set_total_supply(Uint128::new(10_000_000_000_000_000));
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
fn buy_with_coins_too_much_fails() {
    let (mut deps, env) = init();
    let pair = psi_ust_pair();
    deps.querier
        .set_ust_balances(&[(pair.contract_addr.as_str(), &Uint128::new(400_000_000_000))]);
    deps.querier
        .set_total_supply(Uint128::new(10_000_000_000_000_000));
    deps.querier.set_token_balances(&[(
        PSI_TOKEN,
        &[
            (
                env.contract.address.as_str(),
                &Uint128::new(90_000_000_000_000_000),
            ),
            (
                pair.contract_addr.as_str(),
                &Uint128::new(10_000_000_000_000),
            ),
            (VESTING, &Uint128::new(3_000_000_000_000_000)),
            (GOVERNANCE, &Uint128::new(1_000_000_000_000_000)),
        ],
    )]);
    instantiate_with_pairs(&mut deps, env.clone(), vec![pair.clone()]);
    STATE
        .save(
            &mut deps.storage,
            &State {
                bonds_issued: Uint128::new(4_000_000_000_000_000),
            },
        )
        .unwrap();

    let info = testing::mock_info(INVESTOR, &coins(2_000_000_000_000_000, UST));
    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Buy {
            min_amount: min_bonds_amount(),
        },
    );

    assert_eq!(
        Err(ContractError::BondsAmountTooLarge {
            value: Uint128::new(1_404_494_382_022_464),
            maximum: Uint128::new(1_000_000_000_000),
        }),
        resp
    );
}

#[test]
fn buy_with_coins_fails_when_get_less_than_expect() {
    let (mut deps, env) = init();
    let pair = psi_ust_pair();
    deps.querier
        .set_ust_balances(&[(pair.contract_addr.as_str(), &Uint128::new(400_000_000_000))]);
    deps.querier
        .set_total_supply(Uint128::new(10_000_000_000_000_000));
    deps.querier.set_token_balances(&[(
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
            (VESTING, &Uint128::new(3_000_000_000_000_000)),
            (GOVERNANCE, &Uint128::new(1_000_000_000_000_000)),
        ],
    )]);
    instantiate_with_pairs(&mut deps, env.clone(), vec![pair.clone()]);
    STATE
        .save(
            &mut deps.storage,
            &State {
                bonds_issued: Uint128::new(4_000_000_000_000_000),
            },
        )
        .unwrap();

    let info = testing::mock_info(INVESTOR, &coins(2_000_000_000, UST));
    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Buy {
            min_amount: Uint128::new(1_500_000_000),
        },
    );

    assert_eq!(
        Err(ContractError::BondsAmountTooSmall {
            value: Uint128::new(1_404_494_375),
            minimum: Uint128::new(1_500_000_000),
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
    deps.querier
        .set_total_supply(Uint128::new(10_000_000_000_000_000));
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
                (VESTING, &Uint128::new(3_000_000_000_000_000)),
                (GOVERNANCE, &Uint128::new(1_000_000_000_000_000)),
            ],
        ),
        (
            ASTRO_TOKEN,
            &[(env.contract.address.as_str(), &Uint128::zero())],
        ),
    ]);
    instantiate_with_pairs(&mut deps, env.clone(), vec![pair.clone()]);
    STATE
        .save(
            &mut deps.storage,
            &State {
                bonds_issued: Uint128::new(4_000_000_000_000_000),
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
    assert_eq!(
        BuySimulationResponse {
            bonds: Uint128::new(1_404_494_375),
            bond_price: Decimal::from_str("1.424").unwrap(),
            psi_price: Decimal::from_str("0.04").unwrap(),
        },
        from_binary(&query_resp.unwrap()).unwrap(),
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
        Ok(Response::new()
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: VESTING.to_string(),
                msg: to_binary(&services::vesting::ExecuteMsg::AddVestingSchedule {
                    addr: INVESTOR.to_string(),
                    schedule: VestingSchedule {
                        start_time: env.block.time.seconds(),
                        end_time: env.block.time.plus_seconds(VESTING_PERIOD).seconds(),
                        cliff_end_time: env.block.time.seconds(),
                        amount: Uint128::new(1_404_494_375),
                    }
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_submessage(SubMsg::new(WasmMsg::Execute {
                contract_addr: PSI_TOKEN.to_owned(),
                msg: to_binary(&cw20::Cw20ExecuteMsg::IncreaseAllowance {
                    spender: pair.contract_addr.to_string(),
                    amount: Uint128::new(49_999_999_750),
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
                                amount: Uint128::new(49_999_999_750),
                            },
                            Asset {
                                info: AssetInfo::NativeToken {
                                    denom: UST.to_owned(),
                                },
                                amount: Uint128::new(1_999_999_990),
                            },
                        ],
                        slippage_tolerance: None,
                        receiver: None,
                        auto_stake: Some(true),
                    })
                    .unwrap(),
                    funds: coins(1_999_999_990, UST),
                },
                BUY_REPLY_ID,
            ))),
        resp
    );
    assert_eq!(
        State {
            bonds_issued: Uint128::new(4_000_000_000_000_000) + Uint128::new(1_404_494_375),
        },
        STATE.load(&deps.storage).unwrap(),
    );

    deps.querier
        .token_balances
        .get_mut(PSI_TOKEN)
        .unwrap()
        .insert(
            env.contract.address.to_string(),
            Uint128::new(499_950_030_000_000),
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
                    amount: Uint128::new(29_999_750),
                })
                .unwrap(),
                funds: vec![],
            }))
            .add_attribute("action", "buy")
            .add_attribute("asset", UST)
            .add_attribute("psi_price", "0.04")
            .add_attribute("bond_price", "1.424")
            .add_attribute("bonds_issued", "1404494375")
            .add_attribute("pair_with_provided_liquidity", pair.contract_addr)
            .add_attribute("provided_liquidity_in_psi", "49999999750")
            .add_attribute("provided_liquidity_in_asset", "1999999990")
            .add_attribute("astro_tokens_claimed", "10000000")
            .add_attribute("psi_tokens_claimed", "29999750")),
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
    deps.querier
        .set_total_supply(Uint128::new(10_000_000_000_000_000));
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
                (VESTING, &Uint128::new(3_000_000_000_000_000)),
                (GOVERNANCE, &Uint128::new(1_000_000_000_000_000)),
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
    instantiate_with_pairs(
        &mut deps,
        env.clone(),
        vec![ust_pair.clone(), cw_pair.clone()],
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
fn do_not_accept_any_governance_msg_from_non_governance_contract() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![]);
    let info = testing::mock_info("nongovernance", &[]);

    let resp_update_config = execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateConfig {
                psi_token: None,
                vesting: None,
                vesting_period: None,
                bond_control_var: None,
                max_bonds_amount: None,
                community_pool: None,
                autostake_lp_tokens: None,
                astro_generator: None,
                astro_token: None,
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
    let resp_update_excluded_psi = execute(
        deps.as_mut(),
        env.clone(),
        info.clone(),
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateExcludedPsi {
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

    assert_eq!(Err(ContractError::Unauthorized {}), resp_update_config);
    assert_eq!(Err(ContractError::Unauthorized {}), resp_update_pairs);
    assert_eq!(
        Err(ContractError::Unauthorized {}),
        resp_update_excluded_psi
    );
    assert_eq!(
        Err(ContractError::Unauthorized {}),
        resp_update_governance_contract
    );
}

#[test]
fn update_config() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![]);
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
                bond_control_var: Some(Decimal::from_str("3").unwrap()),
                max_bonds_amount: Some(Decimal::from_str("0.1").unwrap()),
                community_pool: Some("new_community_pool".to_owned()),
                autostake_lp_tokens: Some(false),
                astro_generator: Some("new_astro_generator".to_owned()),
                astro_token: Some("new_astro_token".to_owned()),
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
            bond_control_var: Decimal::from_str("3").unwrap(),
            max_bonds_amount: Decimal::from_str("0.1").unwrap(),
            community_pool: Addr::unchecked("new_community_pool"),
            autostake_lp_tokens: false,
            astro_generator: Addr::unchecked("new_astro_generator"),
            astro_token: Addr::unchecked("new_astro_token"),
        },
        new_config
    );
}

#[test]
fn update_pairs() {
    let (mut deps, env) = init();
    let pair0 = random_psi_pair("0");
    instantiate_with_pairs(&mut deps, env.clone(), vec![pair0.clone()]);
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
fn update_excluded_psi() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![]);
    let info = testing::mock_info(GOVERNANCE, &[]);

    let resp = execute(
        deps.as_mut(),
        env,
        info,
        ExecuteMsg::Governance {
            msg: GovernanceMsg::UpdateExcludedPsi {
                add: vec!["abc".to_owned(), "def".to_owned()],
                remove: vec![GOVERNANCE.to_owned()],
            },
        },
    );

    let mut expected = vec![VESTING.to_owned(), "abc".to_owned(), "def".to_owned()];
    expected.sort();
    assert_eq!(
        Ok(Response::new().add_attribute("action", "update_excluded_psi")),
        resp
    );
    assert_eq!(expected, excluded_psi(&deps.storage));
}

#[test]
fn too_late_to_accept_governance_contract() {
    let (mut deps, mut env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![]);

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
    instantiate_with_pairs(&mut deps, env.clone(), vec![]);

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
    instantiate_with_pairs(&mut deps, env.clone(), vec![]);

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
    instantiate_with_pairs(
        &mut deps,
        env.clone(),
        vec![ust_pair.clone(), pair1.clone(), pair2.clone()],
    );

    let resp = from_binary(&query(deps.as_ref(), env, QueryMsg::Config {}).unwrap());

    assert_eq!(
        Ok(ConfigResponse {
            owner: CREATOR.to_owned(),
            governance: GOVERNANCE.to_string(),
            psi_token: PSI_TOKEN.to_string(),
            vesting: VESTING.to_string(),
            vesting_period: VESTING_PERIOD,
            bond_control_var: bcv(),
            max_bonds_amount: max_bonds_amount(),
            excluded_psi: vec![GOVERNANCE.to_owned(), VESTING.to_owned()],
            pairs: vec![
                pair1.contract_addr.to_string(),
                pair2.contract_addr.to_string(),
                ust_pair.contract_addr.to_string(),
            ],
            community_pool: COMMUNITY_POOL.to_string(),
            autostake_lp_tokens: true,
            astro_generator: ASTRO_GENERATOR.to_string(),
            astro_token: ASTRO_TOKEN.to_string(),
        }),
        resp,
    );
}

#[test]
fn query_version() {
    let (mut deps, env) = init();
    instantiate_with_pairs(&mut deps, env.clone(), vec![]);

    let resp = from_binary(&query(deps.as_ref(), env, QueryMsg::Version {}).unwrap());

    assert_eq!(Ok(env!("CARGO_PKG_VERSION").to_owned()), resp,);
}
