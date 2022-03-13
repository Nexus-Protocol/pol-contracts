use astroport::asset::{Asset, AssetInfo, PairInfo};
use cosmwasm_bignumber::{Decimal256, Uint256};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coins, from_binary, to_binary, Addr, Api, Attribute, Binary, Coin, CosmosMsg, Decimal, Deps,
    DepsMut, Env, Fraction, MessageInfo, QuerierWrapper, QueryRequest, Reply, ReplyOn, Response,
    StdError, StdResult, SubMsg, Uint128, WasmMsg, WasmQuery,
};
use cosmwasm_storage::to_length_prefixed;
use cw0::{nonpayable, one_coin, Expiration};
use cw2::{get_contract_version, set_contract_version};
use cw20::{AllowanceResponse, Cw20ReceiveMsg};
use nexus_pol_services::pol::{
    BuySimulationResponse, ConfigResponse, Cw20HookMsg, ExecuteMsg, GovernanceMsg, InstantiateMsg,
    MigrateMsg, Phase, PhaseResponse, QueryMsg,
};
use nexus_pol_services::vesting::VestingSchedule;
use terra_cosmwasm::TerraQuerier;

use crate::error::ContractError;
use crate::state::{
    pair, pairs, phase, remove_pair, save_pair, save_state, Config, GovernanceUpdateState,
    ReplyContext, TokenBalance, CONFIG, GOVERNANCE_UPDATE, PHASE, REPLY_CONTEXT, STATE,
};

const CONTRACT_NAME: &str = "nexus.protocol:protocol-owned-liquidity";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const BUY_REPLY_ID: u64 = 1;
pub const CLAIM_REWARDS_REPLY_ID: u64 = 2;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;

    for pi in &get_pairs_info(deps.as_ref(), msg.pairs)? {
        save_pair(deps.storage, pi)?;
    }

    let config = Config {
        owner: info.sender,
        governance: addr_validate_to_lower(deps.api, &msg.governance)?,
        psi_token: addr_validate_to_lower(deps.api, &msg.psi_token)?,
        vesting: addr_validate_to_lower(deps.api, &msg.vesting)?,
        vesting_period: msg.vesting_period,
        community_pool: addr_validate_to_lower(deps.api, &msg.community_pool)?,
        autostake_lp_tokens: msg.autostake_lp_tokens,
        astro_generator: addr_validate_to_lower(deps.api, &msg.astro_generator)?,
        astro_token: addr_validate_to_lower(deps.api, &msg.astro_token)?,
        utility_token: msg
            .utility_token
            .map(|addr| addr_validate_to_lower(deps.api, &addr))
            .transpose()?,
        bond_cost_in_utility_tokens: msg.bond_cost_in_utility_tokens,
    };
    CONFIG.save(deps.storage, &config)?;

    save_state(deps.storage, Uint128::zero())?;

    if let Some(phase) = msg.initial_phase {
        phase_validate(&phase, env.block.time.seconds())?;
        PHASE.save(deps.storage, &phase.into())?;
    }

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

fn addr_validate_to_lower(api: &dyn Api, addr: &str) -> Result<Addr, ContractError> {
    check_lowercase_addr(addr)?;
    Ok(api.addr_validate(addr)?)
}

fn check_lowercase_addr(addr: &str) -> Result<(), ContractError> {
    if addr.to_lowercase() != addr {
        return Err(ContractError::WrongCaseAddr {
            addr: addr.to_owned(),
        });
    }
    Ok(())
}

fn get_pairs_info(deps: Deps, addrs: Vec<String>) -> Result<Vec<PairInfo>, ContractError> {
    addrs
        .into_iter()
        .map(|addr| {
            addr_validate_to_lower(deps.api, &addr)?;
            deps.querier
                .query_wasm_smart(addr.clone(), &astroport::pair::QueryMsg::Pair {})
                .map_err(|e| ContractError::InvalidPair { addr, source: e })
        })
        .collect()
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Receive(msg) => receive_cw20(deps, env, info, msg),
        ExecuteMsg::Buy { min_amount } => execute_buy(deps, env, info, min_amount),
        ExecuteMsg::ClaimRewards {} => execute_claim_rewards(deps, env, info),
        ExecuteMsg::AcceptGovernance {} => execute_accept_governance(deps, env, info),
        ExecuteMsg::Governance { msg } => {
            nonpayable(&info)?;

            let config = CONFIG.load(deps.storage)?;

            if info.sender != config.governance {
                return Err(ContractError::Unauthorized {});
            }

            match msg {
                GovernanceMsg::Phase { phase } => execute_phase(deps, env, phase),
                GovernanceMsg::UpdateConfig {
                    psi_token,
                    vesting,
                    vesting_period,
                    community_pool,
                    autostake_lp_tokens,
                    astro_generator,
                    astro_token,
                    utility_token,
                    bond_cost_in_utility_tokens,
                } => update_config(
                    deps,
                    config,
                    psi_token,
                    vesting,
                    vesting_period,
                    community_pool,
                    autostake_lp_tokens,
                    astro_generator,
                    astro_token,
                    utility_token,
                    bond_cost_in_utility_tokens,
                ),
                GovernanceMsg::UpdatePairs { add, remove } => update_pairs(deps, add, remove),
                GovernanceMsg::UpdateGovernanceContract {
                    addr,
                    seconds_to_wait_for_accept_gov_tx,
                } => update_governance_addr(deps, env, addr, seconds_to_wait_for_accept_gov_tx),
            }
        }
    }
}

fn phase_validate(phase: &Phase, cur_time: u64) -> Result<(), ContractError> {
    if phase.psi_amount_start > phase.psi_amount_total
        || phase.max_discount >= Decimal::one()
        || phase.start_time >= phase.end_time
        || cur_time >= phase.end_time
    {
        return Err(ContractError::InvalidPhase {});
    }
    Ok(())
}

fn execute_phase(deps: DepsMut, env: Env, phase: Phase) -> Result<Response, ContractError> {
    phase_validate(&phase, env.block.time.seconds())?;
    PHASE.save(deps.storage, &phase.into())?;

    save_state(deps.storage, Uint128::zero())?;

    Ok(Response::new().add_attribute("action", "phase"))
}

fn psi_price(deps: Deps, psi_token: Addr, denom: String) -> Result<(Addr, Decimal), ContractError> {
    let PairWithBalances {
        pair_info,
        balances: [psi_balance, ust_balance],
    } = get_pair_and_balances(deps, &[asset(psi_token), native_asset(denom)])?;
    let psi_price = Decimal::from_ratio(ust_balance, psi_balance);
    Ok((pair_info.contract_addr, psi_price))
}

fn utility_tokens_available(
    deps: Deps,
    env: Env,
    utility_token: Addr,
    owner: String,
) -> Result<Uint128, ContractError> {
    let AllowanceResponse {
        allowance: utility_tokens_available,
        expires: expiration,
    } = deps.querier.query_wasm_smart(
        utility_token,
        &cw20::Cw20QueryMsg::Allowance {
            owner,
            spender: env.contract.address.to_string(),
        },
    )?;
    Ok(if expiration.is_expired(&env.block) {
        Uint128::zero()
    } else {
        utility_tokens_available
    })
}

fn check_utility_tokens(available: Uint128, required: Uint128) -> Result<(), ContractError> {
    if available < required {
        return Err(ContractError::NotEnoughTokens {
            name: "utility".to_owned(),
            value: available,
            required,
        });
    }
    Ok(())
}

fn burn_from(owner: String, token: String, amount: Uint128) -> StdResult<CosmosMsg> {
    Ok(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: token,
        msg: to_binary(&cw20::Cw20ExecuteMsg::BurnFrom { owner, amount })?,
        funds: vec![],
    }))
}

fn burn_utility_tokens(
    deps: Deps,
    env: Env,
    utility_token: Addr,
    owner: String,
    amount: Uint128,
    response: Response,
) -> Result<Response, ContractError> {
    let utility_tokens_available =
        utility_tokens_available(deps, env, utility_token.clone(), owner.clone())?;
    check_utility_tokens(utility_tokens_available, amount)?;
    Ok(response
        .add_attribute("utility_tokens_burned", amount)
        .add_message(burn_from(owner, utility_token.to_string(), amount)?))
}

fn receive_cw20(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;

    let config = CONFIG.load(deps.storage)?;
    let state = STATE.load(deps.storage)?;
    let phase = phase(deps.storage, env.clone())?;

    let cw20_token = info.sender;

    match from_binary(&cw20_msg.msg) {
        Ok(Cw20HookMsg::Buy { min_amount }) => {
            let mut response = Response::new();

            let real_sender = cw20_msg.sender;

            let PairWithBalances {
                pair_info: cw20_pair_info,
                balances: [psi_balance_of_cw20_pair, token_balance_of_cw20_pair],
            } = get_pair_and_balances(
                deps.as_ref(),
                &[asset(config.psi_token.clone()), asset(cw20_token.clone())],
            )?;

            let asset_cost_in_psi =
                cw20_msg.amount * psi_balance_of_cw20_pair / token_balance_of_cw20_pair;
            if asset_cost_in_psi.is_zero() {
                return Err(ContractError::PaymentTooSmall {});
            }
            let mut psi_token_balance =
                query_token_balance(deps.as_ref(), &config.psi_token, &env.contract.address);
            check_psi_balance(psi_token_balance, asset_cost_in_psi)?;
            psi_token_balance -= asset_cost_in_psi;

            let BondsCalculationResult {
                discount,
                bonds_amount,
            } = calculate_bonds(
                asset_cost_in_psi,
                phase.psi_amount_total,
                phase.psi_amount_start,
                state.psi_amount_sold,
                phase.max_discount,
                phase.start_time,
                env.block.time.seconds(),
                phase.end_time,
                min_amount,
            )?;
            if let Some(utility_token) = config.utility_token {
                response = burn_utility_tokens(
                    deps.as_ref(),
                    env.clone(),
                    utility_token,
                    real_sender.clone(),
                    config.bond_cost_in_utility_tokens * bonds_amount,
                    response,
                )?;
            }
            check_psi_balance(psi_token_balance, bonds_amount)?;
            psi_token_balance -= bonds_amount;

            response = response
                .add_attribute("action", "buy")
                .add_attribute("asset", cw20_token.clone())
                .add_attribute("discount", discount.to_string())
                .add_attribute("bonds_issued", bonds_amount)
                .add_attribute(
                    "pair_with_provided_liquidity",
                    cw20_pair_info.contract_addr.clone(),
                )
                .add_attribute("provided_liquidity_in_psi", asset_cost_in_psi)
                .add_attribute("provided_liquidity_in_asset", cw20_msg.amount);

            save_state(deps.storage, state.psi_amount_sold + bonds_amount)?;

            save_reply_context(
                deps,
                &env,
                config.astro_token,
                config.psi_token.clone(),
                psi_token_balance,
                Some(&cw20_token),
                Some(cw20_msg.amount),
                response.attributes.clone(),
            )?;

            Ok(response
                .add_submessages(transfer_and_linear_vesting(
                    &env,
                    &config.vesting,
                    config.vesting_period,
                    &config.psi_token,
                    bonds_amount,
                    real_sender,
                )?)
                .add_submessages(increase_allowances_and_provide_liquidity(
                    &env,
                    &cw20_pair_info.contract_addr,
                    &config.psi_token,
                    asset(cw20_token),
                    asset_cost_in_psi,
                    cw20_msg.amount,
                    config.autostake_lp_tokens,
                )?))
        }
        Err(err) => Err(ContractError::Std(err)),
    }
}

fn asset(addr: Addr) -> AssetInfo {
    AssetInfo::Token {
        contract_addr: addr,
    }
}

fn native_asset(denom: String) -> AssetInfo {
    AssetInfo::NativeToken { denom }
}

fn query_token_balance(deps: Deps, contract_addr: &Addr, account_addr: &Addr) -> Uint128 {
    if let Ok(balance) = query_token_balance_legacy(deps, contract_addr, account_addr) {
        return balance;
    }

    if let Ok(balance) = query_token_balance_new(deps, contract_addr, account_addr) {
        return balance;
    }

    Uint128::zero()
}

fn query_token_balance_new(
    deps: Deps,
    contract_addr: &Addr,
    account_addr: &Addr,
) -> StdResult<Uint128> {
    // load balance form the cw20 token contract version 0.6+
    deps.querier.query(&QueryRequest::Wasm(WasmQuery::Raw {
        contract_addr: contract_addr.to_string(),
        key: Binary::from(concat(
            &to_length_prefixed(b"balance"),
            account_addr.as_bytes(),
        )),
    }))
}

fn query_token_balance_legacy(
    deps: Deps,
    contract_addr: &Addr,
    account_addr: &Addr,
) -> StdResult<Uint128> {
    // load balance form the cw20 token contract version 0.2.x
    deps.querier.query(&QueryRequest::Wasm(WasmQuery::Raw {
        contract_addr: contract_addr.to_string(),
        key: Binary::from(concat(
            &to_length_prefixed(b"balance"),
            (deps.api.addr_canonicalize(account_addr.as_str())?).as_slice(),
        )),
    }))
}

#[inline]
fn concat(namespace: &[u8], key: &[u8]) -> Vec<u8> {
    let mut k = namespace.to_vec();
    k.extend_from_slice(key);
    k
}

fn increase_allowance(
    env: &Env,
    token: &Addr,
    spender: &Addr,
    amount: Uint128,
) -> StdResult<SubMsg> {
    Ok(SubMsg::new(WasmMsg::Execute {
        contract_addr: token.to_string(),
        msg: to_binary(&cw20::Cw20ExecuteMsg::IncreaseAllowance {
            spender: spender.to_string(),
            amount,
            expires: Some(Expiration::AtHeight(env.block.height + 1)),
        })?,
        funds: vec![],
    }))
}

fn provide_liquidity(
    pair: &Addr,
    token: Addr,
    token_amount: Uint128,
    asset_info: AssetInfo,
    asset_amount: Uint128,
    auto_stake: bool,
) -> StdResult<SubMsg> {
    Ok(SubMsg::reply_on_success(
        WasmMsg::Execute {
            contract_addr: pair.to_string(),
            msg: to_binary(&astroport::pair::ExecuteMsg::ProvideLiquidity {
                assets: [
                    Asset {
                        info: asset(token),
                        amount: token_amount,
                    },
                    Asset {
                        info: asset_info.clone(),
                        amount: asset_amount,
                    },
                ],
                slippage_tolerance: None,
                receiver: None,
                auto_stake: Some(auto_stake),
            })?,
            funds: if let AssetInfo::NativeToken { denom } = asset_info {
                coins(asset_amount.u128(), denom)
            } else {
                vec![]
            },
        },
        BUY_REPLY_ID,
    ))
}

fn increase_allowances_and_provide_liquidity(
    env: &Env,
    pair: &Addr,
    token: &Addr,
    asset_info: AssetInfo,
    token_amount: Uint128,
    asset_amount: Uint128,
    auto_stake: bool,
) -> StdResult<Vec<SubMsg>> {
    let mut result = vec![increase_allowance(env, token, pair, token_amount)?];

    if let AssetInfo::Token { ref contract_addr } = asset_info {
        result.push(increase_allowance(env, contract_addr, pair, asset_amount)?);
    }

    result.push(provide_liquidity(
        pair,
        token.clone(),
        token_amount,
        asset_info,
        asset_amount,
        auto_stake,
    )?);

    Ok(result)
}

fn transfer_and_linear_vesting(
    env: &Env,
    vesting: &Addr,
    period: u64,
    psi_token: &Addr,
    amount: Uint128,
    recipient: String,
) -> StdResult<Vec<SubMsg>> {
    let cur_time = env.block.time;
    let vesting_schedule = VestingSchedule {
        start_time: cur_time.seconds(),
        end_time: cur_time.plus_seconds(period).seconds(),
        cliff_end_time: cur_time.seconds(),
        amount,
    };

    Ok(vec![
        SubMsg::new(WasmMsg::Execute {
            contract_addr: psi_token.to_string(),
            msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                recipient: vesting.to_string(),
                amount,
            })?,
            funds: vec![],
        }),
        SubMsg::new(WasmMsg::Execute {
            contract_addr: vesting.to_string(),
            msg: to_binary(
                &nexus_pol_services::vesting::ExecuteMsg::AddVestingSchedule {
                    addr: recipient,
                    schedule: vesting_schedule,
                },
            )?,
            funds: vec![],
        }),
    ])
}

fn ceiled_mul_uint_decimal(a: Uint256, b: Decimal256) -> Uint256 {
    let decimal_output = Decimal256::from_uint256(a) * b;
    let floored_output = Uint256::from(decimal_output.0 / Decimal256::DECIMAL_FRACTIONAL);

    if decimal_output != Decimal256::from_uint256(floored_output) {
        floored_output + Uint256::one()
    } else {
        floored_output
    }
}

pub fn get_taxed(deps: Deps, denom: &str, amount: Uint256) -> StdResult<Uint256> {
    let terra_querier = TerraQuerier::new(&deps.querier);
    let rate = Decimal256::from((terra_querier.query_tax_rate()?).rate);
    let cap = Uint256::from((terra_querier.query_tax_cap(denom)?).cap);

    let tax = if amount.is_zero() {
        Uint256::zero()
    } else {
        let rate_part = Decimal256::one() - Decimal256::one() / (Decimal256::one() + rate);
        ceiled_mul_uint_decimal(amount, rate_part)
    };

    let tax_capped = std::cmp::min(tax, cap);
    Ok(amount - std::cmp::max(tax_capped, Uint256::one()))
}

fn execute_buy(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    min_bonds_amount: Uint128,
) -> Result<Response, ContractError> {
    let mut response = Response::new();

    let config = CONFIG.load(deps.storage)?;

    let Coin {
        denom,
        amount: payment_before_tax,
    } = one_coin(&info)?;
    let payment = Uint128::from(get_taxed(deps.as_ref(), &denom, payment_before_tax.into())?);

    let state = STATE.load(deps.storage)?;
    let phase = phase(deps.storage, env.clone())?;

    let (pair, psi_price) = psi_price(deps.as_ref(), config.psi_token.clone(), denom.clone())?;

    let asset_cost_in_psi =
        Uint128::new(payment.u128() * psi_price.denominator() / psi_price.numerator());
    if asset_cost_in_psi.is_zero() {
        return Err(ContractError::PaymentTooSmall {});
    }
    let mut psi_token_balance =
        query_token_balance(deps.as_ref(), &config.psi_token, &env.contract.address);
    check_psi_balance(psi_token_balance, asset_cost_in_psi)?;
    psi_token_balance -= asset_cost_in_psi;

    let BondsCalculationResult {
        discount,
        bonds_amount,
    } = calculate_bonds(
        asset_cost_in_psi,
        phase.psi_amount_total,
        phase.psi_amount_start,
        state.psi_amount_sold,
        phase.max_discount,
        phase.start_time,
        env.block.time.seconds(),
        phase.end_time,
        min_bonds_amount,
    )?;
    if let Some(utility_token) = config.utility_token {
        response = burn_utility_tokens(
            deps.as_ref(),
            env.clone(),
            utility_token,
            info.sender.to_string(),
            config.bond_cost_in_utility_tokens * bonds_amount,
            response,
        )?;
    };
    check_psi_balance(psi_token_balance, bonds_amount)?;
    psi_token_balance -= bonds_amount;

    response = response
        .add_attribute("action", "buy")
        .add_attribute("asset", denom.clone())
        .add_attribute("psi_price", psi_price.to_string())
        .add_attribute("discount", discount.to_string())
        .add_attribute("bonds_issued", bonds_amount)
        .add_attribute("pair_with_provided_liquidity", pair.clone())
        .add_attribute("provided_liquidity_in_psi", asset_cost_in_psi)
        .add_attribute("provided_liquidity_in_asset", payment);

    save_state(deps.storage, state.psi_amount_sold + bonds_amount)?;

    save_reply_context(
        deps,
        &env,
        config.astro_token,
        config.psi_token.clone(),
        psi_token_balance,
        None,
        None,
        response.attributes.clone(),
    )?;

    Ok(response
        .add_submessages(transfer_and_linear_vesting(
            &env,
            &config.vesting,
            config.vesting_period,
            &config.psi_token,
            bonds_amount,
            info.sender.to_string(),
        )?)
        .add_submessages(increase_allowances_and_provide_liquidity(
            &env,
            &pair,
            &config.psi_token,
            native_asset(denom),
            asset_cost_in_psi,
            payment,
            config.autostake_lp_tokens,
        )?))
}

struct PairWithBalances {
    pair_info: PairInfo,
    balances: [Uint128; 2],
}

fn get_pair_and_balances(
    deps: Deps,
    assets: &[AssetInfo; 2],
) -> Result<PairWithBalances, ContractError> {
    let pair_info = pair(deps.storage, assets).map_err(|_e| ContractError::NotAllowedPair {
        assets_info: assets.clone(),
    })?;

    let mut balances = [Uint128::zero(); 2];
    for (i, asset) in assets.iter().enumerate() {
        let asset_balance =
            query_asset_balance(deps, &deps.querier, asset, &pair_info.contract_addr)?;
        if asset_balance.is_zero() {
            return Err(ContractError::ZeroBalanceInPair {
                token: asset.to_string(),
                addr: pair_info.contract_addr.to_string(),
            });
        }
        balances[i] = asset_balance;
    }

    Ok(PairWithBalances {
        pair_info,
        balances,
    })
}

fn query_asset_balance(
    deps: Deps,
    querier: &QuerierWrapper,
    asset: &AssetInfo,
    addr: &Addr,
) -> StdResult<Uint128> {
    Ok(match asset {
        AssetInfo::Token { contract_addr } => query_token_balance(deps, contract_addr, addr),
        AssetInfo::NativeToken { denom } => querier.query_balance(addr, denom)?.amount,
    })
}

struct BondsCalculationResult {
    discount: Decimal,
    bonds_amount: Uint128,
}

#[allow(clippy::too_many_arguments)]
fn calculate_bonds(
    asset_cost_in_psi: Uint128,
    psi_total: Uint128,
    psi_start: Uint128,
    psi_sold: Uint128,
    max_discount: Decimal,
    start_time: u64,
    cur_time: u64,
    end_time: u64,
    min_bonds_amount: Uint128,
) -> Result<BondsCalculationResult, ContractError> {
    let (discount, bonds_amount) = calculate_bonds_inner(
        asset_cost_in_psi.into(),
        psi_total.into(),
        psi_start.into(),
        psi_sold.into(),
        max_discount.into(),
        start_time,
        cur_time,
        end_time,
        min_bonds_amount.into(),
    )?;
    Ok(BondsCalculationResult {
        discount: discount.into(),
        bonds_amount: bonds_amount.into(),
    })
}

#[allow(clippy::too_many_arguments)]
fn calculate_bonds_inner(
    asset_cost_in_psi: Uint256,
    psi_total: Uint256,
    psi_start: Uint256,
    psi_sold: Uint256,
    max_discount: Decimal256,
    start_time: u64,
    cur_time: u64,
    end_time: u64,
    min_bonds_amount: Uint256,
) -> Result<(Decimal256, Uint256), ContractError> {
    let two = Uint256::from(2u64);

    let topup =
        (psi_total - psi_start).multiply_ratio(cur_time - start_time, end_time - start_time);

    if psi_start + topup < psi_sold {
        return Err(ContractError::NoBondsAvailable {});
    }
    let psi_to_sell = psi_start + topup - psi_sold;

    let a = Decimal256::one() - max_discount * Decimal256::from_ratio(psi_to_sell, psi_total);
    let a2 = a * a;
    let b = max_discount * Decimal256::from_ratio(two * asset_cost_in_psi, psi_total);
    let c: Decimal256 = Decimal::from(a2 + b).sqrt().into();
    let d = Decimal256::from_uint256(psi_total) + Decimal256::from_uint256(psi_total) * c
        - max_discount * Decimal256::from_uint256(psi_to_sell);

    let max_bonds_amount = two * psi_to_sell;
    let bonds_amount = two * psi_total * asset_cost_in_psi / d;
    if bonds_amount > max_bonds_amount {
        return Err(ContractError::BondsAmountTooLarge {
            value: bonds_amount.into(),
            maximum: max_bonds_amount.into(),
        });
    }

    let discount =
        max_discount * Decimal256::from_ratio(max_bonds_amount - bonds_amount, two * psi_total);

    if bonds_amount < min_bonds_amount {
        return Err(ContractError::BondsAmountTooSmall {
            value: bonds_amount.into(),
            minimum: min_bonds_amount.into(),
        });
    }
    Ok((discount, bonds_amount))
}

fn check_psi_balance(current: Uint128, required: Uint128) -> Result<(), ContractError> {
    if current < required {
        return Err(ContractError::NotEnoughTokens {
            name: "psi".to_owned(),
            value: current,
            required,
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn save_reply_context(
    deps: DepsMut,
    env: &Env,
    astro_token: Addr,
    psi_token: Addr,
    psi_token_balance: Uint128,
    token: Option<&Addr>,
    token_amount: Option<Uint128>,
    attributes: Vec<Attribute>,
) -> Result<(), ContractError> {
    let mut astro_token_balance =
        query_token_balance(deps.as_ref(), &astro_token, &env.contract.address);
    if let Some(token) = token {
        if token == &astro_token {
            astro_token_balance -= token_amount.unwrap_or_default();
        }
    }

    REPLY_CONTEXT.save(
        deps.storage,
        &ReplyContext {
            attributes,
            balances: vec![
                (astro_token, "astro".to_owned(), astro_token_balance).into(),
                (psi_token, "psi".to_owned(), psi_token_balance).into(),
            ],
        },
    )?;

    Ok(())
}

fn execute_claim_rewards(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;

    let config = CONFIG.load(deps.storage)?;

    let messages: Result<Vec<SubMsg>, StdError> = pairs(deps.storage)
        .into_iter()
        .map(|pair| {
            Ok(SubMsg::new(WasmMsg::Execute {
                contract_addr: config.astro_generator.to_string(),
                msg: to_binary(&astroport::generator::ExecuteMsg::Withdraw {
                    lp_token: pair.liquidity_token,
                    amount: Uint128::zero(),
                })?,
                funds: vec![],
            }))
        })
        .collect();
    let mut messages = messages?;

    Ok(if let Some(last) = messages.last_mut() {
        last.reply_on = ReplyOn::Success;
        last.id = CLAIM_REWARDS_REPLY_ID;

        let astro_token_balance =
            query_token_balance(deps.as_ref(), &config.astro_token, &env.contract.address);
        let psi_token_balance =
            query_token_balance(deps.as_ref(), &config.psi_token, &env.contract.address);
        REPLY_CONTEXT.save(
            deps.storage,
            &ReplyContext {
                attributes: vec![("action", "claim_rewards").into()],
                balances: vec![
                    (config.astro_token, "astro".to_owned(), astro_token_balance).into(),
                    (config.psi_token, "psi".to_owned(), psi_token_balance).into(),
                ],
            },
        )?;

        Response::new().add_submessages(messages)
    } else {
        Response::new().add_attribute("action", "claim_rewards")
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, env: Env, _msg: Reply) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let mut messages = vec![];
    let mut attributes = vec![];

    let ctx = REPLY_CONTEXT.load(deps.storage)?;
    for TokenBalance {
        token,
        token_name,
        amount: prev_balance,
    } in ctx.balances
    {
        let cur_balance = query_token_balance(deps.as_ref(), &token, &env.contract.address);
        let transfer_amount = cur_balance - prev_balance;
        if transfer_amount.is_zero() {
            continue;
        }
        messages.push(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: token.to_string(),
            msg: to_binary(&cw20::Cw20ExecuteMsg::Transfer {
                recipient: config.community_pool.to_string(),
                amount: transfer_amount,
            })?,
            funds: vec![],
        }));
        attributes.push((format!("{}_tokens_claimed", token_name), transfer_amount));
    }
    REPLY_CONTEXT.remove(deps.storage);

    Ok(Response::new()
        .add_messages(messages)
        .add_attributes(ctx.attributes)
        .add_attributes(attributes))
}

fn execute_accept_governance(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;

    let gov_update = GOVERNANCE_UPDATE.load(deps.storage)?;
    let cur_time = env.block.time.seconds();

    if gov_update.wait_approve_until < cur_time {
        return Err(StdError::generic_err("too late to accept governance owning").into());
    }

    if info.sender != gov_update.new_governance {
        return Err(ContractError::Unauthorized {});
    }

    let new_gov_addr = gov_update.new_governance.to_string();

    let mut config = CONFIG.load(deps.storage)?;
    config.governance = gov_update.new_governance;
    CONFIG.save(deps.storage, &config)?;
    GOVERNANCE_UPDATE.remove(deps.storage);

    Ok(Response::new()
        .add_attribute("action", "change_governance_contract")
        .add_attribute("new_addr", &new_gov_addr))
}

#[allow(clippy::too_many_arguments)]
fn update_config(
    deps: DepsMut,
    mut config: Config,
    psi_token: Option<String>,
    vesting: Option<String>,
    vesting_period: Option<u64>,
    community_pool: Option<String>,
    autostake_lp_tokens: Option<bool>,
    astro_generator: Option<String>,
    astro_token: Option<String>,
    utility_token: Option<String>,
    bond_cost_in_utility_tokens: Option<Decimal>,
) -> Result<Response, ContractError> {
    if let Some(psi_token) = psi_token {
        config.psi_token = addr_validate_to_lower(deps.api, &psi_token)?;
    }

    if let Some(vesting) = vesting {
        config.vesting = addr_validate_to_lower(deps.api, &vesting)?;
    }

    if let Some(vesting_period) = vesting_period {
        config.vesting_period = vesting_period;
    }

    if let Some(community_pool) = community_pool {
        config.community_pool = addr_validate_to_lower(deps.api, &community_pool)?;
    }

    if let Some(autostake_lp_tokens) = autostake_lp_tokens {
        config.autostake_lp_tokens = autostake_lp_tokens;
    }

    if let Some(astro_generator) = astro_generator {
        config.astro_generator = addr_validate_to_lower(deps.api, &astro_generator)?;
    }

    if let Some(astro_token) = astro_token {
        config.astro_token = addr_validate_to_lower(deps.api, &astro_token)?;
    }

    if let Some(utility_token) = utility_token {
        config.utility_token = if utility_token.is_empty() {
            None
        } else {
            Some(addr_validate_to_lower(deps.api, &utility_token)?)
        };
    }

    if let Some(bond_cost_in_utility_tokens) = bond_cost_in_utility_tokens {
        config.bond_cost_in_utility_tokens = bond_cost_in_utility_tokens;
    }

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new().add_attribute("action", "update_config"))
}

fn update_pairs(
    deps: DepsMut,
    add: Vec<String>,
    remove: Vec<String>,
) -> Result<Response, ContractError> {
    for pi in get_pairs_info(deps.as_ref(), add)? {
        save_pair(deps.storage, &pi)?;
    }

    for pi in get_pairs_info(deps.as_ref(), remove)? {
        remove_pair(deps.storage, &pi);
    }

    Ok(Response::new().add_attribute("action", "update_pairs"))
}

fn update_governance_addr(
    deps: DepsMut,
    env: Env,
    addr: String,
    seconds_to_wait_for_accept_gov_tx: u64,
) -> Result<Response, ContractError> {
    let cur_time = env.block.time.seconds();
    let gov_update = GovernanceUpdateState {
        new_governance: addr_validate_to_lower(deps.api, &addr)?,
        wait_approve_until: cur_time + seconds_to_wait_for_accept_gov_tx,
    };
    GOVERNANCE_UPDATE.save(deps.storage, &gov_update)?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_binary(&query_config(deps)?),
        QueryMsg::Phase {} => to_binary(&query_phase(deps)?),
        QueryMsg::BuySimulation { asset } => to_binary(&query_buy_simulation(deps, env, asset)?),
    }
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;

    let pairs = pairs(deps.storage)
        .into_iter()
        .map(|pi| pi.contract_addr.to_string())
        .collect();

    Ok(ConfigResponse {
        owner: config.owner.to_string(),
        governance: config.governance.to_string(),
        psi_token: config.psi_token.to_string(),
        vesting: config.vesting.to_string(),
        vesting_period: config.vesting_period,
        pairs,
        community_pool: config.community_pool.to_string(),
        autostake_lp_tokens: config.autostake_lp_tokens,
        astro_generator: config.astro_generator.to_string(),
        astro_token: config.astro_token.to_string(),
        utility_token: config.utility_token.map(|addr| addr.to_string()),
        bond_cost_in_utility_tokens: config.bond_cost_in_utility_tokens,
    })
}

fn query_phase(deps: Deps) -> StdResult<PhaseResponse> {
    let phase = PHASE.load(deps.storage)?;

    Ok(PhaseResponse {
        phase: phase.into(),
    })
}

fn query_buy_simulation(
    deps: Deps,
    env: Env,
    buy_asset: Asset,
) -> StdResult<BuySimulationResponse> {
    let config = CONFIG.load(deps.storage)?;
    let state = STATE.load(deps.storage)?;
    let phase = phase(deps.storage, env.clone())?;

    let payment = buy_asset.amount;
    if payment.is_zero() {
        return Err(StdError::generic_err("no funds"));
    }

    let calc_result: Result<_, ContractError> = match buy_asset.info {
        AssetInfo::NativeToken { denom } => {
            let payment = Uint128::from(get_taxed(deps, &denom, payment.into())?);

            let (_, psi_price) = psi_price(deps, config.psi_token.clone(), denom)?;

            let asset_cost_in_psi =
                Uint128::new(payment.u128() * psi_price.denominator() / psi_price.numerator());
            if asset_cost_in_psi.is_zero() {
                return Err(ContractError::PaymentTooSmall {}.into());
            }
            let mut psi_token_balance =
                query_token_balance(deps, &config.psi_token, &env.contract.address);
            check_psi_balance(psi_token_balance, asset_cost_in_psi)?;
            psi_token_balance -= asset_cost_in_psi;

            let result = calculate_bonds(
                asset_cost_in_psi,
                phase.psi_amount_total,
                phase.psi_amount_start,
                state.psi_amount_sold,
                phase.max_discount,
                phase.start_time,
                env.block.time.seconds(),
                phase.end_time,
                Uint128::zero(),
            )?;
            check_psi_balance(psi_token_balance, result.bonds_amount)?;

            Ok(result)
        }
        AssetInfo::Token { contract_addr } => {
            let PairWithBalances {
                pair_info: _,
                balances: [psi_balance_of_cw20_pair, token_balance_of_cw20_pair],
            } = get_pair_and_balances(
                deps,
                &[asset(config.psi_token.clone()), asset(contract_addr)],
            )?;

            let asset_cost_in_psi = payment * psi_balance_of_cw20_pair / token_balance_of_cw20_pair;
            if asset_cost_in_psi.is_zero() {
                return Err(ContractError::PaymentTooSmall {}.into());
            }
            let mut psi_token_balance =
                query_token_balance(deps, &config.psi_token, &env.contract.address);
            check_psi_balance(psi_token_balance, asset_cost_in_psi)?;
            psi_token_balance -= asset_cost_in_psi;

            let result = calculate_bonds(
                asset_cost_in_psi,
                phase.psi_amount_total,
                phase.psi_amount_start,
                state.psi_amount_sold,
                phase.max_discount,
                phase.start_time,
                env.block.time.seconds(),
                phase.end_time,
                Uint128::zero(),
            )?;
            check_psi_balance(psi_token_balance, result.bonds_amount)?;

            Ok(result)
        }
    };
    let calc_result = calc_result?;

    Ok(BuySimulationResponse {
        bonds: calc_result.bonds_amount,
        discount: calc_result.discount,
        utility_tokens: calc_result.bonds_amount * config.bond_cost_in_utility_tokens,
    })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    let ver = get_contract_version(deps.storage)?;

    if ver.contract != CONTRACT_NAME {
        return Err(StdError::generic_err("Can only upgrade from same type").into());
    }

    if ver.version.as_str() >= CONTRACT_VERSION {
        return Err(StdError::generic_err("Cannot upgrade from a newer version").into());
    }

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cosmwasm_bignumber::{Decimal256, Uint256};
    use cosmwasm_std::Uint128;

    use crate::error::ContractError;

    use super::calculate_bonds_inner;

    #[test]
    fn calculation_fails_when_no_more_bonds_available() {
        let asset_cost_in_psi = Uint256::from(100u64);
        let psi_total = Uint256::from(36_000_000u64);
        let max_discount = Decimal256::from_str("0.5").unwrap();
        let psi_start = Decimal256::from_str("0.15").unwrap() / max_discount * psi_total;
        let psi_sold = psi_total + Uint256::one();
        let start_time = 1_000;
        let end_time = 5_000;
        let cur_time = end_time;
        let min_bonds_amount = Uint256::zero();

        let r = calculate_bonds_inner(
            asset_cost_in_psi,
            psi_total,
            psi_start,
            psi_sold,
            max_discount,
            start_time,
            cur_time,
            end_time,
            min_bonds_amount,
        );

        assert_eq!(Err(ContractError::NoBondsAvailable {}), r);
    }

    #[test]
    fn calculation_fails_when_trying_to_buy_too_much_bonds() {
        let asset_cost_in_psi = Uint256::from(1_000_000_000u64);
        let psi_total = Uint256::from(36_000_000u64);
        let max_discount = Decimal256::from_str("0.5").unwrap();
        let psi_start = Decimal256::from_str("0.15").unwrap() / max_discount * psi_total;
        let psi_sold = psi_start / Decimal256::from_str("3").unwrap();
        let start_time = 1_000;
        let end_time = 5_000;
        let cur_time = 2_500;
        let min_bonds_amount = Uint256::zero();

        let r = calculate_bonds_inner(
            asset_cost_in_psi,
            psi_total,
            psi_start,
            psi_sold,
            max_discount,
            start_time,
            cur_time,
            end_time,
            min_bonds_amount,
        );

        assert_eq!(
            Err(ContractError::BondsAmountTooLarge {
                value: Uint128::new(328_138_751),
                maximum: Uint128::new(33_300_000)
            }),
            r
        );
    }

    #[test]
    fn calculation_fails_when_get_less_bonds_than_expected() {
        let asset_cost_in_psi = Uint256::from(1_000u64);
        let psi_total = Uint256::from(36_000_000u64);
        let max_discount = Decimal256::from_str("0.5").unwrap();
        let psi_start = Decimal256::from_str("0.15").unwrap() / max_discount * psi_total;
        let psi_sold = psi_start / Decimal256::from_str("3").unwrap();
        let start_time = 1_000;
        let end_time = 5_000;
        let cur_time = 2_500;
        let min_bonds_amount = Uint256::from(9_000_000_000u64);

        let r = calculate_bonds_inner(
            asset_cost_in_psi,
            psi_total,
            psi_start,
            psi_sold,
            max_discount,
            start_time,
            cur_time,
            end_time,
            min_bonds_amount,
        );

        assert_eq!(
            Err(ContractError::BondsAmountTooSmall {
                value: Uint128::new(1_300),
                minimum: Uint128::new(9_000_000_000),
            }),
            r
        );
    }

    #[test]
    fn calculation() {
        let asset_cost_in_psi = Uint256::from(100_000_000u64);
        let psi_total = Uint256::from(36_000_000_000_000u64);
        let max_discount = Decimal256::from_str("0.5").unwrap();
        let psi_start = Decimal256::from_str("0.15").unwrap() / max_discount * psi_total;
        let psi_sold = Uint256::zero();
        let start_time = 1_000;
        let cur_time = 1_000;
        let end_time = 5_000;
        let min_bonds_amount = Uint256::zero();

        let r = calculate_bonds_inner(
            asset_cost_in_psi,
            psi_total,
            psi_start,
            psi_sold,
            max_discount,
            start_time,
            cur_time,
            end_time,
            min_bonds_amount,
        );

        assert_eq!(
            Ok((
                Decimal256::from_str("0.149999183007326388").unwrap(),
                Uint256::from(117_646_945u64)
            )),
            r
        );
    }
}
