use astroport::asset::{Asset, AssetInfo, PairInfo};
use cosmwasm_bignumber::{Decimal256, Uint256};
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    coins, from_binary, to_binary, Addr, Api, Attribute, Binary, CosmosMsg, Decimal, Deps, DepsMut,
    Env, MessageInfo, QuerierWrapper, QueryRequest, Reply, ReplyOn, Response, StdError, StdResult,
    SubMsg, Uint128, WasmMsg, WasmQuery,
};
use cosmwasm_storage::to_length_prefixed;
use cw0::{must_pay, nonpayable, Expiration};
use cw2::{get_contract_version, set_contract_version};
use cw20::Cw20ReceiveMsg;
use cw20_base::state::TokenInfo;
use nexus_pol_services::pol::{
    BuySimulationResponse, ConfigResponse, Cw20HookMsg, ExecuteMsg, GovernanceMsg, InstantiateMsg,
    MigrateMsg, QueryMsg,
};
use nexus_pol_services::vesting::VestingSchedule;
use nexus_services::governance::StakerResponse;
use terra_cosmwasm::TerraQuerier;

use crate::error::ContractError;
use crate::state::{
    excluded_psi, pair, pairs, remove_excluded_psi, remove_pair, save_excluded_psi, save_pair,
    save_state, Config, GovernanceUpdateState, ReplyContext, TokenBalance, CONFIG,
    GOVERNANCE_UPDATE, REPLY_CONTEXT, STATE,
};

const CONTRACT_NAME: &str = "nexus.protocol:protocol-owned-liquidity";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

const UST: &str = "uusd";

pub const BUY_REPLY_ID: u64 = 1;
pub const CLAIM_REWARDS_REPLY_ID: u64 = 2;

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;

    for pi in &get_pairs_info(deps.as_ref(), msg.pairs)? {
        save_pair(deps.storage, pi)?;
    }

    for addr in msg.excluded_psi {
        save_excluded_psi(deps.storage, &addr_validate_to_lower(deps.api, &addr)?)?;
    }

    let config = Config {
        owner: info.sender,
        governance: addr_validate_to_lower(deps.api, &msg.governance)?,
        psi_token: addr_validate_to_lower(deps.api, &msg.psi_token)?,
        min_staked_psi_amount: msg.min_staked_psi_amount,
        vesting: addr_validate_to_lower(deps.api, &msg.vesting)?,
        vesting_period: msg.vesting_period,
        bond_control_var: msg.bond_control_var,
        max_bonds_amount: msg.max_bonds_amount,
        community_pool: addr_validate_to_lower(deps.api, &msg.community_pool)?,
        autostake_lp_tokens: msg.autostake_lp_tokens,
        astro_generator: addr_validate_to_lower(deps.api, &msg.astro_generator)?,
        astro_token: addr_validate_to_lower(deps.api, &msg.astro_token)?,
    };
    CONFIG.save(deps.storage, &config)?;

    save_state(deps.storage, Uint128::zero())?;

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
                GovernanceMsg::UpdateConfig {
                    psi_token,
                    min_staked_psi_amount,
                    vesting,
                    vesting_period,
                    bond_control_var,
                    max_bonds_amount,
                    community_pool,
                    autostake_lp_tokens,
                    astro_generator,
                    astro_token,
                } => update_config(
                    deps,
                    config,
                    psi_token,
                    min_staked_psi_amount,
                    vesting,
                    vesting_period,
                    bond_control_var,
                    max_bonds_amount,
                    community_pool,
                    autostake_lp_tokens,
                    astro_generator,
                    astro_token,
                ),
                GovernanceMsg::UpdatePairs { add, remove } => update_pairs(deps, add, remove),
                GovernanceMsg::UpdateExcludedPsi { add, remove } => {
                    update_excluded_psi(deps, add, remove)
                }
                GovernanceMsg::UpdateGovernanceContract {
                    addr,
                    seconds_to_wait_for_accept_gov_tx,
                } => update_governance_addr(deps, env, addr, seconds_to_wait_for_accept_gov_tx),
            }
        }
    }
}

fn staked_enough_psi(
    deps: Deps,
    governance: &Addr,
    addr: String,
    required: Uint128,
) -> Result<(), ContractError> {
    let staker: StakerResponse = deps.querier.query_wasm_smart(
        governance,
        &nexus_services::governance::QueryMsg::Staker { address: addr },
    )?;
    if staker.balance < required {
        return Err(ContractError::Unauthorized {});
    }
    Ok(())
}

fn receive_cw20(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;

    let config = CONFIG.load(deps.storage)?;

    staked_enough_psi(
        deps.as_ref(),
        &config.governance,
        cw20_msg.sender.clone(),
        config.min_staked_psi_amount,
    )?;

    let state = STATE.load(deps.storage)?;

    let cw20_token = info.sender;

    match from_binary(&cw20_msg.msg) {
        Ok(Cw20HookMsg::Buy { min_amount }) => {
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

            let PairWithBalances {
                pair_info: _,
                balances: [psi_balance_of_psi_ust_pair, ust_balance_of_psi_ust_pair],
            } = get_pair_and_balances(
                deps.as_ref(),
                &[
                    asset(config.psi_token.clone()),
                    native_asset(UST.to_owned()),
                ],
            )?;

            let BondsCalculationResult {
                psi_price,
                bond_price,
                bonds_amount,
            } = calculate_bonds(
                deps.as_ref(),
                asset_cost_in_psi,
                &config.psi_token,
                ust_balance_of_psi_ust_pair,
                psi_balance_of_psi_ust_pair,
                state.bonds_issued,
                config.bond_control_var,
                min_amount,
                config.max_bonds_amount,
            )?;
            check_psi_balance(psi_token_balance, bonds_amount)?;
            psi_token_balance -= bonds_amount;

            save_state(deps.storage, state.bonds_issued + bonds_amount)?;

            save_reply_context(
                deps,
                &env,
                config.astro_token,
                config.psi_token.clone(),
                psi_token_balance,
                Some(&cw20_token),
                Some(cw20_msg.amount),
                vec![
                    ("action", "buy").into(),
                    ("asset", cw20_token.clone()).into(),
                    ("psi_price", psi_price.to_string()).into(),
                    ("bond_price", bond_price.to_string()).into(),
                    ("bonds_issued", bonds_amount).into(),
                    (
                        "pair_with_provided_liquidity",
                        cw20_pair_info.contract_addr.clone(),
                    )
                        .into(),
                    ("provided_liquidity_in_psi", asset_cost_in_psi).into(),
                    ("provided_liquidity_in_asset", cw20_msg.amount).into(),
                ],
            )?;

            Ok(Response::new()
                .add_submessages(transfer_and_linear_vesting(
                    &env,
                    &config.vesting,
                    config.vesting_period,
                    &config.psi_token,
                    bonds_amount,
                    cw20_msg.sender,
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

pub fn query_supply(querier: &QuerierWrapper, contract_addr: &Addr) -> StdResult<Uint128> {
    if let Ok(supply) = query_supply_legacy(querier, contract_addr) {
        return Ok(supply);
    }

    query_supply_new(querier, contract_addr)
}

fn query_supply_new(querier: &QuerierWrapper, contract_addr: &Addr) -> StdResult<Uint128> {
    let token_info: TokenInfo = querier.query(&QueryRequest::Wasm(WasmQuery::Raw {
        contract_addr: contract_addr.to_string(),
        key: Binary::from(b"token_info"),
    }))?;

    Ok(token_info.total_supply)
}

fn query_supply_legacy(querier: &QuerierWrapper, contract_addr: &Addr) -> StdResult<Uint128> {
    let token_info: TokenInfo = querier.query(&QueryRequest::Wasm(WasmQuery::Raw {
        contract_addr: contract_addr.to_string(),
        key: Binary::from(to_length_prefixed(b"token_info")),
    }))?;

    Ok(token_info.total_supply)
}

#[inline]
fn concat(namespace: &[u8], key: &[u8]) -> Vec<u8> {
    let mut k = namespace.to_vec();
    k.extend_from_slice(key);
    k
}

fn psi_circulating_amount(
    deps: Deps,
    psi_token: &Addr,
    psi_total_supply: Uint128,
) -> StdResult<Uint128> {
    let excluded_psi_amount = excluded_psi(deps.storage)
        .into_iter()
        .try_fold(Uint128::zero(), |acc, addr| -> StdResult<_> {
            Ok(acc + query_token_balance(deps, psi_token, &addr))
        })?;
    Ok(psi_total_supply - excluded_psi_amount)
}

fn decimal_division_in_256<A: Into<Decimal256>, B: Into<Decimal256>>(a: A, b: B) -> Decimal {
    let a_u256: Decimal256 = a.into();
    let b_u256: Decimal256 = b.into();
    let c_u256: Decimal = (a_u256 / b_u256).into();
    c_u256
}

fn decimal_multiplication_in_256<A: Into<Decimal256>, B: Into<Decimal256>>(a: A, b: B) -> Decimal {
    let a_u256: Decimal256 = a.into();
    let b_u256: Decimal256 = b.into();
    let c_u256: Decimal = (b_u256 * a_u256).into();
    c_u256
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

pub fn get_taxed(deps: Deps, amount: Uint256) -> StdResult<Uint256> {
    let terra_querier = TerraQuerier::new(&deps.querier);
    let rate = Decimal256::from((terra_querier.query_tax_rate()?).rate);
    let cap = Uint256::from((terra_querier.query_tax_cap(UST)?).cap);

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
    let config = CONFIG.load(deps.storage)?;

    staked_enough_psi(
        deps.as_ref(),
        &config.governance,
        info.sender.to_string(),
        config.min_staked_psi_amount,
    )?;

    let payment_before_tax = must_pay(&info, UST)?;
    let payment = Uint128::from(get_taxed(deps.as_ref(), payment_before_tax.into())?);

    let state = STATE.load(deps.storage)?;

    let PairWithBalances {
        pair_info,
        balances: [psi_balance_of_pair, ust_balance_of_pair],
    } = get_pair_and_balances(
        deps.as_ref(),
        &[
            asset(config.psi_token.clone()),
            native_asset(UST.to_owned()),
        ],
    )?;

    let asset_cost_in_psi = payment * psi_balance_of_pair / ust_balance_of_pair;
    if asset_cost_in_psi.is_zero() {
        return Err(ContractError::PaymentTooSmall {});
    }
    let mut psi_token_balance =
        query_token_balance(deps.as_ref(), &config.psi_token, &env.contract.address);
    check_psi_balance(psi_token_balance, asset_cost_in_psi)?;
    psi_token_balance -= asset_cost_in_psi;

    let BondsCalculationResult {
        psi_price,
        bond_price,
        bonds_amount,
    } = calculate_bonds(
        deps.as_ref(),
        asset_cost_in_psi,
        &config.psi_token,
        ust_balance_of_pair,
        psi_balance_of_pair,
        state.bonds_issued,
        config.bond_control_var,
        min_bonds_amount,
        config.max_bonds_amount,
    )?;
    check_psi_balance(psi_token_balance, bonds_amount)?;
    psi_token_balance -= bonds_amount;

    save_state(deps.storage, state.bonds_issued + bonds_amount)?;

    save_reply_context(
        deps,
        &env,
        config.astro_token,
        config.psi_token.clone(),
        psi_token_balance,
        None,
        None,
        vec![
            ("action", "buy").into(),
            ("asset", UST).into(),
            ("psi_price", psi_price.to_string()).into(),
            ("bond_price", bond_price.to_string()).into(),
            ("bonds_issued", bonds_amount).into(),
            (
                "pair_with_provided_liquidity",
                pair_info.contract_addr.clone(),
            )
                .into(),
            ("provided_liquidity_in_psi", asset_cost_in_psi).into(),
            ("provided_liquidity_in_asset", payment).into(),
        ],
    )?;

    Ok(Response::new()
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
            &pair_info.contract_addr,
            &config.psi_token,
            native_asset(UST.to_owned()),
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

fn calculate_bonds_inner(
    asset_cost_in_psi: Uint128,
    bonds_issued: Uint128,
    psi_price: Decimal,
    psi_circulating_amount: Uint128,
    psi_total_supply: Uint128,
    bond_control_var: Decimal,
) -> (Decimal, Uint128) {
    let psi_intrinsic_value =
        Decimal::from_ratio(psi_circulating_amount * psi_price, psi_total_supply);
    let debt_ratio = Decimal::from_ratio(bonds_issued, psi_total_supply);
    let psi_premium = decimal_multiplication_in_256(debt_ratio, bond_control_var);
    let bond_price = psi_intrinsic_value + psi_premium;
    (
        bond_price,
        decimal_division_in_256(
            Decimal::from_ratio(asset_cost_in_psi * psi_price, Uint128::new(1)),
            bond_price,
        ) * Uint128::new(1),
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use cosmwasm_std::{Decimal, Uint128};

    use super::calculate_bonds_inner;

    #[test]
    fn calculate_1() {
        let (bond_price, bonds_amount) = calculate_bonds_inner(
            Uint128::new(1_000_000_000),
            Uint128::new(10_000_000_000_000),
            Decimal::from_str("0.04").unwrap(),
            Uint128::new(703_300_601_000_000),
            Uint128::new(10_000_000_000_000_000),
            Decimal::from_str("2.5").unwrap(),
        );
        assert_eq!(bond_price, Decimal::from_str("0.005313202404").unwrap());
        assert_eq!(bonds_amount, Uint128::new(7_528_416_378));
    }

    #[test]
    fn calculate_2() {
        let (bond_price, bonds_amount) = calculate_bonds_inner(
            Uint128::new(1_000_000),
            Uint128::new(10_000_000_000_000),
            Decimal::from_str("0.033").unwrap(),
            Uint128::new(703_300_601_000_000),
            Uint128::new(10_000_000_000_000_000),
            Decimal::from_str("2.5").unwrap(),
        );
        assert_eq!(bond_price, Decimal::from_str("0.0048208919833").unwrap());
        assert_eq!(bonds_amount, Uint128::new(6_845_206));
    }

    #[test]
    fn calculate_when_zero_bonds_issued() {
        let (bond_price, bonds_amount) = calculate_bonds_inner(
            Uint128::new(1_000_000),
            Uint128::zero(),
            Decimal::from_str("0.033").unwrap(),
            Uint128::new(703_300_601_000_000),
            Uint128::new(10_000_000_000_000_000),
            Decimal::from_str("2.5").unwrap(),
        );
        assert_eq!(bond_price, Decimal::from_str("0.0023208919833").unwrap());
        assert_eq!(bonds_amount, Uint128::new(14_218_671));
    }

    #[test]
    fn calculate_when_max_bonds_issued() {
        let (bond_price, bonds_amount) = calculate_bonds_inner(
            Uint128::new(1_000_000),
            Uint128::new(10_000_000_000_000_000),
            Decimal::from_str("0.033").unwrap(),
            Uint128::new(703_300_601_000_000),
            Uint128::new(10_000_000_000_000_000),
            Decimal::from_str("2.5").unwrap(),
        );
        assert_eq!(bond_price, Decimal::from_str("2.5023208919833").unwrap());
        assert_eq!(bonds_amount, Uint128::new(13_187));
    }

    #[test]
    fn calculate_when_all_psi_circulating() {
        let (bond_price, bonds_amount) = calculate_bonds_inner(
            Uint128::new(1_000_000),
            Uint128::new(10_000_000_000_000),
            Decimal::from_str("0.033").unwrap(),
            Uint128::new(10_000_000_000_000_000),
            Uint128::new(10_000_000_000_000_000),
            Decimal::from_str("2.5").unwrap(),
        );
        assert_eq!(bond_price, Decimal::from_str("0.0355").unwrap());
        assert_eq!(bonds_amount, Uint128::new(929_577));
    }
}

struct BondsCalculationResult {
    psi_price: Decimal,
    bond_price: Decimal,
    bonds_amount: Uint128,
}

#[allow(clippy::too_many_arguments)]
fn calculate_bonds(
    deps: Deps,
    asset_cost_in_psi: Uint128,
    psi_token: &Addr,
    ust_balance_of_pair: Uint128,
    psi_balance_of_pair: Uint128,
    bonds_issued: Uint128,
    bond_control_var: Decimal,
    min_bonds_amount: Uint128,
    max_bonds_amount: Decimal,
) -> Result<BondsCalculationResult, ContractError> {
    let psi_price = Decimal::from_ratio(ust_balance_of_pair, psi_balance_of_pair);
    let psi_total_supply = query_supply(&deps.querier, psi_token)?;

    let (bond_price, bonds_amount) = calculate_bonds_inner(
        asset_cost_in_psi,
        bonds_issued,
        psi_price,
        psi_circulating_amount(deps, psi_token, psi_total_supply)?,
        psi_total_supply,
        bond_control_var,
    );
    let max_amount = psi_total_supply * max_bonds_amount;
    if bonds_amount > max_amount {
        return Err(ContractError::BondsAmountTooLarge {
            value: bonds_amount,
            maximum: max_amount,
        });
    }
    if bonds_amount < min_bonds_amount {
        return Err(ContractError::BondsAmountTooSmall {
            value: bonds_amount,
            minimum: min_bonds_amount,
        });
    }
    Ok(BondsCalculationResult {
        psi_price,
        bond_price,
        bonds_amount,
    })
}

fn check_psi_balance(current: Uint128, required: Uint128) -> Result<(), ContractError> {
    if current < required {
        return Err(ContractError::NotEnoughPsiTokens {
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
    min_staked_psi_amount: Option<Uint128>,
    vesting: Option<String>,
    vesting_period: Option<u64>,
    bond_control_var: Option<Decimal>,
    max_bonds_amount: Option<Decimal>,
    community_pool: Option<String>,
    autostake_lp_tokens: Option<bool>,
    astro_generator: Option<String>,
    astro_token: Option<String>,
) -> Result<Response, ContractError> {
    if let Some(psi_token) = psi_token {
        config.psi_token = addr_validate_to_lower(deps.api, &psi_token)?;
    }

    if let Some(min_staked_psi_amount) = min_staked_psi_amount {
        config.min_staked_psi_amount = min_staked_psi_amount;
    }

    if let Some(vesting) = vesting {
        config.vesting = addr_validate_to_lower(deps.api, &vesting)?;
    }

    if let Some(vesting_period) = vesting_period {
        config.vesting_period = vesting_period;
    }

    if let Some(bond_control_var) = bond_control_var {
        config.bond_control_var = bond_control_var;
    }

    if let Some(max_bonds_amount) = max_bonds_amount {
        config.max_bonds_amount = max_bonds_amount;
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

fn update_excluded_psi(
    deps: DepsMut,
    add: Vec<String>,
    remove: Vec<String>,
) -> Result<Response, ContractError> {
    for addr in add {
        save_excluded_psi(deps.storage, &addr_validate_to_lower(deps.api, &addr)?)?;
    }

    for addr in remove {
        remove_excluded_psi(deps.storage, &addr_validate_to_lower(deps.api, &addr)?);
    }

    Ok(Response::new().add_attribute("action", "update_excluded_psi"))
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
        QueryMsg::Version {} => to_binary(&query_version()),
        QueryMsg::BuySimulation { asset } => to_binary(&query_buy_simulation(deps, env, asset)?),
        QueryMsg::PsiCirculatingSupply {} => to_binary(&query_psi_circulating_supply(deps)?),
    }
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;

    let pairs = pairs(deps.storage)
        .into_iter()
        .map(|pi| pi.contract_addr.to_string())
        .collect();
    let excluded_psi = excluded_psi(deps.storage)
        .into_iter()
        .map(|addr| addr.to_string())
        .collect();

    Ok(ConfigResponse {
        owner: config.owner.to_string(),
        governance: config.governance.to_string(),
        psi_token: config.psi_token.to_string(),
        min_staked_psi_amount: config.min_staked_psi_amount,
        vesting: config.vesting.to_string(),
        vesting_period: config.vesting_period,
        bond_control_var: config.bond_control_var,
        max_bonds_amount: config.max_bonds_amount,
        excluded_psi,
        pairs,
        community_pool: config.community_pool.to_string(),
        autostake_lp_tokens: config.autostake_lp_tokens,
        astro_generator: config.astro_generator.to_string(),
        astro_token: config.astro_token.to_string(),
    })
}

fn query_version() -> String {
    CONTRACT_VERSION.to_owned()
}

fn query_psi_circulating_supply(deps: Deps) -> StdResult<Uint128> {
    let config = CONFIG.load(deps.storage)?;

    let psi_total_supply = query_supply(&deps.querier, &config.psi_token)?;

    psi_circulating_amount(deps, &config.psi_token, psi_total_supply)
}

fn query_buy_simulation(
    deps: Deps,
    env: Env,
    buy_asset: Asset,
) -> StdResult<BuySimulationResponse> {
    let config = CONFIG.load(deps.storage)?;
    let state = STATE.load(deps.storage)?;

    let payment = buy_asset.amount;
    if payment.is_zero() {
        return Err(StdError::generic_err("no funds"));
    }

    let calc_result: Result<_, ContractError> = match buy_asset.info {
        AssetInfo::NativeToken { denom } => {
            if denom != UST {
                return Err(StdError::generic_err(format!(
                    "invalid denom: only {} allowed",
                    UST
                )));
            }

            let payment = Uint128::from(get_taxed(deps, payment.into())?);

            let PairWithBalances {
                pair_info: _,
                balances: [psi_balance_of_pair, ust_balance_of_pair],
            } = get_pair_and_balances(
                deps,
                &[
                    asset(config.psi_token.clone()),
                    native_asset(UST.to_owned()),
                ],
            )?;

            let asset_cost_in_psi = payment * psi_balance_of_pair / ust_balance_of_pair;
            if asset_cost_in_psi.is_zero() {
                return Err(ContractError::PaymentTooSmall {}.into());
            }
            let mut psi_token_balance =
                query_token_balance(deps, &config.psi_token, &env.contract.address);
            check_psi_balance(psi_token_balance, asset_cost_in_psi)?;
            psi_token_balance -= asset_cost_in_psi;

            let result = calculate_bonds(
                deps,
                asset_cost_in_psi,
                &config.psi_token,
                ust_balance_of_pair,
                psi_balance_of_pair,
                state.bonds_issued,
                config.bond_control_var,
                Uint128::zero(),
                config.max_bonds_amount,
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

            let PairWithBalances {
                pair_info: _,
                balances: [psi_balance_of_psi_ust_pair, ust_balance_of_psi_ust_pair],
            } = get_pair_and_balances(
                deps,
                &[
                    asset(config.psi_token.clone()),
                    native_asset(UST.to_owned()),
                ],
            )?;

            let result = calculate_bonds(
                deps,
                asset_cost_in_psi,
                &config.psi_token,
                ust_balance_of_psi_ust_pair,
                psi_balance_of_psi_ust_pair,
                state.bonds_issued,
                config.bond_control_var,
                Uint128::zero(),
                config.max_bonds_amount,
            )?;
            check_psi_balance(psi_token_balance, result.bonds_amount)?;

            Ok(result)
        }
    };
    let calc_result = calc_result?;

    Ok(BuySimulationResponse {
        bonds: calc_result.bonds_amount,
        bond_price: calc_result.bond_price,
        psi_price: calc_result.psi_price,
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
