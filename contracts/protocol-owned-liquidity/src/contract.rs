#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    Addr, Binary, CosmosMsg, Deps, DepsMut, Env, MessageInfo, QueryRequest, Response, StdError,
    StdResult, Uint128, WasmMsg, WasmQuery,
};
use cw0::PaymentError;
use cw2::set_contract_version;
use cw20::Cw20ReceiveMsg;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use services::vesting::VestingSchedule;
use terraswap::asset::PairInfo;
use terraswap::querier::query_balance;

use crate::error::ContractError;
use crate::msg::{
    ConfigResponse, Cw20HookMsg, ExecuteMsg, GovernanceMsg, InstantiateMsg, QueryMsg,
};
use crate::state::{Config, GovernanceUpdateState, CONFIG, GOVERNANCE_UPDATE};

const CONTRACT_NAME: &str = "nexus.protocol:protocol-owned-liquidity";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    if msg.pairs_addr.is_empty() {
        return Err(ContractError::NoPairs {});
    }

    let pairs_info: Result<Vec<PairInfo>, _> = msg
        .pairs_addr
        .iter()
        .map(|addr| {
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: addr.clone(),
                msg: cosmwasm_std::to_binary(&terraswap::pair::QueryMsg::Pair {})?,
            }))
        })
        .collect();
    let config = Config {
        owner: info.sender.clone(),
        governance_addr: deps.api.addr_validate(&msg.governance_addr)?,
        pairs_info: pairs_info?,
        psi_token_addr: deps.api.addr_validate(&msg.psi_token_addr)?,
        vesting_addr: deps.api.addr_validate(&msg.vesting_addr)?,
    };
    CONFIG.save(deps.storage, &config)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender)
        .add_attribute("governance_addr", config.governance_addr)
        .add_attribute(
            "pair_and_lptoken_addr",
            config
                .pairs_info
                .iter()
                .map(|pi| format!("({}, {})", pi.contract_addr, pi.liquidity_token))
                .collect::<Vec<_>>()
                .join(","),
        )
        .add_attribute("psi_token_addr", config.psi_token_addr)
        .add_attribute("vesting_addr", config.vesting_addr))
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
        ExecuteMsg::Buy {} => execute_buy(deps, env, info),
        ExecuteMsg::Governance { msg } => {
            let config = CONFIG.load(deps.storage)?;
            if info.sender != config.governance_addr {
                return Err(ContractError::Unauthorized {});
            }
            match msg {
                GovernanceMsg::UpdateConfig {
                    pairs_addr,
                    psi_token_addr,
                    vesting_addr,
                } => update_config(deps, config, pairs_addr, psi_token_addr, vesting_addr),
                GovernanceMsg::AddPairsToConfig { pairs_addr } => {
                    add_pairs_to_config(deps, config, pairs_addr)
                }
                GovernanceMsg::UpdateGovernanceContract {
                    addr,
                    tx_duration_sec,
                } => update_governance_addr(deps, env, addr, tx_duration_sec),
            }
        }
        ExecuteMsg::AcceptGovernance {} => execute_accept_governance(deps, env, info),
    }
}

fn add_pairs_to_config(
    deps: DepsMut,
    mut config: Config,
    pairs_addr: Vec<String>,
) -> Result<Response, ContractError> {
    let pairs_info: Result<Vec<PairInfo>, _> = pairs_addr
        .iter()
        .map(|addr| {
            deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                contract_addr: addr.clone(),
                msg: cosmwasm_std::to_binary(&terraswap::pair::QueryMsg::Pair {})?,
            }))
        })
        .collect();
    let mut pairs_info = pairs_info?;
    config.pairs_info.append(&mut pairs_info);
    CONFIG.save(deps.storage, &config)?;
    Ok(Response::new()
        .add_attribute("action", "add_pairs_to_config")
        .add_attribute("pairs_count", pairs_info.len().to_string()))
}

fn execute_accept_governance(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    let gov_update = GOVERNANCE_UPDATE.load(deps.storage)?;
    let cur_time = env.block.time.seconds();

    if gov_update.wait_approve_until < cur_time {
        return Err(StdError::generic_err("too late to accept governance owning").into());
    }

    if info.sender != gov_update.new_governance_addr {
        return Err(ContractError::Unauthorized {});
    }

    let new_gov_addr = gov_update.new_governance_addr.to_string();

    let mut config = CONFIG.load(deps.storage)?;
    config.governance_addr = gov_update.new_governance_addr;
    CONFIG.save(deps.storage, &config)?;
    GOVERNANCE_UPDATE.remove(deps.storage);

    Ok(Response::new()
        .add_attribute("action", "change_governance_contract")
        .add_attribute("new_addr", &new_gov_addr))
}

fn update_governance_addr(
    deps: DepsMut,
    env: Env,
    addr: String,
    tx_duration_sec: u64,
) -> Result<Response, ContractError> {
    let cur_time = env.block.time.seconds();
    let gov_update = GovernanceUpdateState {
        new_governance_addr: deps.api.addr_validate(&addr)?,
        wait_approve_until: cur_time + tx_duration_sec,
    };
    GOVERNANCE_UPDATE.save(deps.storage, &gov_update)?;
    Ok(Response::default())
}

fn update_config(
    deps: DepsMut,
    mut config: Config,
    pairs_addr: Option<Vec<String>>,
    psi_token_addr: Option<String>,
    vesting_addr: Option<String>,
) -> Result<Response, ContractError> {
    if let Some(pairs_addr) = pairs_addr {
        let pairs_info: Result<Vec<PairInfo>, _> = pairs_addr
            .iter()
            .map(|addr| {
                deps.querier.query(&QueryRequest::Wasm(WasmQuery::Smart {
                    contract_addr: addr.clone(),
                    msg: cosmwasm_std::to_binary(&terraswap::pair::QueryMsg::Pair {})?,
                }))
            })
            .collect();
        config.pairs_info = pairs_info?;
    }

    if let Some(psi_token_addr) = psi_token_addr {
        config.psi_token_addr = deps.api.addr_validate(&psi_token_addr)?;
    }

    if let Some(vesting_addr) = vesting_addr {
        config.vesting_addr = deps.api.addr_validate(&vesting_addr)?;
    }

    CONFIG.save(deps.storage, &config)?;

    Ok(Response::default())
}

fn receive_cw20(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    cw20_msg: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    let lp_token_addr = info.sender;

    let config = CONFIG.load(deps.storage)?;

    if cw20_msg.amount.is_zero() {
        return Err(ContractError::Payment(PaymentError::NoFunds {}));
    }

    let pair_info = config
        .pairs_info
        .iter()
        .find(|pi| pi.liquidity_token == lp_token_addr)
        .ok_or(ContractError::NotSupportedLpToken {})?;

    match cosmwasm_std::from_binary(&cw20_msg.msg) {
        Ok(Cw20HookMsg::Buy {}) => {
            let psi_tokens_amount = utils::query_token_balance(
                &deps.as_ref(),
                &config.psi_token_addr,
                &Addr::unchecked(pair_info.contract_addr.clone()),
            )?;
            if psi_tokens_amount.is_zero() {
                return Err(ContractError::ZeroPsiTokensInPair {});
            }

            let lp_tokens_amount_total = utils::query_supply(&deps.querier, &lp_token_addr)?;

            let lp_tokens_price_in_psi =
                Uint128::new(2) * psi_tokens_amount * cw20_msg.amount / lp_tokens_amount_total;

            // TODO: setup schedule properly
            let vesting_schedule = VestingSchedule {
                start_time: env.block.time.seconds(),
                end_time: env.block.time.plus_seconds(5 * 24 * 3600).seconds(),
                cliff_end_time: env.block.time.plus_seconds(4 * 24 * 3600).seconds(),
                amount: lp_tokens_price_in_psi,
            };

            Ok(Response::new()
                .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
                    contract_addr: config.vesting_addr.to_string(),
                    msg: cosmwasm_std::to_binary(
                        &services::vesting::ExecuteMsg::AddVestingSchedule {
                            addr: cw20_msg.sender.clone(),
                            schedule: vesting_schedule,
                        },
                    )?,
                    funds: vec![],
                }))
                .add_attribute("action", "buy")
                .add_attribute("lp_tokens_amount", cw20_msg.amount)
                .add_attribute("lp_tokens_price", lp_tokens_price_in_psi))
        }
        Err(err) => Err(ContractError::Std(err)),
    }
}

pub fn execute_buy(deps: DepsMut, env: Env, info: MessageInfo) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    let payment = cw0::one_coin(&info)?;

    let pair_info = config
        .pairs_info
        .iter()
        .find(|pair| {
            utils::is_suitable_pair(config.psi_token_addr.to_string(), &payment.denom, pair)
        })
        .ok_or(ContractError::PsiNativeTokenPairNotFound {})?;

    let lp_psi_tokens_amount = utils::query_token_balance(
        &deps.as_ref(),
        &config.psi_token_addr,
        &Addr::unchecked(pair_info.contract_addr.clone()),
    )?;
    if lp_psi_tokens_amount.is_zero() {
        return Err(ContractError::ZeroPsiTokensInPair {});
    }

    let lp_native_tokens_amount = query_balance(
        &deps.querier,
        Addr::unchecked(pair_info.contract_addr.clone()),
        payment.denom.clone(),
    )?;
    if lp_native_tokens_amount.is_zero() {
        return Err(ContractError::ZeroNativeTokensInPair {});
    }

    let psi_tokens_amount = payment.amount * lp_psi_tokens_amount / lp_native_tokens_amount;

    // TODO: setup schedule properly
    let vesting_schedule = VestingSchedule {
        start_time: env.block.time.seconds(),
        end_time: env.block.time.plus_seconds(5 * 24 * 3600).seconds(),
        cliff_end_time: env.block.time.plus_seconds(4 * 24 * 3600).seconds(),
        amount: psi_tokens_amount,
    };

    Ok(Response::new()
        .add_message(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: config.vesting_addr.to_string(),
            msg: cosmwasm_std::to_binary(&services::vesting::ExecuteMsg::AddVestingSchedule {
                addr: info.sender.to_string(),
                schedule: vesting_schedule,
            })?,
            funds: vec![],
        }))
        .add_attribute("action", "buy")
        .add_attribute("native_token_denom", payment.denom)
        .add_attribute("lp_psi_tokens_amount", lp_psi_tokens_amount)
        .add_attribute("lp_native_token_amount", lp_native_tokens_amount)
        .add_attribute("native_token_amount", payment.amount)
        .add_attribute("psi_amount", psi_tokens_amount))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => cosmwasm_std::to_binary(&query_config(deps)?),
    }
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    Ok(ConfigResponse {
        owner: config.owner.to_string(),
        governance_addr: config.governance_addr.to_string(),
        pairs_info: config
            .pairs_info
            .iter()
            .map(|pi| format!("({}, {})", pi.contract_addr, pi.liquidity_token))
            .collect::<Vec<_>>()
            .join(","),
        psi_token_addr: config.psi_token_addr.to_string(),
        vesting_addr: config.vesting_addr.to_string(),
    })
}

mod utils {
    use cosmwasm_std::{
        Addr, Binary, Deps, QuerierWrapper, QueryRequest, StdResult, Uint128, WasmQuery,
    };
    use cosmwasm_storage::to_length_prefixed;
    use cw20_base::state::TokenInfo;
    use terraswap::asset::{AssetInfo, PairInfo};

    pub fn query_supply(querier: &QuerierWrapper, contract_addr: &Addr) -> StdResult<Uint128> {
        let token_info: TokenInfo = querier.query(&QueryRequest::Wasm(WasmQuery::Raw {
            contract_addr: contract_addr.to_string(),
            key: Binary::from(b"token_info"),
        }))?;

        Ok(token_info.total_supply)
    }

    pub fn query_token_balance(
        deps: &Deps,
        contract_addr: &Addr,
        account_addr: &Addr,
    ) -> StdResult<Uint128> {
        deps.querier.query(&QueryRequest::Wasm(WasmQuery::Raw {
            contract_addr: contract_addr.to_string(),
            key: Binary::from(concat(
                &to_length_prefixed(b"balance"),
                account_addr.as_bytes(),
            )),
        }))
    }

    #[inline]
    fn concat(namespace: &[u8], key: &[u8]) -> Vec<u8> {
        let mut k = namespace.to_vec();
        k.extend_from_slice(key);
        k
    }

    pub fn is_suitable_pair(
        psi_token_addr: String,
        native_token_denom: &str,
        pair_info: &PairInfo,
    ) -> bool {
        let (mut is_psi, mut is_native) = (false, false);

        for ai in &pair_info.asset_infos {
            match ai {
                AssetInfo::Token { contract_addr } if contract_addr == &psi_token_addr => {
                    is_psi = true
                }
                AssetInfo::NativeToken { denom } if denom == native_token_denom => is_native = true,
                _ => {}
            }
        }

        is_psi && is_native
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct MigrateMsg {}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    let ver = cw2::get_contract_version(deps.storage)?;

    if ver.contract != CONTRACT_NAME {
        return Err(StdError::generic_err("Can only upgrade from same type").into());
    }

    if ver.version.as_str() >= CONTRACT_VERSION {
        return Err(StdError::generic_err("Cannot upgrade from a newer version").into());
    }

    cw2::set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::default())
}
