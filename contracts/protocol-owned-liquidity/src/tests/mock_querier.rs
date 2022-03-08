use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage, MOCK_CONTRACT_ADDR};
use cosmwasm_std::{
    from_slice, to_binary, Addr, BankQuery, Binary, Coin, ContractResult, Decimal, OwnedDeps,
    Querier, QuerierResult, QueryRequest, SystemError, SystemResult, Uint128, WasmQuery,
};
use cosmwasm_storage::to_length_prefixed;
use cw20::TokenInfoResponse;
use std::collections::HashMap;
use std::str::FromStr;
use terra_cosmwasm::{TaxCapResponse, TaxRateResponse, TerraQuery, TerraQueryWrapper, TerraRoute};

pub const UST: &str = "uusd";

pub fn mock_dependencies(
    contract_balance: &[Coin],
) -> OwnedDeps<MockStorage, MockApi, WasmMockQuerier> {
    let custom_querier =
        WasmMockQuerier::new(MockQuerier::new(&[(MOCK_CONTRACT_ADDR, contract_balance)]));

    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: custom_querier,
    }
}

fn balances_to_map(
    balances: &[(&str, &[(&str, &Uint128)])],
) -> HashMap<String, HashMap<String, Uint128>> {
    let mut balances_map = HashMap::new();
    for (contract_addr, balances) in balances {
        let mut contract_balances_map = HashMap::new();
        for (addr, balance) in balances.iter() {
            contract_balances_map.insert(addr.to_string(), **balance);
        }

        balances_map.insert(contract_addr.to_string(), contract_balances_map);
    }
    balances_map
}

pub struct WasmMockQuerier {
    base: MockQuerier<TerraQueryWrapper>,
    pub wasm_query_smart_responses: HashMap<String, Binary>,
    pub token_balances: HashMap<String, HashMap<String, Uint128>>,
    pub ust_balances: HashMap<String, Uint128>,
    token_total_supply: Uint128,
}

impl Querier for WasmMockQuerier {
    fn raw_query(&self, bin_request: &[u8]) -> QuerierResult {
        let request: QueryRequest<TerraQueryWrapper> = match from_slice(bin_request) {
            Ok(v) => v,
            Err(e) => {
                return SystemResult::Err(SystemError::InvalidRequest {
                    error: format!("parsing query request: {}", e),
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
            QueryRequest::Custom(TerraQueryWrapper { route, query_data }) => {
                if &TerraRoute::Treasury == route {
                    match query_data {
                        TerraQuery::TaxRate {} => {
                            let res = TaxRateResponse {
                                rate: Decimal::from_str("0.2").unwrap(),
                            };
                            SystemResult::Ok(ContractResult::from(to_binary(&res)))
                        }
                        TerraQuery::TaxCap { denom: _ } => {
                            let cap = Uint128::new(10);
                            let res = TaxCapResponse { cap };
                            SystemResult::Ok(ContractResult::from(to_binary(&res)))
                        }
                        _ => panic!("DO NOT ENTER HERE"),
                    }
                } else {
                    panic!("DO NOT ENTER HERE")
                }
            }

            QueryRequest::Wasm(WasmQuery::Raw { contract_addr, key }) => {
                let key: &[u8] = key.as_slice();
                let prefix_balance = to_length_prefixed(b"balance");

                if key.starts_with(&prefix_balance) {
                    let key_address: &[u8] = &key[prefix_balance.len()..];
                    let address = Addr::unchecked(std::str::from_utf8(key_address).unwrap());

                    let balances: &HashMap<String, Uint128> =
                        match self.token_balances.get(contract_addr) {
                            Some(balances) => balances,
                            None => {
                                return SystemResult::Err(SystemError::InvalidRequest {
                                    error: format!(
                                        "no balance info exists for the contract {}",
                                        contract_addr
                                    ),
                                    request: key.into(),
                                })
                            }
                        };

                    let balance = match balances.get(address.as_str()) {
                        Some(v) => v,
                        None => {
                            return SystemResult::Err(SystemError::InvalidRequest {
                                error: "balance not found".to_owned(),
                                request: key.into(),
                            })
                        }
                    };

                    SystemResult::Ok(ContractResult::from(to_binary(balance)))
                } else if key == b"token_info" || key == to_length_prefixed(b"token_info") {
                    SystemResult::Ok(ContractResult::from(to_binary(&TokenInfoResponse {
                        name: String::new(),
                        symbol: String::new(),
                        decimals: 6,
                        total_supply: self.token_total_supply,
                    })))
                } else {
                    panic!("DO NOT ENTER HERE")
                }
            }

            QueryRequest::Bank(BankQuery::Balance { address, denom }) => {
                if denom == UST {
                    let bank_res = cosmwasm_std::BalanceResponse {
                        amount: Coin {
                            amount: self.ust_balances.get(address).cloned().unwrap_or_default(),
                            denom: denom.clone(),
                        },
                    };
                    SystemResult::Ok(ContractResult::from(cosmwasm_std::to_binary(&bank_res)))
                } else {
                    panic!("DO NOT ENTER HERE")
                }
            }

            QueryRequest::Wasm(WasmQuery::Smart { contract_addr, msg }) => {
                let response = match self.wasm_query_smart_responses.get(contract_addr) {
                    Some(response) => response,
                    None => {
                        return SystemResult::Err(SystemError::InvalidRequest {
                            error: format!(
                                "no WasmQuery::Smart responses exists for the contract {}",
                                contract_addr
                            ),
                            request: msg.clone(),
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
            ust_balances: HashMap::new(),
            token_total_supply: Uint128::zero(),
            token_balances: HashMap::new(),
        }
    }

    pub fn set_ust_balances(&mut self, balances: &[(&str, &Uint128)]) {
        for (addr, balance) in balances {
            self.ust_balances.insert(addr.to_string(), **balance);
        }
    }

    pub fn set_token_balances(&mut self, balances: &[(&str, &[(&str, &Uint128)])]) {
        self.token_balances = balances_to_map(balances);
    }
}
