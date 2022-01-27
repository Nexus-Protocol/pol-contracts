use astroport::asset::AssetInfo;
use cosmwasm_std::{StdError, Uint128};
use cw0::PaymentError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    Payment(#[from] PaymentError),

    #[error("invalid pair: {addr}, reason: {source}")]
    InvalidPair { addr: String, source: StdError },

    #[error("pair {}-{} not allowed", assets_info[0], assets_info[1])]
    NotAllowedPair { assets_info: [AssetInfo; 2] },

    #[error("address must be in lowercase, but {addr}")]
    WrongCaseAddr { addr: String },

    #[error("unauthorized")]
    Unauthorized {},

    #[error("zero balance of {token} in pair {addr}")]
    ZeroBalanceInPair { token: String, addr: String },

    #[error("bonds amount {value} exceeds limit {maximum}")]
    BondsAmountTooLarge { value: Uint128, maximum: Uint128 },

    #[error("bonds amount {value} is less than expected {minimum}")]
    BondsAmountTooSmall { value: Uint128, minimum: Uint128 },

    #[error("payment too small")]
    PaymentTooSmall {},

    #[error("not enough psi tokens: {value}, but {required} required")]
    NotEnoughPsiTokens { value: Uint128, required: Uint128 },
}

impl From<ContractError> for StdError {
    fn from(e: ContractError) -> Self {
        StdError::generic_err(e.to_string())
    }
}
