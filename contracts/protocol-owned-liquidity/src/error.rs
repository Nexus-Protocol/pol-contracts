use cosmwasm_std::StdError;
use cw0::PaymentError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    Payment(#[from] PaymentError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Psi-NativeToken pair doesn't exist")]
    PsiNativeTokenPairNotFound {},

    #[error("No pairs")]
    NoPairs {},

    #[error("Zero psi tokens in pair")]
    ZeroPsiTokensInPair {},

    #[error("Zero native tokens in pair")]
    ZeroNativeTokensInPair {},

    #[error("Lp token isn't supported yet")]
    NotSupportedLpToken {},
}
