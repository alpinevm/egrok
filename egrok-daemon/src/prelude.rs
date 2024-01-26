// Re-export the crate Error.
pub use crate::error::Error;

// Alias Result to be the crate Result.
pub type Result<T> = core::result::Result<T, Error>;

pub use std::error::Error as StdError;

pub use std::result::Result as StdResult;
