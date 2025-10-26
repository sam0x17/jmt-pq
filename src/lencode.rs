use serde::{de::DeserializeOwned, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("lencode serialization failed: {0}")]
    Serialize(#[from] bincode::Error),
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    bincode::serialize(value).map_err(Error::from)
}

pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    bincode::deserialize(bytes).map_err(Error::from)
}
