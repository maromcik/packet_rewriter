use crate::network::error::{NetworkError, NetworkErrorKind};
use std::fmt::{Debug, Display, Formatter};
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum AppErrorKind {
    NetworkError(NetworkErrorKind),
    ArgumentError,
}

impl Display for AppErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AppErrorKind::NetworkError(err) => std::fmt::Display::fmt(&err, f),
            AppErrorKind::ArgumentError => write!(f, "Invalid arguments"),
        }
    }
}

#[derive(Error, Debug, Clone)]
pub struct AppError {
    pub error_kind: AppErrorKind,
    pub message: String,
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AppError: {}: {}", self.error_kind, self.message)
    }
}

impl AppError {
    pub fn new(error_kind: AppErrorKind, message: &str) -> Self {
        Self {
            error_kind,
            message: message.to_owned(),
        }
    }
}

impl From<NetworkError> for AppError {
    fn from(value: NetworkError) -> Self {
        Self::new(
            AppErrorKind::NetworkError(value.error_kind),
            value.message.as_str(),
        )
    }
}
