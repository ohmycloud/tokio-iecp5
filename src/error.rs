use thiserror::Error;

use crate::{
    client::Request,
    frame::asdu::{CauseOfTransmission, TypeID},
};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("asdu: [type identifier: {0:?}] doesn't match call or time tag")]
    ErrTypeIDNotMatch(TypeID),
    #[error("asdu: [cause of transmission: {0:?}] for command not standard requirement")]
    ErrCmdCause(CauseOfTransmission),

    #[error("Invalid frame")]
    ErrInvalidFrame,

    #[error("SendError {0}")]
    ErrSendRequest(#[from] tokio::sync::mpsc::error::SendError<Request>),

    #[error("Connection is closed")]
    ErrUseClosedConnection,
    #[error("Data transfer is not active; send STARTDT first")]
    ErrNotActive,

    #[error("{0}")]
    ErrAnyHow(#[from] anyhow::Error),
}
