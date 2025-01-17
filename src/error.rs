use core::str;
use std::fmt::{self, Debug};
use std::ffi;
use failure::Fail;


#[derive(Fail, Debug)]
pub enum Error {
    Default,
    PGErr(#[cause] postgres::Error),
    FFI(#[cause] ffi::IntoStringError),
    Parse(#[cause] pg_parse::Error),
    Utf8(#[cause] str::Utf8Error),
    RewriteFailed,
    NotInitialize,
    EncryptFailed,
    CiphertextCompareFailed
}

impl From<ffi::IntoStringError> for Error {
    fn from(err: ffi::IntoStringError) -> Error {
        Error::FFI(err)
    }
}

impl From<postgres::Error> for Error {
    fn from(err: postgres::Error) -> Error {
        Error::PGErr(err)
    }
}

impl From<pg_parse::Error> for Error {
    fn from(err: pg_parse::Error) -> Error {
        Error::Parse(err)
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Error {
        Error::Utf8(err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            _ => write!(f, "")
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;