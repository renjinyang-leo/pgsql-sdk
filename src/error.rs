use std::fmt::{self, Debug};
use std::ffi;
use failure::Fail;


#[derive(Fail, Debug)]
pub enum Error {
    PGErr(#[cause] postgres::Error),
    FFI(#[cause] ffi::IntoStringError),
    Parse(#[cause] pg_parse::Error),
    RewriteFailed,
    NotInitialize,
    NoMatchEncryptType
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

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            _ => write!(f, "")
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;