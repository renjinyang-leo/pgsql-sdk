use crate::error::{Error, Result};


pub fn encode_ciphertext<T>(input: T) -> Result<String> {
    if std::any::type_name::<T>() == "i64" {
        todo!();
    } else if std::any::type_name::<T>() == "String" {
        todo!();
    }
    return Err(Error::NoMatchEncryptType);
}