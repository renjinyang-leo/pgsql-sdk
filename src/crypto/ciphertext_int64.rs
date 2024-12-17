use openssl::symm::{Cipher, Crypter, Mode};

use crate::error::{Error, Result};
use crate::crypto::gore::ore_encrypt_buf;

const INT64_BUF_LEN: usize = 18;
const INT64_CODE_LEN: usize = 9;
type Byte = u8;
#[derive(Debug)]
pub struct CiphertextInt64 {
    pub buf: [Byte; INT64_BUF_LEN],
}

impl CiphertextInt64 {
    fn new() -> Self {
        Self {
            buf: [0; INT64_BUF_LEN]
        }
    }
}

fn encode_ciphertext_int64(ciphertext: &CiphertextInt64) -> String {
    hex::encode(&ciphertext.buf)
}

#[allow(unused)]
pub fn decode_ciphertext_int64(encoded_str: &str) -> Result<CiphertextInt64> {
    if let Ok(buf) = hex::decode(encoded_str) {
        if buf.len() == INT64_BUF_LEN {
            let mut arr = [0; INT64_BUF_LEN];
            arr.copy_from_slice(&buf);
            return Ok(CiphertextInt64 { buf: arr });
        } else {
            return Err(Error::Default);
        }
    } else {
        return Err(Error::Default);
    }
}

pub fn int64_to_gore_ciphertext(value: i64) -> Result<String> {
    let mut ctxt = CiphertextInt64::new();
    let i64_size = std::mem::size_of::<i64>();
    let positive = value >= 0;
    let data: u64 = if positive { value as u64 } else { (-value) as u64 };

    let mut cnt: u8 = 0;
    let mut tmp = data;
    while cnt <= 20 && tmp >= 10 {
        tmp /= 10;
        cnt += 1;
    }

    if positive {
        cnt |= 1 << 7;
    }

    let range: &[Byte] = &[cnt];
    let value: &[Byte] = unsafe { std::slice::from_raw_parts((&data as *const u64) as *const Byte, i64_size) };
    let mut code = vec![0; INT64_CODE_LEN];
    code[..i64_size].copy_from_slice(value);
    code[i64_size..].copy_from_slice(range);
    ore_encrypt_buf(&mut ctxt.buf, &code, positive)?;

    Ok(encode_ciphertext_int64(&ctxt))
}

pub fn int64_to_aes_ciphertext(value: i64) -> Result<String> {
    let key = b"0123456789abcdef";
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    crypter.pad(true);

    let mut buffer = [0; 1024];
    let mut count = crypter.update(&value.to_be_bytes(), &mut buffer).unwrap();
    count += crypter.finalize(&mut buffer[count..]).unwrap();

    Ok(hex::encode(&buffer[..count]))
}

#[allow(unused)]
pub fn int64_aes_decrypt(encrypted_value: &str) -> Result<i64> {
    let key = b"0123456789abcdef";

    let encrypted_data = hex::decode(encrypted_value).unwrap();
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
    crypter.pad(true);

    let mut decrypted_data = Vec::new();
    let mut buffer = [0; 1024];
    let mut count = crypter.update(&encrypted_data, &mut buffer).unwrap();
    count += crypter.finalize(&mut buffer[count..]).unwrap();
    decrypted_data.extend_from_slice(&buffer[..count]);

    let num_bytes: [u8; 8] = decrypted_data[..8].try_into().unwrap();
    let num = i64::from_be_bytes(num_bytes);
    Ok(num)
}