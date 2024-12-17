use core::str;
use hex;
use openssl::symm::{Cipher, Crypter, Mode};

use crate::error::{Result, Error};
use crate::crypto::gore::ore_encrypt_buf;

const VARCHAR_CIPHER_PREFIX: usize = 1;
type Byte = u8;
#[derive(Debug)]
pub struct CiphertextVarChar {
    pub buf: Vec<Byte>,
}

impl CiphertextVarChar {
    fn new(len: usize) -> Self {
        Self {
            buf: vec![0; len],
        }
    }
}

fn encode_ciphertext_varchar(ciphertext: &CiphertextVarChar) -> Result<String> {
    Ok(hex::encode(&ciphertext.buf))
}

#[allow(unused)]
pub fn decode_ciphertext_varchar(encoded_str: &str) -> Result<CiphertextVarChar> {
    match hex::decode(encoded_str) {
        Ok(buf) => Ok(CiphertextVarChar { buf }),
        Err(_) => Err(Error::EncryptFailed),
    }
}

pub fn varchar_to_gore_ciphertext(value: String) -> Result<String> {
    let length = value.len();
    let max_distance: u8 = 255;
    let mut cnt: u8 = 0;
    while cnt <= max_distance {
        let i = cnt as usize / 8;
        let j = cnt as usize % 8;
        let c = value.as_bytes()[i];
            let bit = ((c >> (8 - j - 1)) & 1) == 1;
            if bit {
                break;
        }
        cnt += 1;
    }
    if cnt >= max_distance {
        cnt = 0;
    } else {
        cnt = max_distance - cnt;
    }
    let distance: [Byte; 1] = [cnt];
    let mut code = vec![0; VARCHAR_CIPHER_PREFIX + length];
    code[..length].copy_from_slice(value.as_bytes());

    let nbits = length as u64 * 8;
    for i in 0..nbits as usize {
        let front_i = i / 8;
        let front_j = i % 8;
        let end_i = (nbits as usize - i - 1) / 8;
        let end_j = (nbits as usize - i - 1) % 8;
        let c1 = value.as_bytes()[front_i];
        let c2 = code[end_i];
        let bit = ((c1 >> (8 - front_j - 1)) & 1) == 1;
        if bit {
            code[end_i] = c2 | (1 << end_j);
        } else {
            code[end_i] = c2 & (255 - (1 << end_j));
        }
    }
    code[length..(length + VARCHAR_CIPHER_PREFIX)].copy_from_slice(&distance);
    let mut ctxt = CiphertextVarChar::new(code.len() * 2);
    ore_encrypt_buf(&mut ctxt.buf, &code, true)?;
    Ok(encode_ciphertext_varchar(&ctxt)?)
}

pub fn varchar_to_aes_ciphertext(value: &str) -> Result<String> {
    let key = b"0123456789abcdef";
    let cipher = Cipher::aes_128_cbc();
    let mut crypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
    crypter.pad(true);

    let mut buffer = [0; 1024];
    let mut count = crypter.update(value.as_bytes(), &mut buffer).unwrap();
    count += crypter.finalize(&mut buffer[count..]).unwrap();

    Ok(hex::encode(&buffer[..count]))
}

#[allow(unused)]
pub fn varchar_aes_decrypt(encrypted_value: &str) -> Result<String> {
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

    Ok(String::from_utf8(decrypted_data).unwrap())
}