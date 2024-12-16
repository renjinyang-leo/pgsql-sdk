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

pub fn in64_to_aes_ciphertext(value: i64) -> Result<String> {
    todo!();
}