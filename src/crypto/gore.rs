use num_bigint::BigUint;
use openssl::symm::{Cipher, Crypter, Mode};
use crate::error::{Error, Result};


const OUT_BLK_LEN: u32 = 2;

fn aes_ecb_encrypt(plaintext: &[u8], mut ciphertext: &mut [u8]) -> Result<()> {
        let key = b"0123456789abcdef0123456789abcdef";
        let mut encryptor = match Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None) {
            Ok(c) => c,
            Err(_) => return Err(Error::EncryptFailed)
        };
        encryptor.pad(false);
    
        match encryptor.update(plaintext, &mut ciphertext) {
            Ok(_) => {}
            Err(_) => return Err(Error::EncryptFailed)
        }

        match encryptor.finalize(&mut ciphertext) {
            Ok(_) => {}
            Err(_) => return Err(Error::EncryptFailed)
        }
        Ok(())
}

pub fn ore_encrypt_buf(buf: &mut [u8], code: &[u8], positive: bool) -> Result<()> {
    let nbits = 8 * code.len() as u32;
    let mut block_mask = BigUint::from(1u32);
    block_mask <<= OUT_BLK_LEN;
    block_mask -= BigUint::from(1u32);

    let mut prf_input_buf = vec![0; code.len()];
    let mut prf_output_buf = vec![0; code.len()];


    let code_buf = code.to_vec();

    let mut ctxt_val = BigUint::from(0u32);
    let mut ctxt_block;

    let offset = (8 - (nbits % 8)) % 8;
    for i in 0..nbits {
        let byteind = code.len() as u32 - 1 - (i + offset) / 8;
        let mask = code_buf[byteind as usize] & (1 << ((7 - (i + offset)) % 8));

        aes_ecb_encrypt(&prf_input_buf, &mut prf_output_buf)?;

        // 模拟mpz_import，将字节切片转换为BigUint，这里简单示例，实际可能更复杂
        ctxt_block = BigUint::from_bytes_be(&prf_output_buf[0..1]);

        if positive {
            if mask > 0 {
                ctxt_block += BigUint::from(1u32);
            }
        } else if !positive && i > 0 {
            if mask > 0 {
                ctxt_block += BigUint::from(0u32);
            } else {
                ctxt_block += BigUint::from(1u32);
            }
        }

        ctxt_block &= &block_mask;
        ctxt_block <<= (nbits - i - 1) * OUT_BLK_LEN;
        ctxt_val |= ctxt_block;

        prf_input_buf[code.len() - byteind as usize - 1] |= mask;
    }

    let expected_len = (nbits * OUT_BLK_LEN + 7) / 8;
    let bytes_written = ctxt_val.to_bytes_be().len();
    buf[..bytes_written].copy_from_slice(&ctxt_val.to_bytes_be());
    if bytes_written < expected_len as usize {
        let mut new_buf = vec![0; expected_len as usize];
        new_buf[(expected_len as usize - bytes_written)..].copy_from_slice(&buf[..bytes_written]);
        buf[0..new_buf.len()].copy_from_slice(&new_buf);
    }

    Ok(())
}
