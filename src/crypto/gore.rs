use num_bigint::BigUint;
use openssl::symm::{Cipher, Crypter, Mode};
use crate::error::{Error, Result};


const OUT_BLK_LEN: u32 = 2;

fn aes_ecb_encrypt(plaintext: &[u8], mut ciphertext: &mut [u8]) -> Result<()> {
        let key = b"0123456789abcdef";
        let mut encryptor = match Crypter::new(Cipher::aes_128_ecb(), Mode::Encrypt, key, None) {
            Ok(c) => c,
            Err(_) => return Err(Error::EncryptFailed)
        };
        encryptor.pad(false);
    
        let count = encryptor.update(plaintext, &mut ciphertext).unwrap();
        encryptor.finalize(&mut ciphertext[count..]).unwrap();
        Ok(())
}

pub fn ore_encrypt_buf(buf: &mut [u8], code: &[u8], positive: bool) -> Result<()> {
    let nbits = 8 * code.len() as u32;
    let mut block_mask = BigUint::from(1u32);
    block_mask <<= OUT_BLK_LEN;
    block_mask -= BigUint::from(1u32);

    let padding_len = (code.len() + 15) / 16 * 16;
    let mut prf_input_buf = vec![0; padding_len];
    let mut prf_output_buf = vec![0; padding_len + 16];


    let code_buf = code.to_vec();

    let mut ctxt_val = BigUint::from(0u32);
    let mut ctxt_block;

    let offset = (8 - (nbits % 8)) % 8;
    for i in 0..nbits {
        let byteind = code.len() as u32 - 1 - (i + offset) / 8;
        let mask = code_buf[byteind as usize] & (1u8 << (((7i32 - (i + offset) as i32) % 8 + 8) % 8));

        let tmp_padding_len = (code.len() - byteind as usize + 15) / 16 * 16;
        aes_ecb_encrypt(&prf_input_buf[0..tmp_padding_len], &mut prf_output_buf[0..tmp_padding_len + 16])?;

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


#[allow(unused)]
pub fn ciphertext_compare(buf_1: &[u8], buf_2: &[u8]) -> Result<i32> {
    let nbits1 = (buf_1.len() as u32 / OUT_BLK_LEN) * 8;
    let nbits2 = (buf_2.len() as u32 / OUT_BLK_LEN) * 8;
    let nbits = if nbits1 <= nbits2 { nbits1 } else { nbits2 };

    let ctxt1_val = BigUint::from_bytes_be(buf_1);
    let ctxt2_val = BigUint::from_bytes_be(buf_2);

    let mut modulus = BigUint::from(1u32);
    modulus <<= OUT_BLK_LEN;

    let mut block_mask1 = modulus.clone();
    block_mask1 -= BigUint::from(1u32);
    block_mask1 <<= (nbits1 - 1) * OUT_BLK_LEN;

    let mut block_mask2 = modulus.clone();
    block_mask2 -= BigUint::from(1u32);
    block_mask2 <<= (nbits2 - 1) * OUT_BLK_LEN;

    let mut tmp1;
    let mut tmp2;

    let mut res = 0;
    for i in 0..nbits {
        tmp1 = &ctxt1_val & &block_mask1;
        tmp2 = &ctxt2_val & &block_mask2;

        tmp1 >>= (nbits1 - i - 1) * OUT_BLK_LEN;
        tmp2 >>= (nbits2 - i - 1) * OUT_BLK_LEN;

        while (tmp2 > tmp1) { tmp1 += &modulus; }
        tmp1 -= tmp2;
        tmp1 %= &modulus;

        if tmp1 == BigUint::from(2u32) {
            return Err(Error::CiphertextCompareFailed);
        }

        let mut cmp = tmp1.cmp(&BigUint::from(0u32));
        if cmp != std::cmp::Ordering::Equal {
            cmp = tmp1.cmp(&BigUint::from(1u32));
            res = if cmp == std::cmp::Ordering::Equal { 1 } else { -1 };
            break;
        }
        block_mask1 >>= OUT_BLK_LEN;
        block_mask2 >>= OUT_BLK_LEN;
    }

    if res == 0 && buf_1.len() != buf_2.len() {
        res = if buf_1.len() > buf_2.len() { 1 } else { -1 };
    }

    Ok(res)
}
