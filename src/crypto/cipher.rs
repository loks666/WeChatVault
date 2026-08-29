use aes::Aes256;
use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

pub const PAGE_SZ: usize = 4096;
pub const RESERVE_SZ: usize = 80; // IV(16) + HMAC(64)
pub const KDF_ITER: u32 = 256_000;

type HmacSha512 = Hmac<Sha512>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn pbkdf2_sha512(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    pbkdf2::pbkdf2::<HmacSha512>(password, salt, iterations, output).expect("PBKDF2 HMAC error");
}

pub fn aes_cbc_decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = ciphertext.to_vec();
    if buf.is_empty() {
        return buf;
    }
    let decryptor = Aes256CbcDec::new_from_slices(key, iv).expect("Invalid key or IV length");
    decryptor
        .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
        .expect("AES CBC block decryption error");
    buf
}

pub fn verify_enc_key(enc_key: &[u8], page1: &[u8], explicit_salt: Option<&[u8]>) -> bool {
    if page1.len() < PAGE_SZ {
        return false;
    }

    let (raw_key, salt) = if enc_key.len() == 48 && explicit_salt.is_none() {
        (&enc_key[..32], &enc_key[32..48])
    } else if let Some(s) = explicit_salt {
        if s.len() != 16 {
            return false;
        }
        (&enc_key[..32.min(enc_key.len())], s)
    } else {
        (&enc_key[..32.min(enc_key.len())], &page1[..16])
    };

    if raw_key.len() != 32 || salt.len() != 16 {
        return false;
    }

    let mut mac_salt = [0u8; 16];
    for (i, b) in salt.iter().enumerate() {
        mac_salt[i] = b ^ 0x3A;
    }

    let mut mac_key = [0u8; 32];
    pbkdf2_sha512(raw_key, &mac_salt, 2, &mut mac_key);

    let hmac_data = &page1[16..PAGE_SZ - RESERVE_SZ + 16];
    let stored_hmac = &page1[PAGE_SZ - 64..PAGE_SZ];

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&mac_key).expect("HMAC key length");
    mac.update(hmac_data);

    let mut page_num_bytes = [0u8; 4];
    LittleEndian::write_u32(&mut page_num_bytes, 1);
    mac.update(&page_num_bytes);

    let calculated = mac.finalize().into_bytes();
    calculated.as_slice() == stored_hmac
}

pub fn decrypt_page(enc_key: &[u8], page: &[u8], pgno: usize) -> Vec<u8> {
    let iv = &page[PAGE_SZ - RESERVE_SZ..PAGE_SZ - RESERVE_SZ + 16];
    let actual_key = if enc_key.len() >= 32 { &enc_key[..32] } else { enc_key };

    let mut result = Vec::with_capacity(PAGE_SZ);

    if pgno == 1 {
        if enc_key.len() == 48 {
            // 明文头模式 (Raw Key with Explicit Salt)
            let enc = &page[16..PAGE_SZ - RESERVE_SZ];
            let pt = aes_cbc_decrypt(actual_key, iv, enc);
            result.extend_from_slice(&page[..16]);
            result.extend_from_slice(&pt);
            result.extend_from_slice(&[0u8; RESERVE_SZ]);
        } else {
            // 标准 SQLCipher 4 模式
            let enc = &page[16..PAGE_SZ - RESERVE_SZ];
            let pt = aes_cbc_decrypt(actual_key, iv, enc);
            result.extend_from_slice(b"SQLite format 3\0");
            result.extend_from_slice(&pt);
            result.extend_from_slice(&[0u8; RESERVE_SZ]);
        }
    } else {
        let enc = &page[..PAGE_SZ - RESERVE_SZ];
        let pt = aes_cbc_decrypt(actual_key, iv, enc);
        result.extend_from_slice(&pt);
        result.extend_from_slice(&[0u8; RESERVE_SZ]);
    }

    result
}

pub fn decrypt_file<P1: AsRef<Path>, P2: AsRef<Path>>(src: P1, dst: P2, key: &[u8]) -> Result<()> {
    let mut file = File::open(src.as_ref())?;
    let file_len = file.metadata()?.len() as usize;
    let total_pages = (file_len + PAGE_SZ - 1) / PAGE_SZ;

    if let Some(parent) = dst.as_ref().parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut out_file = File::create(dst.as_ref())?;
    let mut page_buf = vec![0u8; PAGE_SZ];

    for pgno in 1..=total_pages {
        let n = file.read(&mut page_buf)?;
        if n == 0 {
            break;
        }
        if n < PAGE_SZ {
            page_buf[n..].fill(0);
        }
        let decrypted = decrypt_page(key, &page_buf, pgno);
        out_file.write_all(&decrypted)?;
    }

    out_file.flush()?;
    Ok(())
}
