use crate::crypto::cipher::{pbkdf2_sha512, verify_enc_key, KDF_ITER, PAGE_SZ};
use crate::scanner::process::{find_weixin_pids, ProcessHandle};
use anyhow::Result;
use byteorder::{ByteOrder, LittleEndian};
use regex::bytes::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::Path;

const CONFIG_CIPHER_NAME: &[u8] = b"com.Tencent.WCDB.Config.Cipher";
const CONFIG_XOR_MASK: &[u8] = &[
    0xd2, 0xc7, 0x44, 0x24, 0x58, 0x02, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x50, 0x48,
    0x8b, 0x45, 0x00, 0x48, 0x84, 0x4c, 0x24, 0x48, 0x48, 0x89, 0x44, 0x25, 0x40, 0x48, 0x58,
    0x4c, 0x24,
];

const MASTER_DLL_PATTERN: &[u8] = &[
    0x83, 0xec, 0x40, 0x48, 0x89, 0xd6, 0x48, 0x89, 0xcb, 0x0f, 0x57, 0xc0, 0x0f, 0x11, 0x42,
    0x10, 0x0f, 0x11, 0x02, 0x4c, 0x8b, 0xb1, 0xc8, 0x02, 0x00, 0x00, 0x48, 0x83, 0xb9, 0xd0,
    0x02, 0x00, 0x00, 0x10, 0x72, 0x09, 0x48, 0x8b, 0x9b, 0xb8, 0x02, 0x00, 0x00, 0xeb, 0x07,
    0x48, 0x81, 0xc3, 0xb8, 0x02, 0x00, 0x00, 0x4d, 0x85, 0xf6, 0x0f, 0x88, 0x0a, 0x02, 0x00,
    0x00, 0x49, 0x83, 0xfe, 0x10, 0x73, 0x6d, 0x4c, 0x89, 0x76, 0x10, 0x48, 0xc7, 0x46, 0x18,
    0x0f, 0x00, 0x00, 0x00, 0x0f, 0x10, 0x03, 0x0f, 0x11, 0x06, 0x48, 0xb8,
];

const MASTER_DLL_VERIFY: [&[u8]; 3] = [
    b"488944242048b8",
    b"488944242848b8",
    b"488944243048b8",
];

const CFG_LANDMARK: &[u8] = b"global_config";
const CFG_PTR_BACK: usize = 0x138;
const CFG_OFFSET: usize = 0x68;
const CFG_CIPHER_OFF: usize = 0x2B8;

pub struct DbFileTarget {
    pub rel_path: String,
    pub full_path: String,
    pub page1: Vec<u8>,
}

impl DbFileTarget {
    pub fn new<P: AsRef<Path>>(rel: &str, full: P) -> Option<Self> {
        let mut file = File::open(full.as_ref()).ok()?;
        let mut page1 = vec![0u8; PAGE_SZ];
        if file.read_exact(&mut page1).is_ok() {
            Some(Self {
                rel_path: rel.to_string(),
                full_path: full.as_ref().to_string_lossy().to_string(),
                page1,
            })
        } else {
            None
        }
    }
}

pub fn scan_and_extract_keys(
    targets: &[DbFileTarget],
) -> Result<HashMap<String, Vec<u8>>> {
    let pids = find_weixin_pids();
    if pids.is_empty() {
        anyhow::bail!("未检测到 Weixin.exe 进程，请先登录微信客户端再运行本工具。");
    }

    let mut keys: HashMap<String, Vec<u8>> = HashMap::new();
    let mut tested_cands: HashSet<Vec<u8>> = HashSet::new();

    let hex_regex = Regex::new(r#"(?i)[xX]'([0-9a-fA-F]{64,192})'"#).unwrap();

    for &pid in &pids {
        if let Some(proc) = ProcessHandle::open(pid) {
            let regions = proc.query_memory_regions();

            // 1. 寻找 needle "com.Tencent.WCDB.Config.Cipher" 的内存地址
            let mut needle_addrs = Vec::new();
            for &(base, size) in &regions {
                if let Some(buf) = proc.read_memory(base, size) {
                    let mut start = 0;
                    while let Some(pos) = buf[start..].windows(CONFIG_CIPHER_NAME.len()).position(|w| w == CONFIG_CIPHER_NAME) {
                        let hit = start + pos;
                        needle_addrs.push(base + hit);
                        start = hit + 1;
                    }
                }
            }

            if needle_addrs.is_empty() {
                continue;
            }

            // 2. 构造 needle 结构指针 (addr, len)
            let mut needle_pairs = Vec::new();
            for &addr in &needle_addrs {
                let mut pair = [0u8; 16];
                LittleEndian::write_u64(&mut pair[0..8], addr as u64);
                LittleEndian::write_u64(&mut pair[8..16], CONFIG_CIPHER_NAME.len() as u64);
                needle_pairs.push(pair);
            }

            // 3. 搜索引用该 pair 的节点
            let mut pair_hits = Vec::new();
            for &(base, size) in &regions {
                if let Some(buf) = proc.read_memory(base, size) {
                    for pair in &needle_pairs {
                        let mut start = 0;
                        while let Some(pos) = buf[start..].windows(pair.len()).position(|w| w == pair) {
                            let hit = start + pos;
                            pair_hits.push(base + hit);
                            start = hit + 1;
                        }
                    }
                }
            }

            // 4. 从 pair 节点向上向下解析 Config.Cipher 对象
            for qaddr in pair_hits {
                if qaddr < 0x10 {
                    continue;
                }
                let node_buf = match proc.read_memory(qaddr - 0x10, 0x50) {
                    Some(b) if b.len() >= 0x40 => b,
                    _ => continue,
                };

                let ptr_check = LittleEndian::read_u64(&node_buf[0x10..0x18]) as usize;
                if !needle_addrs.contains(&ptr_check) {
                    continue;
                }
                if LittleEndian::read_u64(&node_buf[0x18..0x20]) != CONFIG_CIPHER_NAME.len() as u64 {
                    continue;
                }

                let config_ptr = LittleEndian::read_u64(&node_buf[0x28..0x30]) as usize;
                if config_ptr < 0x10000 || config_ptr >= 0x8000_0000_0000 {
                    continue;
                }

                let obj_buf = match proc.read_memory(config_ptr + 0x88, 0x28) {
                    Some(b) if b.len() >= 0x18 => b,
                    _ => continue,
                };

                let data_ptr = LittleEndian::read_u64(&obj_buf[0x08..0x10]) as usize;
                let data_len = LittleEndian::read_u64(&obj_buf[0x10..0x18]) as usize;

                if data_len == 0 || data_len > 1024 || data_ptr < 0x10000 || data_ptr >= 0x8000_0000_0000 {
                    continue;
                }

                let blob = match proc.read_memory(data_ptr, data_len) {
                    Some(b) if b.len() == data_len => b,
                    _ => continue,
                };

                // XOR 解码
                let decoded: Vec<u8> = blob
                    .iter()
                    .enumerate()
                    .map(|(i, &v)| v ^ CONFIG_XOR_MASK[i % CONFIG_XOR_MASK.len()])
                    .collect();

                // 正则捕获十六进制 hex 字符串
                for cap in hex_regex.captures_iter(&decoded) {
                    if let Some(m) = cap.get(1) {
                        let hex_str = String::from_utf8_lossy(m.as_bytes()).to_lowercase();
                        let mut starts = vec![0];
                        if hex_str.len() > 96 {
                            let mut s = 0;
                            while s + 63 < hex_str.len() {
                                starts.push(s);
                                s += 32;
                            }
                            starts.push(hex_str.len().saturating_sub(64));
                        }

                        starts.sort_unstable();
                        starts.dedup();

                        for s in starts {
                            if s + 64 > hex_str.len() {
                                continue;
                            }
                            let cand_hex = &hex_str[s..s + 64];
                            let cand_bytes = match hex::decode(cand_hex) {
                                Ok(b) if b.len() == 32 => b,
                                _ => continue,
                            };

                            if tested_cands.contains(&cand_bytes) || !is_probable_key(&cand_bytes) {
                                continue;
                            }
                            tested_cands.insert(cand_bytes.clone());

                            let explicit_salt = if s + 96 <= hex_str.len() {
                                hex::decode(&hex_str[s + 64..s + 96]).ok()
                            } else {
                                None
                            };

                            let salt_choices = vec![None, explicit_salt.as_deref()];

                            for salt_opt in salt_choices {
                                for target in targets {
                                    if keys.contains_key(&target.rel_path) {
                                        continue;
                                    }
                                    if verify_enc_key(&cand_bytes, &target.page1, salt_opt) {
                                        let mut final_key = cand_bytes.clone();
                                        if let Some(salt) = salt_opt {
                                            final_key.extend_from_slice(salt);
                                        }
                                        keys.insert(target.rel_path.clone(), final_key);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            if keys.len() >= targets.len() {
                break;
            }
        }
    }

    Ok(keys)
}

fn is_probable_key(b: &[u8]) -> bool {
    if b.len() != 32 {
        return false;
    }
    let mut set = HashSet::new();
    for &byte in b {
        set.insert(byte);
    }
    set.len() >= 15 && b != &[0u8; 32] && b != &[0xFFu8; 32]
}

pub fn derive_keys_from_master(
    master_hex: &str,
    targets: &[DbFileTarget],
) -> Result<HashMap<String, Vec<u8>>> {
    let master_bytes = hex::decode(master_hex.trim())?;
    if master_bytes.len() != 32 {
        anyhow::bail!("主密钥必须为 32 字节 (64 位十六进制字符)");
    }

    let mut keys = HashMap::new();
    for target in targets {
        if target.page1.len() < PAGE_SZ {
            continue;
        }
        let salt = &target.page1[..16];
        let mut derived = [0u8; 32];
        pbkdf2_sha512(&master_bytes, salt, KDF_ITER, &mut derived);
        if verify_enc_key(&derived, &target.page1, None) {
            keys.insert(target.rel_path.clone(), derived.to_vec());
        }
    }
    Ok(keys)
}
