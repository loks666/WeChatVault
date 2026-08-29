use crate::crypto::cipher::{decrypt_page, PAGE_SZ};
use anyhow::Result;
use byteorder::{BigEndian, ByteOrder};
use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const WAL_HEADER_SZ: usize = 32;
pub const WAL_FRAME_SZ: usize = 4120; // 24 header + 4096 page

pub fn merge_wal<P1: AsRef<Path>, P2: AsRef<Path>>(
    dst: P1,
    wal_path: P2,
    key: &[u8],
    from_frame: usize,
) -> Result<usize> {
    if !dst.as_ref().exists() || !wal_path.as_ref().exists() {
        return Ok(0);
    }

    let mut wal_file = std::fs::File::open(wal_path.as_ref())?;
    let wal_len = wal_file.metadata()?.len() as usize;
    if wal_len < WAL_HEADER_SZ {
        return Ok(0);
    }

    let mut wal_hdr = [0u8; WAL_HEADER_SZ];
    wal_file.read_exact(&mut wal_hdr)?;
    let wal_salt = &wal_hdr[16..24];

    let total_frames = (wal_len - WAL_HEADER_SZ) / WAL_FRAME_SZ;
    if from_frame >= total_frames {
        return Ok(from_frame);
    }

    let mut out_file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dst.as_ref())?;

    let mut max_pgno = 0usize;
    let mut last_applied = from_frame;

    let mut frame_hdr = [0u8; 24];
    let mut page_buf = [0u8; PAGE_SZ];

    for i in from_frame..total_frames {
        let frame_offset = (WAL_HEADER_SZ + i * WAL_FRAME_SZ) as u64;
        wal_file.seek(SeekFrom::Start(frame_offset))?;

        if wal_file.read_exact(&mut frame_hdr).is_err() {
            break;
        }
        if wal_file.read_exact(&mut page_buf).is_err() {
            break;
        }

        let pgno = BigEndian::read_u32(&frame_hdr[0..4]) as usize;
        last_applied = i + 1;

        if &frame_hdr[8..16] != wal_salt {
            continue;
        }

        let pt = decrypt_page(key, &page_buf, pgno);
        if pgno == 1 {
            if key.len() == 48 {
                if pt.len() < PAGE_SZ || &pt[16..18] != b"\x01\x01" {
                    continue;
                }
            } else if !pt.starts_with(b"SQLite format 3\0") {
                continue;
            }
        } else if !matches!(pt[0], 0 | 2 | 5 | 10 | 13) {
            continue;
        }

        let write_offset = ((pgno - 1) * PAGE_SZ) as u64;
        out_file.seek(SeekFrom::Start(write_offset))?;
        out_file.write_all(&pt)?;

        if pgno > max_pgno {
            max_pgno = pgno;
        }
    }

    out_file.flush()?;

    let final_out_len = out_file.metadata()?.len() as usize;
    let db_pages = (final_out_len + PAGE_SZ - 1) / PAGE_SZ;

    // 更新 Page 1 中的总页数 (offset 28..32)
    out_file.seek(SeekFrom::Start(0))?;
    let mut page1 = [0u8; PAGE_SZ];
    if out_file.read_exact(&mut page1).is_ok() {
        let hdr_pages = BigEndian::read_u32(&page1[28..32]) as usize;
        let new_pages = hdr_pages.max(max_pgno).max(db_pages);
        if new_pages != hdr_pages {
            BigEndian::write_u32(&mut page1[28..32], new_pages as u32);
            out_file.seek(SeekFrom::Start(0))?;
            out_file.write_all(&page1)?;
            out_file.flush()?;
        }
    }

    Ok(last_applied)
}
