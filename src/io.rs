//! Low-level read helpers for block and physical-address access.

use std::io::{Read, Seek, SeekFrom};

/// Reads `len` bytes from absolute byte offset `off`.
pub fn read_at<T: Read + Seek>(body: &mut T, off: u64, len: usize) -> Result<Vec<u8>, String> {
    body.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; len];
    body.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Reads one logical block at block index `block_index`.
pub fn read_block<T: Read + Seek>(
    body: &mut T,
    block_size: u64,
    paddr: u64,
) -> Result<Vec<u8>, String> {
    let off = paddr
        .checked_mul(block_size)
        .ok_or_else(|| "paddr*block_size overflow".to_string())?;
    read_at(body, off, block_size as usize)
}

/// Read `len` bytes starting at physical block `paddr` (not necessarily aligned to one block).
/// Reads `len` bytes from a physical block address `paddr`.
pub fn read_phys<T: Read + Seek>(
    body: &mut T,
    block_size: u64,
    paddr: u64,
    len: usize,
) -> Result<Vec<u8>, String> {
    let off = paddr
        .checked_mul(block_size)
        .ok_or_else(|| "paddr*block_size overflow".to_string())?;
    read_at(body, off, len)
}
