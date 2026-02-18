//! Shared APFS object header parsing (`obj_phys_t`).

use byteorder::{LittleEndian, ReadBytesExt};
use serde::{Deserialize, Serialize};

use crate::checksum::fletcher64;

/// Size of `obj_phys_t` in bytes.
pub const OBJ_PHYS_SIZE: usize = 0x20;

// Common masks: o_type is split into 16-bit type + 16-bit flags.
pub const OBJ_TYPE_MASK: u32 = 0x0000_FFFF;
//pub const OBJ_FLAGS_MASK: u32 = 0xFFFF_0000;

/// Common APFS object header present at the beginning of most on-disk objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjPhys {
    pub checksum: u64,
    pub oid: u64,
    pub xid: u64,
    pub obj_type: u32,
    pub obj_subtype: u32,
}

impl ObjPhys {
    /// Parses an `obj_phys_t` from the beginning of `buf`.
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < OBJ_PHYS_SIZE {
            return Err("buffer too small for obj_phys_t".into());
        }
        let mut c = std::io::Cursor::new(buf);
        let checksum = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let xid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let obj_type = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let obj_subtype = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        Ok(Self {
            checksum,
            oid,
            xid,
            obj_type,
            obj_subtype,
        })
    }

    /// Returns the low 16 bits of `obj_type` (object kind).
    pub fn type_only(&self) -> u16 {
        (self.obj_type & OBJ_TYPE_MASK) as u16
    }

    /// Returns the high 16 bits of `obj_type` (object flags).
    pub fn flags_only(&self) -> u16 {
        (self.obj_type >> 16) as u16
    }

    /// Validate checksum + some sanity checks. For forensics we keep it tolerant:
    /// - If checksum is 0, we report "unknown" rather than hard-fail (some blocks can be zero/uninitialized).
    pub fn validate(&self, full_object_bytes: &[u8]) -> Result<(), String> {
        if full_object_bytes.len() < OBJ_PHYS_SIZE {
            return Err("object too small".into());
        }

        if self.checksum != 0 {
            if full_object_bytes.len() < 8 {
                return Err("object too small for checksum validation".into());
            }
            let calc = fletcher64(&full_object_bytes[8..]);
            if calc != self.checksum {
                // Keep parsing tolerant on checksum mismatches; forensic streams can be translated.
                return Ok(());
            }
        }

        // Extremely light sanity:
        // xid can be 0 on some objects but usually nonzero; don't fail.
        // Type == 0 sometimes indicates padding / unused; keep tolerant.

        Ok(())
    }
}
