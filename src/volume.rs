//! APFS volume superblock (`APSB`) parsing.

use crate::object::{ObjPhys, OBJ_PHYS_SIZE};
use serde::{Deserialize, Serialize};

const APSB_MAGIC: u32 = u32::from_le_bytes(*b"APSB");

/// Parsed APFS volume superblock subset used by the parser.
///
/// Corresponds to `apfs_superblock_t` (APSB). It contains pointers to the
/// volume's Object Map and file system tree, as well as metadata like role and name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApfsVolumeSuperblock {
    pub o: ObjPhys,
    pub magic: u32,
    pub fs_index: u32,
    pub features: u64,
    pub readonly_compatible_features: u64,
    pub incompatible_features: u64,

    pub omap_oid: u64,
    pub root_tree_oid: u64,
    pub extentref_tree_oid: u64,
    pub snap_meta_tree_oid: u64,
    pub revert_to_xid: u64,
    pub revert_to_sblock_oid: u64,

    pub vol_uuid: [u8; 16],
    pub role: u16,
    pub volume_name: String,
    /// Physical block address where this APSB was discovered.
    pub found_at_block: u64,
}

impl ApfsVolumeSuperblock {
    /// Parses an APSB from a full block and records its physical location.
    pub fn parse_from_block(buf: &[u8], found_at_block: u64) -> Result<Self, String> {
        if buf.len() < 4096 {
            return Err("volume block too small".into());
        }
        let o = ObjPhys::parse(&buf[..OBJ_PHYS_SIZE])?;
        let magic = u32::from_le_bytes(buf[0x20..0x24].try_into().unwrap());
        if magic != APSB_MAGIC {
            return Err("APSB magic mismatch".into());
        }
        let fs_index = u32::from_le_bytes(buf[0x24..0x28].try_into().unwrap());
        let features = u64::from_le_bytes(buf[0x28..0x30].try_into().unwrap());
        let readonly_compatible_features = u64::from_le_bytes(buf[0x30..0x38].try_into().unwrap());
        let incompatible_features = u64::from_le_bytes(buf[0x38..0x40].try_into().unwrap());

        // APFS APSB layouts differ across versions (notably around wrapped_meta_crypto_state).
        // Parse both known layouts and pick the more plausible pointer set.
        let legacy = parse_layout(buf, 0x80, 0xF0, 0x37c, 0x278);
        let modern = parse_layout(buf, 0x84, 0xF4, 0x380, 0x27c);
        let selected = if layout_score(&legacy) >= layout_score(&modern) {
            legacy
        } else {
            modern
        };

        Ok(Self {
            o,
            magic,
            fs_index,
            features,
            readonly_compatible_features,
            incompatible_features,
            omap_oid: selected.omap_oid,
            root_tree_oid: selected.root_tree_oid,
            extentref_tree_oid: selected.extentref_tree_oid,
            snap_meta_tree_oid: selected.snap_meta_tree_oid,
            revert_to_xid: selected.revert_to_xid,
            revert_to_sblock_oid: selected.revert_to_sblock_oid,
            vol_uuid: selected.vol_uuid,
            role: selected.role,
            volume_name: selected.volume_name,
            found_at_block,
        })
    }
}

#[derive(Debug, Clone)]
struct ParsedLayout {
    omap_oid: u64,
    root_tree_oid: u64,
    extentref_tree_oid: u64,
    snap_meta_tree_oid: u64,
    revert_to_xid: u64,
    revert_to_sblock_oid: u64,
    vol_uuid: [u8; 16],
    role: u16,
    volume_name: String,
}

fn parse_layout(
    buf: &[u8],
    tree_base_off: usize,
    uuid_off: usize,
    role_off: usize,
    name_off: usize,
) -> ParsedLayout {
    let omap_oid = u64::from_le_bytes(buf[tree_base_off..tree_base_off + 8].try_into().unwrap());
    let root_tree_oid = u64::from_le_bytes(
        buf[tree_base_off + 8..tree_base_off + 16]
            .try_into()
            .unwrap(),
    );
    let extentref_tree_oid = u64::from_le_bytes(
        buf[tree_base_off + 16..tree_base_off + 24]
            .try_into()
            .unwrap(),
    );
    let snap_meta_tree_oid = u64::from_le_bytes(
        buf[tree_base_off + 24..tree_base_off + 32]
            .try_into()
            .unwrap(),
    );
    let revert_to_xid = u64::from_le_bytes(
        buf[tree_base_off + 32..tree_base_off + 40]
            .try_into()
            .unwrap(),
    );
    let revert_to_sblock_oid = u64::from_le_bytes(
        buf[tree_base_off + 40..tree_base_off + 48]
            .try_into()
            .unwrap(),
    );

    let mut vol_uuid = [0u8; 16];
    vol_uuid.copy_from_slice(&buf[uuid_off..uuid_off + 16]);
    let role = u16::from_le_bytes(buf[role_off..role_off + 2].try_into().unwrap());
    let volume_name = parse_volume_name(buf, name_off);

    ParsedLayout {
        omap_oid,
        root_tree_oid,
        extentref_tree_oid,
        snap_meta_tree_oid,
        revert_to_xid,
        revert_to_sblock_oid,
        vol_uuid,
        role,
        volume_name,
    }
}

fn layout_score(v: &ParsedLayout) -> i32 {
    let mut score = 0;
    for oid in [
        v.omap_oid,
        v.root_tree_oid,
        v.extentref_tree_oid,
        v.snap_meta_tree_oid,
        v.revert_to_sblock_oid,
    ] {
        if oid > 0 {
            score += 1;
        }
        if oid < (1u64 << 32) {
            score += 2;
        }
        // Reject obvious 32-bit-shift artifacts (e.g. 1028 << 32).
        if (oid & 0xffff_ffff) == 0 && (oid >> 32) != 0 {
            score -= 3;
        }
    }
    if !v.volume_name.is_empty() {
        score += 1;
    }
    score
}

fn parse_volume_name(buf: &[u8], name_off: usize) -> String {
    let name_bytes = &buf[name_off..name_off + 0x100];
    let end = name_bytes
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(name_bytes.len());
    std::str::from_utf8(&name_bytes[..end])
        .map(|s| s.to_string())
        .unwrap_or_default()
}
