//! APFS (Apple File System) – forensic metadata reader (v1)
//!
//! This crate focuses on parsing APFS on-disk metadata structures.
//! Current scope:
//!   - Parse APFS container superblock (NXSB)
//!   - Heuristic scan for volume superblocks (APSB) and parse basic fields
//!
//! Future work (not implemented yet):
//!   - Container OMAP + volume OMAP traversal (OID -> physical block mapping)
//!   - FS tree traversal for directory listings, file records, etc.

use byteorder::{LittleEndian, ReadBytesExt};
use log::{debug, info, warn};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fmt;
use std::io::{Read, Seek, SeekFrom};

/// APFS object header size (obj_phys_t) in bytes.
const OBJ_PHYS_SIZE: usize = 0x20;

/// Magic values are stored as u32 in little-endian, but are typically expressed as ASCII.
const NXSB_MAGIC: u32 = u32::from_le_bytes(*b"NXSB");
const APSB_MAGIC: u32 = u32::from_le_bytes(*b"APSB");

/// Read exactly `len` bytes from `body` at absolute offset.
fn read_at<T: Read + Seek>(body: &mut T, off: u64, len: usize) -> Result<Vec<u8>, String> {
    body.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; len];
    body.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

/// Format a 16-byte UUID in standard 8-4-4-4-12 hex form.
/// (APFS stores UUID as 16 raw bytes; endianness is “as stored”.)
fn fmt_uuid(u: &[u8; 16]) -> String {
    // Standard display: 8-4-4-4-12
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3],
        u[4], u[5],
        u[6], u[7],
        u[8], u[9],
        u[10], u[11], u[12], u[13], u[14], u[15],
    )
}

/// Minimal APFS object header (obj_phys_t).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjPhys {
    pub checksum: u64,
    pub oid: u64,
    pub xid: u64,
    pub obj_type: u32,
    pub obj_subtype: u32,
}

impl ObjPhys {
    fn parse(buf: &[u8]) -> Result<Self, String> {
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
}

/// APFS container superblock (nx_superblock_t) – **partial** parsing.
/// Enough for identification, block sizing and checkpoint metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NxSuperblock {
    pub o: ObjPhys,
    pub magic: u32,
    pub block_size: u32,
    pub block_count: u64,

    pub features: u64,
    pub readonly_compatible_features: u64,
    pub incompatible_features: u64,

    pub uuid: [u8; 16],

    pub next_oid: u64,
    pub next_xid: u64,

    // Checkpoint descriptor/data areas (used for newer objects, snapshots, etc.)
    pub xp_desc_base: u64,
    pub xp_desc_blocks: u32,
    pub xp_data_base: u64,
    pub xp_data_blocks: u32,

    // Key OIDs (not physically resolvable without OMAP, but useful to display)
    pub spaceman_oid: u64,
    pub omap_oid: u64,
    pub reaper_oid: u64,

    pub max_file_systems: u32,

    /// Raw file system OID array entries that are non-zero (volume superblock OIDs).
    pub fs_oids: Vec<u64>,
}

impl NxSuperblock {
    /// Parse from the start of an APFS container (usually offset 0 of the container).
    /// We read at least 4096 bytes because APFS commonly uses 4KiB blocks.
    pub fn parse_from_container<T: Read + Seek>(body: &mut T) -> Result<Self, String> {
        // Read a “minimum” chunk. Even if block size is larger, NXSB lives at block 0.
        let buf = read_at(body, 0, 4096)?;

        // Object header at 0x00, magic at 0x20
        let o = ObjPhys::parse(&buf[..OBJ_PHYS_SIZE])?;
        let mut c = std::io::Cursor::new(&buf);

        c.set_position(0x20);
        let magic = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        if magic != NXSB_MAGIC {
            return Err(format!(
                "Not an APFS container: NXSB magic mismatch (got 0x{:08x})",
                magic
            ));
        }

        let block_size = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let block_count = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;

        // These offsets follow the “classic” nx_superblock_t layout:
        // features triplet + uuid + next_oid/next_xid + checkpoint info + key OIDs.
        let features = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let readonly_compatible_features =
            c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let incompatible_features = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;

        let mut uuid = [0u8; 16];
        c.read_exact(&mut uuid).map_err(|e| e.to_string())?;

        let next_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let next_xid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;

        // Checkpoint descriptor/data areas (base in blocks)
        let xp_desc_base = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let xp_desc_blocks = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let _xp_desc_len = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?; // often present; keep but ignore

        let xp_data_base = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let xp_data_blocks = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let _xp_data_len = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;

        // Key object IDs
        let spaceman_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let omap_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let reaper_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;

        // The exact layout after this varies across versions.
        // We robustly “seek” for max_file_systems + fs oid array by scanning a small window.
        //
        // Heuristic:
        //   - Look for a plausible max_file_systems (1..=100) followed by many u64 values (fs_oids).
        //   - In Apple headers, nx_max_file_systems is commonly near the fs_oid array.
        //
        // This is defensive: if the layout differs, we still parse NXSB basics.
        let (max_file_systems, fs_oids) = Self::find_fs_oid_array(&buf).unwrap_or((0, Vec::new()));

        Ok(Self {
            o,
            magic,
            block_size,
            block_count,
            features,
            readonly_compatible_features,
            incompatible_features,
            uuid,
            next_oid,
            next_xid,
            xp_desc_base,
            xp_desc_blocks,
            xp_data_base,
            xp_data_blocks,
            spaceman_oid,
            omap_oid,
            reaper_oid,
            max_file_systems,
            fs_oids,
        })
    }

    fn find_fs_oid_array(buf: &[u8]) -> Option<(u32, Vec<u64>)> {
        // Scan a limited range after the start; NXSB is within first block.
        // We look for a u32 in [1..=100], then interpret next 100 * u64 as array.
        for off in (0x80..(buf.len().saturating_sub(4 + 8 * 100))).step_by(4) {
            let max_fs = u32::from_le_bytes(buf[off..off + 4].try_into().ok()?);
            if max_fs == 0 || max_fs > 100 {
                continue;
            }

            // Candidate array starts right after max_fs
            let arr_off = off + 4;
            let mut oids = Vec::new();
            for i in 0..(max_fs as usize) {
                let start = arr_off + i * 8;
                let oid = u64::from_le_bytes(buf[start..start + 8].try_into().ok()?);
                if oid != 0 {
                    oids.push(oid);
                }
            }

            // Accept if it looks plausible: at least one non-zero
            if !oids.is_empty() {
                return Some((max_fs, oids));
            }
        }
        None
    }

    pub fn uuid_string(&self) -> String {
        fmt_uuid(&self.uuid)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "container": {
                "magic": format!("0x{:08x}", self.magic),
                "uuid": self.uuid_string(),
                "block_size": self.block_size,
                "block_count": self.block_count,
                "features": format!("0x{:016x}", self.features),
                "readonly_compatible_features": format!("0x{:016x}", self.readonly_compatible_features),
                "incompatible_features": format!("0x{:016x}", self.incompatible_features),
                "next_oid": self.next_oid,
                "next_xid": self.next_xid,
                "xp_desc_base": self.xp_desc_base,
                "xp_desc_blocks": self.xp_desc_blocks,
                "xp_data_base": self.xp_data_base,
                "xp_data_blocks": self.xp_data_blocks,
                "spaceman_oid": self.spaceman_oid,
                "omap_oid": self.omap_oid,
                "reaper_oid": self.reaper_oid,
                "max_file_systems": self.max_file_systems,
                "fs_oids": self.fs_oids,
            }
        })
    }
}

/// APFS volume superblock (apfs_superblock_t) – **partial** parsing.
/// We locate these by scanning for APSB magic at offset 0x20 (object header + magic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApfsVolumeSuperblock {
    pub o: ObjPhys,
    pub magic: u32,
    pub fs_index: u32,
    pub features: u64,
    pub readonly_compatible_features: u64,
    pub incompatible_features: u64,
    pub uuid: [u8; 16],

    // Commonly useful:
    pub root_tree_oid: u64,
    pub extentref_tree_oid: u64,
    pub snap_meta_tree_oid: u64,
    pub omap_oid: u64,

    /// Physical block address where we found this APSB (scan result).
    pub found_at_block: u64,
}

impl ApfsVolumeSuperblock {
    fn parse_from_block(buf: &[u8], found_at_block: u64) -> Result<Self, String> {
        if buf.len() < 4096 {
            return Err("volume buffer too small".into());
        }
        let o = ObjPhys::parse(&buf[..OBJ_PHYS_SIZE])?;

        let mut c = std::io::Cursor::new(buf);
        c.set_position(0x20);
        let magic = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        if magic != APSB_MAGIC {
            return Err("APSB magic mismatch".into());
        }

        // The following fields are “typical” early apfs_superblock_t members.
        // Layout varies; keep this tolerant.
        let fs_index = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let features = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let readonly_compatible_features =
            c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let incompatible_features = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;

        let mut uuid = [0u8; 16];
        c.read_exact(&mut uuid).map_err(|e| e.to_string())?;

        // These OIDs are often present in early volume superblocks. If offsets shift, values may be garbage,
        // so we guard by reading only if we still have room.
        let mut read_u64_safe = |cur: &mut std::io::Cursor<&[u8]>| -> u64 {
            if (cur.position() as usize) + 8 <= buf.len() {
                cur.read_u64::<LittleEndian>().unwrap_or(0)
            } else {
                0
            }
        };

        let root_tree_oid = read_u64_safe(&mut c);
        let extentref_tree_oid = read_u64_safe(&mut c);
        let snap_meta_tree_oid = read_u64_safe(&mut c);
        let omap_oid = read_u64_safe(&mut c);

        Ok(Self {
            o,
            magic,
            fs_index,
            features,
            readonly_compatible_features,
            incompatible_features,
            uuid,
            root_tree_oid,
            extentref_tree_oid,
            snap_meta_tree_oid,
            omap_oid,
            found_at_block,
        })
    }

    pub fn uuid_string(&self) -> String {
        fmt_uuid(&self.uuid)
    }

    pub fn to_json(&self) -> Value {
        json!({
            "magic": format!("0x{:08x}", self.magic),
            "uuid": self.uuid_string(),
            "fs_index": self.fs_index,
            "features": format!("0x{:016x}", self.features),
            "readonly_compatible_features": format!("0x{:016x}", self.readonly_compatible_features),
            "incompatible_features": format!("0x{:016x}", self.incompatible_features),
            "root_tree_oid": self.root_tree_oid,
            "extentref_tree_oid": self.extentref_tree_oid,
            "snap_meta_tree_oid": self.snap_meta_tree_oid,
            "omap_oid": self.omap_oid,
            "found_at_block": self.found_at_block
        })
    }
}

/// High-level APFS container view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APFS<T: Read + Seek> {
    pub nx: NxSuperblock,
    pub volumes: Vec<ApfsVolumeSuperblock>,
    #[serde(skip)]
    pub body: T,
}

impl<T: Read + Seek> APFS<T> {
    /// Open an APFS container from a reader positioned at container start (use BodySlice).
    pub fn new(mut body: T) -> Result<Self, String> {
        let nx = NxSuperblock::parse_from_container(&mut body)?;
        Ok(Self {
            nx,
            volumes: Vec::new(),
            body,
        })
    }

    /// Heuristic scan for volume superblocks (APSB).
    ///
    /// This does NOT use OMAP (OID -> physical mapping). It simply scans blocks for APSB magic.
    /// `max_blocks` is a safety limit (e.g., 1_048_576 blocks = 4 GiB at 4KiB).
    pub fn scan_volumes(&mut self, max_blocks: u64) -> Result<(), String> {
        let bs = self.nx.block_size as u64;
        if bs == 0 || bs > 1024 * 1024 {
            return Err(format!("implausible APFS block size: {}", bs));
        }

        info!(
            "Scanning for APSB volume superblocks: up to {} blocks (block_size={} bytes)",
            max_blocks, bs
        );

        // Keep unique UUIDs; APFS can store multiple copies.
        let mut seen = std::collections::HashSet::<[u8; 16]>::new();

        for b in 0..max_blocks {
            let off = b.saturating_mul(bs);
            let buf = match read_at(&mut self.body, off, bs as usize) {
                Ok(v) => v,
                Err(e) => {
                    warn!("scan read failed at block {} (0x{:x}): {}", b, off, e);
                    break;
                }
            };

            if buf.len() < 0x24 {
                break;
            }
            let magic = u32::from_le_bytes(buf[0x20..0x24].try_into().unwrap());
            if magic != APSB_MAGIC {
                continue;
            }

            if let Ok(vsb) = ApfsVolumeSuperblock::parse_from_block(&buf, b) {
                if seen.insert(vsb.uuid) {
                    info!(
                        "Found APSB volume superblock: uuid={} at block {}",
                        vsb.uuid_string(),
                        b
                    );
                    self.volumes.push(vsb);
                } else {
                    debug!(
                        "Duplicate APSB for uuid={} at block {}",
                        vsb.uuid_string(),
                        b
                    );
                }
            }
        }

        if self.volumes.is_empty() {
            warn!("No APSB volume superblocks found in the scanned range.");
        }
        Ok(())
    }

    pub fn print_info(&self) {
        info!("APFS Container Information:");
        info!("  Magic: NXSB");
        info!("  Container UUID: {}", self.nx.uuid_string());
        info!("  Block Size: {} bytes", self.nx.block_size);
        info!("  Block Count: {}", self.nx.block_count);
        info!(
            "  Features: rw=0x{:016x} ro_compat=0x{:016x} incompat=0x{:016x}",
            self.nx.features, self.nx.readonly_compatible_features, self.nx.incompatible_features
        );
        info!("  Next OID: {}", self.nx.next_oid);
        info!("  Next XID: {}", self.nx.next_xid);
        info!(
            "  Checkpoint: desc_base={} desc_blocks={} data_base={} data_blocks={}",
            self.nx.xp_desc_base,
            self.nx.xp_desc_blocks,
            self.nx.xp_data_base,
            self.nx.xp_data_blocks
        );
        info!(
            "  Key OIDs: spaceman={} omap={} reaper={}",
            self.nx.spaceman_oid, self.nx.omap_oid, self.nx.reaper_oid
        );

        if self.nx.max_file_systems != 0 {
            info!("  Max Filesystems: {}", self.nx.max_file_systems);
            if !self.nx.fs_oids.is_empty() {
                info!(
                    "  Volume superblock OIDs (from NXSB): {:?}",
                    self.nx.fs_oids
                );
                info!("  (Note: OIDs require OMAP to resolve to physical blocks.)");
            }
        }

        if !self.volumes.is_empty() {
            info!("APFS Volumes (scan results): {}", self.volumes.len());
            for v in &self.volumes {
                info!(
                    "  - UUID={} fs_index={} found_at_block={} root_tree_oid={} omap_oid={}",
                    v.uuid_string(),
                    v.fs_index,
                    v.found_at_block,
                    v.root_tree_oid,
                    v.omap_oid
                );
            }
        }
    }

    pub fn to_json(&self) -> Value {
        let vols = self.volumes.iter().map(|v| v.to_json()).collect::<Vec<_>>();
        let mut j = self.nx.to_json();
        if let Some(obj) = j.as_object_mut() {
            obj.insert("volumes".to_string(), json!(vols));
        }
        j
    }
}

impl fmt::Display for NxSuperblock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "APFS NXSB")?;
        writeln!(f, "  UUID: {}", self.uuid_string())?;
        writeln!(f, "  Block size: {}", self.block_size)?;
        writeln!(f, "  Block count: {}", self.block_count)?;
        Ok(())
    }
}
