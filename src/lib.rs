//! APFS container and volume parsing primitives.
//!
//! This crate provides a metadata-first approach to parsing Apple File System (APFS)
//! structures directly from a readable and seekable body (e.g., a disk image or block device).
//!
//! # Core Components
//! - [`APFS`]: The main entry point, representing an APFS container.
//! - [`NxSuperblock`]: The container-level superblock (NXSB).
//! - [`ApfsVolumeSuperblock`]: The volume-level superblock (APSB).
//! - [`FsTree`]: High-level access to the file system tree of a volume.
//!
//! # Features
//! - NXSB parsing and volume discovery (including checkpoint resolution).
//! - Container and volume-level Object Map (OMAP) resolution.
//! - Virtual and physical B-tree traversal.
//! - Fallback mechanisms for corrupted or complex volume states.

mod btree;
mod checksum;
mod fstree;
pub mod io;
mod object;
mod omap;
mod path;
mod volume;

pub use btree::{BTree, BTreeKeyCmp};
use byteorder::{LittleEndian, ReadBytesExt};
pub use fstree::{DirEntry, FsTree, InodeVal, JKey, is_dir_mode, apfs_kind, apfs_mode_to_string, fmt_apfs_ns_utc};
use log::{info, warn};
use serde::{Deserialize, Serialize};
pub use volume::ApfsVolumeSuperblock;

use serde_json::{json, Value};
use std::io::{Read, Seek, SeekFrom};

use crate::omap::Omap;

const OBJ_PHYS_SIZE: usize = 0x20;

/// Minimal APFS object header (`obj_phys_t`).
///
/// Every on-disk APFS object begins with this header, which includes a checksum,
/// object ID (oid), transaction ID (xid), and type information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjPhys {
    /// Fletcher-64 checksum of the object data (excluding the checksum field).
    pub checksum: u64,
    /// The object's unique identifier.
    pub oid: u64,
    /// The transaction identifier when this version of the object was written.
    pub xid: u64,
    /// The main object type (e.g., NXSB, APSB, Btree).
    pub obj_type: u32,
    /// The object subtype (e.g., OMAP, SNAPSHOT_METADATA).
    pub obj_subtype: u32,
}

impl ObjPhys {
    /// Parses a 32-byte object header from a buffer.
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

    /// Validates the object's checksum against the provided data.
    pub fn validate(&self, full_object_bytes: &[u8]) -> Result<(), String> {
        if full_object_bytes.len() < OBJ_PHYS_SIZE {
            return Err("object too small".into());
        }
        if self.checksum != 0 {
            let calc = crate::checksum::fletcher64(&full_object_bytes[8..]);
            if calc != self.checksum {
                // Checksum failure is common in some scenarios; we report it as a Result.
                return Err("checksum mismatch".into());
            }
        }
        Ok(())
    }
}

/// APFS container superblock (`nx_superblock_t`).
///
/// Represents the top-level structure of an APFS container, containing
/// block size information, checkpoint ranges, and volume object IDs.
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

    /// Base block address of the checkpoint descriptor area.
    pub xp_desc_base: u64,
    /// Number of blocks in the checkpoint descriptor area.
    pub xp_desc_blocks: u32,
    /// Base block address of the checkpoint data area.
    pub xp_data_base: u64,
    /// Number of blocks in the checkpoint data area.
    pub xp_data_blocks: u32,

    // Key OIDs (not physically resolvable without OMAP, but useful to display)
    pub spaceman_oid: u64,
    pub omap_oid: u64,
    pub reaper_oid: u64,

    pub max_file_systems: u32,

    /// Valid volume superblock object IDs discovered in the container.
    pub fs_oids: Vec<u64>,
}

/// Magic values are stored as u32 in little-endian, but are typically expressed as ASCII.
const NXSB_MAGIC: u32 = u32::from_le_bytes(*b"NXSB");

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

/// Read exactly `len` bytes from `body` at absolute offset.
fn read_at<T: Read + Seek>(body: &mut T, off: u64, len: usize) -> Result<Vec<u8>, String> {
    body.seek(SeekFrom::Start(off)).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; len];
    body.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

impl NxSuperblock {
    /// Parse from the start of an APFS container (usually offset 0 of the container).
    /// We parse block 0 first, then prefer the latest valid checkpointed NXSB from xp_desc.
    pub fn parse_from_container<T: Read + Seek>(body: &mut T) -> Result<Self, String> {
        // Read a minimum chunk; NXSB block 0 provides block_size + checkpoint ranges.
        let buf0 = read_at(body, 0, 4096)?;
        let mut best = Self::parse_from_nx_block(&buf0)?;
        let mut best_xid = best.o.xid;
        let bs = best.block_size as u64;

        // Search checkpoint descriptor area for newer NXSB objects.
        // This is metadata-guided (bounded by xp_desc_*), not whole-container scanning.
        for i in 0..(best.xp_desc_blocks as u64) {
            let paddr = best.xp_desc_base.saturating_add(i);
            let off = paddr
                .checked_mul(bs)
                .ok_or_else(|| "checkpoint paddr*block_size overflow".to_string())?;
            let buf = match read_at(body, off, bs as usize) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if buf.len() < 0x24 {
                continue;
            }

            let magic = u32::from_le_bytes(match buf[0x20..0x24].try_into() {
                Ok(v) => v,
                Err(_) => continue,
            });
            if magic != NXSB_MAGIC {
                continue;
            }

            let candidate = match Self::parse_from_nx_block(&buf) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if candidate.o.validate(&buf).is_err() {
                continue;
            }
            if candidate.o.xid >= best_xid {
                best_xid = candidate.o.xid;
                best = candidate;
            }
        }

        Ok(best)
    }

    fn parse_from_nx_block(buf: &[u8]) -> Result<Self, String> {
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

        // Canonical nx_superblock_t layout (post obj_phys):
        // magic, block_size, block_count, features triplet, uuid,
        // next_oid, next_xid, checkpoint fields, then key object OIDs.
        let features = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let readonly_compatible_features =
            c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let incompatible_features = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;

        let mut uuid = [0u8; 16];
        c.read_exact(&mut uuid).map_err(|e| e.to_string())?;

        let next_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let next_xid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;

        // Checkpoint descriptor/data areas.
        let xp_desc_blocks = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let xp_data_blocks = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let xp_desc_base = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let xp_data_base = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let _xp_desc_next = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let _xp_data_next = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let _xp_desc_index = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let _xp_desc_len = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let _xp_data_index = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let _xp_data_len = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;

        // Key object IDs
        let spaceman_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let omap_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let reaper_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let _test_type = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let max_file_systems = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        // nx_fs_oid[] is 8-byte aligned; consume optional 4-byte padding.
        if !c.position().is_multiple_of(8) {
            let _pad = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        }

        // nx_fs_oid[] is 100 entries in current public layouts.
        // We parse up to the declared max (clamped to available bytes and 100).
        let mut fs_oids = Vec::new();
        let to_read = (max_file_systems as usize).min(100);
        for _ in 0..to_read {
            let oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
            if oid != 0 {
                fs_oids.push(oid);
            }
        }

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

/// Main APFS container handle.
///
/// This structure holds the container superblock, discovered volumes,
/// and the underlying body stream. It also maintains an active context
/// for OMAP and transaction ID (xid) resolution used during B-tree traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APFS<T: Read + Seek> {
    /// The container superblock.
    pub nx: crate::NxSuperblock,
    /// Volumes discovered within the container.
    pub volumes: Vec<ApfsVolumeSuperblock>,
    #[serde(skip)]
    pub body: T,

    /// Active Object Map used for virtual child resolution.
    #[serde(skip)]
    pub(crate) active_omap: Option<Omap>,
    /// Active transaction ID used for temporal lookups.
    #[serde(skip)]
    pub(crate) active_xid: u64,
}


impl<T: Read + Seek> APFS<T> {
    /// Returns the APFS logical block size in bytes.
    pub fn block_size_u64(&self) -> u64 {
        self.nx.block_size as u64
    }

    /// Sets the active Object Map and transaction ID context.
    ///
    /// This context is used during B-tree traversal to resolve virtual object IDs.
    pub fn set_active_omap(&mut self, omap: Option<Omap>, xid: u64) {
        self.active_omap = omap;
        self.active_xid = xid;
    }

    /// Opens an APFS container from a body stream.
    ///
    /// This method parses the container superblock and automatically discovers
    /// all available volumes.
    pub fn new(mut body: T) -> Result<Self, String> {
        let nx = crate::NxSuperblock::parse_from_container(&mut body)?;

        info!(
            "NXSB ok: block_size={} block_count={} next_xid={} uuid={}",
            nx.block_size,
            nx.block_count,
            nx.next_xid,
            nx.uuid_string(),
        );

        let mut apfs = Self {
            nx,
            volumes: Vec::new(),
            body,
            active_omap: None,
            active_xid: 0,
        };

        apfs.load_volumes_from_metadata()?;
        Ok(apfs)
    }

    /// Populates the volume list using container metadata.
    ///
    /// Attempts to resolve volume superblocks via the container OMAP. If the OMAP
    /// is unavailable or incomplete, it falls back to scanning checkpoint descriptor blocks.
    pub fn load_volumes_from_metadata(&mut self) -> Result<(), String> {
        if self.nx.fs_oids.is_empty() {
            return Err("NXSB does not expose any fs_oids (cannot enumerate volumes)".into());
        }

        let omap_oid = self.nx.omap_oid;
        if omap_oid == 0 {
            return Err("NXSB omap_oid is zero (cannot resolve fs_oids to paddr)".into());
        }

        let xid = self.nx.next_xid.saturating_sub(1);
        let container_omap: Option<crate::omap::Omap> = match crate::omap::Omap::open(
            self, omap_oid,
        ) {
            Ok(v) => Some(v),
            Err(first_err) => {
                // On many APFS images nx_omap_oid is an object-id (not direct paddr).
                // Resolve it from checkpoint metadata and retry.
                match self
                    .resolve_checkpoint_paddr_for_oid(omap_oid)
                    .and_then(|omap_paddr| {
                        crate::omap::Omap::open(self, omap_paddr).map_err(|e| {
                            format!(
                                "Cannot open container OMAP (oid {} -> paddr {}): {}",
                                omap_oid, omap_paddr, e
                            )
                        })
                    }) {
                    Ok(v) => Some(v),
                    Err(second_err) => {
                        warn!(
                            "Container OMAP unavailable (direct: {}; checkpoint-resolved: {}). Falling back to fs_oids as physical paddr.",
                            first_err, second_err
                        );
                        None
                    }
                }
            }
        };

        let bs = self.block_size_u64();
        self.volumes.clear();

        if container_omap.is_none() {
            self.load_volumes_from_checkpoint_blocks()?;
            info!(
                "Loaded {} APFS volume(s) from checkpoint metadata blocks",
                self.volumes.len()
            );
            return Ok(());
        }

        let mut seen = std::collections::HashSet::<(u32, [u8; 16], u64)>::new();
        for fs_oid in self.nx.fs_oids.clone() {
            let paddr = if let Some(container_omap) = &container_omap {
                match container_omap.lookup(self, fs_oid, xid) {
                    Ok(m) => {
                        if m.paddr >= self.nx.block_count {
                            if fs_oid < self.nx.block_count {
                                warn!(
                                    "Container OMAP returned implausible paddr={} for fs_oid={} at xid={}; falling back to fs_oid as paddr",
                                    m.paddr, fs_oid, xid
                                );
                                fs_oid
                            } else {
                                return Err(format!(
                                    "Container OMAP returned implausible paddr={} for fs_oid={} (block_count={})",
                                    m.paddr, fs_oid, self.nx.block_count
                                ));
                            }
                        } else {
                            m.paddr
                        }
                    }
                    Err(e) => {
                        // Some images still store physical addresses directly in fs_oids.
                        if fs_oid < self.nx.block_count {
                            warn!(
                                "Container OMAP lookup failed for fs_oid={} at xid={}; falling back to paddr={} ({})",
                                fs_oid, xid, fs_oid, e
                            );
                            fs_oid
                        } else {
                            return Err(format!(
                                "Cannot resolve volume fs_oid={} through container OMAP at xid={}: {}",
                                fs_oid, xid, e
                            ));
                        }
                    }
                }
            } else {
                if fs_oid >= self.nx.block_count {
                    return Err(format!(
                        "fs_oid={} cannot be used as paddr (block_count={})",
                        fs_oid, self.nx.block_count
                    ));
                }
                fs_oid
            };

            let buf = crate::io::read_block(&mut self.body, bs, paddr)
                .map_err(|e| format!("Cannot read APSB block at paddr={}: {}", paddr, e))?;
            let vsb = match crate::volume::ApfsVolumeSuperblock::parse_from_block(&buf, paddr) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "Skipping non-APSB candidate at paddr={} (fs_oid={}): {}",
                        paddr, fs_oid, e
                    );
                    continue;
                }
            };

            // Keep checksum validation tolerant but informative.
            if let Err(e) = vsb.o.validate(&buf) {
                warn!(
                    "APSB checksum/sanity validation warning at paddr={} fs_oid={}: {}",
                    paddr, fs_oid, e
                );
            }

            let key = (vsb.fs_index, vsb.vol_uuid, vsb.found_at_block);
            if seen.insert(key) {
                self.volumes.push(vsb);
            }
        }

        if self.volumes.is_empty() {
            self.load_volumes_from_checkpoint_blocks()?;
            info!(
                "Loaded {} APFS volume(s) from checkpoint metadata blocks",
                self.volumes.len()
            );
            return Ok(());
        }

        // Augment metadata enumeration with checkpoint APSBs, then keep newest per volume.
        if let Err(e) = self.load_volumes_from_checkpoint_blocks() {
            warn!("Checkpoint APSB augmentation failed: {}", e);
        }
        let mut newest = std::collections::HashMap::<(u32, [u8; 16]), ApfsVolumeSuperblock>::new();
        for v in self.volumes.drain(..) {
            let key = (v.fs_index, v.vol_uuid);
            match newest.get(&key) {
                Some(cur) if (cur.o.xid, cur.found_at_block) >= (v.o.xid, v.found_at_block) => {}
                _ => {
                    newest.insert(key, v);
                }
            }
        }
        self.volumes = newest.into_values().collect();
        self.volumes.sort_by_key(|v| v.fs_index);

        info!(
            "Loaded {} APFS volume(s) from NXSB metadata (no block scanning)",
            self.volumes.len()
        );
        Ok(())
    }

    /// Resolves an object ID (oid) to its latest physical block address.
    ///
    /// Scans the container's checkpoint metadata ranges for the version of the object
    /// with the highest transaction ID (xid).
    fn resolve_checkpoint_paddr_for_oid(&mut self, oid: u64) -> Result<u64, String> {
        let bs = self.block_size_u64();
        let mut best: Option<(u64, u64)> = None; // (xid, paddr)

        let ranges = [
            (
                self.nx.xp_desc_base,
                self.nx.xp_desc_blocks as u64,
                "xp_desc",
            ),
            (
                self.nx.xp_data_base,
                self.nx.xp_data_blocks as u64,
                "xp_data",
            ),
        ];

        for (base, blocks, _name) in ranges {
            for i in 0..blocks {
                let paddr = base.saturating_add(i);
                let buf = match crate::io::read_block(&mut self.body, bs, paddr) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let obj = match crate::object::ObjPhys::parse(&buf) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if obj.oid != oid {
                    continue;
                }

                if obj.validate(&buf).is_err() {
                    continue;
                }

                match best {
                    Some((best_xid, _)) if best_xid >= obj.xid => {}
                    _ => best = Some((obj.xid, paddr)),
                }
            }
        }

        let (_, paddr) = best.ok_or_else(|| {
            format!(
                "No valid checkpoint object found for oid={} in xp_desc/xp_data ranges",
                oid
            )
        })?;
        Ok(paddr)
    }

    /// Loads volume superblocks from checkpoint metadata.
    ///
    /// This is used as a fallback if the main volume enumeration fails or to discover
    /// snapshots and older versions of volumes.
    fn load_volumes_from_checkpoint_blocks(&mut self) -> Result<(), String> {
        let bs = self.block_size_u64();
        let mut seen = self
            .volumes
            .iter()
            .map(|v| (v.fs_index, v.vol_uuid, v.found_at_block))
            .collect::<std::collections::HashSet<_>>();

        let ranges = [
            (self.nx.xp_desc_base, self.nx.xp_desc_blocks as u64),
            (self.nx.xp_data_base, self.nx.xp_data_blocks as u64),
        ];

        for (base, blocks) in ranges {
            for i in 0..blocks {
                let paddr = base.saturating_add(i);
                let buf = match crate::io::read_block(&mut self.body, bs, paddr) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if buf.len() < 0x24 {
                    continue;
                }
                let magic = u32::from_le_bytes(buf[0x20..0x24].try_into().unwrap());
                if magic != u32::from_le_bytes(*b"APSB") {
                    continue;
                }

                let vsb = match crate::volume::ApfsVolumeSuperblock::parse_from_block(&buf, paddr) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if vsb.o.validate(&buf).is_err() {
                    continue;
                }

                let key = (vsb.fs_index, vsb.vol_uuid, vsb.found_at_block);
                if seen.insert(key) {
                    self.volumes.push(vsb);
                }
            }
        }

        if self.volumes.is_empty() {
            return Err(
                "No APSB volume superblocks found in checkpoint metadata blocks (xp_desc/xp_data)"
                    .into(),
            );
        }
        Ok(())
    }



    fn open_container_omap_for_xid(&mut self, xid: u64) -> Result<crate::omap::Omap, String> {
        let direct = crate::omap::Omap::open(self, self.nx.omap_oid);
        match direct {
            Ok(v) => Ok(v),
            Err(first_err) => {
                let omap_paddr = self.resolve_checkpoint_paddr_for_oid(self.nx.omap_oid)?;
                crate::omap::Omap::open(self, omap_paddr).map_err(|e| {
                    format!(
                        "Cannot open container OMAP for xid={} (direct err: {}; checkpoint paddr={} err: {})",
                        xid, first_err, omap_paddr, e
                    )
                })
            }
        }
    }

    /// Opens and validates a filesystem tree for a volume.
    pub fn open_fstree_for_volume(
        &mut self,
        vol: &ApfsVolumeSuperblock,
    ) -> Result<crate::fstree::FsTree, String> {
        let (omap, traversal_xid) = self.open_volume_omap_for_volume(vol)?;
        let root_tree =
            crate::btree::BTree::open_virtual(self, vol.root_tree_oid, &omap, traversal_xid)?;

        // Ensure this xid/omap pair yields a traversable FS tree.
        self.set_active_omap(Some(omap.clone()), traversal_xid);
        let probe_res = match root_tree.seek(self, &[], &crate::btree::BTreeKeyCmp::Lex) {
            Ok(mut c) => c.next(self).map_err(|e| e.to_string()).and_then(|v| {
                if v.is_some() {
                    Ok(())
                } else {
                    Err("empty tree".into())
                }
            }),
            Err(e) => Err(e),
        };
        if let Err(e) = probe_res {
            warn!(
                "root_tree probe warning for fs_index={} root_tree_oid={} xid={}: {}",
                vol.fs_index, vol.root_tree_oid, traversal_xid, e
            );
            if let Some((alt_tree, alt_xid, alt_oid)) =
                self.open_revert_sblock_fallback_tree(vol, &omap, traversal_xid)?
            {
                warn!(
                    "Using revert_to_sblock fallback for fs_index={} alt_root_tree_oid={} xid={}",
                    vol.fs_index, alt_oid, alt_xid
                );
                return Ok(crate::fstree::FsTree::new(omap, alt_tree, alt_xid));
            }
            if let Some((alt_tree, alt_xid, alt_oid)) =
                self.open_snapshot_fallback_tree(vol, &omap, traversal_xid)?
            {
                warn!(
                    "Using snapshot fallback tree for fs_index={} alt_root_tree_oid={} xid={}",
                    vol.fs_index, alt_oid, alt_xid
                );
                return Ok(crate::fstree::FsTree::new(omap, alt_tree, alt_xid));
            }
        }
        Ok(crate::fstree::FsTree::new(omap, root_tree, traversal_xid))
    }

    fn open_revert_sblock_fallback_tree(
        &mut self,
        vol: &ApfsVolumeSuperblock,
        omap: &crate::omap::Omap,
        effective_xid: u64,
    ) -> Result<Option<(crate::btree::BTree, u64, u64)>, String> {
        if vol.revert_to_sblock_oid == 0 {
            return Ok(None);
        }

        let mut lookup_xids = vec![vol.revert_to_xid, vol.o.xid, effective_xid];
        if !lookup_xids.contains(&u64::MAX) {
            lookup_xids.push(u64::MAX);
        }
        lookup_xids.retain(|x| *x != 0);
        lookup_xids.sort_unstable();
        lookup_xids.dedup();

        let bs = self.block_size_u64();
        for lxid in lookup_xids {
            let Ok((sb_xid, map)) = omap.lookup_with_key_xid(self, vol.revert_to_sblock_oid, lxid)
            else {
                continue;
            };
            if map.paddr >= self.nx.block_count {
                continue;
            }

            let Ok(buf) = crate::io::read_block(&mut self.body, bs, map.paddr) else {
                continue;
            };
            if buf.get(0x20..0x24) != Some(b"APSB".as_ref()) {
                continue;
            }

            let Ok(snap_vsb) =
                crate::volume::ApfsVolumeSuperblock::parse_from_block(&buf, map.paddr)
            else {
                continue;
            };

            let mut root_xids = vec![snap_vsb.o.xid, vol.revert_to_xid, sb_xid, effective_xid];
            if !root_xids.contains(&u64::MAX) {
                root_xids.push(u64::MAX);
            }
            root_xids.retain(|x| *x != 0);
            root_xids.sort_unstable();
            root_xids.dedup();

            for rxid in root_xids {
                let Ok((root_xid, _)) =
                    omap.lookup_with_key_xid(self, snap_vsb.root_tree_oid, rxid)
                else {
                    continue;
                };
                let Ok(tree) =
                    crate::btree::BTree::open_virtual(self, snap_vsb.root_tree_oid, omap, root_xid)
                else {
                    continue;
                };
                let trial = crate::fstree::FsTree::new(omap.clone(), tree.clone(), root_xid);
                if trial.detect_root_inode_id(self)?.is_some() {
                    warn!(
                        "revert_to_sblock fallback: sblock_oid={} sblock_paddr={} root_tree_oid={} root_xid={}",
                        vol.revert_to_sblock_oid, map.paddr, snap_vsb.root_tree_oid, root_xid
                    );
                    return Ok(Some((tree, root_xid, snap_vsb.root_tree_oid)));
                }
            }
        }

        Ok(None)
    }

    fn open_snapshot_fallback_tree(
        &mut self,
        vol: &ApfsVolumeSuperblock,
        omap: &crate::omap::Omap,
        effective_xid: u64,
    ) -> Result<Option<(crate::btree::BTree, u64, u64)>, String> {
        if vol.snap_meta_tree_oid == 0 {
            warn!("snapshot fallback: snap_meta_tree_oid is zero");
            return Ok(None);
        }

        let snap_tree = if omap
            .lookup_with_key_xid(self, vol.snap_meta_tree_oid, effective_xid)
            .is_ok()
        {
            match crate::btree::BTree::open_virtual(
                self,
                vol.snap_meta_tree_oid,
                omap,
                effective_xid,
            ) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "snapshot fallback: open_virtual snap_meta_tree oid={} xid={} failed: {}",
                        vol.snap_meta_tree_oid, effective_xid, e
                    );
                    return Ok(None);
                }
            }
        } else if vol.snap_meta_tree_oid < self.nx.block_count {
            match crate::btree::BTree::open_physical(self, vol.snap_meta_tree_oid) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "snapshot fallback: open_physical snap_meta_tree paddr={} failed: {}",
                        vol.snap_meta_tree_oid, e
                    );
                    return Ok(None);
                }
            }
        } else {
            warn!(
                "snapshot fallback: snap_meta_tree_oid={} unresolved and outside block_count",
                vol.snap_meta_tree_oid
            );
            return Ok(None);
        };

        self.set_active_omap(Some(omap.clone()), effective_xid);
        let mut cur = match snap_tree.seek(self, &[], &crate::btree::BTreeKeyCmp::Lex) {
            Ok(v) => v,
            Err(e) => {
                warn!("snapshot fallback: snap_meta_tree seek failed: {}", e);
                return Ok(None);
            }
        };

        // First pass: snapshot metadata records commonly store snapshot APSB pointers.
        let mut candidates = std::collections::HashSet::<u64>::new();
        let mut scanned = 0usize;
        const MAX_SNAP_KEYS: usize = 2048;
        while let Some((k, v)) = cur.next(self)? {
            scanned += 1;
            if scanned > MAX_SNAP_KEYS {
                break;
            }
            if let Some(h) = crate::fstree::JKey::from_bytes(&k) {
                if h.obj_type == 1 && v.len() >= 16 {
                    let p0 = u64::from_le_bytes(v[0..8].try_into().unwrap());
                    let p1 = u64::from_le_bytes(v[8..16].try_into().unwrap());
                    if let Some(found) =
                        self.try_snapshot_apsb_fallback(vol, omap, effective_xid, p0)?
                    {
                        return Ok(Some(found));
                    }
                    if let Some(found) =
                        self.try_snapshot_apsb_fallback(vol, omap, effective_xid, p1)?
                    {
                        return Ok(Some(found));
                    }
                }
            }

            let slots = (v.len() / 8).min(32);
            for i in 0..slots {
                let start = i * 8;
                let cand = u64::from_le_bytes(v[start..start + 8].try_into().unwrap());
                if cand == 0
                    || cand == vol.root_tree_oid
                    || cand == vol.snap_meta_tree_oid
                    || cand == vol.omap_oid
                {
                    continue;
                }
                candidates.insert(cand);
            }
        }
        let mut candidates: Vec<u64> = candidates.into_iter().collect();
        candidates.sort_unstable();
        warn!(
            "snapshot fallback: collected {} candidate oids from snap_meta_tree",
            candidates.len()
        );
        if !candidates.is_empty() {
            let preview = candidates
                .iter()
                .take(24)
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            warn!("snapshot fallback: candidate preview: {}", preview);
        }

        for oid in candidates {
            if let Ok((xid, _m)) = omap.lookup_with_key_xid(self, oid, effective_xid) {
                if let Ok(tree) = crate::btree::BTree::open_virtual(self, oid, omap, xid) {
                    let trial = crate::fstree::FsTree::new(omap.clone(), tree.clone(), xid);
                    match trial.detect_root_inode_id(self) {
                        Ok(Some(_)) => {
                            warn!(
                                "snapshot fallback: selected virtual candidate root_tree_oid={} xid={}",
                                oid, xid
                            );
                            return Ok(Some((tree, xid, oid)));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(
                                "snapshot fallback: virtual candidate oid={} xid={} probe error: {}",
                                oid, xid, e
                            );
                        }
                    }
                }
            }

            if oid < self.nx.block_count {
                if let Ok(tree) = crate::btree::BTree::open_physical(self, oid) {
                    let trial =
                        crate::fstree::FsTree::new(omap.clone(), tree.clone(), effective_xid);
                    match trial.detect_root_inode_id(self) {
                        Ok(Some(_)) => {
                            warn!(
                                "snapshot fallback: selected physical candidate paddr={} xid={}",
                                oid, effective_xid
                            );
                            return Ok(Some((tree, effective_xid, oid)));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            warn!(
                                "snapshot fallback: physical candidate paddr={} probe error: {}",
                                oid, e
                            );
                        }
                    }
                }
            }
        }

        warn!("snapshot fallback: no viable alternate fs tree");
        Ok(None)
    }

    fn try_snapshot_apsb_fallback(
        &mut self,
        vol: &ApfsVolumeSuperblock,
        omap: &crate::omap::Omap,
        effective_xid: u64,
        paddr: u64,
    ) -> Result<Option<(crate::btree::BTree, u64, u64)>, String> {
        if paddr >= self.nx.block_count {
            return Ok(None);
        }
        let bs = self.block_size_u64();
        let Ok(buf) = crate::io::read_block(&mut self.body, bs, paddr) else {
            return Ok(None);
        };
        if buf.get(0x20..0x24) != Some(b"APSB".as_ref()) {
            return Ok(None);
        }
        let Ok(snap_vsb) = crate::volume::ApfsVolumeSuperblock::parse_from_block(&buf, paddr)
        else {
            return Ok(None);
        };

        let mut xids_to_try = vec![effective_xid, snap_vsb.o.xid, vol.o.xid];
        if !xids_to_try.contains(&u64::MAX) {
            xids_to_try.push(u64::MAX);
        }
        xids_to_try.retain(|x| *x != 0);
        xids_to_try.sort_unstable();
        xids_to_try.dedup();

        for txid in xids_to_try {
            let Ok((_root_xid, _)) = omap.lookup_with_key_xid(self, snap_vsb.root_tree_oid, txid)
            else {
                continue;
            };
            let Ok(tree) =
                crate::btree::BTree::open_virtual(self, snap_vsb.root_tree_oid, omap, txid)
            else {
                continue;
            };
            let trial = crate::fstree::FsTree::new(omap.clone(), tree.clone(), txid);
            match trial.detect_root_inode_id(self) {
                Ok(Some(_)) => {
                    warn!(
                        "snapshot fallback: using APSB paddr={} root_tree_oid={} xid={}",
                        paddr, snap_vsb.root_tree_oid, txid
                    );
                    return Ok(Some((tree, txid, snap_vsb.root_tree_oid)));
                }
                Ok(None) => {}
                Err(e) => {
                    warn!(
                        "snapshot fallback: APSB paddr={} root_tree_oid={} xid={} probe error: {}",
                        paddr, snap_vsb.root_tree_oid, txid, e
                    );
                }
            }
        }
        Ok(None)
    }

    /// Opens the volume OMAP and returns it with the selected traversal xid.
    pub fn open_volume_omap_for_volume(
        &mut self,
        vol: &ApfsVolumeSuperblock,
    ) -> Result<(crate::omap::Omap, u64), String> {
        let nx_xid = self.nx.next_xid.saturating_sub(1);
        let mut xids = vec![vol.o.xid];
        if nx_xid != vol.o.xid {
            xids.push(nx_xid);
        }
        if !xids.contains(&u64::MAX) {
            xids.push(u64::MAX);
        }

        let mut errors = Vec::new();

        for xid in xids {
            let mut omap_paddrs = Vec::<u64>::new();
            if let Ok(container_omap) = self.open_container_omap_for_xid(xid) {
                if let Ok(m) = container_omap.lookup(self, vol.omap_oid, xid) {
                    if m.paddr < self.nx.block_count {
                        omap_paddrs.push(m.paddr);
                    }
                }
            }
            if vol.omap_oid < self.nx.block_count && !omap_paddrs.contains(&vol.omap_oid) {
                omap_paddrs.push(vol.omap_oid);
            }

            for omap_paddr in omap_paddrs {
                let omap = match crate::omap::Omap::open(self, omap_paddr) {
                    Ok(v) => v,
                    Err(e) => {
                        errors.push(format!(
                            "xid={} omap_paddr={} open_omap failed: {}",
                            xid, omap_paddr, e
                        ));
                        continue;
                    }
                };

                return Ok((omap, xid));
            }
        }

        Err(format!(
            "Could not open volume OMAP. Attempts: {}",
            errors.join(" | ")
        ))
    }
}
