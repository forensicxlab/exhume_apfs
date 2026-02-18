//! APFS OMAP parsing and lookup helpers.

use byteorder::{LittleEndian, ReadBytesExt};
use log::debug;
use serde::{Deserialize, Serialize};

use crate::btree::{BTree, BTreeKeyCmp};
use crate::object::ObjPhys;

/// Parsed `omap_phys_t` header.
///
/// An Object Map (OMAP) manages the mapping between virtual object IDs (oid)
/// and their physical block addresses (paddr). This allows APFS to write
/// new versions of objects without changing their stable identifiers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmapPhys {
    pub o: ObjPhys,
    pub flags: u32,
    pub snap_count: u32,
    pub tree_type: u32,
    pub snapshot_tree_type: u32,
    /// The root oid of the B-tree holding the oid-to-paddr mappings.
    pub tree_oid: u64,
    pub snapshot_tree_oid: u64,
}

impl OmapPhys {
    /// Parses `omap_phys_t` from an OMAP object block.
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        let o = ObjPhys::parse(buf)?;
        let mut c = std::io::Cursor::new(buf);
        c.set_position(0x20);
        let flags = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let snap_count = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let tree_type = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let snapshot_tree_type = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let tree_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let snapshot_tree_oid = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        Ok(Self {
            o,
            flags,
            snap_count,
            tree_type,
            snapshot_tree_type,
            tree_oid,
            snapshot_tree_oid,
        })
    }
}

/// OMAP key: `(oid, xid)`.
///
/// Used to lookup an object's location at a specific transaction ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmapKey {
    /// The virtual object ID.
    pub oid: u64,
    /// The transaction ID representing the version of the object.
    pub xid: u64,
}

impl OmapKey {
    /// Serializes key in APFS little-endian on-disk ordering.
    pub fn to_bytes(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.oid.to_le_bytes());
        out[8..].copy_from_slice(&self.xid.to_le_bytes());
        out
    }
}

/// OMAP value mapping a virtual object to a physical address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OmapVal {
    /// The physical block address of the object.
    pub paddr: u64,
    /// Size of the object in bytes.
    pub size: u32,
    pub flags: u32,
}

impl OmapVal {
    /// Parses `omap_val_t`.
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 16 {
            return Err("omap_val too small".into());
        }
        let mut c = std::io::Cursor::new(buf);
        // APFS omap_val_t layout: flags (u32), size (u32), paddr (u64)
        let flags = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let size = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let paddr = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        Ok(Self { paddr, size, flags })
    }
}

/// OMAP wrapper: holds its header and the mapping B-tree root.
#[derive(Debug, Clone)]
pub struct Omap {
    pub phys: OmapPhys,
    pub tree: BTree,
}

impl Omap {
    /// The OMAP itself is a physical object (volume and container store it as a physical oid).
    /// `omap_paddr` is a physical block address.
    pub fn open<T: std::io::Read + std::io::Seek>(
        apfs: &mut crate::APFS<T>,
        omap_paddr: u64,
    ) -> Result<Self, String> {
        let bs = apfs.block_size_u64();
        let buf = crate::io::read_block(&mut apfs.body, bs, omap_paddr)?;
        let phys = OmapPhys::parse(&buf)?;
        phys.o.validate(&buf)?; // checksum validation (tolerant)
        let tree = BTree::open_physical(apfs, phys.tree_oid)?;
        Ok(Self { phys, tree })
    }

    /// Looks up the best mapping match for a given object ID and transaction ID.
    ///
    /// This method first attempts an exact match. If no exact match exists, it
    /// falls back to scanning for the version with the highest transaction ID
    /// that is less than or equal to the target `xid`.
    pub fn lookup<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        oid: u64,
        xid: u64,
    ) -> Result<OmapVal, String> {
        Ok(self.lookup_with_key_xid(apfs, oid, xid)?.1)
    }

    /// Lookup best match and return both matched key xid and mapping value.
    pub fn lookup_with_key_xid<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        oid: u64,
        xid: u64,
    ) -> Result<(u64, OmapVal), String> {
        let exact = OmapKey { oid, xid }.to_bytes();
        if let Some(val_bytes) = self.tree.get(apfs, &exact, &BTreeKeyCmp::OmapKey)? {
            let v = OmapVal::parse(&val_bytes)?;
            debug!(
                "OMAP exact: oid={} xid={} -> paddr={} size={} flags=0x{:x}",
                oid, xid, v.paddr, v.size, v.flags
            );
            return Ok((xid, v));
        }

        // Fallback without backward stepping:
        // seek to the beginning of this OID range and scan forward, keeping latest xid <= target.
        let start = OmapKey { oid, xid: 0 }.to_bytes();
        let mut it = self.tree.seek(apfs, &start, &BTreeKeyCmp::OmapKey)?;
        let mut best: Option<(u64, OmapVal)> = None;
        let mut first_above: Option<(u64, OmapVal)> = None;

        while let Some((k, v)) = it.next(apfs)? {
            if k.len() < 16 {
                continue;
            }
            let koid = u64::from_le_bytes(k[0..8].try_into().unwrap());
            let kxid = u64::from_le_bytes(k[8..16].try_into().unwrap());

            if koid < oid {
                continue;
            }
            if koid > oid {
                break;
            }

            if kxid <= xid {
                let parsed = OmapVal::parse(&v)?;
                best = Some((kxid, parsed));
                continue;
            }

            // keys are ordered by (oid, xid); once xid exceeds target for same oid, keep the
            // first-above entry as a last-resort fallback, then stop.
            if first_above.is_none() {
                let parsed = OmapVal::parse(&v)?;
                first_above = Some((kxid, parsed));
            }
            break;
        }

        if let Some((best_xid, out)) = best {
            debug!(
                "OMAP fallback: oid={} xid<={} matched kxid={} -> paddr={} size={} flags=0x{:x}",
                oid, xid, best_xid, out.paddr, out.size, out.flags
            );
            return Ok((best_xid, out));
        }

        if let Some((best_xid, out)) = first_above {
            debug!(
                "OMAP fallback-above: oid={} xid<={} had no lower xid; using kxid={} -> paddr={} size={} flags=0x{:x}",
                oid, xid, best_xid, out.paddr, out.size, out.flags
            );
            return Ok((best_xid, out));
        }

        Err(format!("OMAP: no mapping for oid={} xid<={}", oid, xid))
    }

    /// Dump up to `limit` OMAP versions for a given oid (ordered by xid).
    pub fn dump_versions<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        oid: u64,
        limit: usize,
    ) -> Result<Vec<(u64, OmapVal)>, String> {
        let start = OmapKey { oid, xid: 0 }.to_bytes();
        let mut it = self.tree.seek(apfs, &start, &BTreeKeyCmp::OmapKey)?;
        let mut out = Vec::new();
        while let Some((k, v)) = it.next(apfs)? {
            if k.len() < 16 {
                continue;
            }
            let koid = u64::from_le_bytes(k[0..8].try_into().unwrap());
            let kxid = u64::from_le_bytes(k[8..16].try_into().unwrap());
            if koid != oid {
                if koid > oid {
                    break;
                }
                continue;
            }
            let parsed = OmapVal::parse(&v)?;
            out.push((kxid, parsed));
            if out.len() >= limit {
                break;
            }
        }
        Ok(out)
    }
}
