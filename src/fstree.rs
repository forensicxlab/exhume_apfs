//! APFS filesystem tree record parsing helpers.

use byteorder::{LittleEndian, ReadBytesExt};
use chrono::{TimeZone, Utc};
use prettytable::{Table, row};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::HashMap;

pub type ScanAllRecordsResult = (
    std::collections::HashMap<u64, InodeVal>,
    std::collections::HashMap<u64, Vec<DirEntry>>,
);

use crate::btree::{BTree, BTreeKeyCmp};
use crate::omap::Omap;

const J_KEY_OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
const J_KEY_TYPE_MASK: u64 = 0xf000_0000_0000_0000;
const J_KEY_TYPE_SHIFT: u64 = 60;

// j_obj_types values you need
const APFS_TYPE_INODE: u8 = 3;
const APFS_TYPE_FILE_EXTENT: u8 = 8;
const APFS_TYPE_DIR_REC: u8 = 9;

// inode ext field types
const INO_EXT_TYPE_DSTREAM: u8 = 8;

/// Parsed APFS filesystem key header (`j_key_t`).
///
/// This header is used for all records in the file system tree. It combines
/// an object ID and a record type into a single 64-bit value for B-tree ordering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JKey {
    /// The object ID this record belongs to.
    pub obj_id: u64,
    /// The record type (e.g., Inode, DirRec, FileExtent).
    pub obj_type: u8,
}

impl JKey {
    /// Parses a key header from raw key bytes.
    pub fn from_bytes(k: &[u8]) -> Option<Self> {
        if k.len() < 8 {
            return None;
        }
        let raw = u64::from_le_bytes(k[0..8].try_into().ok()?);
        let obj_id = raw & J_KEY_OBJ_ID_MASK;
        let obj_type = ((raw & J_KEY_TYPE_MASK) >> J_KEY_TYPE_SHIFT) as u8;
        Some(Self { obj_id, obj_type })
    }

    /// Serializes a key header for seek/get operations.
    pub fn to_bytes(obj_id: u64, obj_type: u8) -> [u8; 8] {
        let raw = (obj_id & J_KEY_OBJ_ID_MASK) | ((obj_type as u64) << J_KEY_TYPE_SHIFT);
        raw.to_le_bytes()
    }
}

/// Parsed data stream metadata from inode xfields (`j_dstream_t`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JDStream {
    pub size: u64,
    pub alloced_size: u64,
    pub default_crypto_id: u64,
    pub total_bytes_written: u64,
    pub total_bytes_read: u64,
}

impl JDStream {
    /// Parses `j_dstream_t`.
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        if buf.len() < 40 {
            return Err("j_dstream_t too small".into());
        }
        let mut c = std::io::Cursor::new(buf);
        Ok(Self {
            size: c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?,
            alloced_size: c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?,
            default_crypto_id: c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?,
            total_bytes_written: c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?,
            total_bytes_read: c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?,
        })
    }
}

/// Parsed inode value with a best-effort subset of APFS inode fields.
///
/// Corresponds to `j_inode_val_t`. Note that some fields are extracted from
/// variable-length xfields (extended fields) that follow the fixed header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InodeVal {
    /// Inode ID of the parent directory.
    pub parent_id: u64,
    /// Private ID (used for hard links and snapshots).
    pub private_id: u64,
    /// Creation time in nanoseconds since the Unix epoch.
    pub create_time: u64,
    /// Last modification time.
    pub mod_time: u64,
    /// Last inode change time.
    pub change_time: u64,
    /// Last access time.
    pub access_time: u64,
    pub internal_flags: u64,
    /// Number of children (for directories) or hard links (for files).
    pub nchildren_or_nlink: u32,
    pub default_protection_class: u32,
    pub write_gen_counter: u32,
    pub bsd_flags: u32,
    pub owner: u32,
    pub group: u32,
    /// Unix file mode (permissions and file type).
    pub mode: u16,
    /// Logical size of the file in bytes.
    pub uncompressed_size: u64,
    /// Optional data stream descriptor (for regular files).
    pub dstream: Option<JDStream>,
}

impl InodeVal {
    /// Parses an inode record value.
    pub fn parse(buf: &[u8]) -> Result<Self, String> {
        // ... (existing implementation)
        if buf.len() < 88 {
            return Err("j_inode_val_t too small".into());
        }
        let mut c = std::io::Cursor::new(buf);
        let parent_id = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let private_id = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let create_time = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let mod_time = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let change_time = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let access_time = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let internal_flags = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;

        let nchildren_or_nlink = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let default_protection_class = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let write_gen_counter = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let bsd_flags = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let owner = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let group = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let mode = c.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
        let _pad1 = c.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
        let mut uncompressed_size = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;

        // APFS inode xfields are version-dependent; try multiple plausible starts.
        let dstream = parse_xfields_find_dstream_any(buf)?;
        if let Some(ds) = &dstream {
            // dstream is authoritative for file size; helps avoid bogus fixed-offset parsing.
            uncompressed_size = ds.size;
        }

        Ok(Self {
            parent_id,
            private_id,
            create_time,
            mod_time,
            change_time,
            access_time,
            internal_flags,
            nchildren_or_nlink,
            default_protection_class,
            write_gen_counter,
            bsd_flags,
            owner,
            group,
            mode,
            uncompressed_size,
            dstream,
        })
    }

    /// Returns a string representation of the inode metadata formatted as a table.
    pub fn metadata_table(&self, inode_id: u64) -> String {
        let mut t = Table::new();
        t.add_row(row!["field", "value"]);
        t.add_row(row!["inode_id", format!("{}", inode_id)]);
        t.add_row(row!["parent_id", self.parent_id]);
        t.add_row(row!["private_id", self.private_id]);
        t.add_row(row!["owner", self.owner]);
        t.add_row(row!["group", self.group]);
        t.add_row(row!["mode", format!("0{:o}", self.mode)]);
        t.add_row(row!["permissions", apfs_mode_to_string(self.mode)]);
        t.add_row(row!["kind", apfs_kind(self.mode)]);
        t.add_row(row!["created", fmt_apfs_ns_utc(self.create_time)]);
        t.add_row(row!["modified", fmt_apfs_ns_utc(self.mod_time)]);
        t.add_row(row!["changed", fmt_apfs_ns_utc(self.change_time)]);
        t.add_row(row!["accessed", fmt_apfs_ns_utc(self.access_time)]);
        t.add_row(row!["uncompressed_size", self.uncompressed_size]);
        if let Some(ds) = self.dstream.clone() {
            t.add_row(row!["dstream.size", ds.size]);
            t.add_row(row!["dstream.alloced_size", ds.alloced_size]);
            t.add_row(row!["dstream.default_crypto_id", ds.default_crypto_id]);
        }
        t.to_string()
    }
}

pub fn apfs_mode_to_string(mode: u16) -> String {
    let mut out = String::with_capacity(10);
    out.push(match mode & 0o170000 {
        0o040000 => 'd',
        0o100000 => '-',
        0o120000 => 'l',
        0o060000 => 'b',
        0o020000 => 'c',
        0o010000 => 'p',
        0o140000 => 's',
        _ => '?',
    });
    for &(bit, ch) in &[
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ] {
        out.push(if (mode & bit) != 0 { ch } else { '-' });
    }
    // setuid / setgid / sticky bits.
    if (mode & 0o4000) != 0 {
        out.replace_range(3..4, if (mode & 0o100) != 0 { "s" } else { "S" });
    }
    if (mode & 0o2000) != 0 {
        out.replace_range(6..7, if (mode & 0o010) != 0 { "s" } else { "S" });
    }
    if (mode & 0o1000) != 0 {
        out.replace_range(9..10, if (mode & 0o001) != 0 { "t" } else { "T" });
    }
    out
}

pub fn fmt_apfs_ns_utc(ns: u64) -> String {
    let secs = ns / 1_000_000_000;
    let nsec = (ns % 1_000_000_000) as u32;
    match Utc.timestamp_opt(secs as i64, nsec).single() {
        Some(ts) => ts.format("%Y-%m-%d %H:%M:%S%.f UTC").to_string(),
        None => format!("{}", ns),
    }
}

fn parse_xfields_find_dstream_any(buf: &[u8]) -> Result<Option<JDStream>, String> {
    // Common observed starts for xf_blob_t in j_inode_val_t variants.
    // Keep these first for fast-path parsing.
    for start in [96usize, 92, 88, 84] {
        if start >= buf.len() {
            continue;
        }
        match parse_xfields_find_dstream(&buf[start..]) {
            Ok(Some(ds)) => return Ok(Some(ds)),
            Ok(None) => {}
            // Best-effort parsing: malformed/variant xfields must not make the
            // whole inode unreadable.
            Err(_) => {}
        }
    }

    // Fallback: slide over a bounded range to catch layout variants where
    // xfields are shifted by additional headers.
    if buf.len() > 68 {
        let end = buf.len().saturating_sub(4).min(256);
        for start in 64usize..end {
            match parse_xfields_find_dstream(&buf[start..]) {
                Ok(Some(ds)) => return Ok(Some(ds)),
                Ok(None) => {}
                Err(_) => {}
            }
        }
    }

    Ok(None)
}

fn parse_xfields_find_dstream(xfields: &[u8]) -> Result<Option<JDStream>, String> {
    // xf_blob_t: u16 num_exts, u16 used_data, followed by x_field_t entries + data.
    if xfields.len() < 4 {
        return Ok(None);
    }
    let num = u16::from_le_bytes(xfields[0..2].try_into().unwrap()) as usize;
    let used = u16::from_le_bytes(xfields[2..4].try_into().unwrap()) as usize;
    if num == 0 || used == 0 || xfields.len() < 4 + used {
        return Ok(None);
    }

    // x_field_t is 4 bytes: u8 type, u8 flags, u16 size
    let mut meta_off = 4;
    // Data section starts after the header (4 bytes) and all meta entries (num * 4 bytes).
    let data_section_start = 4 + (num * 4);
    if data_section_start > xfields.len() {
        return Ok(None);
    }
    // Track offset within the data section; each entry's data is 8-byte aligned within it.
    let mut data_off_in_section = 0usize;

    for _ in 0..num {
        if meta_off + 4 > xfields.len() {
            break;
        }
        let x_type = xfields[meta_off];
        let _x_flags = xfields[meta_off + 1];
        let x_size =
            u16::from_le_bytes(xfields[meta_off + 2..meta_off + 4].try_into().unwrap()) as usize;
        meta_off += 4;

        // 8-byte alignment is within the data section, not from the xf_blob start.
        let aligned_in_section = (data_off_in_section + 7) & !7;
        let abs_off = data_section_start + aligned_in_section;

        if abs_off + x_size > xfields.len() {
            break;
        }
        let data = &xfields[abs_off..abs_off + x_size];
        if x_type == INO_EXT_TYPE_DSTREAM
            && let Ok(ds) = JDStream::parse(data) {
                return Ok(Some(ds));
            }
        data_off_in_section = aligned_in_section + x_size;
    }

    Ok(None)
}

/// Directory entry record returned from `dir_children`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    /// Name of the file or directory.
    pub name: String,
    /// The raw object ID (could be an inode or a private ID).
    pub raw_id: u64,
    /// Resolved inode ID, if available.
    pub inode_id: Option<u64>,
    /// Directory entry flags (e.g., file type hints).
    pub flags: u16,
    /// Time the entry was added to the directory.
    pub date_added: u64,
}

/// File extent mapping for one owner id.
///
/// Maps a logical range within a file to a physical block range on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileExtent {
    /// Logical address within the file.
    pub logical_addr: u64,
    /// Physical block address.
    pub phys_block_num: u64,
    /// Length of the extent in bytes.
    pub length_bytes: u64,
    /// Cryptographic identifier for the extent data.
    pub crypto_id: u64,
}

/// Filesystem-tree access wrapper bound to a volume OMAP and transaction ID.
///
/// This structure provides high-level methods to lookup inodes, list directory
/// contents, and map file extents. It maintains internal caches to optimize
/// frequent lookups and handle complex private-id to inode-id mappings.
#[derive(Clone)]
pub struct FsTree {
    pub omap: Omap,
    pub root_tree: BTree,
    pub xid: u64,
    inode_lookup: RefCell<Option<HashMap<u64, InodeVal>>>,
    inode_private_to_id: RefCell<Option<HashMap<u64, u64>>>,
    drec_target_cache: RefCell<HashMap<u64, Option<u64>>>,
}

impl FsTree {
    pub(crate) fn new(omap: Omap, root_tree: BTree, xid: u64) -> Self {
        Self {
            omap,
            root_tree,
            xid,
            inode_lookup: RefCell::new(None),
            inode_private_to_id: RefCell::new(None),
            drec_target_cache: RefCell::new(HashMap::new()),
        }
    }

    fn resolve_drec_target_fallback<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        raw_id: u64,
    ) -> Result<Option<u64>, String> {
        if let Some(cached) = self.drec_target_cache.borrow().get(&raw_id) {
            return Ok(*cached);
        }

        // Probe all APFS key types for this object id and try to recover an inode id
        // from plausible u64 slots in the value.
        for obj_type in 0u8..=15u8 {
            let probe = JKey::to_bytes(raw_id, obj_type);
            let mut cur = self.root_tree.seek(apfs, &probe, &BTreeKeyCmp::Lex)?;
            let mut scanned = 0usize;
            const MAX_SCAN_PER_TYPE: usize = 64;
            while let Some((k, v)) = cur.next(apfs)? {
                scanned += 1;
                if scanned > MAX_SCAN_PER_TYPE {
                    break;
                }
                let Some(hdr) = JKey::from_bytes(&k) else {
                    continue;
                };
                if hdr.obj_type != obj_type {
                    break;
                }
                if hdr.obj_id != raw_id {
                    continue;
                }

                // Try multiple u64 fields as candidate inode ids.
                // Some APFS variants store useful target ids beyond the first few slots.
                let slots = (v.len() / 8).min(32);
                for i in 0..slots {
                    let start = i * 8;
                    let cand = u64::from_le_bytes(v[start..start + 8].try_into().unwrap());
                    if cand == 0 || cand == raw_id {
                        continue;
                    }
                    if self.inode_by_id(apfs, cand)?.is_some() {
                        self.drec_target_cache
                            .borrow_mut()
                            .insert(raw_id, Some(cand));
                        return Ok(Some(cand));
                    }
                    if let Some(mapped) = self.inode_id_by_private_id(apfs, cand)? {
                        self.drec_target_cache
                            .borrow_mut()
                            .insert(raw_id, Some(mapped));
                        return Ok(Some(mapped));
                    }
                }
            }
        }

        self.drec_target_cache.borrow_mut().insert(raw_id, None);
        Ok(None)
    }

    fn build_inode_indexes<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
    ) -> Result<(), String> {
        if self.inode_lookup.borrow().is_some() && self.inode_private_to_id.borrow().is_some() {
            return Ok(());
        }

        apfs.set_active_omap(Some(self.omap.clone()), self.xid);
        let mut cur = self.root_tree.seek(apfs, &[], &BTreeKeyCmp::Lex)?;
        let mut by_key = HashMap::<u64, InodeVal>::new();
        let mut private_to_id = HashMap::<u64, u64>::new();

        while let Some((k, v)) = cur.next(apfs)? {
            let Some(hdr) = JKey::from_bytes(&k) else {
                continue;
            };
            if hdr.obj_type != APFS_TYPE_INODE {
                continue;
            }
            let inode = match InodeVal::parse(&v) {
                Ok(i) => i,
                Err(_) => continue,
            };
            by_key.entry(hdr.obj_id).or_insert_with(|| inode.clone());
            by_key
                .entry(inode.private_id)
                .or_insert_with(|| inode.clone());
            private_to_id.entry(inode.private_id).or_insert(hdr.obj_id);
        }

        *self.inode_lookup.borrow_mut() = Some(by_key);
        *self.inode_private_to_id.borrow_mut() = Some(private_to_id);
        Ok(())
    }

    /// Looks up an inode by its unique identifier.
    ///
    /// This method first attempts a direct B-tree lookup. If the record is not found
    /// (e.g., due to key ordering subtleties), it falls back to a scan and then
    /// builds a full in-memory index of the inode tree.
    pub fn inode_by_id<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        inode_id: u64,
    ) -> Result<Option<InodeVal>, String> {
        apfs.set_active_omap(Some(self.omap.clone()), self.xid);
        let k = JKey::to_bytes(inode_id, APFS_TYPE_INODE);
        if let Some(bytes) = self.root_tree.get(apfs, &k, &BTreeKeyCmp::ApfsJKey)? {
            return Ok(Some(InodeVal::parse(&bytes)?));
        }

        // Fallback for datasets where direct key lookup misses due to key-order nuances:
        // seek near the target and scan a small window for an inode with matching id.
        let mut cur = self.root_tree.seek(apfs, &k, &BTreeKeyCmp::ApfsJKey)?;
        let mut scanned = 0usize;
        const MAX_SCAN_KEYS: usize = 200_000;
        while let Some((kk, vv)) = cur.next(apfs)? {
            scanned += 1;
            if scanned > MAX_SCAN_KEYS {
                break;
            }
            let Some(hdr) = JKey::from_bytes(&kk) else {
                continue;
            };
            if hdr.obj_type != APFS_TYPE_INODE || hdr.obj_id != inode_id {
                continue;
            }
            return Ok(Some(InodeVal::parse(&vv)?));
        }

        self.build_inode_indexes(apfs)?;
        if let Some(idx) = self.inode_lookup.borrow().as_ref()
            && let Some(inode) = idx.get(&inode_id) {
                return Ok(Some(inode.clone()));
            }
        Ok(None)
    }

    /// Backward-compatible alias for inode lookup.
    pub fn inode_by_file_id<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        file_id: u64,
    ) -> Result<Option<InodeVal>, String> {
        self.inode_by_id(apfs, file_id)
    }

    /// Resolves inode object-id from a private-id, if present.
    pub fn inode_id_by_private_id<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        private_id: u64,
    ) -> Result<Option<u64>, String> {
        self.build_inode_indexes(apfs)?;
        Ok(self
            .inode_private_to_id
            .borrow()
            .as_ref()
            .and_then(|m| m.get(&private_id).copied()))
    }

    fn dir_children_raw<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        dir_owner_id: u64,
    ) -> Result<Vec<DirEntry>, String> {
        apfs.set_active_omap(Some(self.omap.clone()), self.xid);

        let prefix = JKey::to_bytes(dir_owner_id, APFS_TYPE_DIR_REC);
        let mut cur = self.root_tree.seek(apfs, &prefix, &BTreeKeyCmp::ApfsJKey)?;
        let mut out = Vec::new();

        loop {
            let Some((k, v)) = cur.next(apfs)? else {
                break;
            };
            let Some(hdr) = JKey::from_bytes(&k) else {
                continue;
            };
            if hdr.obj_id != dir_owner_id || hdr.obj_type != APFS_TYPE_DIR_REC {
                break;
            }

            let name = parse_drec_name(&k).unwrap_or_else(|| "<non-utf8>".to_string());
            let drec = match DrecVal::parse(&v) {
                Some(v) => v,
                None => continue,
            };
            let inode_id = if self.inode_by_id(apfs, drec.file_id)?.is_some() {
                Some(drec.file_id)
            } else {
                self.inode_id_by_private_id(apfs, drec.file_id)?
                    .or(self.resolve_drec_target_fallback(apfs, drec.file_id)?)
            };

            out.push(DirEntry {
                name,
                raw_id: drec.file_id,
                inode_id,
                flags: drec.flags,
                date_added: drec.date_added,
            });
        }

        Ok(out)
    }

    /// Lists the direct children of a directory.
    ///
    /// Resolves directory record entries (DREC) to their corresponding target inodes,
    /// handling both direct object ID mappings and private ID resolution.
    pub fn dir_children<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        dir_id: u64,
    ) -> Result<Vec<DirEntry>, String> {
        self.dir_children_raw(apfs, dir_id)
    }

    /// Lists file extents for an owner id.
    pub fn file_extents<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        owner_id: u64,
    ) -> Result<Vec<FileExtent>, String> {
        apfs.set_active_omap(Some(self.omap.clone()), self.xid);

        let prefix = JKey::to_bytes(owner_id, APFS_TYPE_FILE_EXTENT);
        let mut cur = self.root_tree.seek(apfs, &prefix, &BTreeKeyCmp::ApfsJKey)?;
        let mut out = Vec::new();

        loop {
            let Some((k, v)) = cur.next(apfs)? else {
                break;
            };
            let Some(hdr) = JKey::from_bytes(&k) else {
                continue;
            };
            if hdr.obj_id != owner_id || hdr.obj_type != APFS_TYPE_FILE_EXTENT {
                break;
            }
            if k.len() < 16 || v.len() < 24 {
                continue;
            }
            let logical_addr = u64::from_le_bytes(k[8..16].try_into().unwrap());

            let len_and_flags = u64::from_le_bytes(v[0..8].try_into().unwrap());
            let length_bytes = len_and_flags & 0x00ff_ffff_ffff_ffff; // per spec mask  [oai_citation:5‡Internet Archive](https://archive.org/stream/AppleFileSystemReference/Apple-File-System-Reference_djvu.txt)
            let phys_block_num = u64::from_le_bytes(v[8..16].try_into().unwrap());
            let crypto_id = u64::from_le_bytes(v[16..24].try_into().unwrap());

            out.push(FileExtent {
                logical_addr,
                phys_block_num,
                length_bytes,
                crypto_id,
            });
        }

        Ok(out)
    }

    /// Scans the entire BTree sequentially and returns all Inodes and Directory Records.
    /// This avoids O(N log N) disk seeks during full filesystem enumeration.
    pub fn scan_all_records<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        mut progress: Option<&mut dyn FnMut(usize)>,
    ) -> Result<ScanAllRecordsResult, String> {
        apfs.set_active_omap(Some(self.omap.clone()), self.xid);
        let mut cur = self.root_tree.seek(apfs, &[], &BTreeKeyCmp::Lex)?;

        let mut inodes = std::collections::HashMap::new();
        let mut raw_drecs = Vec::new();
        let mut private_to_id = std::collections::HashMap::new();
        let mut scanned = 0;

        while let Some((k, v)) = cur.next(apfs)? {
            scanned += 1;
            if scanned % 10000 == 0
                && let Some(cb) = progress.as_mut() {
                    cb(scanned);
                }
            let Some(hdr) = JKey::from_bytes(&k) else {
                continue;
            };
            if hdr.obj_type == APFS_TYPE_INODE {
                if let Ok(inode) = InodeVal::parse(&v) {
                    inodes.insert(hdr.obj_id, inode.clone());
                    private_to_id.insert(inode.private_id, hdr.obj_id);
                }
            } else if hdr.obj_type == APFS_TYPE_DIR_REC {
                let name = parse_drec_name(&k).unwrap_or_else(|| "<non-utf8>".to_string());
                if let Some(drec) = DrecVal::parse(&v) {
                    raw_drecs.push((
                        hdr.obj_id,
                        DirEntry {
                            name,
                            raw_id: drec.file_id,
                            inode_id: None,
                            flags: drec.flags,
                            date_added: drec.date_added,
                        },
                    ));
                }
            }
        }

        // Resolve inode_ids for all drecs
        let mut drecs: std::collections::HashMap<u64, Vec<DirEntry>> =
            std::collections::HashMap::new();
        for (parent_id, mut entry) in raw_drecs {
            if inodes.contains_key(&entry.raw_id) {
                entry.inode_id = Some(entry.raw_id);
            } else if let Some(id) = private_to_id.get(&entry.raw_id) {
                entry.inode_id = Some(*id);
            } else {
                // Ignore fallback resolution for speed; fallback requires BTree point lookups.
                // In practice, well-formed APFS datasets map via raw_id or private_id.
            }
            drecs.entry(parent_id).or_default().push(entry);
        }

        Ok((inodes, drecs))
    }

    /// Heuristic root inode detection for a volume.
    /// Fast path checks inode 2.
    pub fn detect_root_inode_id<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
    ) -> Result<Option<u64>, String> {
        if let Some(inode2) = self.inode_by_id(apfs, 2)?
            && is_dir_mode(inode2.mode) {
                return Ok(Some(2));
            }
        Ok(None)
    }
}

fn parse_drec_name(k: &[u8]) -> Option<String> {
    if k.len() <= 8 {
        return None;
    }
    if k.len() >= 12 {
        // Common APFS drec form:
        // j_drec_hashed_key_t = j_key_t (8) + name_len_and_hash (4) + name bytes.
        // The low 10 bits carry the name length.
        let nlh = u32::from_le_bytes(k[8..12].try_into().ok()?);
        let name_len = (nlh & 0x03ff) as usize;
        if name_len > 0 && 12usize.saturating_add(name_len) <= k.len() {
            let mut name_bytes = &k[12..12 + name_len];
            while let Some((&last, rest)) = name_bytes.split_last() {
                if last != 0 {
                    break;
                }
                name_bytes = rest;
            }
            if let Ok(s) = std::str::from_utf8(name_bytes) {
                return Some(s.to_string());
            }
        }
    }

    // Fallback for older/variant keys with null-terminated tail.
    let name_start = if k.len() >= 12 { 12 } else { 10 };
    let mut name_bytes = &k[name_start..];
    if let Some(nul) = name_bytes.iter().position(|&b| b == 0) {
        name_bytes = &name_bytes[..nul];
    }
    std::str::from_utf8(name_bytes)
        .ok()
        .map(ToString::to_string)
}

#[derive(Debug, Clone)]
struct DrecVal {
    file_id: u64,
    date_added: u64,
    flags: u16,
    _xfields_len: Option<u16>,
}

impl DrecVal {
    fn parse(v: &[u8]) -> Option<Self> {
        if v.len() < 18 {
            return None;
        }
        let file_id = u64::from_le_bytes(v[0..8].try_into().ok()?);
        let date_added = u64::from_le_bytes(v[8..16].try_into().ok()?);
        let flags = u16::from_le_bytes(v[16..18].try_into().ok()?);

        // Some APFS variants include xfields length right after flags.
        let xfields_len = if v.len() >= 20 {
            let xf = u16::from_le_bytes(v[18..20].try_into().ok()?);
            if (20usize + xf as usize) <= v.len() {
                Some(xf)
            } else {
                None
            }
        } else {
            None
        };

        Some(Self {
            file_id,
            date_added,
            flags,
            _xfields_len: xfields_len,
        })
    }
}

pub fn is_dir_mode(mode: u16) -> bool {
    (mode & 0o170000) == 0o040000
}

pub fn apfs_kind(mode: u16) -> &'static str {
    match mode & 0o170000 {
        0o040000 => "dir",
        0o100000 => "file",
        0o120000 => "symlink",
        0o060000 => "block",
        0o020000 => "char",
        0o010000 => "fifo",
        0o140000 => "socket",
        _ => "other",
    }
}
