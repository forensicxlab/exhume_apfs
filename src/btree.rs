//! APFS B-tree reader and cursor traversal primitives.

use crate::object::ObjPhys;
use byteorder::{LittleEndian, ReadBytesExt};

const BTREE_INFO_SIZE: usize = 40; // btree_info_t total
const BTNODE_ROOT: u16 = 0x0001;
const BTNODE_FIXED_KV_SIZE: u16 = 0x0004;

const BTREE_PHYSICAL: u32 = 0x0002; // bt_flags bit (child links are physical)

/* nloc_t */
#[derive(Debug, Clone, Copy)]
struct NLoc {
    off: u16,
    len: u16,
}

impl NLoc {
    fn parse(c: &mut std::io::Cursor<&[u8]>) -> Result<Self, String> {
        let off = c.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
        let len = c.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
        Ok(Self { off, len })
    }
}

#[derive(Debug, Clone)]
enum TocEntry {
    Fixed { k_off: u16, v_off: u16 },
    Var { k: NLoc, v: NLoc },
}

#[derive(Debug, Clone)]
pub struct BTreeInfoFixed {
    /// B-tree flags (`btree_info_fixed_t.flags`).
    pub flags: u32,
    /// Node size in bytes.
    pub node_size: u32,
    /// Fixed key size (`0` means variable-sized keys).
    pub key_size: u32,
    /// Fixed value size (`0` means variable-sized values).
    pub val_size: u32,
}

#[derive(Debug, Clone)]
pub struct BTreeInfo {
    /// Fixed b-tree parameters.
    pub fixed: BTreeInfoFixed,
    /// Longest key in bytes.
    pub longest_key: u32,
    /// Longest value in bytes.
    pub longest_val: u32,
    /// Total number of keys.
    pub key_count: u64,
    /// Total number of nodes.
    pub node_count: u64,
}

#[derive(Debug, Clone)]
struct NodeHeader {
    obj: ObjPhys,
    flags: u16,
    level: u16,
    nkeys: u32,
    table_space: NLoc,
    _free_space: NLoc,
    _key_free_list: NLoc,
    _val_free_list: NLoc,
}

/// A single B-tree node in the APFS hierarchy.
#[derive(Debug, Clone)]
struct Node {
    /// Physical object header and node header.
    hdr: NodeHeader,
    /// Whether the node includes a physical object header (`obj_phys_t`).
    has_obj_header: bool,
    /// Size of the header in bytes.
    header_size: usize,
    /// Table of contents entries for keys and values.
    toc: Vec<TocEntry>,
    /// B-tree parameters (only present in the root node).
    info: Option<BTreeInfo>,
}

impl Node {
    /// Parses a B-tree node from a buffer.
    fn parse(buf: &[u8], assumed_node_size: usize, has_obj_header: bool) -> Result<Self, String> {
        let min_header = if has_obj_header { 0x38 } else { 0x18 };
        if buf.len() < min_header {
            return Err("btree node too small".into());
        }
        let obj = if has_obj_header {
            ObjPhys::parse(buf)?
        } else {
            ObjPhys {
                checksum: 0,
                oid: 0,
                xid: 0,
                obj_type: 0,
                obj_subtype: 0,
            }
        };
        let mut c = std::io::Cursor::new(buf);
        c.set_position(if has_obj_header { 0x20 } else { 0x00 });
        let flags = c.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
        let level = c.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
        let nkeys = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let table_space = NLoc::parse(&mut c)?;
        let free_space = NLoc::parse(&mut c)?;
        let key_free_list = NLoc::parse(&mut c)?;
        let val_free_list = NLoc::parse(&mut c)?;

        let hdr = NodeHeader {
            obj,
            flags,
            level,
            nkeys,
            table_space,
            _free_space: free_space,
            _key_free_list: key_free_list,
            _val_free_list: val_free_list,
        };

        let header_size = c.position() as usize;
        let node_size = assumed_node_size.min(buf.len());
        if header_size >= node_size {
            return Err("invalid node header size".into());
        }

        let table_start = header_size + (table_space.off as usize);
        let table_len = table_space.len as usize;

        if table_start + table_len > node_size {
            return Err(format!(
                "table space out of bounds: table_start=0x{:x} table_len=0x{:x} node_size=0x{:x} hdr_size=0x{:x} nkeys={}",
                table_start, table_len, node_size, header_size, nkeys
            ));
        }

        let fixed_kv = (flags & BTNODE_FIXED_KV_SIZE) != 0;
        let entry_size = if fixed_kv { 4 } else { 8 };

        let need = (nkeys as usize)
            .checked_mul(entry_size)
            .ok_or_else(|| "toc size overflow".to_string())?;

        if need > table_len {
            return Err(format!(
                "toc does not fit in table space: need=0x{:x} table_len=0x{:x} entry_size={} nkeys={} table_off=0x{:x}",
                need, table_len, entry_size, nkeys, table_space.off
            ));
        }

        let mut toc = Vec::with_capacity(nkeys as usize);
        let mut tc = std::io::Cursor::new(&buf[table_start..table_start + need]);
        for _ in 0..nkeys {
            if fixed_kv {
                let k_off = tc.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
                let v_off = tc.read_u16::<LittleEndian>().map_err(|e| e.to_string())?;
                toc.push(TocEntry::Fixed { k_off, v_off });
            } else {
                let k = NLoc::parse(&mut tc)?;
                let v = NLoc::parse(&mut tc)?;
                toc.push(TocEntry::Var { k, v });
            }
        }

        let is_root = (flags & BTNODE_ROOT) != 0;
        let info = if is_root {
            if node_size < BTREE_INFO_SIZE {
                None
            } else {
                let start = node_size - BTREE_INFO_SIZE;
                Some(Self::parse_btree_info(&buf[start..node_size])?)
            }
        } else {
            None
        };

        Ok(Self {
            hdr,
            has_obj_header,
            header_size,
            toc,
            info,
        })
    }

    fn parse_btree_info(buf: &[u8]) -> Result<BTreeInfo, String> {
        let mut c = std::io::Cursor::new(buf);
        let flags = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let node_size = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let key_size = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let val_size = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let longest_key = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let longest_val = c.read_u32::<LittleEndian>().map_err(|e| e.to_string())?;
        let key_count = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        let node_count = c.read_u64::<LittleEndian>().map_err(|e| e.to_string())?;
        Ok(BTreeInfo {
            fixed: BTreeInfoFixed {
                flags,
                node_size,
                key_size,
                val_size,
            },
            longest_key,
            longest_val,
            key_count,
            node_count,
        })
    }

    fn key_area_start(&self) -> usize {
        let ts = self.hdr.table_space;
        self.header_size + (ts.off as usize) + (ts.len as usize)
    }

    fn value_area_end(&self, node_size: usize) -> usize {
        if (self.hdr.flags & BTNODE_ROOT) != 0 {
            if node_size > BTREE_INFO_SIZE {
                node_size - BTREE_INFO_SIZE
            } else {
                node_size
            }
        } else {
            node_size
        }
    }

    fn entry_key_val<'a>(
        &'a self,
        buf: &'a [u8],
        node_size: usize,
        i: usize,
        key_size: usize,
        val_size_leaf: usize,
    ) -> Result<(&'a [u8], &'a [u8]), String> {
        let key_area = self.key_area_start();
        let val_end = self.value_area_end(node_size);

        match self.toc.get(i).ok_or("toc index OOB")? {
            TocEntry::Fixed { k_off, v_off } => {
                let k0 = key_area + (*k_off as usize);
                let k1 = k0 + key_size;
                if k1 > buf.len() {
                    return Err("key out of bounds".into());
                }

                let val_len = if self.hdr.level == 0 {
                    val_size_leaf
                } else {
                    8 // index-node value: child oid/paddr (hash ignored)
                };

                let v_off_usize = *v_off as usize;
                if v_off_usize == 0xffff {
                    return Ok((&buf[k0..k1], &[])); // No value
                }
                let v0 = if v_off_usize <= val_end {
                    val_end - v_off_usize
                } else {
                    // Fallback: some APFS variants might have v_off relative to the absolute end.
                    if v_off_usize <= node_size {
                        node_size - v_off_usize
                    } else {
                        return Err(format!(
                            "val offset underflow: v_off={} val_end={} node_size={}",
                            v_off_usize, val_end, node_size
                        ));
                    }
                };
                let v1 = v0 + val_len;
                if v1 > buf.len() || v0 > v1 {
                    return Err("val out of bounds".into());
                }
                Ok((&buf[k0..k1], &buf[v0..v1]))
            }
            TocEntry::Var { k, v } => {
                let k0 = key_area + (k.off as usize);
                let k1 = k0 + (k.len as usize);
                if k1 > buf.len() {
                    return Err("var key out of bounds".into());
                }
                let v_off_usize = v.off as usize;
                if v_off_usize == 0xffff {
                    return Ok((&buf[k0..k1], &[])); // No value
                }
                let v0 = if v_off_usize <= val_end {
                    val_end - v_off_usize
                } else if v_off_usize <= node_size {
                    node_size - v_off_usize
                } else {
                    return Err(format!(
                        "var val offset underflow: v_off={} val_end={} node_size={}",
                        v_off_usize, val_end, node_size
                    ));
                };
                let v1 = v0 + (v.len as usize);
                if v1 > buf.len() {
                    return Err("var val out of bounds".into());
                }
                Ok((&buf[k0..k1], &buf[v0..v1]))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum BTreeKeyCmp {
    /// Raw lexicographic byte comparison.
    Lex,
    /// APFS OMAP key ordering `(oid, xid)`.
    OmapKey,
    /// APFS filesystem key ordering on key header + suffix.
    ApfsJKey,
}

fn cmp_keys(cmp: &BTreeKeyCmp, a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    match cmp {
        BTreeKeyCmp::Lex => a.cmp(b),
        BTreeKeyCmp::OmapKey => {
            if a.len() < 16 || b.len() < 16 {
                return a.cmp(b);
            }
            let a_oid = u64::from_le_bytes(a[0..8].try_into().unwrap());
            let a_xid = u64::from_le_bytes(a[8..16].try_into().unwrap());
            let b_oid = u64::from_le_bytes(b[0..8].try_into().unwrap());
            let b_xid = u64::from_le_bytes(b[8..16].try_into().unwrap());
            a_oid.cmp(&b_oid).then(a_xid.cmp(&b_xid))
        }
        BTreeKeyCmp::ApfsJKey => {
            if a.len() < 8 || b.len() < 8 {
                return a.cmp(b);
            }
            // j_key_t ordering: object id first, then object type, then key suffix.
            // Raw packed header cannot be compared directly because type lives in high bits.
            const J_KEY_OBJ_ID_MASK: u64 = 0x0fff_ffff_ffff_ffff;
            const J_KEY_TYPE_MASK: u64 = 0xf000_0000_0000_0000;
            const J_KEY_TYPE_SHIFT: u64 = 60;

            let a_raw = u64::from_le_bytes(a[0..8].try_into().unwrap());
            let b_raw = u64::from_le_bytes(b[0..8].try_into().unwrap());
            let a_obj = a_raw & J_KEY_OBJ_ID_MASK;
            let b_obj = b_raw & J_KEY_OBJ_ID_MASK;
            let a_ty = ((a_raw & J_KEY_TYPE_MASK) >> J_KEY_TYPE_SHIFT) as u8;
            let b_ty = ((b_raw & J_KEY_TYPE_MASK) >> J_KEY_TYPE_SHIFT) as u8;

            a_obj
                .cmp(&b_obj)
                .then(a_ty.cmp(&b_ty))
                .then(a[8..].cmp(&b[8..]))
        }
    }
}

/// Generic B-tree handle.
///
/// Represents an APFS B-tree, which can be either physical (addressed by block numbers)
/// or virtual (addressed by object IDs through an OMAP).
#[derive(Debug, Clone)]
pub struct BTree {
    /// The root identifier (paddr or oid).
    root_id: u64,
    /// Whether the root is a physical block address.
    root_is_physical: bool,
    /// B-tree parameters from the root node.
    pub info: BTreeInfo,
    /// Root object type.
    pub root_obj_type: u32,
    /// Root object subtype (subtype of the object header).
    pub root_obj_subtype: u32,
    /// Current number of levels in the tree (0 for leaf-only).
    pub root_level: u16,
    /// Number of keys in the root node.
    pub root_nkeys: u32,
    /// Physical block address of the root node.
    root_paddr: u64,
}

impl BTreeCursor {
    pub fn current_key_gt_target(&self) -> bool {
        self.state.gt_target
    }
}

#[derive(Debug, Clone)]
pub struct CursorState {
    // path from root to current node: (node_id, node_paddr, node, chosen_child_index)
    stack: Vec<(u64, u64, Node, usize)>,
    // current leaf node
    leaf_id: u64,
    leaf: Node,
    leaf_index: usize,
    _target_key: Vec<u8>,
    gt_target: bool,
}

// impl CursorState {
//     pub fn current_key_gt_target(&self) -> bool {
//         self.gt_target
//     }
// }

impl BTree {
    /// Opens a physical-root b-tree at a known physical block address.
    pub fn open_physical<T: std::io::Read + std::io::Seek>(
        apfs: &mut crate::APFS<T>,
        root_paddr: u64,
    ) -> Result<Self, String> {
        Self::open_physical_with_size(apfs, root_paddr, None)
    }

    /// Opens a physical-root b-tree at `root_paddr`.
    fn open_physical_with_size<T: std::io::Read + std::io::Seek>(
        apfs: &mut crate::APFS<T>,
        root_paddr: u64,
        root_obj_size: Option<u32>,
    ) -> Result<Self, String> {
        let bs = apfs.block_size_u64() as usize;
        let lens: Vec<usize> = match root_obj_size.map(|s| s as usize).filter(|&s| s > 0) {
            Some(v) => vec![v.max(bs)],
            None => vec![bs, bs * 2, bs * 4, bs * 8, bs * 16],
        };

        let mut last_err = String::new();
        for read_len in lens {
            let buf = match crate::io::read_phys(&mut apfs.body, bs as u64, root_paddr, read_len) {
                Ok(v) => v,
                Err(e) => {
                    last_err = e;
                    continue;
                }
            };
            // Prefer normal node-header parsing for roots to preserve compatibility with
            // datasets where OMAP NOHEADER is set but btree node headers are still present.
            let parse_modes: [bool; 2] = [true, false];
            let mut root_opt = None;
            for has_obj_header in parse_modes {
                match Node::parse(&buf, read_len, has_obj_header) {
                    Ok(v) => {
                        if has_obj_header
                            && let Err(e) = v.hdr.obj.validate(&buf) {
                                last_err = e;
                                continue;
                            }
                        root_opt = Some(v);
                        break;
                    }
                    Err(e) => last_err = e,
                }
            }
            let Some(root) = root_opt else {
                continue;
            };
            let info = match root.info.clone() {
                Some(v) => v,
                None => {
                    last_err = "root node missing btree_info".into();
                    continue;
                }
            };
            if (info.fixed.node_size as usize) > read_len && root_obj_size.is_none() {
                last_err = format!(
                    "root btree node_size={} requires larger read (had {})",
                    info.fixed.node_size, read_len
                );
                continue;
            }

            return Ok(Self {
                root_id: root_paddr,
                root_is_physical: true,
                info,
                root_obj_type: root.hdr.obj.obj_type,
                root_obj_subtype: root.hdr.obj.obj_subtype,
                root_level: root.hdr.level,
                root_nkeys: root.hdr.nkeys,
                root_paddr,
            });
        }

        Err(format!(
            "could not open physical btree root at paddr={} ({})",
            root_paddr, last_err
        ))
    }

    /// Opens a virtual-root b-tree by resolving `root_oid` through `omap`.
    pub fn open_virtual<T: std::io::Read + std::io::Seek>(
        apfs: &mut crate::APFS<T>,
        root_oid: u64,
        omap: &crate::omap::Omap,
        xid: u64,
    ) -> Result<Self, String> {
        // resolve root oid -> paddr via OMAP, then open physical at that paddr
        let m = omap.lookup(apfs, root_oid, xid)?;
        let mut tree = Self::open_physical_with_size(apfs, m.paddr, Some(m.size))?;
        tree.root_id = root_oid;
        tree.root_is_physical = false;
        tree.root_paddr = m.paddr;
        Ok(tree)
    }

    /// Loads a B-tree node from disk.
    ///
    /// Depending on whether the tree is physical or virtual, this method will either
    /// read a block directly or resolve its object ID through an OMAP.
    fn load_node<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        node_id: u64,
        omap: Option<(&crate::omap::Omap, u64)>,
        base_paddr: Option<u64>,
    ) -> Result<(u64, Vec<u8>, Node), String> {
        let node_size = self.info.fixed.node_size as usize;
        let bsize = apfs.block_size_u64();
        let physical_children = (self.info.fixed.flags & BTREE_PHYSICAL) != 0;
        let (paddr, buf, map_flags) = if self.root_is_physical && physical_children {
            // Physical btree: child links are physical addresses; node_id is paddr.
            let b = crate::io::read_phys(&mut apfs.body, bsize, node_id, node_size)?;
            (node_id, b, 0u32)
        } else if self.root_is_physical {
            // Physical root, but virtual children (rare); treat child as oid via omap if provided.
            let (omap, xid) = omap.ok_or("omap required for virtual child")?;
            let m = omap.lookup(apfs, node_id, xid)?;
            let b = crate::io::read_phys(&mut apfs.body, bsize, m.paddr, node_size)?;
            (m.paddr, b, m.flags)
        } else if node_id == self.root_id {
            // Virtual btree root id is an oid.
            let (omap, xid) = omap.ok_or("omap required for virtual btree root")?;
            let m = omap.lookup(apfs, node_id, xid)?;
            let b = crate::io::read_phys(&mut apfs.body, bsize, m.paddr, node_size)?;
            (m.paddr, b, m.flags)
        } else {
            // Virtual btree child: resolve oid via omap.
            let (omap, xid) = omap.ok_or("omap required for virtual btree")?;
            match omap.lookup(apfs, node_id, xid) {
                Ok(m) => {
                    let b = crate::io::read_phys(&mut apfs.body, bsize, m.paddr, node_size)?;
                    (m.paddr, b, m.flags)
                }
                Err(omap_err) if physical_children => {
                    let mut paddrs = vec![node_id];
                    if let Some(base) = base_paddr {
                        let delta = base.saturating_add(node_id);
                        if delta != node_id {
                            paddrs.push(delta);
                        }
                    }
                    let delta = self.root_paddr.saturating_add(node_id);
                    if delta != node_id {
                        paddrs.push(delta);
                    }
                    let mut loaded: Option<(u64, Vec<u8>)> = None;
                    for paddr in paddrs {
                        let Ok(b) = crate::io::read_phys(&mut apfs.body, bsize, paddr, node_size)
                        else {
                            continue;
                        };
                        let parsed = Node::parse(&b, node_size, true)
                            .or_else(|_| Node::parse(&b, node_size, false));
                        let Ok(n) = parsed else {
                            continue;
                        };
                        if n.has_obj_header
                            && n.hdr.obj.validate(&b).is_err() {
                                continue;
                            }
                        loaded = Some((paddr, b));
                        break;
                    }
                    if let Some((paddr, b)) = loaded {
                        (paddr, b, 0u32)
                    } else {
                        return Err(omap_err);
                    }
                }
                Err(e) => return Err(e),
            }
        };

        let _ = map_flags;
        let node = match Node::parse(&buf, node_size, true) {
            Ok(n) => n,
            Err(_) => Node::parse(&buf, node_size, false)?,
        };
        if node.has_obj_header {
            node.hdr.obj.validate(&buf)?;
        }
        Ok((paddr, buf, node))
    }

    /// Gets a key's value if an exact match exists under the provided comparator.
    pub fn get<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        key: &[u8],
        cmp: &BTreeKeyCmp,
    ) -> Result<Option<Vec<u8>>, String> {
        let mut cur = self.seek(apfs, key, cmp)?;
        if let Some((k, v)) = cur.current(apfs)?
            && cmp_keys(cmp, &k, key) == std::cmp::Ordering::Equal {
                return Ok(Some(v));
            }
        Ok(None)
    }

    /// Seeks to the first key `>= target` under the provided comparator.
    pub fn seek<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        key: &[u8],
        cmp: &BTreeKeyCmp,
    ) -> Result<BTreeCursor, String> {
        BTreeCursor::seek(self, apfs, key, cmp)
    }
}

/// Stateful cursor/iterator
pub struct BTreeCursor {
    tree: BTree,
    _cmp: BTreeKeyCmp,
    omap: Option<crate::omap::Omap>,
    xid: u64,
    state: CursorState,
    // cache of current leaf bytes:
    leaf_buf: Vec<u8>,
}

impl BTreeCursor {
    fn seek<T: std::io::Read + std::io::Seek>(
        tree: &BTree,
        apfs: &mut crate::APFS<T>,
        key: &[u8],
        cmp: &BTreeKeyCmp,
    ) -> Result<Self, String> {
        // we only support omap-fed traversal if caller set apfs.active_volume_omap()
        let omap: Option<crate::omap::Omap> = apfs.active_omap.clone();
        let xid: u64 = apfs.active_xid;
        let omap_ref = omap.as_ref().map(|o| (o, xid));
        // Start from root node id: physical root uses paddr, virtual root uses oid
        let start_id = if tree.root_is_physical {
            // physical btree root is stored at tree.info/root_paddr in open_physical, but tree.root_id holds paddr
            // if open_virtual, root_id holds oid and root_is_physical=false.
            // Here root_is_physical==true => we stored physical paddr in info by open_physical.
            // We'll keep root paddr in apfs.active_root_paddr for simplicity; instead load from tree.info by using start_id=???.
            // In this implementation, for physical btrees, we interpret root_id as paddr.
            tree.root_id
        } else {
            tree.root_id
        };

        // Load root
        let (root_paddr, root_buf, root_node) = tree.load_node(apfs, start_id, omap_ref, None)?;

        // Descend to leaf using “largest key <= target” rule.
        let mut stack: Vec<(u64, u64, Node, usize)> = Vec::new();
        let mut cur_id = start_id;
        let mut cur_paddr = root_paddr;
        let mut cur_buf = root_buf;
        let mut cur_node = root_node;

        while cur_node.hdr.level != 0 {
            let chosen = choose_child_index(tree, &cur_node, &cur_buf, key, cmp)?;
            let mut errs = Vec::<String>::new();
            let mut loaded: Option<(usize, u64, u64, Vec<u8>, Node)> = None;

            // Try the selected branch first, then subsequent branches as recovery.
            for idx in chosen..(cur_node.hdr.nkeys as usize) {
                let candidates =
                    child_id_candidates_from_index_val(tree, &cur_node, &cur_buf, idx)?;
                for child_id in candidates {
                    match tree.load_node(apfs, child_id, omap_ref, Some(cur_paddr)) {
                        Ok((child_paddr, nb, nn)) => {
                            loaded = Some((idx, child_id, child_paddr, nb, nn));
                            break;
                        }
                        Err(e) => errs.push(format!("idx={} child_id={} err={}", idx, child_id, e)),
                    }
                }
                if loaded.is_some() {
                    break;
                }
            }

            let Some((used_idx, child_id, child_paddr, nb, nn)) = loaded else {
                return Err(format!(
                    "could not load any child for chosen index {}: {}",
                    chosen,
                    errs.join(" | ")
                ));
            };
            stack.push((cur_id, cur_paddr, cur_node, used_idx));
            cur_id = child_id;
            cur_paddr = child_paddr;
            cur_buf = nb;
            cur_node = nn;
        }

        let leaf = cur_node;
        let leaf_id = cur_id;
        let leaf_buf2 = cur_buf;

        let idx = lower_bound_in_leaf(tree, &leaf, &leaf_buf2, key, cmp)?;
        let gt_target = if idx < leaf.hdr.nkeys as usize {
            let (k, _) = leaf.entry_key_val(
                &leaf_buf2,
                tree.info.fixed.node_size as usize,
                idx,
                tree.info.fixed.key_size as usize,
                tree.info.fixed.val_size as usize,
            )?;
            cmp_keys(cmp, k, key) == std::cmp::Ordering::Greater
        } else {
            true
        };

        Ok(Self {
            tree: tree.clone(),
            _cmp: cmp.clone(),
            omap,
            xid,
            state: CursorState {
                stack,
                leaf_id,
                leaf,
                leaf_index: idx,
                _target_key: key.to_vec(),
                gt_target,
            },
            leaf_buf: leaf_buf2,
        })
    }

    /// Returns the current key/value pair without advancing the cursor.
    pub fn current<T: std::io::Read + std::io::Seek>(
        &mut self,
        _apfs: &mut crate::APFS<T>,
    ) -> Result<Option<KeyValue>, String> {
        let i = self.state.leaf_index;
        if i >= self.state.leaf.hdr.nkeys as usize {
            return Ok(None);
        }
        let (k, v) = self.state.leaf.entry_key_val(
            &self.leaf_buf,
            self.tree.info.fixed.node_size as usize,
            i,
            self.tree.info.fixed.key_size as usize,
            self.tree.info.fixed.val_size as usize,
        )?;
        Ok(Some((k.to_vec(), v.to_vec())))
    }

    /// Returns the current key/value pair and then advances to the next record.
    pub fn next<T: std::io::Read + std::io::Seek>(
        &mut self,
        apfs: &mut crate::APFS<T>,
    ) -> Result<Option<KeyValue>, String> {
        // Return current then advance. Some trees contain empty leaves; skip them.
        loop {
            let out = self.current(apfs)?;
            if let Some(kv) = out {
                self.state.leaf_index += 1;
                if self.state.leaf_index >= self.state.leaf.hdr.nkeys as usize {
                    self.advance_to_next_leaf(apfs)?;
                }
                return Ok(Some(kv));
            }

            let prev_leaf_id = self.state.leaf_id;
            let prev_idx = self.state.leaf_index;
            let prev_stack_len = self.state.stack.len();
            self.advance_to_next_leaf(apfs)?;

            // No forward progress => end of tree.
            if self.state.leaf_id == prev_leaf_id
                && self.state.leaf_index == prev_idx
                && self.state.stack.len() == prev_stack_len
            {
                return Ok(None);
            }
        }
    }

    pub fn prev<T: std::io::Read + std::io::Seek>(
        &mut self,
        apfs: &mut crate::APFS<T>,
    ) -> Result<(), String> {
        if self.state.leaf_index > 0 {
            self.state.leaf_index -= 1;
            self.state.gt_target = false;
            return Ok(());
        }
        self.advance_to_prev_leaf(apfs)?;
        Ok(())
    }

    fn advance_to_next_leaf<T: std::io::Read + std::io::Seek>(
        &mut self,
        apfs: &mut crate::APFS<T>,
    ) -> Result<(), String> {
        // climb until we can increment a chosen child index
        while let Some((nid, npaddr, node, chosen)) = self.state.stack.pop() {
            let nkeys = node.hdr.nkeys as usize;
            let next_child = chosen + 1;
            if next_child < nkeys {
                // descend into next_child then go all the way left
                let omap_ref = self.omap.as_ref().map(|o| (o, self.xid));
                let (_parent_paddr, parent_buf, _parent_node) =
                    self.tree.load_node(apfs, nid, omap_ref, None)?;
                let candidates =
                    child_id_candidates_from_index_val(&self.tree, &node, &parent_buf, next_child)?;
                let mut loaded: Option<(u64, u64, Vec<u8>, Node)> = None;
                for child_id in candidates {
                    if let Ok((child_paddr, buf, nn)) =
                        self.tree.load_node(apfs, child_id, omap_ref, Some(npaddr))
                    {
                        loaded = Some((child_id, child_paddr, buf, nn));
                        break;
                    }
                }
                let Some((first_child, first_paddr, mut buf, mut nn)) = loaded else {
                    continue;
                };

                // BUG FIX: Push the current level back with the ADVANCED index
                // so we don't skip its subsequent siblings after we're done with this branch.
                self.state
                    .stack
                    .push((nid, npaddr, node.clone(), next_child));

                let mut cur_id = first_child;
                let mut cur_paddr = first_paddr;

                while nn.hdr.level != 0 {
                    let left = 0usize;
                    self.state.stack.push((cur_id, cur_paddr, nn.clone(), left));
                    let candidates =
                        child_id_candidates_from_index_val(&self.tree, &nn, &buf, left)?;
                    let mut loaded_left: Option<(u64, u64, Vec<u8>, Node)> = None;
                    for cid in candidates {
                        if let Ok((cp, b2, n2)) =
                            self.tree.load_node(apfs, cid, omap_ref, Some(cur_paddr))
                        {
                            loaded_left = Some((cid, cp, b2, n2));
                            break;
                        }
                    }
                    let Some((cid, cp, b2, n2)) = loaded_left else {
                        break;
                    };
                    cur_id = cid;
                    cur_paddr = cp;
                    buf = b2;
                    nn = n2;
                }

                self.state.leaf_id = cur_id;
                self.state.leaf = nn;
                self.leaf_buf = buf;
                self.state.leaf_index = 0;
                self.state.gt_target = false;
                return Ok(());
            }
        }
        // end of tree
        self.state.leaf_index = self.state.leaf.hdr.nkeys as usize;
        Ok(())
    }

    fn advance_to_prev_leaf<T: std::io::Read + std::io::Seek>(
        &mut self,
        _apfs: &mut crate::APFS<T>,
    ) -> Result<(), String> {
        // Minimal backward stepping is tricky without a parent-aware stack rebuild.
        // For OMAP fallback we only needed a few prev() steps after seek(),
        // so we implement a conservative approach: mark “no current”.
        self.state.leaf_index = 0;
        Err("prev across leaf boundary not implemented (seek fallback reached boundary)".into())
    }
}

/// Chooses the child index to descend into when seeking a target key.
///
/// Implements the "largest key <= target" rule for B-tree index nodes.
fn choose_child_index(
    tree: &BTree,
    node: &Node,
    node_buf: &[u8],
    target: &[u8],
    cmp: &BTreeKeyCmp,
) -> Result<usize, String> {
    if target.is_empty() {
        return Ok(0);
    }
    // largest key <= target; if all keys > target, choose 0
    let mut best = 0usize;
    for i in 0..(node.hdr.nkeys as usize) {
        let (k, _) = node.entry_key_val(
            node_buf,
            tree.info.fixed.node_size as usize,
            i,
            tree.info.fixed.key_size as usize,
            tree.info.fixed.val_size as usize,
        )?;
        if cmp_keys(cmp, k, target) != std::cmp::Ordering::Greater {
            best = i;
        } else {
            break;
        }
    }
    Ok(best)
}

/// Performs a lower bound search within a leaf node.
///
/// Returns the index of the first key that is not less than the target.
fn lower_bound_in_leaf(
    tree: &BTree,
    leaf: &Node,
    leaf_buf: &[u8],
    target: &[u8],
    cmp: &BTreeKeyCmp,
) -> Result<usize, String> {
    if target.is_empty() {
        return Ok(0);
    }
    for i in 0..(leaf.hdr.nkeys as usize) {
        let (k, _) = leaf.entry_key_val(
            leaf_buf,
            tree.info.fixed.node_size as usize,
            i,
            tree.info.fixed.key_size as usize,
            tree.info.fixed.val_size as usize,
        )?;
        if cmp_keys(cmp, k, target) != std::cmp::Ordering::Less {
            return Ok(i);
        }
    }
    Ok(leaf.hdr.nkeys as usize)
}

/// Extracts all candidate child addresses from an index node entry.
///
/// In some APFS variants or corrupted states, a single entry might point to multiple
/// versions or alternate locations for a child. This helper returns all unique
/// identifiers found in the value slots.
fn child_id_candidates_from_index_val(
    tree: &BTree,
    node: &Node,
    node_buf: &[u8],
    i: usize,
) -> Result<Vec<u64>, String> {
    let (_k, v) = node.entry_key_val(
        node_buf,
        tree.info.fixed.node_size as usize,
        i,
        tree.info.fixed.key_size as usize,
        tree.info.fixed.val_size as usize,
    )?;
    if v.len() < 8 {
        return Err("index node value too small".into());
    }
    let first = u64::from_le_bytes(v[0..8].try_into().unwrap());
    let mut out = vec![first];

    if node.hdr.level != 0 {
        if let Some(TocEntry::Fixed { v_off, .. }) = node.toc.get(i) {
            // Fixed-size index values may contain additional u64 fields beyond the first.
            let node_size = tree.info.fixed.node_size as usize;
            let val_end = node.value_area_end(node_size);
            let v0 = val_end
                .checked_sub(*v_off as usize)
                .ok_or("index val offset underflow")?;
            let max_slots = ((tree.info.fixed.val_size as usize) / 8).min(8);
            for slot in 1..max_slots {
                let s0 = v0 + slot * 8;
                let s1 = s0 + 8;
                if s1 > node_buf.len() {
                    break;
                }
                let cand = u64::from_le_bytes(node_buf[s0..s1].try_into().unwrap());
                if cand != 0 && !out.contains(&cand) {
                    out.push(cand);
                }
            }
        } else {
            // Variable-size index values (observed as 40 bytes in APFST2 captures)
            // can keep child references in later u64 slots.
            let slots = (v.len() / 8).min(8);
            for slot in 1..slots {
                let s0 = slot * 8;
                let s1 = s0 + 8;
                let cand = u64::from_le_bytes(v[s0..s1].try_into().unwrap());
                if cand != 0 && !out.contains(&cand) {
                    out.push(cand);
                }
            }
        }
    }
    Ok(out)
}

/// Owned key/value pair yielded by a [`BTreeCursor`].
pub type KeyValue = (Vec<u8>, Vec<u8>);
