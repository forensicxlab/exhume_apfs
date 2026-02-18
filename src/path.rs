//! High-level path resolution and file reading helpers.

use crate::fstree::{FsTree, InodeVal};

const MAX_READ_BYTES: u64 = 512 * 1024 * 1024;

/// Result of resolving an absolute APFS path.
#[derive(Debug, Clone)]
pub struct ResolvedPath {
    pub inode_id: u64,
    pub inode: InodeVal,
}

impl FsTree {
    /// Resolves an absolute path using directory records and returns its inode.
    pub fn resolve_path<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        path: &str,
    ) -> Result<ResolvedPath, String> {
        let mut cur_id: u64 = self
            .detect_root_inode_id(apfs)?
            .ok_or_else(|| "could not determine root inode id".to_string())?;

        let parts = path.split('/').filter(|p| !p.is_empty());
        for part in parts {
            let kids = self.dir_children(apfs, cur_id)?;
            let next = kids
                .into_iter()
                .find(|e| e.name == part)
                .ok_or_else(|| format!("path component not found: {}", part))?;
            cur_id = match next.inode_id {
                Some(v) => v,
                None => {
                    // Some records expose raw id only; attempt direct inode lookup before failing.
                    if self.inode_by_id(apfs, next.raw_id)?.is_some() {
                        next.raw_id
                    } else {
                        return Err(format!(
                            "path component '{}' has unresolved inode (raw_id={})",
                            part, next.raw_id
                        ));
                    }
                }
            };
        }

        let inode = self
            .inode_by_id(apfs, cur_id)?
            .ok_or_else(|| format!("inode not found for id={}", cur_id))?;

        Ok(ResolvedPath {
            inode_id: cur_id,
            inode,
        })
    }

    /// Reads file data for a resolved path using extent mappings (raw bytes).
    pub fn read_file_by_path<T: std::io::Read + std::io::Seek>(
        &self,
        apfs: &mut crate::APFS<T>,
        path: &str,
    ) -> Result<Vec<u8>, String> {
        let r = self.resolve_path(apfs, path)?;
        if (r.inode.mode & 0o170000) != 0o100000 {
            return Err(format!(
                "path '{}' does not resolve to a regular file (mode=0{:o})",
                path, r.inode.mode
            ));
        }

        // Determine file size from INO_EXT_TYPE_DSTREAM if present.
        let size = r
            .inode
            .dstream
            .as_ref()
            .map(|d| d.size)
            .unwrap_or(r.inode.uncompressed_size);

        // Extents can be keyed by inode_id or by private_id depending on layout; try both.
        let mut ext = self.file_extents(apfs, r.inode_id)?;
        if ext.is_empty() && r.inode.private_id != 0 {
            ext = self.file_extents(apfs, r.inode.private_id)?;
        }
        let mut max_end = 0u64;
        for e in &ext {
            max_end = max_end.max(e.logical_addr.saturating_add(e.length_bytes));
        }
        let mut out_size = size;
        if max_end > 0 && (out_size == 0 || out_size > max_end) {
            out_size = max_end;
        }
        if out_size > MAX_READ_BYTES {
            return Err(format!(
                "refusing to allocate {} bytes (cap={} bytes)",
                out_size, MAX_READ_BYTES
            ));
        }
        let out_size_usize = usize::try_from(out_size)
            .map_err(|_| format!("output size does not fit usize: {}", out_size))?;
        let mut out = vec![0u8; out_size_usize];

        for e in ext {
            let off = e.logical_addr as usize;
            let len = e.length_bytes as usize;
            if off >= out.len() {
                continue;
            }
            let to_copy = len.min(out.len() - off);

            // read extent bytes from phys blocks
            let start_paddr = e.phys_block_num;
            let bsize = apfs.block_size_u64();
            let data = crate::io::read_phys(&mut apfs.body, bsize, start_paddr, to_copy)?;
            out[off..off + to_copy].copy_from_slice(&data[..to_copy]);

            // NOTE: encrypted extents require crypto handling; we leave raw bytes.
        }

        Ok(out)
    }
}
