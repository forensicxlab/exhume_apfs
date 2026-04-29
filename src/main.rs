use clap::*;
use clap_num::maybe_hex;
use exhume_apfs::{APFS, apfs_kind, apfs_mode_to_string, fmt_apfs_ns_utc};
use exhume_body::{Body, BodySlice};
use log::{LevelFilter, debug, error, info};
use prettytable::{Table, row};
use serde_json::{self, json};

const MAX_DUMP_BYTES: u64 = 512 * 1024 * 1024;

fn fmt_uuid(u: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0],
        u[1],
        u[2],
        u[3],
        u[4],
        u[5],
        u[6],
        u[7],
        u[8],
        u[9],
        u[10],
        u[11],
        u[12],
        u[13],
        u[14],
        u[15]
    )
}

fn is_dir_mode(mode: u16) -> bool {
    (mode & 0o170000) == 0o040000
}

fn main() {
    let matches = Command::new("exhume_apfs")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Exhume metadata from an Apple APFS container.")
        .arg(
            Arg::new("body")
                .short('b')
                .long("body")
                .value_parser(value_parser!(String))
                .required(true),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_parser(value_parser!(String))
                .required(false),
        )
        .arg(
            Arg::new("offset")
                .short('o')
                .long("offset")
                .value_parser(maybe_hex::<u64>)
                .required(true),
        )
        .arg(
            Arg::new("size")
                .short('s')
                .long("size")
                .value_parser(maybe_hex::<u64>)
                .required(true),
        )
        .arg(
            Arg::new("volume_index")
                .long("volume-index")
                .value_parser(maybe_hex::<u32>)
                .required(false)
                .default_value("0"),
        )
        .arg(
            Arg::new("list_volumes")
                .long("list-volumes")
                .action(ArgAction::SetTrue)
                .help("List all discovered APFS volumes with metadata."),
        )
        .arg(
            Arg::new("root_inode")
                .long("root-inode")
                .action(ArgAction::SetTrue)
                .help("Auto-detect and print the root inode id for the selected volume."),
        )
        .arg(
            Arg::new("inode")
                .long("inode")
                .value_parser(maybe_hex::<u64>)
                .required(false)
                .help("Show inode metadata for inode number."),
        )
        .arg(
            Arg::new("dir_entry")
                .long("dir_entry")
                .action(ArgAction::SetTrue)
                .requires("inode")
                .help("If --inode is a directory, list its directory entries."),
        )
        .arg(
            Arg::new("path")
                .long("path")
                .value_parser(value_parser!(String))
                .required(false)
                .help("Resolve a path and show inode."),
        )
        .arg(
            Arg::new("dump")
                .long("dump")
                .action(ArgAction::SetTrue)
                .requires("inode")
                .help("If --inode is a regular file, dump raw content to stdout."),
        )
        .arg(
            Arg::new("omap_oid")
                .long("omap-oid")
                .value_parser(maybe_hex::<u64>)
                .required(false)
                .help("Query selected volume OMAP for this object id."),
        )
        .arg(
            Arg::new("omap_xid")
                .long("omap-xid")
                .value_parser(maybe_hex::<u64>)
                .required(false)
                .help("Optional xid for exact/fallback OMAP lookup."),
        )
        .arg(
            Arg::new("omap_limit")
                .long("omap-limit")
                .value_parser(maybe_hex::<u32>)
                .required(false)
                .default_value("32")
                .help("Maximum number of OMAP versions returned by --omap-oid."),
        )
        .arg(
            Arg::new("json")
                .short('j')
                .long("json")
                .action(ArgAction::SetTrue),
        )
        .arg(
            Arg::new("log_level")
                .short('l')
                .long("log-level")
                .value_parser(["error", "warn", "info", "debug", "trace"])
                .default_value("info"),
        )
        .get_matches();

    // Logger
    let level_filter = match matches.get_one::<String>("log_level").unwrap().as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => LevelFilter::Info,
    };
    env_logger::Builder::new().filter_level(level_filter).init();

    let file_path = matches.get_one::<String>("body").unwrap();
    let auto = String::from("auto");
    let format = matches.get_one::<String>("format").unwrap_or(&auto);
    let offset = *matches.get_one::<u64>("offset").unwrap();
    let size_sectors = *matches.get_one::<u64>("size").unwrap();
    let json_output = matches.get_flag("json");
    let vol_index = *matches.get_one::<u32>("volume_index").unwrap();
    let list_volumes = matches.get_flag("list_volumes");
    let root_inode_q = matches.get_flag("root_inode");

    let inode_q = matches.get_one::<u64>("inode").copied();
    let dir_q = matches.get_flag("dir_entry");
    let path_q = matches.get_one::<String>("path").cloned();
    let dump_q = matches.get_flag("dump");
    let omap_oid_q = matches.get_one::<u64>("omap_oid").copied();
    let omap_xid_q = matches.get_one::<u64>("omap_xid").copied();
    let omap_limit_q = *matches.get_one::<u32>("omap_limit").unwrap() as usize;

    // Prepare Body + slice
    let body = Body::new(file_path.to_owned(), format);
    debug!("Created Body from '{}'", file_path);

    let container_size_bytes = size_sectors * body.get_sector_size() as u64;
    let slice = match BodySlice::new(&body, offset, container_size_bytes) {
        Ok(s) => s,
        Err(e) => {
            error!("Could not create BodySlice: {}", e);
            return;
        }
    };

    info!(
        "Opening APFS container at offset=0x{:x} size={} bytes",
        offset, container_size_bytes
    );

    let mut apfs = match APFS::new(slice) {
        Ok(fs) => fs,
        Err(e) => {
            error!("Could not parse APFS container: {}", e);
            return;
        }
    };

    if apfs.volumes.is_empty() {
        error!("No APFS volumes found via NXSB metadata.");
        return;
    }

    if list_volumes {
        let mut vols = apfs.volumes.clone();
        vols.sort_by_key(|v| v.fs_index);

        if json_output {
            let mut out = Vec::new();
            for v in vols {
                let root_detect = match apfs.open_fstree_for_volume(&v) {
                    Ok(fst) => match fst.detect_root_inode_id(&mut apfs) {
                        Ok(id) => json!({"root_inode_id": id, "error": null}),
                        Err(e) => json!({"root_inode_id": null, "error": e}),
                    },
                    Err(e) => json!({"root_inode_id": null, "error": e}),
                };

                out.push(json!({
                    "fs_index": v.fs_index,
                    "oid": v.o.oid,
                    "xid": v.o.xid,
                    "found_at_block": v.found_at_block,
                    "uuid": fmt_uuid(&v.vol_uuid),
                    "name": v.volume_name,
                    "role": format!("0x{:x}", v.role),
                    "omap_oid": v.omap_oid,
                    "root_tree_oid": v.root_tree_oid,
                    "extentref_tree_oid": v.extentref_tree_oid,
                    "snap_meta_tree_oid": v.snap_meta_tree_oid,
                    "revert_to_xid": v.revert_to_xid,
                    "revert_to_sblock_oid": v.revert_to_sblock_oid,
                    "features": format!("0x{:x}", v.features),
                    "readonly_compatible_features": format!("0x{:x}", v.readonly_compatible_features),
                    "incompatible_features": format!("0x{:x}", v.incompatible_features),
                    "root_detection": root_detect,
                }));
            }
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            let mut t = Table::new();
            t.add_row(row![
                "fs_index",
                "oid",
                "xid",
                "found_block",
                "name",
                "role",
                "uuid",
                "omap_oid",
                "root_tree_oid",
                "revert_sblock_oid",
                "root_inode"
            ]);
            for v in vols {
                let root_inode_text = match apfs.open_fstree_for_volume(&v) {
                    Ok(fst) => match fst.detect_root_inode_id(&mut apfs) {
                        Ok(Some(id)) => id.to_string(),
                        Ok(None) => "-".to_string(),
                        Err(e) => format!("err: {}", e),
                    },
                    Err(e) => format!("err: {}", e),
                };
                t.add_row(row![
                    v.fs_index,
                    v.o.oid,
                    v.o.xid,
                    v.found_at_block,
                    v.volume_name,
                    format!("0x{:x}", v.role),
                    fmt_uuid(&v.vol_uuid),
                    v.omap_oid,
                    v.root_tree_oid,
                    v.revert_to_sblock_oid,
                    root_inode_text
                ]);
            }
            t.printstd();
        }
        return;
    }

    let mut vol_candidates: Vec<_> = apfs
        .volumes
        .iter()
        .filter(|v| v.fs_index == vol_index)
        .cloned()
        .collect();
    if vol_candidates.is_empty() {
        error!("No volume with fs_index={}", vol_index);
        return;
    }
    vol_candidates.sort_by_key(|v| {
        (
            std::cmp::Reverse(v.o.xid),
            std::cmp::Reverse(v.found_at_block),
        )
    });
    let mut selected_vol = None;
    for cand in &vol_candidates {
        if apfs.open_fstree_for_volume(cand).is_ok() {
            selected_vol = Some(cand.clone());
            break;
        }
    }
    let vol = selected_vol.unwrap_or_else(|| vol_candidates[0].clone());

    if let Some(oid) = omap_oid_q {
        let (omap, xid) = match apfs.open_volume_omap_for_volume(&vol) {
            Ok(v) => v,
            Err(e) => {
                error!("Could not open volume OMAP: {}", e);
                return;
            }
        };

        let versions = match omap.dump_versions(&mut apfs, oid, omap_limit_q) {
            Ok(v) => v,
            Err(e) => {
                error!("OMAP dump failed for oid={}: {}", oid, e);
                return;
            }
        };
        let lookup_xid = omap_xid_q.unwrap_or(xid);
        let lookup = omap.lookup(&mut apfs, oid, lookup_xid).ok();

        if json_output {
            let out = json!({
                "volume_index": vol.fs_index,
                "omap_xid": xid,
                "query_oid": oid,
                "lookup_xid": lookup_xid,
                "lookup": lookup.as_ref().map(|m| json!({
                    "paddr": m.paddr,
                    "size": m.size,
                    "flags": format!("0x{:x}", m.flags),
                })),
                "versions": versions.iter().map(|(vxid, m)| json!({
                    "xid": vxid,
                    "paddr": m.paddr,
                    "size": m.size,
                    "flags": format!("0x{:x}", m.flags),
                })).collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        } else {
            let mut t = Table::new();
            t.add_row(row!["volume_index", vol.fs_index]);
            t.add_row(row!["omap_xid", xid]);
            t.add_row(row!["query_oid", oid]);
            t.add_row(row!["lookup_xid", lookup_xid]);
            if let Some(m) = lookup {
                t.add_row(row!["lookup_paddr", m.paddr]);
                t.add_row(row!["lookup_size", m.size]);
                t.add_row(row!["lookup_flags", format!("0x{:x}", m.flags)]);
            } else {
                t.add_row(row!["lookup", "<none>"]);
            }
            t.printstd();

            let mut vtab = Table::new();
            vtab.add_row(row!["xid", "paddr", "size", "flags"]);
            for (vxid, m) in versions {
                vtab.add_row(row![vxid, m.paddr, m.size, format!("0x{:x}", m.flags)]);
            }
            vtab.printstd();
        }
        return;
    }

    let needs_fst = inode_q.is_some() || dir_q || path_q.is_some() || dump_q || root_inode_q;
    let fst = if needs_fst {
        match apfs.open_fstree_for_volume(&vol) {
            Ok(v) => Some(v),
            Err(e) => {
                error!("Could not open volume FSTree: {}", e);
                return;
            }
        }
    } else {
        None
    };

    // --- Queries ---

    if let Some(id) = inode_q {
        match fst.as_ref().unwrap().inode_by_id(&mut apfs, id) {
            Ok(Some(inode)) => {
                if dir_q {
                    if !is_dir_mode(inode.mode) {
                        error!("requested --dir_entry but inode {} is not a directory", id);
                        return;
                    }
                    match fst.as_ref().unwrap().dir_children(&mut apfs, id) {
                        Ok(children) => {
                            if json_output {
                                let mut out = Vec::with_capacity(children.len());
                                for e in children {
                                    let resolved = e.inode_id.and_then(|iid| {
                                        fst.as_ref()
                                            .unwrap()
                                            .inode_by_id(&mut apfs, iid)
                                            .ok()
                                            .flatten()
                                    });
                                    out.push(json!({
                                        "name": e.name,
                                        "inode_id": e.inode_id,
                                        "raw_id": e.raw_id,
                                        "flags": format!("0x{:04x}", e.flags),
                                        "date_added_ns": e.date_added,
                                        "date_added_utc": fmt_apfs_ns_utc(e.date_added),
                                        "mode": resolved.as_ref().map(|i| format!("0{:o}", i.mode)),
                                        "permissions": resolved.as_ref().map(|i| apfs_mode_to_string(i.mode)),
                                        "kind": resolved.as_ref().map(|i| apfs_kind(i.mode)),
                                    }));
                                }
                                println!("{}", serde_json::to_string_pretty(&out).unwrap());
                            } else {
                                let mut t = Table::new();
                                t.add_row(row![
                                    "inode",
                                    "perm",
                                    "kind",
                                    "added_utc",
                                    "name",
                                    "raw_id",
                                    "flags"
                                ]);
                                for e in children {
                                    let mut inode_text = "-".to_string();
                                    let mut perm_text = "??????????".to_string();
                                    let mut kind_text = "-".to_string();
                                    if let Some(iid) = e.inode_id {
                                        inode_text = iid.to_string();
                                        if let Ok(Some(i)) =
                                            fst.as_ref().unwrap().inode_by_id(&mut apfs, iid)
                                        {
                                            perm_text = apfs_mode_to_string(i.mode);
                                            kind_text = apfs_kind(i.mode).to_string();
                                        }
                                    }
                                    t.add_row(row![
                                        inode_text,
                                        perm_text,
                                        kind_text,
                                        fmt_apfs_ns_utc(e.date_added),
                                        e.name,
                                        e.raw_id,
                                        format!("0x{:04x}", e.flags),
                                    ]);
                                }
                                t.printstd();
                            }
                        }
                        Err(e) => error!("dir enumeration failed: {}", e),
                    }
                } else if json_output {
                    println!("{}", serde_json::to_string_pretty(&inode).unwrap());
                } else {
                    print!("{}", inode.metadata_table(id));
                }

                if dump_q {
                    if (inode.mode & 0o170000) != 0o100000 {
                        error!(
                            "refusing dump for inode_id={} (mode=0{:o} is not a regular file)",
                            id, inode.mode
                        );
                        return;
                    }
                    // Read extents by inode id; fallback to private_id for layouts that key by private id.
                    let declared_size = inode
                        .dstream
                        .as_ref()
                        .map(|d| d.size)
                        .unwrap_or(inode.uncompressed_size);
                    let mut ext = fst
                        .as_ref()
                        .unwrap()
                        .file_extents(&mut apfs, id)
                        .unwrap_or_default();
                    if ext.is_empty() && inode.private_id != 0 {
                        ext = fst
                            .as_ref()
                            .unwrap()
                            .file_extents(&mut apfs, inode.private_id)
                            .unwrap_or_default();
                    }
                    let mut max_end = 0u64;
                    for e in &ext {
                        max_end = max_end.max(e.logical_addr.saturating_add(e.length_bytes));
                    }
                    // Size selection: prefer the declared logical size (from dstream or
                    // uncompressed_size) because it is byte-exact.  Fall back to extent
                    // coverage (max_end) only when no declared size is available — extent
                    // lengths are block-aligned and would append spurious null bytes.
                    let out_size = if declared_size > 0 && declared_size <= MAX_DUMP_BYTES {
                        // Cap at extent coverage: cannot extract bytes beyond what is on disk.
                        if max_end > 0 { declared_size.min(max_end) } else { declared_size }
                    } else if max_end > 0 {
                        max_end
                    } else {
                        error!(
                            "refusing dump for inode_id={} (no extent-backed content, declared_size={})",
                            id, declared_size
                        );
                        return;
                    };
                    if out_size > MAX_DUMP_BYTES {
                        error!(
                            "refusing dump for inode_id={} (size={} cap={})",
                            id, out_size, MAX_DUMP_BYTES
                        );
                        return;
                    }
                    let out_size_usize = match usize::try_from(out_size) {
                        Ok(v) => v,
                        Err(_) => {
                            error!("dump size does not fit usize: {}", out_size);
                            return;
                        }
                    };

                    let mut out = vec![0u8; out_size_usize];
                    for e in ext {
                        let off = e.logical_addr as usize;
                        let len = (e.length_bytes as usize).min(out.len().saturating_sub(off));
                        if len == 0 {
                            continue;
                        }
                        let bs = apfs.block_size_u64();
                        let data = match exhume_apfs::io::read_phys(
                            &mut apfs.body,
                            bs,
                            e.phys_block_num,
                            len,
                        ) {
                            Ok(v) => v,
                            Err(e) => {
                                error!("extent read failed for inode_id={}: {}", id, e);
                                return;
                            }
                        };
                        out[off..off + len].copy_from_slice(&data[..len]);
                    }
                    use std::io::Write;
                    std::io::stdout().write_all(&out).ok();
                }
            }
            Ok(None) => error!("inode not found for inode_id={}", id),
            Err(e) => error!("inode lookup failed: {}", e),
        }
        return;
    }

    if let Some(path) = path_q {
        match fst.as_ref().unwrap().resolve_path(&mut apfs, &path) {
            Ok(r) => {
                if json_output {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "path": path,
                            "inode_id": r.inode_id,
                            "private_id": r.inode.private_id,
                            "mode": r.inode.mode,
                            "size": r.inode.dstream.as_ref().map(|d| d.size).unwrap_or(r.inode.uncompressed_size),
                            "inode": r.inode,
                        }))
                        .unwrap()
                    );
                } else {
                    let mut t = Table::new();
                    t.add_row(row!["path", path]);
                    t.add_row(row!["inode_id", r.inode_id]);
                    if let Some(ds) = &r.inode.dstream {
                        t.add_row(row!["size", ds.size]);
                    } else {
                        t.add_row(row!["size(uncompressed)", r.inode.uncompressed_size]);
                    }
                    t.add_row(row!["private_id", r.inode.private_id]);
                    t.printstd();
                }
            }
            Err(e) => error!("path resolution failed: {}", e),
        }
        return;
    }

    // default: show container+volume overview
    if json_output {
        println!("{}", serde_json::to_string_pretty(&apfs).unwrap());
    } else {
        info!(
            "Volume selected: fs_index={} uuid={}",
            vol.fs_index,
            fmt_uuid(&vol.vol_uuid)
        );
        info!(
            "omap_oid={} root_tree_oid={}",
            vol.omap_oid, vol.root_tree_oid
        );
        info!("Tip: use --inode, --dir_entry, --path, or --dump");
    }
}
