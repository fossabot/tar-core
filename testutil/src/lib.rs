//! Shared test utilities for tar-core.
//!
//! Provides an owned entry type and helpers to parse tar archives with
//! both tar-core and the `tar` crate, for use in integration tests and
//! fuzz targets.

use std::io::{Cursor, Read};

use tar_core::parse::{Limits, ParseError, ParseEvent, Parser};
use tar_core::{HEADER_SIZE, PAX_SCHILY_XATTR};

/// Owned snapshot of a parsed tar entry, including content bytes.
///
/// All byte-oriented fields use `Vec<u8>` since tar paths and xattr
/// values are not necessarily valid UTF-8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedEntry {
    pub entry_type: u8,
    pub path: Vec<u8>,
    pub link_target: Option<Vec<u8>>,
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub mtime: u64,
    pub size: u64,
    pub uname: Option<Vec<u8>>,
    pub gname: Option<Vec<u8>>,
    /// Device major number (for block/char devices).
    pub dev_major: Option<u32>,
    /// Device minor number (for block/char devices).
    pub dev_minor: Option<u32>,
    /// Extended attributes (from PAX `SCHILY.xattr.*` records).
    /// Each pair is `(attr_name, value)` where `attr_name` is the part
    /// after `SCHILY.xattr.` (e.g. `user.mime_type`).
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    pub content: Vec<u8>,
}

/// Maximum content size read per entry (prevents OOM on fuzzed inputs).
const MAX_CONTENT_READ: u64 = 256 * 1024;

/// Result of parsing with tar-core: entries collected so far plus an
/// optional terminal error (if parsing stopped due to an error rather
/// than reaching end-of-archive or running out of data).
pub struct TarCoreParseResult {
    pub entries: Vec<OwnedEntry>,
    pub error: Option<ParseError>,
}

/// Parse a tar archive with tar-core's sans-IO parser using permissive limits.
pub fn parse_tar_core(data: &[u8]) -> Vec<OwnedEntry> {
    parse_tar_core_detailed(data, Limits::permissive()).entries
}

/// Parse a tar archive with tar-core using the given limits.
pub fn parse_tar_core_with_limits(data: &[u8], limits: Limits) -> Vec<OwnedEntry> {
    parse_tar_core_detailed(data, limits).entries
}

/// Parse a tar archive with tar-core, returning both entries and
/// any terminal parse error.
pub fn parse_tar_core_detailed(data: &[u8], limits: Limits) -> TarCoreParseResult {
    let mut results = Vec::new();
    let mut parser = Parser::new(limits);
    // Allow entries with empty paths so we don't stop parsing early.
    // We skip them below to match parse_tar_rs's behaviour.
    parser.set_allow_empty_path(true);
    let mut offset = 0;
    let mut terminal_error = None;

    loop {
        if offset > data.len() {
            break;
        }
        let input = &data[offset..];

        match parser.parse(input) {
            Ok(ParseEvent::NeedData { .. }) => break,
            Ok(ParseEvent::Entry { consumed, entry })
            | Ok(ParseEvent::SparseEntry {
                consumed, entry, ..
            }) => {
                offset += consumed;

                let size = entry.size;

                // Require enough data for the content bytes we'll actually
                // read. tar-rs reads `size` bytes (via read_exact) but
                // does not require the padding to be present.
                let read_size = size.min(MAX_CONTENT_READ) as usize;
                if offset.saturating_add(read_size) > data.len() {
                    break;
                }
                let content = data[offset..offset + read_size].to_vec();

                let xattrs: Vec<(Vec<u8>, Vec<u8>)> = entry
                    .xattrs
                    .iter()
                    .map(|(k, v)| (k.to_vec(), v.to_vec()))
                    .collect();

                // Skip metadata-only entry types to match parse_tar_rs.
                // When a header lacks valid magic, tar-core (and tar-rs)
                // emit extension types (L/K/x/g) as regular entries.
                // parse_tar_rs skips these, so we must too.
                let is_metadata_type = matches!(
                    entry.entry_type,
                    tar_core::EntryType::GnuLongName
                        | tar_core::EntryType::GnuLongLink
                        | tar_core::EntryType::XHeader
                        | tar_core::EntryType::XGlobalHeader
                );
                if is_metadata_type {
                    let padded = (size as usize).next_multiple_of(HEADER_SIZE);
                    if offset.saturating_add(padded) > data.len() {
                        break;
                    }
                    offset += padded;
                    continue;
                }

                // Skip entries with empty paths to match parse_tar_rs.
                if entry.path.is_empty() {
                    let padded = (size as usize).next_multiple_of(HEADER_SIZE);
                    if offset.saturating_add(padded) > data.len() {
                        break;
                    }
                    offset += padded;
                    continue;
                }

                results.push(OwnedEntry {
                    entry_type: entry.entry_type.to_byte(),
                    path: entry.path.to_vec(),
                    link_target: entry.link_target.as_ref().map(|v| v.to_vec()),
                    mode: entry.mode,
                    uid: entry.uid,
                    gid: entry.gid,
                    mtime: entry.mtime,
                    size,
                    uname: entry.uname.as_ref().map(|v| v.to_vec()),
                    gname: entry.gname.as_ref().map(|v| v.to_vec()),
                    dev_major: entry.dev_major,
                    dev_minor: entry.dev_minor,
                    xattrs,
                    content,
                });

                // Advance past content + padding to reach the next header.
                let padded = (size as usize).next_multiple_of(HEADER_SIZE);
                if offset.saturating_add(padded) > data.len() {
                    break;
                }
                offset += padded;
            }
            Ok(ParseEvent::GlobalExtensions { consumed, .. }) => {
                // Global PAX headers don't represent file entries; skip them.
                offset += consumed;
            }
            Ok(ParseEvent::End { .. }) => break,
            Err(e) => {
                terminal_error = Some(e);
                break;
            }
        }
    }

    TarCoreParseResult {
        entries: results,
        error: terminal_error,
    }
}

/// Truncate a byte slice at the first NUL byte, if any.
///
/// GNU LongName/LongLink content is NUL-terminated (C-string convention).
/// tar-core truncates at the first NUL when resolving these extension headers,
/// matching GNU tar and POSIX filesystem semantics (NUL is not a valid filename
/// character). tar-rs does not perform this truncation, so we normalize its
/// output here before comparison.
fn truncate_at_nul(bytes: Vec<u8>) -> Vec<u8> {
    match bytes.iter().position(|&b| b == 0) {
        Some(pos) => bytes[..pos].to_vec(),
        None => bytes,
    }
}

/// Parse a tar archive with the `tar` crate, returning owned entries.
pub fn parse_tar_rs(data: &[u8]) -> Vec<OwnedEntry> {
    let mut results = Vec::new();
    let cursor = Cursor::new(data);
    let mut archive = tar::Archive::new(cursor);

    let entries = match archive.entries() {
        Ok(e) => e,
        Err(_) => return results,
    };

    for entry in entries {
        let mut entry = match entry {
            Ok(e) => e,
            Err(_) => break,
        };
        let header = entry.header().clone();
        let entry_type = header.entry_type().as_byte();

        // Normalize NUL-termination: tar-rs does not truncate GNU LongName/
        // LongLink content at the first NUL byte; tar-core does (matching the
        // C-string convention used by GNU tar). Truncate here so we compare
        // equivalent representations.
        let path = truncate_at_nul(entry.path_bytes().into_owned());
        let size = entry.size();

        // Require that numeric fields parse successfully.  tar-core
        // treats invalid numeric fields as hard errors, so if tar-rs
        // silently defaulted to 0 we'd get false mismatches.
        //
        // These checks must come before ALL skip logic (metadata types,
        // empty paths) so both parsers stop on the same invalid fields.
        let Ok(mode) = header.mode() else { break };
        let Ok(uid) = header.uid() else { break };
        let Ok(gid) = header.gid() else { break };
        let Ok(mtime) = header.mtime() else { break };
        // tar-rs normally uses unwrap_or(None) for device fields, but
        // tar-core propagates errors. Break here to match.
        let Ok(dev_major) = header.device_major() else {
            break;
        };
        let Ok(dev_minor) = header.device_minor() else {
            break;
        };

        // Skip metadata-only entry types that tar-core handles internally
        // (GNU long name/link, PAX headers, global PAX headers).
        match header.entry_type() {
            tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink
            | tar::EntryType::XHeader
            | tar::EntryType::XGlobalHeader => continue,
            _ => {}
        }

        // tar-core rejects entries with empty paths; skip them here
        // to match.
        if path.is_empty() {
            continue;
        }
        // entry.link_name_bytes() applies PAX linkpath and GNU long link
        // overrides, unlike header.link_name_bytes() which is raw.
        // Also truncate at the first NUL to match tar-core's behavior for
        // GNU LongLink content (same NUL-termination normalization as path).
        let link_target = entry
            .link_name_bytes()
            .filter(|b| !b.is_empty())
            .map(|b| truncate_at_nul(b.to_vec()));

        // Extract PAX-overridden uname/gname and xattrs from PAX extensions.
        // tar-rs does not expose PAX uname/gname through entry-level methods,
        // so we must read the raw PAX records ourselves.
        let mut uname: Option<Vec<u8>> = None;
        let mut gname: Option<Vec<u8>> = None;
        let mut xattrs = Vec::new();
        if let Ok(Some(pax)) = entry.pax_extensions() {
            for ext in pax.flatten() {
                if let Ok(key) = std::str::from_utf8(ext.key_bytes()) {
                    if let Some(attr_name) = key.strip_prefix(PAX_SCHILY_XATTR) {
                        xattrs.push((attr_name.as_bytes().to_vec(), ext.value_bytes().to_vec()));
                    } else if key == "uname" {
                        let v = ext.value_bytes();
                        if !v.is_empty() {
                            uname = Some(v.to_vec());
                        }
                    } else if key == "gname" {
                        let v = ext.value_bytes();
                        if !v.is_empty() {
                            gname = Some(v.to_vec());
                        }
                    }
                }
            }
        }
        // Fall back to raw header values if PAX didn't override.
        if uname.is_none() {
            uname = header
                .username_bytes()
                .filter(|b| !b.is_empty())
                .map(|b| b.to_vec());
        }
        if gname.is_none() {
            gname = header
                .groupname_bytes()
                .filter(|b| !b.is_empty())
                .map(|b| b.to_vec());
        }

        let read_size = size.min(MAX_CONTENT_READ) as usize;
        let mut content = vec![0u8; read_size];
        if entry.read_exact(&mut content).is_err() {
            break;
        }

        results.push(OwnedEntry {
            entry_type,
            path,
            link_target,
            mode,
            uid,
            gid,
            mtime,
            size,
            uname,
            gname,
            dev_major,
            dev_minor,
            xattrs,
            content,
        });
    }

    results
}
