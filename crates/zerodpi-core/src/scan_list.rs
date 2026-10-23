//! Shared input-file preparation for SNI and IP scans.

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use anyhow::Context;

pub(crate) fn read_scan_list(
    path: &Path,
    deduplicate: bool,
    entry_key: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read scan list '{}'", path.display()))?;
    if !deduplicate {
        return Ok(content);
    }

    let mut seen = HashSet::new();
    let mut cleaned = String::with_capacity(content.len());
    let mut removed = 0;
    for line in content.split_inclusive('\n') {
        let entry = line.trim();
        if !entry.is_empty() && !entry.starts_with('#') {
            if let Some(key) = entry_key(entry) {
                if !seen.insert(key) {
                    removed += 1;
                    continue;
                }
            }
        }
        cleaned.push_str(line);
    }

    if removed > 0 {
        // Prepare the replacement alongside the original so a failed write
        // cannot truncate the user's list, and replacement stays on one volume.
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
        let mut replacement = tempfile::NamedTempFile::new_in(parent.unwrap_or(Path::new(".")))
            .with_context(|| format!("cannot prepare scan list '{}'", path.display()))?;
        replacement.write_all(cleaned.as_bytes())?;
        replacement.as_file().sync_all()?;
        replacement
            .as_file()
            .set_permissions(std::fs::metadata(path)?.permissions())?;
        replacement
            .persist(path)
            .with_context(|| format!("cannot replace scan list '{}'", path.display()))?;
        tracing::info!(path = %path.display(), removed, "removed duplicate scan-list entries");
    }
    Ok(cleaned)
}
