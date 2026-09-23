//! Synchronize `vendor/rustls` with an upstream rustls release.
//!
//! The workspace pins a reviewed source fork of rustls through
//! `[patch.crates-io]` (see `vendor/rustls/QID-PATCHES.md`). This command
//! reapplies the qid changes onto a new upstream base as a reviewable
//! three-way merge:
//!
//! ```text
//! base = crates.io package of the currently vendored version
//! qid  = current vendor/rustls tree (upstream base + qid patches)
//! new  = crates.io package of the target version
//! ```
//!
//! Files that only one side changed merge automatically. Files changed on
//! both sides are reported as conflicts and the vendor tree is left
//! untouched, so the operator resolves them deliberately per
//! `QID-PATCHES.md` before accepting the update.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command as Shell;

const CRATE_NAME: &str = "rustls";
const CRATES_IO_BASE_URL: &str = "https://static.crates.io/crates";
const UPSTREAM_GIT_URL: &str = "https://github.com/rustls/rustls.git";
const VENDOR_DIR: &str = "vendor/rustls";
const VENDOR_SRC_DIR: &str = "vendor/rustls/src";
const VENDOR_ORIG_MANIFEST: &str = "vendor/rustls/Cargo.toml.orig";
const PROVENANCE_FILE: &str = "vendor/rustls/QID-PATCHES.md";
const TESTDATA_PREFIX: &str = "src/testdata";

/// Scratch directory removed automatically on completion.
struct WorkDir {
    path: PathBuf,
}

impl WorkDir {
    fn create() -> anyhow::Result<Self> {
        let path = std::env::temp_dir().join(format!("qid-vendor-sync-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        for name in ["base", "new", "merged"] {
            fs::create_dir_all(path.join(name))?;
        }
        Ok(Self { path })
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// Outcome of classifying one relative path across base, qid, and new trees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MergeDecision {
    /// Take the new upstream content (qid side untouched).
    TakeNew,
    /// Keep the qid content (upstream untouched).
    TakeQid,
    /// Both sides changed; run `git merge-file`.
    Merge,
}

/// Classify a path from the presence and content on each side.
fn classify(base: Option<&[u8]>, qid: Option<&[u8]>, new: Option<&[u8]>) -> MergeDecision {
    if qid == new {
        return MergeDecision::TakeNew;
    }
    if base == qid {
        return MergeDecision::TakeNew;
    }
    if base == new {
        return MergeDecision::TakeQid;
    }
    MergeDecision::Merge
}

/// Parse a `major.minor.patch` version string.
fn parse_version(text: &str) -> anyhow::Result<(u64, u64, u64)> {
    let parts: Vec<&str> = text.trim().split('.').collect();
    if parts.len() != 3 {
        anyhow::bail!("version must look like major.minor.patch, got '{text}'");
    }
    let mut numbers = [0u64; 3];
    for (index, part) in parts.iter().enumerate() {
        numbers[index] = part
            .parse()
            .map_err(|_| anyhow::anyhow!("version part is not a number: '{part}'"))?;
    }
    Ok((numbers[0], numbers[1], numbers[2]))
}

/// A target version is acceptable when it stays on the patched line and moves forward.
fn is_supported_bump(current: (u64, u64, u64), target: (u64, u64, u64)) -> bool {
    current.0 == target.0 && current.1 == target.1 && target.2 > current.2
}

/// Read the `[package] version` from the vendored original manifest.
fn read_vendored_version(vendor_orig: &Path) -> anyhow::Result<String> {
    let content = fs::read_to_string(vendor_orig)?;
    let mut in_package = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if in_package && let Some(value) = line.strip_prefix("version") {
            let value = value
                .trim()
                .trim_start_matches('=')
                .trim()
                .trim_matches('"');
            if !value.is_empty() {
                return Ok(value.to_string());
            }
        }
    }
    anyhow::bail!("package version not found in {}", vendor_orig.display())
}

/// Rewrite the provenance bullet to the new upstream crate and tag.
fn rewrite_provenance(content: &str, new_version: &str) -> String {
    content
        .lines()
        .map(|line| {
            if line.starts_with("- Upstream crate and tag:") {
                format!("- Upstream crate and tag: `rustls` {new_version}, `v/{new_version}`")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
        + "\n"
}

/// Collect relative file paths below `dir`.
fn collect_files(dir: &Path) -> anyhow::Result<BTreeSet<PathBuf>> {
    let mut files = BTreeSet::new();
    if !dir.exists() {
        return Ok(files);
    }
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
    {
        if entry.file_type().is_file() {
            let relative = entry
                .path()
                .strip_prefix(dir)
                .map_err(|error| anyhow::anyhow!("failed to relativize path: {error}"))?;
            files.insert(relative.to_path_buf());
        }
    }
    Ok(files)
}

/// Copy a directory tree, creating missing parents.
fn copy_tree(source: &Path, destination: &Path) -> anyhow::Result<()> {
    for entry in walkdir::WalkDir::new(source)
        .into_iter()
        .filter_map(Result::ok)
    {
        let relative = entry
            .path()
            .strip_prefix(source)
            .map_err(|error| anyhow::anyhow!("failed to relativize path: {error}"))?;
        let target = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target)?;
        } else {
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Run a command and bail with its stderr on failure.
fn run_logged(program: &str, args: &[&str], workdir: &Path, label: &str) -> anyhow::Result<()> {
    let status = Shell::new(program)
        .args(args)
        .current_dir(workdir)
        .status()
        .map_err(|error| anyhow::anyhow!("failed to start {label}: {error}"))?;
    if !status.success() {
        anyhow::bail!("{label} failed with status {status}");
    }
    Ok(())
}

/// Download a crates.io `.crate` file.
fn download_crate(version: &str, destination: &Path) -> anyhow::Result<()> {
    let url = format!("{CRATES_IO_BASE_URL}/{CRATE_NAME}/{CRATE_NAME}-{version}.crate");
    println!("DOWNLOAD: {url}");
    let status = Shell::new("curl")
        .args(["-sSL", "--fail", "-o", &destination.to_string_lossy(), &url])
        .status()
        .map_err(|error| anyhow::anyhow!("failed to start curl: {error}"))?;
    if !status.success() {
        anyhow::bail!(
            "download failed for rustls {version}; verify the version exists on crates.io"
        );
    }
    Ok(())
}

/// Extract a `.crate` archive into `destination`.
fn extract_crate(archive: &Path, destination: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(destination)?;
    run_logged(
        "tar",
        &[
            "-xzf",
            &archive.to_string_lossy(),
            "-C",
            &destination.to_string_lossy(),
        ],
        destination,
        "crate extraction",
    )
}

/// Fetch `rustls/src/testdata` for a tag (crates.io packages exclude it).
fn fetch_testdata(tag: &str, workdir: &Path, destination: &Path) -> anyhow::Result<()> {
    let clone_dir = workdir.join("rustls-git");
    if !clone_dir.exists() {
        println!("CLONE: {UPSTREAM_GIT_URL} (shallow, no blobs)");
        run_logged(
            "git",
            &[
                "clone",
                "--quiet",
                "--filter=blob:none",
                "--no-checkout",
                UPSTREAM_GIT_URL,
                &clone_dir.to_string_lossy(),
            ],
            workdir,
            "upstream git clone",
        )?;
    }
    println!("ARCHIVE: tag v/{tag} rustls/src/testdata");
    let archive = Shell::new("git")
        .args(["archive", &format!("v/{tag}"), "rustls/src/testdata"])
        .current_dir(&clone_dir)
        .output()
        .map_err(|error| anyhow::anyhow!("failed to start git archive: {error}"))?;
    if !archive.status.success() {
        anyhow::bail!("git archive failed for tag v/{tag}; verify the upstream tag exists");
    }
    fs::create_dir_all(workdir)?;
    let archive_path = workdir.join("testdata.tar");
    fs::write(&archive_path, &archive.stdout)?;
    if destination.exists() {
        fs::remove_dir_all(destination)?;
    }
    fs::create_dir_all(
        destination
            .parent()
            .ok_or_else(|| anyhow::anyhow!("testdata destination has no parent directory"))?,
    )?;
    let unpack_dir = workdir.join("testdata-unpack");
    if unpack_dir.exists() {
        fs::remove_dir_all(&unpack_dir)?;
    }
    fs::create_dir_all(&unpack_dir)?;
    run_logged(
        "tar",
        &[
            "-x",
            "-f",
            &archive_path.to_string_lossy(),
            "-C",
            &unpack_dir.to_string_lossy(),
        ],
        workdir,
        "testdata extraction",
    )?;
    let extracted = unpack_dir.join("rustls/src/testdata");
    if !extracted.exists() {
        anyhow::bail!("testdata not found in upstream tag v/{tag}");
    }
    copy_tree(&extracted, destination)?;
    Ok(())
}

/// Merge one file with `git merge-file`; returns true when conflicts remain.
fn merge_one_file(base: &Path, qid: &Path, new: &Path, output: &Path) -> anyhow::Result<bool> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(new, output)?;
    let status = Shell::new("git")
        .args([
            "merge-file",
            &output.to_string_lossy(),
            &base.to_string_lossy(),
            &qid.to_string_lossy(),
        ])
        .status()
        .map_err(|error| anyhow::anyhow!("failed to start git merge-file: {error}"))?;
    Ok(!status.success())
}

/// Count conflict hunks in merged output.
fn count_conflicts(path: &Path) -> anyhow::Result<usize> {
    let content = fs::read_to_string(path)?;
    Ok(content
        .lines()
        .filter(|line| line.starts_with("<<<<<<< "))
        .count())
}

#[allow(clippy::too_many_lines)]
pub fn cmd_vendor_sync(to: &str, dry_run: bool, run_vendor_tests: bool) -> anyhow::Result<()> {
    let root = crate::workspace_root()?;
    let vendor = root.join(VENDOR_DIR);
    let vendor_src = root.join(VENDOR_SRC_DIR);
    if !vendor_src.exists() {
        anyhow::bail!("{} not found; nothing to synchronize", vendor.display());
    }

    let current = read_vendored_version(&root.join(VENDOR_ORIG_MANIFEST))?;
    let current_version = parse_version(&current)?;
    let target_version = parse_version(to)?;
    let target = to.trim().to_string();
    println!("VENDOR-SYNC: rustls {current} -> {target}");
    if current == target {
        println!("PASS: vendor/rustls is already at {target}");
        return Ok(());
    }
    if !is_supported_bump(current_version, target_version) {
        anyhow::bail!(
            "target {target} must stay on the 0.{} line and move forward from {current}",
            current_version.1
        );
    }

    let work = WorkDir::create()?;
    let workdir = &work.path;

    let base_archive = workdir.join(format!("{CRATE_NAME}-{current}.crate"));
    let new_archive = workdir.join(format!("{CRATE_NAME}-{target}.crate"));
    download_crate(&current, &base_archive)?;
    download_crate(&target, &new_archive)?;
    extract_crate(&base_archive, &workdir.join("base"))?;
    extract_crate(&new_archive, &workdir.join("new"))?;

    let base_root = workdir.join("base").join(format!("{CRATE_NAME}-{current}"));
    let new_root = workdir.join("new").join(format!("{CRATE_NAME}-{target}"));
    let base_src = base_root.join("src");
    let new_src = new_root.join("src");
    let merged_src = workdir.join("merged/src");
    fs::create_dir_all(&merged_src)?;

    let base_files = collect_files(&base_src)?;
    let qid_files = collect_files(&vendor_src)?;
    let new_files = collect_files(&new_src)?;
    let mut union: BTreeSet<PathBuf> = BTreeSet::new();
    union.extend(base_files.iter().cloned());
    union.extend(qid_files.iter().cloned());
    union.extend(new_files.iter().cloned());

    let read_optional = |dir: &Path, relative: &Path| -> anyhow::Result<Option<Vec<u8>>> {
        let path = dir.join(relative);
        if path.exists() {
            Ok(Some(fs::read(&path)?))
        } else {
            Ok(None)
        }
    };

    let mut stats: BTreeMap<&str, usize> = BTreeMap::new();
    let mut conflicts: Vec<(PathBuf, usize)> = Vec::new();
    for relative in &union {
        if relative.starts_with(TESTDATA_PREFIX) {
            continue;
        }
        let base = read_optional(&base_src, relative)?;
        let qid = read_optional(&vendor_src, relative)?;
        let new = read_optional(&new_src, relative)?;
        match classify(base.as_deref(), qid.as_deref(), new.as_deref()) {
            MergeDecision::TakeNew => {
                *stats.entry("upstream").or_insert(0) += 1;
                if let Some(bytes) = new {
                    let output = merged_src.join(relative);
                    if let Some(parent) = output.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&output, &bytes)?;
                }
            }
            MergeDecision::TakeQid => {
                *stats.entry("qid-carried").or_insert(0) += 1;
                if let Some(bytes) = qid {
                    let output = merged_src.join(relative);
                    if let Some(parent) = output.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    fs::write(&output, &bytes)?;
                }
            }
            MergeDecision::Merge => {
                *stats.entry("merged").or_insert(0) += 1;
                let scratch = workdir.join("merge-scratch");
                if scratch.exists() {
                    fs::remove_dir_all(&scratch)?;
                }
                fs::create_dir_all(&scratch)?;
                let base_tmp = scratch.join("base");
                let qid_tmp = scratch.join("qid");
                let new_tmp = scratch.join("new");
                let output = merged_src.join(relative);
                if let Some(bytes) = base {
                    fs::write(&base_tmp, &bytes)?;
                } else {
                    fs::write(&base_tmp, [])?;
                }
                if let Some(bytes) = qid {
                    fs::write(&qid_tmp, &bytes)?;
                } else {
                    fs::write(&qid_tmp, [])?;
                }
                if let Some(bytes) = new {
                    fs::write(&new_tmp, &bytes)?;
                } else {
                    fs::write(&new_tmp, [])?;
                }
                if merge_one_file(&base_tmp, &qid_tmp, &new_tmp, &output)? {
                    let hunks = count_conflicts(&output)?;
                    conflicts.push((relative.clone(), hunks));
                }
            }
        }
    }

    fetch_testdata(&target, workdir, &merged_src.join("testdata"))?;

    // Top-level crate files always follow the new upstream release, except
    // the qid provenance record which is rewritten in place.
    let merged_root = workdir.join("merged");
    for entry in fs::read_dir(&new_root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == "src" {
            continue;
        }
        let target_path = merged_root.join(&name);
        if entry.file_type()?.is_dir() {
            if target_path.exists() {
                fs::remove_dir_all(&target_path)?;
            }
            copy_tree(&entry.path(), &target_path)?;
        } else {
            fs::copy(entry.path(), &target_path)?;
        }
    }
    let provenance = rewrite_provenance(&fs::read_to_string(root.join(PROVENANCE_FILE))?, &target);
    fs::write(merged_root.join("QID-PATCHES.md"), &provenance)?;

    println!(
        "MERGE: upstream={} qid-carried={} merged={}",
        stats.get("upstream").copied().unwrap_or(0),
        stats.get("qid-carried").copied().unwrap_or(0),
        stats.get("merged").copied().unwrap_or(0)
    );

    if !conflicts.is_empty() {
        println!("FAIL: {} file(s) need manual resolution:", conflicts.len());
        for (path, hunks) in &conflicts {
            println!("FAIL: {} ({} conflict hunk(s))", path.display(), hunks);
        }
        println!(
            "FAIL: vendor tree left untouched; resolve the hunks, then re-run with the resolutions applied"
        );
        anyhow::bail!("vendor sync has {} conflicted file(s)", conflicts.len());
    }

    if dry_run {
        println!("PASS: dry run; vendor tree left untouched");
        return Ok(());
    }

    if vendor.exists() {
        fs::remove_dir_all(&vendor)?;
    }
    copy_tree(&merged_root, &vendor)?;
    println!("PASS: vendor/rustls synchronized to {target}");

    if run_vendor_tests {
        println!("TEST: cargo test --manifest-path vendor/rustls/Cargo.toml --lib");
        run_logged(
            "cargo",
            &[
                "test",
                "--manifest-path",
                "vendor/rustls/Cargo.toml",
                "--lib",
            ],
            &root,
            "vendor lib tests",
        )?;
    }

    println!("NEXT: run workspace tests, then `cargo deny check` and `cargo audit`");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identical_sides_take_new() {
        let bytes = b"same";
        assert_eq!(
            classify(Some(bytes), Some(bytes), Some(bytes)),
            MergeDecision::TakeNew
        );
        assert_eq!(classify(None, None, None), MergeDecision::TakeNew);
    }

    #[test]
    fn untouched_qid_side_takes_new() {
        assert_eq!(
            classify(Some(b"base"), Some(b"base"), Some(b"new")),
            MergeDecision::TakeNew
        );
        // File added upstream (absent in base and qid).
        assert_eq!(classify(None, None, Some(b"new")), MergeDecision::TakeNew);
        // File removed upstream (present and untouched in qid).
        assert_eq!(
            classify(Some(b"base"), Some(b"base"), None),
            MergeDecision::TakeNew
        );
    }

    #[test]
    fn untouched_upstream_side_keeps_qid() {
        assert_eq!(
            classify(Some(b"base"), Some(b"qid"), Some(b"base")),
            MergeDecision::TakeQid
        );
        // File added by qid (absent in base and new).
        assert_eq!(classify(None, Some(b"qid"), None), MergeDecision::TakeQid);
        // File removed by qid (present and untouched upstream).
        assert_eq!(
            classify(Some(b"base"), None, Some(b"base")),
            MergeDecision::TakeQid
        );
    }

    #[test]
    fn diverged_sides_require_merge() {
        assert_eq!(
            classify(Some(b"base"), Some(b"qid"), Some(b"new")),
            MergeDecision::Merge
        );
    }

    #[test]
    fn version_parsing_rejects_malformed_input() {
        assert_eq!(parse_version("0.23.45").unwrap(), (0, 23, 45));
        assert!(parse_version("0.23").is_err());
        assert!(parse_version("0.23.x").is_err());
        assert!(parse_version("").is_err());
    }

    #[test]
    fn bump_guard_keeps_patch_line_moving_forward() {
        assert!(is_supported_bump((0, 23, 41), (0, 23, 45)));
        assert!(!is_supported_bump((0, 23, 45), (0, 23, 45)));
        assert!(!is_supported_bump((0, 23, 45), (0, 23, 44)));
        assert!(!is_supported_bump((0, 23, 45), (0, 24, 0)));
        assert!(!is_supported_bump((0, 23, 45), (1, 0, 0)));
    }

    #[test]
    fn provenance_rewrite_updates_only_the_bullet() {
        let content = "# Title\n\n- Upstream project: `x`\n- Upstream crate and tag: `rustls` 0.23.41, `v/0.23.41`\n- Other: 0.23.41\n";
        let rewritten = rewrite_provenance(content, "0.23.45");
        assert!(rewritten.contains("- Upstream crate and tag: `rustls` 0.23.45, `v/0.23.45`"));
        assert!(rewritten.contains("- Other: 0.23.41"));
        assert!(rewritten.ends_with('\n'));
    }
}
