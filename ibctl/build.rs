//! Build script: embeds the git version tag as a compile-time constant.
//!
//! The version is available in Rust code via `env!("IBCTL_VERSION")`.
//! Falls back to CARGO_PKG_VERSION if not in a git repo or no tags exist.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs/tags");

    // Priority: IBCTL_BUILD_VERSION env var (set by Dockerfile/CI) > git tag > Cargo.toml
    let version = std::env::var("IBCTL_BUILD_VERSION").ok()
        .filter(|s| !s.is_empty())
        .or_else(git_version)
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());
    println!("cargo:rustc-env=IBCTL_VERSION={}", version);
}

fn git_version() -> Option<String> {
    // Try `git describe --tags --always` for the closest tag
    let output = Command::new("git")
        .args(["describe", "--tags", "--always"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let version = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if version.is_empty() {
        return None;
    }

    // Strip leading 'v' if present (v0.9.1 -> 0.9.1)
    Some(version.strip_prefix('v').unwrap_or(&version).to_string())
}
