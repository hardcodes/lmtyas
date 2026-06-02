// Source - https://stackoverflow.com/a/44407625
// Posted by kennytm
// Retrieved 2026-05-27, License - CC BY-SA 3.0

// build.rs
use std::process::Command;
fn main() {
    // note: add error checking yourself.
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
}

