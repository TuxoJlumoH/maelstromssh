use std::process::Command;

fn main() {
    // Embed the app icon as a Windows resource (Explorer/Alt-Tab icon).
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_env != "gnu" {
        // MSVC tooling (rc.exe) isn't wired up here; the installer still
        // ships the icon separately.
        return;
    }

    let manifest = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let icon = std::path::Path::new(&manifest)
        .join("..")
        .join("assets")
        .join("icon.ico")
        .canonicalize()
        .expect("assets/icon.ico missing");

    let out = std::env::var("OUT_DIR").unwrap();
    let rc = format!("{out}/app.rc");
    let obj = format!("{out}/app-res.o");

    // "1 ICON" registers the icon as the app's default icon resource.
    std::fs::write(&rc, format!("1 ICON \"{}\"\n", icon.display())).unwrap();

    let windres = if cfg!(windows) {
        "windres".to_string()
    } else {
        // Cross-compiling from a non-Windows host: MinGW's triple-prefixed tool.
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        format!(
            "{}-w64-mingw32-windres",
            if arch == "i686" { "i686" } else { "x86_64" }
        )
    };

    let status = Command::new(&windres)
        .arg(format!("-I{manifest}"))
        .arg(&rc)
        .arg(&obj)
        .status()
        .expect("failed to run windres");
    assert!(status.success(), "windres failed");

    // Link the object file directly: an archive member with no symbols would
    // be skipped by lazy archive linking.
    println!("cargo:rustc-link-arg={obj}");
}
