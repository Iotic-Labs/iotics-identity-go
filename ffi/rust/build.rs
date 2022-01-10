use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("Failed get OUT_DIR.");
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("Failed get CARGO_MANIFEST_DIR.");

    let lock_path = Path::new(&manifest_dir).join("Cargo.lock");
    let lock_path = lock_path
        .to_str()
        .expect("Failed to get the FFI wrapper path.");

    let ffi_wrapper_path = Path::new(&manifest_dir)
        .parent()
        .expect("Failed to get the FFI wrapper dir.")
        .join("ffi_wrapper.go");
    let ffi_wrapper_path = ffi_wrapper_path
        .to_str()
        .expect("Failed to get the FFI wrapper path.");

    // Add search path and link to static library.
    cargo_emit::rustc_link_search!(
        out_dir => "native"
    );
    cargo_emit::rustc_link_lib!(
        "ffi" => "static"
    );
    cargo_emit::rerun_if_changed!(lock_path);
    cargo_emit::rerun_if_changed!(ffi_wrapper_path);

    // Call command to create a static library (C archive file).
    std::process::Command::new("go")
        .args(&[
            "build",
            "-o",
            &format!("{}/libffi.a", &out_dir),
            "-buildmode=c-archive",
            ffi_wrapper_path,
        ])
        .status()
        .expect("Failed to create C archive.");

    // Configure and generate Rust bindings from C header file.
    let bindings = bindgen::builder()
        .header(&format!("{}/libffi.h", &out_dir))
        .derive_copy(false) // Allow for implementing `Drop`.
        .generate()
        .expect("Failed to configure bindgen builder.");

    // Write the generated bindings to an output file.
    bindings
        .write_to_file("src/ffi_wrapper.rs")
        .expect("Failed to create Rust bindings.");
}
