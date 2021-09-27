use std::env;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("Failed get OUT_DIR.");

    // Add search path and link to static library.
    cargo_emit::rustc_link_search!(
        "./target" => "native"
    );
    cargo_emit::rustc_link_lib!(
        "ffi" => "static"
    );
    cargo_emit::rerun_if_changed!("../ffi_wrapper.go", "src/ffi_wrapper.rs");

    // Call command to create a static library (C archive file).
    std::process::Command::new("go")
        .args(&[
            "build",
            "-o",
            &format!("{}/libffi.a", &out_dir),
            "-buildmode=c-archive",
            "../ffi_wrapper.go",
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
