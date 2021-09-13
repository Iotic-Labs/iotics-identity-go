fn main() {
    // Add search path and link to static library.
    println!("cargo:rustc-link-search=native=./target");
    println!("cargo:rustc-link-lib=static=ffi");
    println!("cargo:rerun-if-changed=src/ffi_wrapper.rs");
    // Call command to create a static library (C archive file).
    std::process::Command::new("go").args(&[
        "build",
        "-o",
        "target/libffi.a",
        "-buildmode=c-archive",
        "../ffi_wrapper.go"
    ]).status().expect("Failed to create C archive.");
    // Configure and generate Rust bindings from C header file.
    let bindings = bindgen::builder().header("target/libffi.h")
        .derive_copy(false)  // Allow for implementing `Drop`.
        .generate()
        .expect("Failed to configure bindgen builder.");
    // Write the generated bindings to an output file.
    bindings.write_to_file("src/ffi_wrapper.rs").expect("Failed to create Rust bindings.");
}
