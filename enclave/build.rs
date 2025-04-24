fn main() {
    println!("cargo:rustc-link-lib=dylib=aws-c-common");
    println!("cargo:rustc-link-lib=dylib=aws-nitro-enclaves-sdk-c");
}