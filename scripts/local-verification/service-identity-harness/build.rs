#[allow(dead_code)]
#[path = "../../../crates/service-identity/build_support.rs"]
mod build_support;

fn main() {
    let root = std::path::Path::new(&std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .join("../../..")
        .canonicalize()
        .expect("owned test harness repository root");
    build_support::build_with_root(&root);
}
