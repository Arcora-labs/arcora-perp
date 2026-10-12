#[path = "../service-identity/build_support.rs"]
mod service_identity_build;

fn main() {
    service_identity_build::build();
}
