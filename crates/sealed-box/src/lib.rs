#![no_std]
extern crate alloc;

/// Placeholder to prove the crate builds; replaced in Task 2.
pub const SEALED_BOX_VERSION: u8 = 0x01;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn version_is_one() {
        assert_eq!(SEALED_BOX_VERSION, 0x01);
    }
}
