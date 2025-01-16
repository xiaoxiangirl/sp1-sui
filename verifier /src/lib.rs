#[cfg(test)]
mod test;

pub mod ark_converter;

/// Groth16 verification keys for different SP1 versions.
pub const GROTH16_VK_3_0_0_BYTES: &[u8] = include_bytes!("../vk/v3.0.0/groth16_vk.bin");
pub const GROTH16_VK_3_0_0_RC4_BYTES: &[u8] = include_bytes!("../vk/v3.0.0rc4/groth16_vk.bin");
pub const GROTH16_VK_2_0_0_BYTES: &[u8] = include_bytes!("../vk/v2.0.0/groth16_vk.bin");
