//! `vendor_boot.img` header parsing (MediaTek only): recover
//! `kernel_phys_load` / `kernel_phys_offset` without root, from the stock
//! image alone.
use std::path::Path;

use crate::error::{ExtractError, Result};

const VNDRBOOT_MAGIC: &[u8; 8] = b"VNDRBOOT";

// No 32 Bit support, Just use 64 Bit text align
const ARM64_TEXT_ALIGN: u64 = 0x8_0000; // 512 KiB

/// Reads `vendor_boot.img`'s `kernel_addr` field and derives
/// `(kernel_phys_load, kernel_phys_offset)`.
pub fn recover_kernel_phys_from_vendor_boot(path: &Path) -> Result<(u64, u64)> {
    let data = std::fs::read(path)?;
    parse_vendor_boot_header(&data)
}

/// Layout (`vendor_boot_img_hdr_v3/v4` common prefix, little-endian):
/// `magic[8] header_version[4] page_size[4] kernel_addr[4] ...`
fn parse_vendor_boot_header(data: &[u8]) -> Result<(u64, u64)> {
    if data.len() < 20 || &data[0..8] != VNDRBOOT_MAGIC {
        return Err(ExtractError::new(
            "not a vendor_boot.img (missing VNDRBOOT magic)",
        ));
    }
    let header_version = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let kernel_addr = u32::from_le_bytes(data[16..20].try_into().unwrap()) as u64;
    if header_version < 3 {
        return Err(ExtractError::new(format!(
            "unexpected vendor_boot header_version={header_version} (expected >= 3)"
        )));
    }
    classify(kernel_addr)
}

/// `kernel_phys_load = kernel_addr` (vendor_boot carries no separate base
/// field; it is already the combined physical load address). From that,
/// derive `kernel_phys_offset` from the low-20-bit alignment pattern.
fn classify(phys_load: u64) -> Result<(u64, u64)> {
    let low = phys_load & 0xF_FFFF;
    let phys_offset = if low == ARM64_TEXT_ALIGN {
        phys_load - ARM64_TEXT_ALIGN
    } else if low == 0 {
        phys_load
    } else {
        return Err(ExtractError::new(format!(
            "kernel_phys_load=0x{phys_load:x} matches neither known MediaTek \
             alignment pattern (low 20 bits=0x{low:05x}); refusing to guess \
             kernel_phys_offset"
        )));
    };
    Ok((phys_load, phys_offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(kernel_addr: u32) -> Vec<u8> {
        let mut data = VNDRBOOT_MAGIC.to_vec();
        data.extend_from_slice(&3u32.to_le_bytes()); // header_version
        data.extend_from_slice(&4096u32.to_le_bytes()); // page_size
        data.extend_from_slice(&kernel_addr.to_le_bytes()); // kernel_addr
        data
    }

    #[test]
    fn case_a_arm64_gki_alignment() {
        // Use an example (Helio G81 Ultra): kernel_addr=0x40080000 -> phys_offset=0x40000000.
        let (load, offset) = parse_vendor_boot_header(&header(0x4008_0000)).unwrap();
        assert_eq!(load, 0x4008_0000);
        assert_eq!(offset, 0x4000_0000);
    }

    #[test]
    fn case_b_bootloader_internal_alignment() {
        // Use an example (Dimensity 6300): kernel_addr=0x40000000 -> phys_offset=0x40000000.
        let (load, offset) = parse_vendor_boot_header(&header(0x4000_0000)).unwrap();
        assert_eq!(load, 0x4000_0000);
        assert_eq!(offset, 0x4000_0000);
    }

    #[test]
    fn unknown_alignment_is_refused_not_guessed() {
        let err = parse_vendor_boot_header(&header(0x4012_3456)).unwrap_err();
        assert!(err.to_string().contains("refusing to guess"));
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let err = parse_vendor_boot_header(b"ANDROID!\x00\x00\x00\x00\x00\x00\x00\x00").unwrap_err();
        assert!(err.to_string().contains("VNDRBOOT"));
    }

    #[test]
    fn old_header_version_is_rejected() {
        let mut data = VNDRBOOT_MAGIC.to_vec();
        data.extend_from_slice(&2u32.to_le_bytes()); // header_version < 3
        data.extend_from_slice(&4096u32.to_le_bytes());
        data.extend_from_slice(&0x4008_0000u32.to_le_bytes());
        let err = parse_vendor_boot_header(&data).unwrap_err();
        assert!(err.to_string().contains("header_version"));
    }
}
