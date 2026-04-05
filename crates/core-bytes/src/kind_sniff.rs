use std::path::Path;
use tinkerspark_core_types::DetectedKind;

/// OpenPGP armor headers we recognize.
const ARMOR_HEADERS: &[&[u8]] = &[
    b"-----BEGIN PGP MESSAGE-----",
    b"-----BEGIN PGP PUBLIC KEY BLOCK-----",
    b"-----BEGIN PGP PRIVATE KEY BLOCK-----",
    b"-----BEGIN PGP SIGNATURE-----",
    b"-----BEGIN PGP SIGNED MESSAGE-----",
    b"-----BEGIN PGP ARMORED FILE-----",
];

/// OpenPGP binary packet tag: old-format bit set (0x80) is required.
/// We check for common tag byte patterns that look like valid OpenPGP packets.
fn looks_like_openpgp_binary(header: &[u8]) -> bool {
    if header.is_empty() {
        return false;
    }
    let tag = header[0];
    // Bit 7 must be set for any OpenPGP packet.
    if tag & 0x80 == 0 {
        return false;
    }
    // Old-format: bits 5-2 are the packet tag (0-15).
    // New-format: bits 5-0 are the packet tag.
    // Common first-packet tags: 1 (PKESK), 2 (Signature), 4 (One-Pass Sig),
    // 5 (Secret Key), 6 (Public Key), 11 (Literal Data), 13 (User ID).
    // This is intentionally conservative — just a heuristic.
    let is_new_format = tag & 0x40 != 0;
    let pkt_tag = if is_new_format {
        tag & 0x3F
    } else {
        (tag & 0x3C) >> 2
    };
    matches!(
        pkt_tag,
        1..=6 | 8 | 9 | 11 | 13 | 14 | 17 | 18 | 19 | 20 | 21
    )
}

/// File extensions we treat as OpenPGP candidates.
fn is_openpgp_extension(path: &Path) -> bool {
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "pgp" | "gpg" | "asc" | "sig" | "key" | "pub" | "sec"
    )
}

/// Detect file kind by content first, extension second.
///
/// `header` should be the first few hundred bytes of the file (at least 64 is ideal).
pub fn sniff_kind(header: &[u8], path: &Path, file_size: u64) -> DetectedKind {
    if file_size == 0 {
        return DetectedKind::Empty;
    }

    // Content-based detection first.
    for armor_header in ARMOR_HEADERS {
        if header
            .iter()
            // Skip leading whitespace/BOM.
            .copied()
            .skip_while(|&b| b == b' ' || b == b'\t' || b == b'\r' || b == b'\n' || b == 0xEF)
            .take(armor_header.len())
            .eq(armor_header.iter().copied())
        {
            return DetectedKind::OpenPgpArmored;
        }
    }

    if looks_like_openpgp_binary(header) {
        return DetectedKind::OpenPgpBinary;
    }

    // Extension-based fallback.
    if is_openpgp_extension(path) {
        return DetectedKind::OpenPgpByExtension;
    }

    // Heuristic: if all bytes in the header are printable ASCII / common whitespace,
    // classify as text.
    let text_like = header
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
    if text_like && !header.is_empty() {
        return DetectedKind::Text;
    }

    DetectedKind::Binary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_armored_pgp() {
        let header = b"-----BEGIN PGP PUBLIC KEY BLOCK-----\nmore data here";
        let kind = sniff_kind(header, &PathBuf::from("key.asc"), header.len() as u64);
        assert_eq!(kind, DetectedKind::OpenPgpArmored);
    }

    #[test]
    fn detects_armored_pgp_with_leading_whitespace() {
        let header = b"\n  -----BEGIN PGP SIGNATURE-----\ndata";
        let kind = sniff_kind(header, &PathBuf::from("sig.txt"), header.len() as u64);
        assert_eq!(kind, DetectedKind::OpenPgpArmored);
    }

    #[test]
    fn detects_binary_openpgp_old_format_public_key() {
        // Old-format public key packet: tag byte = 0x99 (bit7=1, old-format, tag=6)
        let header = &[0x99, 0x01, 0x0A, 0x04];
        let kind = sniff_kind(header, &PathBuf::from("key.bin"), 100);
        assert_eq!(kind, DetectedKind::OpenPgpBinary);
    }

    #[test]
    fn detects_binary_openpgp_new_format() {
        // New-format public key packet: tag byte = 0xC6 (bit7=1, bit6=1, tag=6)
        let header = &[0xC6, 0x10, 0x04];
        let kind = sniff_kind(header, &PathBuf::from("key.bin"), 100);
        assert_eq!(kind, DetectedKind::OpenPgpBinary);
    }

    #[test]
    fn falls_back_to_extension() {
        // Not a valid OpenPGP header content, but has .pgp extension.
        let header = b"\x00\x00\x00\x00";
        let kind = sniff_kind(header, &PathBuf::from("file.pgp"), 4);
        assert_eq!(kind, DetectedKind::OpenPgpByExtension);
    }

    #[test]
    fn detects_text() {
        let header = b"Hello, this is a plain text file.\n";
        let kind = sniff_kind(header, &PathBuf::from("readme.txt"), header.len() as u64);
        assert_eq!(kind, DetectedKind::Text);
    }

    #[test]
    fn detects_binary() {
        let header = &[0x00, 0x01, 0x02, 0xFF, 0xFE, 0x03];
        let kind = sniff_kind(header, &PathBuf::from("data.bin"), 6);
        assert_eq!(kind, DetectedKind::Binary);
    }

    #[test]
    fn detects_empty() {
        let kind = sniff_kind(&[], &PathBuf::from("empty"), 0);
        assert_eq!(kind, DetectedKind::Empty);
    }
}
