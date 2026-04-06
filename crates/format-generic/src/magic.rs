use tinkerspark_core_types::ByteRange;

/// A recognized magic/signature found in the data.
#[derive(Debug, Clone)]
pub struct DetectedSignature {
    pub name: &'static str,
    pub offset: u64,
    pub length: u64,
}

impl DetectedSignature {
    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.offset, self.length)
    }
}

struct MagicEntry {
    name: &'static str,
    /// Byte offset where the magic typically appears (usually 0).
    offset: usize,
    bytes: &'static [u8],
}

/// Known binary signatures. Ordered by specificity (longer/rarer first where practical).
const MAGIC_TABLE: &[MagicEntry] = &[
    // Image formats
    MagicEntry {
        name: "PNG",
        offset: 0,
        bytes: b"\x89PNG\r\n\x1a\n",
    },
    MagicEntry {
        name: "JPEG",
        offset: 0,
        bytes: &[0xFF, 0xD8, 0xFF],
    },
    MagicEntry {
        name: "GIF87a",
        offset: 0,
        bytes: b"GIF87a",
    },
    MagicEntry {
        name: "GIF89a",
        offset: 0,
        bytes: b"GIF89a",
    },
    MagicEntry {
        name: "BMP",
        offset: 0,
        bytes: b"BM",
    },
    MagicEntry {
        name: "TIFF (little-endian)",
        offset: 0,
        bytes: b"II\x2a\x00",
    },
    MagicEntry {
        name: "TIFF (big-endian)",
        offset: 0,
        bytes: b"MM\x00\x2a",
    },
    MagicEntry {
        name: "WebP",
        offset: 0,
        // RIFF....WEBP
        bytes: b"RIFF",
    },
    // Archive / container formats
    MagicEntry {
        name: "ZIP",
        offset: 0,
        bytes: b"PK\x03\x04",
    },
    MagicEntry {
        name: "ZIP (empty)",
        offset: 0,
        bytes: b"PK\x05\x06",
    },
    MagicEntry {
        name: "gzip",
        offset: 0,
        bytes: &[0x1F, 0x8B],
    },
    MagicEntry {
        name: "bzip2",
        offset: 0,
        bytes: b"BZh",
    },
    MagicEntry {
        name: "XZ",
        offset: 0,
        bytes: &[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],
    },
    MagicEntry {
        name: "Zstandard",
        offset: 0,
        bytes: &[0x28, 0xB5, 0x2F, 0xFD],
    },
    MagicEntry {
        name: "7z",
        offset: 0,
        bytes: b"7z\xBC\xAF\x27\x1C",
    },
    MagicEntry {
        name: "RAR",
        offset: 0,
        bytes: b"Rar!\x1a\x07",
    },
    MagicEntry {
        name: "tar (ustar)",
        offset: 257,
        bytes: b"ustar",
    },
    // Executable / object formats
    MagicEntry {
        name: "ELF",
        offset: 0,
        bytes: b"\x7fELF",
    },
    MagicEntry {
        name: "PE (MZ)",
        offset: 0,
        bytes: b"MZ",
    },
    MagicEntry {
        name: "Mach-O (32-bit)",
        offset: 0,
        bytes: &[0xFE, 0xED, 0xFA, 0xCE],
    },
    MagicEntry {
        name: "Mach-O (64-bit)",
        offset: 0,
        bytes: &[0xFE, 0xED, 0xFA, 0xCF],
    },
    MagicEntry {
        name: "Mach-O (universal)",
        offset: 0,
        bytes: &[0xCA, 0xFE, 0xBA, 0xBE],
    },
    MagicEntry {
        name: "WebAssembly",
        offset: 0,
        bytes: b"\x00asm",
    },
    // Document formats
    MagicEntry {
        name: "PDF",
        offset: 0,
        bytes: b"%PDF-",
    },
    // Crypto / certificate formats
    MagicEntry {
        name: "ASN.1 SEQUENCE",
        offset: 0,
        bytes: &[0x30],
    },
    // PEM boundary
    MagicEntry {
        name: "PEM",
        offset: 0,
        bytes: b"-----BEGIN ",
    },
    // Database
    MagicEntry {
        name: "SQLite",
        offset: 0,
        bytes: b"SQLite format 3\x00",
    },
    // Font
    MagicEntry {
        name: "WOFF",
        offset: 0,
        bytes: b"wOFF",
    },
    MagicEntry {
        name: "WOFF2",
        offset: 0,
        bytes: b"wOF2",
    },
];

/// Scan the header bytes for known magic signatures.
///
/// Returns all matches found (there may be more than one if signatures overlap
/// or if the file contains embedded objects).
pub fn detect_signatures(data: &[u8]) -> Vec<DetectedSignature> {
    let mut results = Vec::new();

    for entry in MAGIC_TABLE {
        let start = entry.offset;
        let end = start + entry.bytes.len();
        if end <= data.len() && &data[start..end] == entry.bytes {
            // For ASN.1 SEQUENCE, only report if it has a valid length byte after.
            if entry.name == "ASN.1 SEQUENCE" && data.len() > 1 {
                let len_byte = data[1];
                // Require plausible DER length (short form or long form indicator).
                if len_byte == 0 || (len_byte >= 0x80 && len_byte <= 0x84) || len_byte < 0x80 {
                    // Accept it — but don't duplicate if we already have a more specific match.
                    if results.iter().any(|r: &DetectedSignature| r.offset == 0) {
                        continue;
                    }
                }
            }
            results.push(DetectedSignature {
                name: entry.name,
                offset: start as u64,
                length: entry.bytes.len() as u64,
            });
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_png() {
        let data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let sigs = detect_signatures(data);
        assert!(sigs.iter().any(|s| s.name == "PNG"));
    }

    #[test]
    fn detects_zip() {
        let data = b"PK\x03\x04\x14\x00\x00\x00";
        let sigs = detect_signatures(data);
        assert!(sigs.iter().any(|s| s.name == "ZIP"));
    }

    #[test]
    fn detects_pdf() {
        let data = b"%PDF-1.7\n";
        let sigs = detect_signatures(data);
        assert!(sigs.iter().any(|s| s.name == "PDF"));
    }

    #[test]
    fn detects_elf() {
        let data = b"\x7fELF\x02\x01\x01\x00";
        let sigs = detect_signatures(data);
        assert!(sigs.iter().any(|s| s.name == "ELF"));
    }

    #[test]
    fn no_match_on_random_bytes() {
        let data = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        let sigs = detect_signatures(data);
        // May match ASN.1 SEQUENCE (0x30) — filter that out
        let non_asn1: Vec<_> = sigs.iter().filter(|s| s.name != "ASN.1 SEQUENCE").collect();
        assert!(non_asn1.is_empty());
    }
}
