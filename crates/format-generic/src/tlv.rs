use tinkerspark_core_types::ByteRange;

/// A candidate TLV (Tag-Length-Value) element found in data.
#[derive(Debug, Clone)]
pub struct TlvCandidate {
    pub offset: u64,
    pub tag: u64,
    pub tag_len: u64,
    pub length_field_len: u64,
    pub value_len: u64,
    pub encoding: TlvEncoding,
}

impl TlvCandidate {
    pub fn total_len(&self) -> u64 {
        self.tag_len + self.length_field_len + self.value_len
    }

    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.offset, self.total_len())
    }
}

/// A chain of consecutive TLV elements.
#[derive(Debug, Clone)]
pub struct TlvChain {
    pub offset: u64,
    pub length: u64,
    pub encoding: TlvEncoding,
    pub elements: Vec<TlvCandidate>,
    pub confidence: f64,
}

impl TlvChain {
    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.offset, self.length)
    }
}

/// Supported TLV length encoding schemes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlvEncoding {
    /// ASN.1 BER/DER: tag + BER-encoded length + value.
    Asn1Ber,
    /// Simple 1-byte tag + 2-byte BE length + value.
    Tag1Len2Be,
    /// Simple 1-byte tag + 4-byte BE length + value.
    Tag1Len4Be,
    /// Simple 1-byte tag + 2-byte LE length + value.
    Tag1Len2Le,
    /// Simple 1-byte tag + 4-byte LE length + value.
    Tag1Len4Le,
    /// Simple 1-byte tag + LEB128 unsigned varint length + value.
    /// Conservative: requires longer chains than the fixed-width encodings
    /// because varint headers parse from almost any byte sequence.
    Tag1LenVarint,
}

impl TlvEncoding {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Asn1Ber => "ASN.1 BER/DER",
            Self::Tag1Len2Be => "1-byte tag + 2-byte BE length",
            Self::Tag1Len4Be => "1-byte tag + 4-byte BE length",
            Self::Tag1Len2Le => "1-byte tag + 2-byte LE length",
            Self::Tag1Len4Le => "1-byte tag + 4-byte LE length",
            Self::Tag1LenVarint => "1-byte tag + LEB128 varint length",
        }
    }
}

/// Minimum chain length for varint TLV detection. Varint headers are very
/// permissive (almost any byte sequence parses), so we require more elements
/// than the fixed-width encodings before reporting a chain regardless of the
/// caller's `min_chain_len`.
const VARINT_MIN_CHAIN_LEN: usize = 4;

/// Try to detect TLV chains starting from offset 0.
///
/// Reports chains where consecutive elements parse cleanly with no gaps. The
/// `min_chain_len` and `max_chains` parameters control how aggressively chains
/// are reported — stricter values reduce false positives at the cost of
/// missing short or weak chains.
pub fn detect_tlv_chains(
    data: &[u8],
    base_offset: u64,
    min_chain_len: usize,
    max_chains: usize,
) -> Vec<TlvChain> {
    // A chain of zero elements is meaningless and would let try_parse_chain
    // index an empty Vec on data that does not parse. Clamp at the boundary.
    let min_chain_len = min_chain_len.max(1);

    let mut chains = Vec::new();

    // Try each encoding scheme. Varint requires its own (stricter) floor on
    // chain length to keep noise out — the encoding accepts almost anything.
    for &encoding in &[
        TlvEncoding::Asn1Ber,
        TlvEncoding::Tag1Len2Be,
        TlvEncoding::Tag1Len4Be,
        TlvEncoding::Tag1Len2Le,
        TlvEncoding::Tag1Len4Le,
        TlvEncoding::Tag1LenVarint,
    ] {
        let effective_min = if encoding == TlvEncoding::Tag1LenVarint {
            min_chain_len.max(VARINT_MIN_CHAIN_LEN)
        } else {
            min_chain_len
        };
        if let Some(chain) = try_parse_chain(data, base_offset, encoding, effective_min) {
            if chain.elements.len() >= effective_min {
                chains.push(chain);
            }
        }
    }

    // Sort by confidence descending.
    chains.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    chains.truncate(max_chains);
    chains
}

fn try_parse_chain(
    data: &[u8],
    base_offset: u64,
    encoding: TlvEncoding,
    min_chain_len: usize,
) -> Option<TlvChain> {
    let mut elements = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        match try_parse_one(&data[pos..], base_offset + pos as u64, encoding) {
            Some(elem) => {
                let total = elem.total_len() as usize;
                if total == 0 {
                    break;
                }
                pos += total;
                elements.push(elem);
                // Safety limit.
                if elements.len() >= 100 {
                    break;
                }
            }
            None => break,
        }
    }

    if elements.len() < min_chain_len {
        return None;
    }

    let chain_start = elements[0].offset;
    let chain_end = elements
        .last()
        .map(|e| e.offset + e.total_len())
        .unwrap_or(chain_start);
    let chain_len = chain_end - chain_start;

    // Confidence: ratio of data covered by the chain, scaled by element count.
    let coverage = chain_len as f64 / data.len() as f64;
    let count_factor = (elements.len() as f64).min(20.0) / 20.0;
    let confidence = (coverage * 0.6 + count_factor * 0.4).min(1.0);

    Some(TlvChain {
        offset: chain_start,
        length: chain_len,
        encoding,
        elements,
        confidence,
    })
}

fn try_parse_one(data: &[u8], base_offset: u64, encoding: TlvEncoding) -> Option<TlvCandidate> {
    match encoding {
        TlvEncoding::Asn1Ber => parse_asn1_ber(data, base_offset),
        TlvEncoding::Tag1Len2Be => parse_tag1_len_int(data, base_offset, 2, true),
        TlvEncoding::Tag1Len4Be => parse_tag1_len_int(data, base_offset, 4, true),
        TlvEncoding::Tag1Len2Le => parse_tag1_len_int(data, base_offset, 2, false),
        TlvEncoding::Tag1Len4Le => parse_tag1_len_int(data, base_offset, 4, false),
        TlvEncoding::Tag1LenVarint => parse_tag1_len_varint(data, base_offset),
    }
}

fn parse_asn1_ber(data: &[u8], base_offset: u64) -> Option<TlvCandidate> {
    if data.is_empty() {
        return None;
    }

    // Tag: one byte (we don't handle multi-byte tags for simplicity).
    let tag = data[0] as u64;
    // Filter out implausible tag values.
    if tag == 0x00 || tag == 0xFF {
        return None;
    }
    let tag_len = 1u64;

    if data.len() < 2 {
        return None;
    }

    // Length encoding.
    let (value_len, length_field_len) = match data[1] {
        n if n < 0x80 => (n as u64, 1u64),
        0x80 => return None, // Indefinite length — skip.
        0x81 => {
            if data.len() < 3 {
                return None;
            }
            (data[2] as u64, 2)
        }
        0x82 => {
            if data.len() < 4 {
                return None;
            }
            (u16::from_be_bytes([data[2], data[3]]) as u64, 3)
        }
        0x83 => {
            if data.len() < 5 {
                return None;
            }
            let l = (data[2] as u64) << 16 | (data[3] as u64) << 8 | data[4] as u64;
            (l, 4)
        }
        _ => return None, // 0x84+ is too large for our conservative approach.
    };

    let total = tag_len + length_field_len + value_len;
    if total as usize > data.len() {
        return None;
    }

    Some(TlvCandidate {
        offset: base_offset,
        tag,
        tag_len,
        length_field_len,
        value_len,
        encoding: TlvEncoding::Asn1Ber,
    })
}

fn parse_tag1_len_int(
    data: &[u8],
    base_offset: u64,
    len_bytes: usize,
    big_endian: bool,
) -> Option<TlvCandidate> {
    let min_header = 1 + len_bytes;
    if data.len() < min_header {
        return None;
    }

    let tag = data[0] as u64;
    if tag == 0x00 || tag == 0xFF {
        return None;
    }

    let value_len = match (len_bytes, big_endian) {
        (2, true) => u16::from_be_bytes([data[1], data[2]]) as u64,
        (2, false) => u16::from_le_bytes([data[1], data[2]]) as u64,
        (4, true) => u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as u64,
        (4, false) => u32::from_le_bytes([data[1], data[2], data[3], data[4]]) as u64,
        _ => return None,
    };

    // Sanity: value shouldn't be larger than remaining data.
    let total = 1 + len_bytes as u64 + value_len;
    if total as usize > data.len() || value_len > 1_000_000 {
        return None;
    }

    Some(TlvCandidate {
        offset: base_offset,
        tag,
        tag_len: 1,
        length_field_len: len_bytes as u64,
        value_len,
        encoding: match (len_bytes, big_endian) {
            (2, true) => TlvEncoding::Tag1Len2Be,
            (2, false) => TlvEncoding::Tag1Len2Le,
            (4, true) => TlvEncoding::Tag1Len4Be,
            (_, _) => TlvEncoding::Tag1Len4Le,
        },
    })
}

/// Parse a 1-byte tag followed by an LEB128 unsigned varint length.
///
/// LEB128 encodes 7 bits of payload per byte; the high bit (0x80) is the
/// continuation flag. We cap the varint at 5 bytes (~35-bit value) which is
/// more than enough for any plausible record length and bounds runtime.
fn parse_tag1_len_varint(data: &[u8], base_offset: u64) -> Option<TlvCandidate> {
    if data.len() < 2 {
        return None;
    }

    let tag = data[0] as u64;
    if tag == 0x00 || tag == 0xFF {
        return None;
    }

    let mut value_len: u64 = 0;
    let mut shift: u32 = 0;
    let mut length_field_len: u64 = 0;
    let max_varint_bytes = 5;
    for i in 0..max_varint_bytes {
        let idx = 1 + i;
        if idx >= data.len() {
            return None;
        }
        let byte = data[idx];
        let payload = (byte & 0x7F) as u64;
        value_len |= payload << shift;
        length_field_len += 1;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if i + 1 == max_varint_bytes {
            // Continuation bit set on the last allowed byte → over-long varint.
            return None;
        }
    }

    // Reject zero-length values: a varint chain of zero-length records would
    // collapse to a single byte per element and matches almost anything.
    if value_len == 0 {
        return None;
    }

    let total = 1 + length_field_len + value_len;
    if total as usize > data.len() || value_len > 1_000_000 {
        return None;
    }

    Some(TlvCandidate {
        offset: base_offset,
        tag,
        tag_len: 1,
        length_field_len,
        value_len,
        encoding: TlvEncoding::Tag1LenVarint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_asn1_chain() {
        // Two consecutive SEQUENCE elements → forms a chain.
        let data = &[
            0x30, 0x03, 0x02, 0x01, 0x2A, // SEQUENCE { INTEGER 42 }
            0x30, 0x03, 0x02, 0x01, 0x2B, // SEQUENCE { INTEGER 43 }
        ];
        let chains = detect_tlv_chains(data, 0, 2, 5);
        assert!(
            chains.iter().any(|c| c.encoding == TlvEncoding::Asn1Ber),
            "should detect ASN.1 BER chain"
        );
        let asn1_chain = chains
            .iter()
            .find(|c| c.encoding == TlvEncoding::Asn1Ber)
            .unwrap();
        assert_eq!(asn1_chain.elements.len(), 2);
    }

    #[test]
    fn stricter_min_chain_len_rejects_short_chain() {
        let data = &[
            0x30, 0x03, 0x02, 0x01, 0x2A, // SEQUENCE { INTEGER 42 }
            0x30, 0x03, 0x02, 0x01, 0x2B, // SEQUENCE { INTEGER 43 }
        ];
        let chains = detect_tlv_chains(data, 0, 3, 5);
        assert!(
            chains.is_empty(),
            "min_chain_len=3 should reject a 2-element chain"
        );
    }

    #[test]
    fn no_chain_on_random_data() {
        let data = &[0x00, 0x00, 0x00, 0x00];
        let chains = detect_tlv_chains(data, 0, 2, 5);
        assert!(chains.is_empty(), "should not find chains in null data");
    }

    #[test]
    fn parses_tag1_len2_le_chain() {
        // Two 4-byte payloads with 1-byte tag + 2-byte LE length each.
        let data = &[
            0x10, 0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD, // tag=0x10, len=4 LE
            0x11, 0x04, 0x00, 0x11, 0x22, 0x33, 0x44, // tag=0x11, len=4 LE
        ];
        let chains = detect_tlv_chains(data, 0, 2, 5);
        assert!(
            chains.iter().any(|c| c.encoding == TlvEncoding::Tag1Len2Le),
            "should detect Tag1Len2Le chain"
        );
        // Same bytes interpreted BE would yield value_len 0x0400 = 1024,
        // which is far longer than the data, so the BE encoding must NOT
        // claim this chain.
        assert!(
            !chains.iter().any(|c| c.encoding == TlvEncoding::Tag1Len2Be),
            "BE encoding should not match a clearly-LE payload"
        );
    }

    #[test]
    fn parses_tag1_len4_le_chain() {
        let data = &[
            0x20, 0x02, 0x00, 0x00, 0x00, 0xAA, 0xBB, // tag=0x20, len=2 LE (4 bytes)
            0x21, 0x02, 0x00, 0x00, 0x00, 0xCC, 0xDD, // tag=0x21, len=2 LE (4 bytes)
        ];
        let chains = detect_tlv_chains(data, 0, 2, 5);
        assert!(
            chains.iter().any(|c| c.encoding == TlvEncoding::Tag1Len4Le),
            "should detect Tag1Len4Le chain"
        );
    }

    #[test]
    fn parses_varint_chain() {
        // 4 elements: tag=0x42, varint length=2 (single byte), 2 payload bytes.
        let data: Vec<u8> = vec![
            0x42, 0x02, 0xAA, 0xBB, // element 0
            0x42, 0x02, 0xCC, 0xDD, // element 1
            0x42, 0x02, 0xEE, 0xFF, // element 2
            0x42, 0x02, 0x11, 0x22, // element 3
        ];
        let chains = detect_tlv_chains(&data, 0, 2, 5);
        assert!(
            chains
                .iter()
                .any(|c| c.encoding == TlvEncoding::Tag1LenVarint),
            "should detect a 4-element varint chain"
        );
    }

    #[test]
    fn varint_requires_stricter_minimum_chain_len() {
        // Only 2 elements — below VARINT_MIN_CHAIN_LEN even though caller
        // passes min_chain_len=2. This blocks varint false positives.
        let data: Vec<u8> = vec![
            0x42, 0x02, 0xAA, 0xBB, //
            0x42, 0x02, 0xCC, 0xDD, //
        ];
        let chains = detect_tlv_chains(&data, 0, 2, 5);
        assert!(
            !chains
                .iter()
                .any(|c| c.encoding == TlvEncoding::Tag1LenVarint),
            "2-element varint chain should be rejected by VARINT_MIN_CHAIN_LEN"
        );
    }

    #[test]
    fn varint_rejects_zero_length_records() {
        // Zero-length varint records would let the chain consume only one
        // byte per element, matching almost anything.
        let data: Vec<u8> = vec![0x42, 0x00, 0x42, 0x00, 0x42, 0x00, 0x42, 0x00];
        let chains = detect_tlv_chains(&data, 0, 2, 5);
        assert!(
            !chains
                .iter()
                .any(|c| c.encoding == TlvEncoding::Tag1LenVarint),
            "zero-length varint records must not form a chain"
        );
    }

    #[test]
    fn varint_rejects_overlong_encoding() {
        // 5+ continuation bytes is over-long for our cap; must not parse.
        let mut data = vec![0x42];
        data.extend(vec![0x80; 6]);
        data.extend(vec![0xAA; 32]);
        let chains = detect_tlv_chains(&data, 0, 2, 5);
        assert!(
            !chains
                .iter()
                .any(|c| c.encoding == TlvEncoding::Tag1LenVarint),
            "over-long varint must not produce a chain"
        );
    }

    #[test]
    fn min_chain_len_zero_is_clamped_safely() {
        // Empty data: caller passes 0 — must not panic via try_parse_chain
        // indexing an empty Vec.
        let chains = detect_tlv_chains(&[], 0, 0, 5);
        assert!(chains.is_empty());

        // Non-parsing data with min_chain_len 0 — same panic path on the
        // original implementation.
        let chains = detect_tlv_chains(&[0xFF, 0xFF, 0xFF, 0xFF], 0, 0, 5);
        assert!(chains.is_empty());

        // A real chain should still be reported when 0 is clamped to 1.
        let data = &[
            0x30, 0x03, 0x02, 0x01, 0x2A, // SEQUENCE { INTEGER 42 }
            0x30, 0x03, 0x02, 0x01, 0x2B, // SEQUENCE { INTEGER 43 }
        ];
        let chains = detect_tlv_chains(data, 0, 0, 5);
        assert!(
            chains.iter().any(|c| c.encoding == TlvEncoding::Asn1Ber),
            "0 should clamp to 1 and still find the real chain"
        );
    }
}
