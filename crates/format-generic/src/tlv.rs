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
}

impl TlvEncoding {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Asn1Ber => "ASN.1 BER/DER",
            Self::Tag1Len2Be => "1-byte tag + 2-byte BE length",
            Self::Tag1Len4Be => "1-byte tag + 4-byte BE length",
        }
    }
}

/// Maximum number of TLV chains to return.
const MAX_CHAINS: usize = 5;

/// Minimum chain length (elements) to report.
const MIN_CHAIN_LEN: usize = 2;

/// Try to detect TLV chains starting from offset 0.
///
/// Conservative: only reports chains where multiple consecutive elements parse
/// cleanly with no gaps or overlaps.
pub fn detect_tlv_chains(data: &[u8], base_offset: u64) -> Vec<TlvChain> {
    let mut chains = Vec::new();

    // Try each encoding scheme.
    for &encoding in &[
        TlvEncoding::Asn1Ber,
        TlvEncoding::Tag1Len2Be,
        TlvEncoding::Tag1Len4Be,
    ] {
        if let Some(chain) = try_parse_chain(data, base_offset, encoding) {
            if chain.elements.len() >= MIN_CHAIN_LEN {
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
    chains.truncate(MAX_CHAINS);
    chains
}

fn try_parse_chain(data: &[u8], base_offset: u64, encoding: TlvEncoding) -> Option<TlvChain> {
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

    if elements.len() < MIN_CHAIN_LEN {
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
        TlvEncoding::Tag1Len2Be => parse_tag1_len_be(data, base_offset, 2),
        TlvEncoding::Tag1Len4Be => parse_tag1_len_be(data, base_offset, 4),
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

fn parse_tag1_len_be(data: &[u8], base_offset: u64, len_bytes: usize) -> Option<TlvCandidate> {
    let min_header = 1 + len_bytes;
    if data.len() < min_header {
        return None;
    }

    let tag = data[0] as u64;
    if tag == 0x00 || tag == 0xFF {
        return None;
    }

    let value_len = match len_bytes {
        2 => u16::from_be_bytes([data[1], data[2]]) as u64,
        4 => u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as u64,
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
        encoding: match len_bytes {
            2 => TlvEncoding::Tag1Len2Be,
            _ => TlvEncoding::Tag1Len4Be,
        },
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
        let chains = detect_tlv_chains(data, 0);
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
    fn no_chain_on_random_data() {
        let data = &[0x00, 0x00, 0x00, 0x00];
        let chains = detect_tlv_chains(data, 0);
        assert!(chains.is_empty(), "should not find chains in null data");
    }
}
