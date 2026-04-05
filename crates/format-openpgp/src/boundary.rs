/// A packet's position and size in the binary stream.
#[derive(Debug, Clone)]
pub struct PacketBoundary {
    /// Byte offset of the first byte (the CTB).
    pub offset: u64,
    /// Length of the header (CTB + length encoding). For partial-body
    /// packets this is the total framing bytes (CTB + all length octets).
    pub header_len: u64,
    /// Length of the body (content data only, excluding interleaved
    /// length octets in partial-body packets).
    pub body_len: u64,
    /// Whether this packet uses partial body length encoding.
    pub partial: bool,
}

/// Walk binary OpenPGP data and identify top-level packet boundaries.
///
/// Returns an entry for each packet found, in order. Stops at the first
/// byte that doesn't look like a valid packet tag, or at end of data.
pub fn walk_boundaries(data: &[u8]) -> Vec<PacketBoundary> {
    let mut boundaries = Vec::new();
    let mut pos = 0usize;

    while pos < data.len() {
        let start = pos;
        let ctb = data[pos];

        // Bit 7 must be set for a valid OpenPGP packet.
        if ctb & 0x80 == 0 {
            break;
        }

        pos += 1; // consume CTB

        if ctb & 0x40 != 0 {
            // New format packet.
            match parse_new_body_length(data, &mut pos) {
                NewLength::Known(body_len) => {
                    let header_len = (pos - start) as u64;
                    let available = data.len().saturating_sub(pos) as u64;
                    let actual_body = body_len.min(available);
                    pos += actual_body as usize;
                    boundaries.push(PacketBoundary {
                        offset: start as u64,
                        header_len,
                        body_len: actual_body,
                        partial: false,
                    });
                }
                NewLength::Partial { framing, content } => {
                    // Partial body: pos has been advanced past all chunks.
                    boundaries.push(PacketBoundary {
                        offset: start as u64,
                        header_len: framing,
                        body_len: content,
                        partial: true,
                    });
                }
                NewLength::Truncated => break,
            }
        } else {
            // Old format packet.
            match parse_old_body_length(ctb, data, &mut pos) {
                Some(body_len) => {
                    let header_len = (pos - start) as u64;
                    let available = data.len().saturating_sub(pos) as u64;
                    let actual_body = body_len.min(available);
                    pos += actual_body as usize;
                    boundaries.push(PacketBoundary {
                        offset: start as u64,
                        header_len,
                        body_len: actual_body,
                        partial: false,
                    });
                }
                None => break,
            }
        }
    }

    boundaries
}

enum NewLength {
    /// Normal length: body_len is known, pos is after the length bytes.
    Known(u64),
    /// Partial body: all chunks consumed. Fields are (framing_bytes, content_bytes).
    /// framing_bytes = CTB + all length octets. content_bytes = actual data.
    Partial { framing: u64, content: u64 },
    /// Truncated header.
    Truncated,
}

/// Parse old-format body length from the CTB's length-type bits.
fn parse_old_body_length(ctb: u8, data: &[u8], pos: &mut usize) -> Option<u64> {
    let length_type = ctb & 0x03;
    match length_type {
        0 => {
            if *pos >= data.len() {
                return None;
            }
            let len = data[*pos] as u64;
            *pos += 1;
            Some(len)
        }
        1 => {
            if *pos + 2 > data.len() {
                return None;
            }
            let len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as u64;
            *pos += 2;
            Some(len)
        }
        2 => {
            if *pos + 4 > data.len() {
                return None;
            }
            let len =
                u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
                    as u64;
            *pos += 4;
            Some(len)
        }
        3 => {
            // Indeterminate — extends to EOF.
            Some(data.len().saturating_sub(*pos) as u64)
        }
        _ => unreachable!(),
    }
}

/// Parse new-format body length. Returns a NewLength result.
fn parse_new_body_length(data: &[u8], pos: &mut usize) -> NewLength {
    if *pos >= data.len() {
        return NewLength::Truncated;
    }

    let first = data[*pos];
    *pos += 1;

    match first {
        0..=191 => NewLength::Known(first as u64),
        192..=223 => {
            if *pos >= data.len() {
                return NewLength::Truncated;
            }
            let second = data[*pos];
            *pos += 1;
            NewLength::Known(((first as u64 - 192) << 8) + second as u64 + 192)
        }
        224..=254 => {
            // Partial body. Walk all chunks, tracking framing vs content.
            // framing = CTB (already consumed) + first partial len byte + continuation len octets
            // content = actual data bytes
            let mut framing: u64 = 2; // CTB + this first partial length byte
            let mut content: u64 = 0;
            let mut chunk_len = 1u64 << (first & 0x1F);
            loop {
                let available = data.len().saturating_sub(*pos) as u64;
                let actual = chunk_len.min(available);
                content += actual;
                *pos += actual as usize;

                if *pos >= data.len() {
                    break;
                }

                let next = data[*pos];
                *pos += 1;
                framing += 1; // continuation length octet

                match next {
                    0..=191 => {
                        // Final chunk: 1-byte length (already counted in framing).
                        let available = data.len().saturating_sub(*pos) as u64;
                        let actual = (next as u64).min(available);
                        content += actual;
                        *pos += actual as usize;
                        break;
                    }
                    192..=223 => {
                        // Final chunk: 2-byte length.
                        if *pos >= data.len() {
                            break;
                        }
                        let second = data[*pos];
                        *pos += 1;
                        framing += 1; // second byte of 2-byte length
                        let len = ((next as u64 - 192) << 8) + second as u64 + 192;
                        let available = data.len().saturating_sub(*pos) as u64;
                        let actual = len.min(available);
                        content += actual;
                        *pos += actual as usize;
                        break;
                    }
                    224..=254 => {
                        // Another partial chunk.
                        chunk_len = 1u64 << (next & 0x1F);
                    }
                    255 => {
                        // Final chunk: 5-byte length (1 already counted).
                        if *pos + 4 > data.len() {
                            break;
                        }
                        framing += 4; // 4-byte big-endian length
                        let len = u32::from_be_bytes([
                            data[*pos],
                            data[*pos + 1],
                            data[*pos + 2],
                            data[*pos + 3],
                        ]) as u64;
                        *pos += 4;
                        let available = data.len().saturating_sub(*pos) as u64;
                        let actual = len.min(available);
                        content += actual;
                        *pos += actual as usize;
                        break;
                    }
                }
            }
            NewLength::Partial { framing, content }
        }
        255 => {
            if *pos + 4 > data.len() {
                return NewLength::Truncated;
            }
            let len =
                u32::from_be_bytes([data[*pos], data[*pos + 1], data[*pos + 2], data[*pos + 3]])
                    as u64;
            *pos += 4;
            NewLength::Known(len)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_data() {
        assert!(walk_boundaries(&[]).is_empty());
    }

    #[test]
    fn invalid_first_byte() {
        assert!(walk_boundaries(&[0x00, 0x01, 0x02]).is_empty());
    }

    #[test]
    fn old_format_one_byte_length() {
        // CTB: old format, tag 2 (signature), length_type=0 (1 byte)
        // 0x88 = 1000_1000
        let mut data = vec![0x88, 0x03];
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        let bounds = walk_boundaries(&data);
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].offset, 0);
        assert_eq!(bounds[0].header_len, 2);
        assert_eq!(bounds[0].body_len, 3);
    }

    #[test]
    fn new_format_one_byte_length() {
        // 0xC2 = 1100_0010 → new format, tag=2
        let mut data = vec![0xC2, 0x05];
        data.extend_from_slice(&[0; 5]);

        let bounds = walk_boundaries(&data);
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].offset, 0);
        assert_eq!(bounds[0].header_len, 2);
        assert_eq!(bounds[0].body_len, 5);
    }

    #[test]
    fn multiple_packets() {
        let mut data = vec![0x88, 0x02, 0xAA, 0xBB];
        data.extend_from_slice(&[0x88, 0x01, 0xCC]);

        let bounds = walk_boundaries(&data);
        assert_eq!(bounds.len(), 2);
        assert_eq!(bounds[0].offset, 0);
        assert_eq!(bounds[0].body_len, 2);
        assert_eq!(bounds[1].offset, 4);
        assert_eq!(bounds[1].body_len, 1);
    }

    #[test]
    fn truncated_body() {
        // Body says 10, only 3 available.
        let data = vec![0x88, 0x0A, 0xAA, 0xBB, 0xCC];

        let bounds = walk_boundaries(&data);
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].header_len, 2);
        assert_eq!(bounds[0].body_len, 3);
    }

    #[test]
    fn new_format_five_byte_length() {
        // 0xC2, 0xFF, then 4-byte big-endian length = 256
        let mut data = vec![0xC2, 0xFF, 0x00, 0x00, 0x01, 0x00];
        data.extend_from_slice(&[0xAB; 256]);

        let bounds = walk_boundaries(&data);
        assert_eq!(bounds.len(), 1);
        assert_eq!(bounds[0].header_len, 6);
        assert_eq!(bounds[0].body_len, 256);
    }
}
