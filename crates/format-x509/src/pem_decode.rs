/// Result of PEM decoding.
pub struct PemDecoded {
    pub label: String,
    pub der_bytes: Vec<u8>,
}

/// Try to decode PEM data, returning the label and DER bytes.
/// Returns None if the data doesn't look like PEM.
pub fn try_decode_pem(data: &[u8]) -> Option<PemDecoded> {
    // Look for PEM BEGIN marker.
    let text = std::str::from_utf8(data).ok()?;
    let begin_marker = "-----BEGIN ";
    let begin_pos = text.find(begin_marker)?;
    let after_begin = &text[begin_pos + begin_marker.len()..];
    let dash_pos = after_begin.find("-----")?;
    let label = after_begin[..dash_pos].to_string();

    // Find the matching END marker.
    let end_marker = format!("-----END {}-----", label);
    let end_pos = text.find(&end_marker)?;

    // Extract base64 content between BEGIN and END.
    let header_end = begin_pos + begin_marker.len() + dash_pos + 5; // "-----" length
    let base64_text = &text[header_end..end_pos];

    // Strip whitespace and decode base64.
    let clean: String = base64_text.chars().filter(|c| !c.is_whitespace()).collect();

    let der_bytes = base64_decode(&clean)?;
    Some(PemDecoded { label, der_bytes })
}

/// Simple base64 decoder (standard alphabet with padding).
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let mut result = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;

    for ch in input.bytes() {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            _ => return None,
        };
        buf = (buf << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            result.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_simple_pem() {
        let pem = "-----BEGIN TEST-----\nSGVsbG8=\n-----END TEST-----\n";
        let decoded = try_decode_pem(pem.as_bytes()).unwrap();
        assert_eq!(decoded.label, "TEST");
        assert_eq!(decoded.der_bytes, b"Hello");
    }

    #[test]
    fn returns_none_for_non_pem() {
        let data = b"not a PEM file at all";
        assert!(try_decode_pem(data).is_none());
    }

    #[test]
    fn base64_decode_works() {
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("!!!").is_none());
    }
}
