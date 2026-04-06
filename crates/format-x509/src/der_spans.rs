//! DER TLV span extraction for X.509 certificates.
//!
//! Walks the outer DER structure to locate exact byte ranges for the major
//! certificate sections. This avoids relying on parser-internal pointers
//! that may not cover the full TLV envelope (tag + length + value).

use tinkerspark_core_types::ByteRange;

/// Spans for the top-level certificate structure.
///
/// A certificate is: SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
#[derive(Debug)]
pub struct CertSpans {
    /// The outer SEQUENCE (the whole certificate).
    pub certificate: ByteRange,
    /// The TBSCertificate SEQUENCE.
    pub tbs: ByteRange,
    /// The signature algorithm identifier (after TBS).
    pub signature_algorithm: ByteRange,
    /// The signature BIT STRING.
    pub signature_value: ByteRange,
}

/// Spans for the TBSCertificate fields.
///
/// TBSCertificate is: SEQUENCE { version, serial, sigAlg, issuer, validity,
/// subject, subjectPKI, [extensions] }
#[derive(Debug)]
pub struct TbsSpans {
    /// EXPLICIT [0] version (if present).
    pub version: Option<ByteRange>,
    /// INTEGER serial number.
    pub serial: Option<ByteRange>,
    /// AlgorithmIdentifier for signature.
    pub signature: Option<ByteRange>,
    /// Issuer Name SEQUENCE.
    pub issuer: Option<ByteRange>,
    /// Validity SEQUENCE.
    pub validity: Option<ByteRange>,
    /// Subject Name SEQUENCE.
    pub subject: Option<ByteRange>,
    /// SubjectPublicKeyInfo SEQUENCE.
    pub subject_pki: Option<ByteRange>,
    /// Extensions [3] EXPLICIT (if present).
    pub extensions: Option<ByteRange>,
}

/// Spans for the Validity SEQUENCE internals.
#[derive(Debug)]
pub struct ValiditySpans {
    /// notBefore time element.
    pub not_before: Option<ByteRange>,
    /// notAfter time element.
    pub not_after: Option<ByteRange>,
}

/// Span for a single extension wrapper (OID + critical + extnValue).
#[derive(Debug)]
pub struct ExtensionSpan {
    /// The full SEQUENCE wrapping this extension.
    pub wrapper: ByteRange,
}

/// Spans for SubjectPublicKeyInfo internals.
#[derive(Debug)]
pub struct SpkiSpans {
    /// The AlgorithmIdentifier SEQUENCE.
    pub algorithm: ByteRange,
    /// The subjectPublicKey BIT STRING.
    pub subject_public_key: ByteRange,
}

/// Parse a DER length, returning (content_length, header_bytes_consumed).
fn parse_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    let first = data[0];
    if first < 0x80 {
        Some((first as usize, 1))
    } else if first == 0x80 {
        None // Indefinite length — not valid DER.
    } else {
        let num_bytes = (first & 0x7F) as usize;
        if num_bytes > 4 || data.len() < 1 + num_bytes {
            return None;
        }
        let mut len = 0usize;
        for i in 0..num_bytes {
            len = (len << 8) | data[1 + i] as usize;
        }
        Some((len, 1 + num_bytes))
    }
}

/// Read a single TLV element at `offset` within `data`.
/// Returns (tag_byte, content_offset, content_length, total_element_length).
fn read_tlv(data: &[u8], offset: usize) -> Option<(u8, usize, usize, usize)> {
    if offset >= data.len() {
        return None;
    }
    let tag_byte = data[offset];
    let after_tag = offset + 1;
    if after_tag >= data.len() {
        return None;
    }
    let (content_len, len_bytes) = parse_length(&data[after_tag..])?;
    let content_offset = after_tag + len_bytes;
    let total = 1 + len_bytes + content_len;
    if offset + total > data.len() {
        return None;
    }
    Some((tag_byte, content_offset, content_len, total))
}

/// Extract top-level certificate spans from DER data.
pub fn extract_cert_spans(der: &[u8], base_offset: u64) -> Option<CertSpans> {
    // Outer SEQUENCE.
    let (tag, content_off, content_len, total) = read_tlv(der, 0)?;
    if tag != 0x30 {
        return None; // Not a SEQUENCE.
    }
    let certificate = ByteRange::new(base_offset, total as u64);

    // Inside the outer SEQUENCE, read 3 children: tbs, sigAlg, sigValue.
    let mut pos = content_off;
    let end = content_off + content_len;

    // 1. TBSCertificate (SEQUENCE)
    let (_, _, _, tbs_total) = read_tlv(der, pos)?;
    let tbs = ByteRange::new(base_offset + pos as u64, tbs_total as u64);
    pos += tbs_total;
    if pos > end {
        return None;
    }

    // 2. signatureAlgorithm (SEQUENCE)
    let (_, _, _, sig_alg_total) = read_tlv(der, pos)?;
    let signature_algorithm = ByteRange::new(base_offset + pos as u64, sig_alg_total as u64);
    pos += sig_alg_total;
    if pos > end {
        return None;
    }

    // 3. signatureValue (BIT STRING)
    let (_, _, _, sig_val_total) = read_tlv(der, pos)?;
    let signature_value = ByteRange::new(base_offset + pos as u64, sig_val_total as u64);

    Some(CertSpans {
        certificate,
        tbs,
        signature_algorithm,
        signature_value,
    })
}

/// Extract TBSCertificate field spans from DER data.
///
/// `tbs_range` is the ByteRange of the TBSCertificate SEQUENCE within `der`.
pub fn extract_tbs_spans(der: &[u8], tbs_range: ByteRange, base_offset: u64) -> TbsSpans {
    let mut spans = TbsSpans {
        version: None,
        serial: None,
        signature: None,
        issuer: None,
        validity: None,
        subject: None,
        subject_pki: None,
        extensions: None,
    };

    let tbs_start = (tbs_range.offset() - base_offset) as usize;
    // Read the TBS SEQUENCE header to get the content start.
    let (tag, content_off, content_len, _) = match read_tlv(der, tbs_start) {
        Some(t) => t,
        None => return spans,
    };
    if tag != 0x30 {
        return spans;
    }

    let mut pos = content_off;
    let end = content_off + content_len;
    let mut field_index = 0;

    // TBS fields in order:
    // [0] version (EXPLICIT, context tag 0, optional)
    // serial (INTEGER)
    // signature (SEQUENCE)
    // issuer (SEQUENCE)
    // validity (SEQUENCE)
    // subject (SEQUENCE)
    // subjectPublicKeyInfo (SEQUENCE)
    // [1] issuerUniqueID (optional, context tag 1)
    // [2] subjectUniqueID (optional, context tag 2)
    // [3] extensions (EXPLICIT, context tag 3, optional)

    while pos < end {
        let (tag_byte, _, _, total) = match read_tlv(der, pos) {
            Some(t) => t,
            None => break,
        };
        let element_range = ByteRange::new(base_offset + pos as u64, total as u64);

        let class = tag_byte >> 6;
        let tag_num = tag_byte & 0x1F;

        if class == 2 {
            // Context-specific tag.
            match tag_num {
                0 => spans.version = Some(element_range),
                3 => spans.extensions = Some(element_range),
                _ => {} // issuerUniqueID(1), subjectUniqueID(2) — skip.
            }
        } else {
            // Universal tag — assign by position.
            match field_index {
                0 => spans.serial = Some(element_range),
                1 => spans.signature = Some(element_range),
                2 => spans.issuer = Some(element_range),
                3 => spans.validity = Some(element_range),
                4 => spans.subject = Some(element_range),
                5 => spans.subject_pki = Some(element_range),
                _ => {} // Unexpected extra fields — ignore.
            }
            field_index += 1;
        }

        pos += total;
    }

    spans
}

/// Walk inside a Validity SEQUENCE to extract notBefore and notAfter spans.
pub fn extract_validity_spans(
    der: &[u8],
    validity_range: ByteRange,
    base_offset: u64,
) -> ValiditySpans {
    let mut spans = ValiditySpans {
        not_before: None,
        not_after: None,
    };

    let start = (validity_range.offset() - base_offset) as usize;
    let (tag, content_off, content_len, _) = match read_tlv(der, start) {
        Some(t) => t,
        None => return spans,
    };
    if tag != 0x30 {
        return spans;
    }

    let mut pos = content_off;
    let end = content_off + content_len;

    // notBefore (UTCTime or GeneralizedTime)
    if pos < end {
        if let Some((_, _, _, total)) = read_tlv(der, pos) {
            spans.not_before = Some(ByteRange::new(base_offset + pos as u64, total as u64));
            pos += total;
        }
    }

    // notAfter (UTCTime or GeneralizedTime)
    if pos < end {
        if let Some((_, _, _, total)) = read_tlv(der, pos) {
            spans.not_after = Some(ByteRange::new(base_offset + pos as u64, total as u64));
        }
    }

    spans
}

/// Walk inside the extensions [3] EXPLICIT wrapper to extract individual
/// extension SEQUENCE spans.
///
/// The structure is: [3] EXPLICIT { SEQUENCE { ext1, ext2, ... } }
/// Each ext is: SEQUENCE { OID, [BOOLEAN critical], OCTET STRING value }
pub fn extract_extension_spans(
    der: &[u8],
    extensions_range: ByteRange,
    base_offset: u64,
) -> Vec<ExtensionSpan> {
    let mut result = Vec::new();

    let start = (extensions_range.offset() - base_offset) as usize;
    // Read the [3] EXPLICIT wrapper.
    let (_, explicit_content_off, explicit_content_len, _) = match read_tlv(der, start) {
        Some(t) => t,
        None => return result,
    };

    // Inside the EXPLICIT wrapper is a SEQUENCE of extensions.
    let (tag, seq_content_off, seq_content_len, _) = match read_tlv(der, explicit_content_off) {
        Some(t) => t,
        None => return result,
    };
    if tag != 0x30 {
        return result;
    }

    // Clamp to the actual EXPLICIT content.
    let end = (seq_content_off + seq_content_len).min(explicit_content_off + explicit_content_len);
    let mut pos = seq_content_off;

    while pos < end {
        let (_, _, _, total) = match read_tlv(der, pos) {
            Some(t) => t,
            None => break,
        };
        result.push(ExtensionSpan {
            wrapper: ByteRange::new(base_offset + pos as u64, total as u64),
        });
        pos += total;
    }

    result
}

/// Walk inside SubjectPublicKeyInfo to extract AlgorithmIdentifier and
/// subjectPublicKey spans.
///
/// SPKI is: SEQUENCE { AlgorithmIdentifier, BIT STRING }
pub fn extract_spki_spans(
    der: &[u8],
    spki_range: ByteRange,
    base_offset: u64,
) -> Option<SpkiSpans> {
    let start = (spki_range.offset() - base_offset) as usize;
    let (tag, content_off, content_len, _) = read_tlv(der, start)?;
    if tag != 0x30 {
        return None;
    }

    let mut pos = content_off;
    let end = content_off + content_len;

    // 1. AlgorithmIdentifier (SEQUENCE)
    let (_, _, _, alg_total) = read_tlv(der, pos)?;
    let algorithm = ByteRange::new(base_offset + pos as u64, alg_total as u64);
    pos += alg_total;
    if pos > end {
        return None;
    }

    // 2. subjectPublicKey (BIT STRING)
    let (_, _, _, pk_total) = read_tlv(der, pos)?;
    let subject_public_key = ByteRange::new(base_offset + pos as u64, pk_total as u64);

    Some(SpkiSpans {
        algorithm,
        subject_public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_tlv_basic() {
        // SEQUENCE, short length 3: 30 03 01 01 FF
        let data = [0x30, 0x03, 0x01, 0x01, 0xFF];
        let (tag, content_off, content_len, total) = read_tlv(&data, 0).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(content_off, 2);
        assert_eq!(content_len, 3);
        assert_eq!(total, 5);
    }

    #[test]
    fn read_tlv_long_form_length() {
        // SEQUENCE with 2-byte length: 30 82 01 00
        let mut data = vec![0x30, 0x82, 0x01, 0x00];
        data.extend(vec![0x00; 256]);
        let (tag, content_off, content_len, total) = read_tlv(&data, 0).unwrap();
        assert_eq!(tag, 0x30);
        assert_eq!(content_off, 4);
        assert_eq!(content_len, 256);
        assert_eq!(total, 260);
    }

    #[test]
    fn parse_length_short_form() {
        assert_eq!(parse_length(&[0x03]), Some((3, 1)));
        assert_eq!(parse_length(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn parse_length_long_form() {
        assert_eq!(parse_length(&[0x81, 0x80]), Some((128, 2)));
        assert_eq!(parse_length(&[0x82, 0x01, 0x00]), Some((256, 3)));
    }

    #[test]
    fn extract_cert_spans_on_real_der() {
        let der = std::fs::read("../../testdata/x509/self-signed.der");
        if let Ok(der) = der {
            let spans = extract_cert_spans(&der, 0).unwrap();
            assert_eq!(spans.certificate.offset(), 0);
            assert_eq!(spans.certificate.length(), der.len() as u64);
            assert!(spans.tbs.length() > 0);
            assert!(spans.signature_algorithm.length() > 0);
            assert!(spans.signature_value.length() > 0);
            // TBS should be the first element inside the certificate.
            assert!(spans.tbs.offset() > 0);

            let tbs_spans = extract_tbs_spans(&der, spans.tbs, 0);
            // A v3 cert should have version.
            assert!(tbs_spans.serial.is_some());
            assert!(tbs_spans.issuer.is_some());
            assert!(tbs_spans.validity.is_some());
            assert!(tbs_spans.subject.is_some());
            assert!(tbs_spans.subject_pki.is_some());
        }
    }
}
