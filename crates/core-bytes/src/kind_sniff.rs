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

/// X.509 certificate PEM headers (only actual certificates — CRLs and CSRs
/// are left as generic Pem until dedicated parsers exist).
const X509_PEM_HEADERS: &[&[u8]] = &[
    b"-----BEGIN CERTIFICATE-----",
    b"-----BEGIN TRUSTED CERTIFICATE-----",
];

/// SSH private key PEM header.
const SSH_PRIVATE_HEADER: &[u8] = b"-----BEGIN OPENSSH PRIVATE KEY-----";

/// SSH public key prefixes (the key type token before the base64 blob).
const SSH_PUBKEY_PREFIXES: &[&[u8]] = &[
    b"ssh-rsa ",
    b"ssh-ed25519 ",
    b"ssh-dss ",
    b"ecdsa-sha2-nistp256 ",
    b"ecdsa-sha2-nistp384 ",
    b"ecdsa-sha2-nistp521 ",
    b"sk-ssh-ed25519@openssh.com ",
    b"sk-ecdsa-sha2-nistp256@openssh.com ",
];

/// age encrypted file header.
const AGE_HEADER: &[u8] = b"age-encryption.org/";

/// age identity key prefix.
const AGE_KEY_PREFIX: &[u8] = b"AGE-SECRET-KEY-";

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

/// Conservative check for DER-encoded X.509: starts with ASN.1 SEQUENCE tag
/// (0x30) and has a plausible DER length encoding.
fn looks_like_der_x509(header: &[u8], file_size: u64) -> bool {
    if header.len() < 4 || header[0] != 0x30 {
        return false;
    }
    // Parse DER length to check plausibility.
    let (content_len, header_len) = match header[1] {
        // Short form: length < 128
        n if n < 0x80 => (n as u64, 2u64),
        // Long form: 0x81 = 1 byte length, 0x82 = 2 bytes, etc.
        0x81 if header.len() >= 3 => (header[2] as u64, 3),
        0x82 if header.len() >= 4 => (u16::from_be_bytes([header[2], header[3]]) as u64, 4),
        0x83 if header.len() >= 5 => {
            let len = (header[2] as u64) << 16 | (header[3] as u64) << 8 | header[4] as u64;
            (len, 5)
        }
        _ => return false,
    };
    // Total DER object size should be close to file size (within reason).
    let total = header_len + content_len;
    // Must be at least 20 bytes (tiny cert) and not exceed file size.
    total >= 20 && total <= file_size
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

/// Strip leading whitespace/BOM bytes from a header for PEM/text detection.
fn skip_leading_whitespace(header: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < header.len() {
        match header[i] {
            b' ' | b'\t' | b'\r' | b'\n' | 0xEF | 0xBB | 0xBF => i += 1,
            _ => break,
        }
    }
    &header[i..]
}

/// Check if `data` starts with `prefix`.
fn starts_with(data: &[u8], prefix: &[u8]) -> bool {
    data.len() >= prefix.len() && &data[..prefix.len()] == prefix
}

/// Detect file kind by content first, extension second.
///
/// `header` should be the first few hundred bytes of the file (at least 64 is ideal).
pub fn sniff_kind(header: &[u8], path: &Path, file_size: u64) -> DetectedKind {
    if file_size == 0 {
        return DetectedKind::Empty;
    }

    let trimmed = skip_leading_whitespace(header);

    // ── PEM-based detection (order matters: specific formats first) ──

    // OpenPGP armored
    for armor_header in ARMOR_HEADERS {
        if starts_with(trimmed, armor_header) {
            return DetectedKind::OpenPgpArmored;
        }
    }

    // SSH private key
    if starts_with(trimmed, SSH_PRIVATE_HEADER) {
        return DetectedKind::SshPrivateKey;
    }

    // X.509 PEM
    for x509_header in X509_PEM_HEADERS {
        if starts_with(trimmed, x509_header) {
            return DetectedKind::X509Pem;
        }
    }

    // age encrypted file
    if starts_with(trimmed, AGE_HEADER) {
        return DetectedKind::AgeEncrypted;
    }

    // age identity key (may appear in key files with comment lines first)
    if starts_with(trimmed, AGE_KEY_PREFIX) || has_age_key_line(header) {
        return DetectedKind::AgeKey;
    }

    // SSH public key (on first non-empty line)
    for prefix in SSH_PUBKEY_PREFIXES {
        if starts_with(trimmed, prefix) {
            return DetectedKind::SshPublicKey;
        }
    }

    // Generic PEM (not matched by any specific format above)
    if starts_with(trimmed, b"-----BEGIN ") {
        return DetectedKind::Pem;
    }

    // JWT: compact serialization starts with base64url-encoded JSON header "eyJ"
    if starts_with(trimmed, b"eyJ") && trimmed.iter().any(|&b| b == b'.') {
        return DetectedKind::JsonWebToken;
    }

    // JWK: JSON object containing "kty" key
    if looks_like_jwk(trimmed) {
        return DetectedKind::JsonWebKey;
    }

    // ── Binary content-based detection ──

    if looks_like_openpgp_binary(header) {
        return DetectedKind::OpenPgpBinary;
    }

    if looks_like_der_x509(header, file_size) {
        return DetectedKind::X509Der;
    }

    // ── Extension-based fallback ──

    if is_openpgp_extension(path) {
        return DetectedKind::OpenPgpByExtension;
    }

    // ── Heuristic text/binary fallback ──

    let text_like = header
        .iter()
        .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
    if text_like && !header.is_empty() {
        return DetectedKind::Text;
    }

    DetectedKind::Binary
}

/// Check if the header contains an age key line (possibly after comment lines).
fn has_age_key_line(header: &[u8]) -> bool {
    for line in header.split(|&b| b == b'\n') {
        let line = line.strip_suffix(&[b'\r']).unwrap_or(line);
        let line = line.strip_prefix(&[b' ']).unwrap_or(line);
        if line.is_empty() || line.starts_with(b"#") {
            continue;
        }
        return line.starts_with(AGE_KEY_PREFIX);
    }
    false
}

/// Conservative JWK detection: looks like a JSON object with a "kty" key.
fn looks_like_jwk(data: &[u8]) -> bool {
    if data.first() != Some(&b'{') {
        return false;
    }
    // Quick scan for "kty" in the first 512 bytes.
    let scan = &data[..data.len().min(512)];
    scan.windows(5).any(|w| w == b"\"kty\"" || w == b"'kty'")
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

    // ── New format detection tests ──

    #[test]
    fn detects_x509_pem() {
        let header = b"-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...";
        let kind = sniff_kind(header, &PathBuf::from("cert.pem"), header.len() as u64);
        assert_eq!(kind, DetectedKind::X509Pem);
    }

    #[test]
    fn detects_x509_der() {
        // ASN.1 SEQUENCE tag (0x30) + 2-byte length (0x82 0x03 0x00) = 768 bytes
        let mut header = vec![0x30, 0x82, 0x03, 0x00];
        header.extend_from_slice(&[0x30; 60]); // padding
        let kind = sniff_kind(&header, &PathBuf::from("cert.der"), 772);
        assert_eq!(kind, DetectedKind::X509Der);
    }

    #[test]
    fn detects_ssh_private_key() {
        let header = b"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r...";
        let kind = sniff_kind(header, &PathBuf::from("id_ed25519"), header.len() as u64);
        assert_eq!(kind, DetectedKind::SshPrivateKey);
    }

    #[test]
    fn detects_ssh_public_key_rsa() {
        let header = b"ssh-rsa AAAAB3NzaC1yc2EAAA... user@host";
        let kind = sniff_kind(header, &PathBuf::from("id_rsa.pub"), header.len() as u64);
        assert_eq!(kind, DetectedKind::SshPublicKey);
    }

    #[test]
    fn detects_ssh_public_key_ed25519() {
        let header = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA... user@host";
        let kind = sniff_kind(
            header,
            &PathBuf::from("id_ed25519.pub"),
            header.len() as u64,
        );
        assert_eq!(kind, DetectedKind::SshPublicKey);
    }

    #[test]
    fn detects_age_encrypted() {
        let header = b"age-encryption.org/v1\n-> X25519 abc123\n";
        let kind = sniff_kind(header, &PathBuf::from("secret.age"), header.len() as u64);
        assert_eq!(kind, DetectedKind::AgeEncrypted);
    }

    #[test]
    fn detects_age_key() {
        let header = b"# created: 2024-01-01\nAGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQ";
        let kind = sniff_kind(header, &PathBuf::from("key.txt"), header.len() as u64);
        assert_eq!(kind, DetectedKind::AgeKey);
    }

    #[test]
    fn detects_jwt() {
        // "eyJ" is base64url for '{"' — the start of a JWT header
        let header = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig";
        let kind = sniff_kind(header, &PathBuf::from("token.jwt"), header.len() as u64);
        assert_eq!(kind, DetectedKind::JsonWebToken);
    }

    #[test]
    fn detects_jwk() {
        let header = br#"{"kty":"RSA","n":"0vx7...","e":"AQAB"}"#;
        let kind = sniff_kind(header, &PathBuf::from("key.jwk"), header.len() as u64);
        assert_eq!(kind, DetectedKind::JsonWebKey);
    }

    #[test]
    fn detects_generic_pem() {
        let header = b"-----BEGIN EC PRIVATE KEY-----\nMHQCAQ...";
        let kind = sniff_kind(header, &PathBuf::from("ec.pem"), header.len() as u64);
        assert_eq!(kind, DetectedKind::Pem);
    }

    #[test]
    fn pgp_armored_wins_over_generic_pem() {
        let header = b"-----BEGIN PGP MESSAGE-----\ndata";
        let kind = sniff_kind(header, &PathBuf::from("msg.asc"), header.len() as u64);
        assert_eq!(kind, DetectedKind::OpenPgpArmored);
    }
}
