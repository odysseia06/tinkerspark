//! Manual binary parser for the OpenSSH private key container.
//!
//! Format reference (openssh PROTOCOL.key):
//! ```text
//! "openssh-key-v1\0"     auth magic
//! string  ciphername
//! string  kdfname
//! string  kdfoptions
//! uint32  number of keys
//! string  publickey1
//! ...
//! string  publickeyN
//! string  encrypted_section   (contains private keys + padding)
//! ```
//!
//! The encrypted section, when decrypted (or when cipher=none), contains:
//! ```text
//! uint32  checkint1
//! uint32  checkint2
//! For each key:
//!   string  keytype
//!   ... algorithm-specific fields ...
//!   string  comment
//! padding  (1, 2, 3, ... repeating to block alignment)
//! ```

use tinkerspark_core_types::ByteRange;

/// Auth magic for OpenSSH private keys.
pub const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";

/// A parsed span within the binary data: offset and length relative to
/// the start of the decoded binary blob.
#[derive(Debug, Clone, Copy)]
pub struct Span {
    pub offset: usize,
    pub length: usize,
}

impl Span {
    pub fn to_range(self, base: u64) -> ByteRange {
        ByteRange::new(base + self.offset as u64, self.length as u64)
    }
}

/// Result of parsing the outer OpenSSH private key container.
#[derive(Debug)]
pub struct ParsedContainer {
    pub auth_magic: Span,
    pub ciphername: StringField,
    pub kdfname: StringField,
    pub kdfoptions: StringField,
    pub nkeys: u32,
    pub nkeys_span: Span,
    pub public_keys: Vec<StringField>,
    pub private_section: StringField,
    pub is_encrypted: bool,
}

/// A length-prefixed string field with its full span (including the 4-byte
/// length prefix) and value span (just the content bytes).
#[derive(Debug, Clone)]
pub struct StringField {
    /// Span of the entire field (4-byte length + content).
    pub full_span: Span,
    /// Span of just the content bytes.
    pub value_span: Span,
    /// The raw content bytes.
    pub value: Vec<u8>,
}

impl StringField {
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.value).ok()
    }
}

/// Result of parsing the unencrypted private section.
#[derive(Debug)]
pub struct ParsedPrivateSection {
    pub checkint1: u32,
    pub checkint1_span: Span,
    pub checkint2: u32,
    pub checkint2_span: Span,
    pub keys: Vec<PrivateKeyEntry>,
    /// Validated OpenSSH padding (1, 2, 3, ...). Only set when the bytes
    /// were actually checked; never set for undecoded remainder.
    pub padding_span: Option<Span>,
    /// Undecoded bytes remaining after parsing stopped early. Distinct from
    /// padding — these bytes were not validated.
    pub unparsed_remainder: Option<Span>,
    pub checkints_match: bool,
    /// True when parsing stopped before reaching all keys in a multi-key
    /// container (e.g. an unsupported algorithm in a non-final position).
    pub multi_key_limited: bool,
}

/// A single private key entry within the private section.
#[derive(Debug)]
pub struct PrivateKeyEntry {
    /// Span covering the entire key entry (keytype through comment).
    pub full_span: Span,
    pub keytype: StringField,
    /// Algorithm-specific decoded fields, or a coarse fallback span.
    pub key_fields: KeyFields,
    pub comment: StringField,
}

/// Algorithm-specific private key fields.
#[derive(Debug)]
pub enum KeyFields {
    /// Ed25519: public key (32 bytes) + combined seed||pubkey (64 bytes).
    Ed25519 {
        pubkey: StringField,
        combined: StringField,
    },
    /// RSA: n, e, d, iqmp, p, q (all mpints encoded as length-prefixed strings).
    Rsa {
        n: StringField,
        e: StringField,
        d: StringField,
        iqmp: StringField,
        p: StringField,
        q: StringField,
    },
    /// ECDSA: curve name, public key, private scalar.
    Ecdsa {
        curve: StringField,
        pubkey: StringField,
        privkey: StringField,
    },
    /// Algorithm not yet decoded — coarse span covering all key data.
    Opaque { data_span: Span, algorithm: String },
}

/// Cursor for reading through a byte slice with position tracking.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.pos + n > self.data.len() {
            return Err(ParseError::Truncated {
                needed: n,
                available: self.remaining(),
                context: "bytes",
            });
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn read_u32(&mut self) -> Result<(u32, Span), ParseError> {
        let offset = self.pos;
        let bytes = self.read_bytes(4).map_err(|_| ParseError::Truncated {
            needed: 4,
            available: self.remaining(),
            context: "uint32",
        })?;
        let val = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        Ok((val, Span { offset, length: 4 }))
    }

    fn read_string(&mut self) -> Result<StringField, ParseError> {
        let field_offset = self.pos;
        let (len, _) = self.read_u32().map_err(|_| ParseError::Truncated {
            needed: 4,
            available: self.remaining(),
            context: "string length",
        })?;
        let len = len as usize;
        // Sanity: reject strings > 1 MiB to avoid allocation bombs.
        if len > 1_048_576 {
            return Err(ParseError::InvalidLength {
                length: len,
                context: "string field",
            });
        }
        let value_offset = self.pos;
        let value = self.read_bytes(len)?.to_vec();
        Ok(StringField {
            full_span: Span {
                offset: field_offset,
                length: 4 + len,
            },
            value_span: Span {
                offset: value_offset,
                length: len,
            },
            value,
        })
    }
}

#[derive(Debug)]
pub enum ParseError {
    BadMagic,
    Truncated {
        needed: usize,
        available: usize,
        context: &'static str,
    },
    InvalidLength {
        length: usize,
        context: &'static str,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadMagic => write!(f, "missing openssh-key-v1 magic"),
            Self::Truncated {
                needed,
                available,
                context,
            } => write!(
                f,
                "truncated: need {needed} bytes for {context}, only {available} available"
            ),
            Self::InvalidLength { length, context } => {
                write!(f, "invalid length {length} for {context}")
            }
        }
    }
}

/// Parse the outer OpenSSH private key container from decoded binary data.
pub fn parse_container(data: &[u8]) -> Result<ParsedContainer, ParseError> {
    let mut cur = Cursor::new(data);

    // Auth magic.
    let magic_bytes = cur
        .read_bytes(AUTH_MAGIC.len())
        .map_err(|_| ParseError::BadMagic)?;
    if magic_bytes != AUTH_MAGIC {
        return Err(ParseError::BadMagic);
    }
    let auth_magic = Span {
        offset: 0,
        length: AUTH_MAGIC.len(),
    };

    // Header strings.
    let ciphername = cur.read_string()?;
    let kdfname = cur.read_string()?;
    let kdfoptions = cur.read_string()?;

    // Number of keys.
    let (nkeys, nkeys_span) = cur.read_u32()?;
    if nkeys == 0 || nkeys > 16 {
        return Err(ParseError::InvalidLength {
            length: nkeys as usize,
            context: "key count",
        });
    }

    // Public key blobs.
    let mut public_keys = Vec::with_capacity(nkeys as usize);
    for _ in 0..nkeys {
        public_keys.push(cur.read_string()?);
    }

    // Encrypted/private section.
    let private_section = cur.read_string()?;

    let is_encrypted = ciphername.as_str() != Some("none");

    Ok(ParsedContainer {
        auth_magic,
        ciphername,
        kdfname,
        kdfoptions,
        nkeys,
        nkeys_span,
        public_keys,
        private_section,
        is_encrypted,
    })
}

/// Parse the unencrypted private section.
/// Only call this when `is_encrypted` is false.
pub fn parse_private_section(
    data: &[u8],
    nkeys: u32,
    section_offset: usize,
) -> Result<ParsedPrivateSection, ParseError> {
    let mut cur = Cursor::new(data);

    // Check ints.
    let (checkint1, ci1_span) = cur.read_u32()?;
    let (checkint2, ci2_span) = cur.read_u32()?;

    // Adjust spans to be relative to the outer container, not the section.
    let ci1_span = Span {
        offset: section_offset + ci1_span.offset,
        length: ci1_span.length,
    };
    let ci2_span = Span {
        offset: section_offset + ci2_span.offset,
        length: ci2_span.length,
    };

    let multi_key = nkeys > 1;

    let mut keys = Vec::with_capacity(nkeys as usize);
    for i in 0..nkeys {
        let entry_start = cur.pos;

        let keytype = cur.read_string()?;
        let algo = std::str::from_utf8(&keytype.value)
            .unwrap_or("")
            .to_string();

        // Dispatch to algorithm-specific parsing. Each arm reads the
        // fixed fields for that algorithm and then the comment string.
        let (key_fields, comment) = match algo.as_str() {
            "ssh-ed25519" => parse_ed25519_fields(&mut cur, section_offset)?,
            "ssh-rsa" => parse_rsa_fields(&mut cur, section_offset)?,
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
                parse_ecdsa_fields(&mut cur, section_offset)?
            }
            _ => {
                // Unknown algorithm — fall back to heuristic scanning, but
                // only for the last key (where padding follows).
                if i < nkeys - 1 {
                    // Cannot safely delimit this key entry. Stop parsing.
                    let keytype = adjust_string_field(keytype, section_offset);
                    keys.push(PrivateKeyEntry {
                        full_span: Span {
                            offset: section_offset + entry_start,
                            length: cur.pos - entry_start,
                        },
                        keytype,
                        key_fields: KeyFields::Opaque {
                            data_span: Span {
                                offset: section_offset + cur.pos,
                                length: 0,
                            },
                            algorithm: algo.clone(),
                        },
                        comment: empty_string_field(section_offset + cur.pos),
                    });
                    break;
                }
                parse_opaque_fields(&mut cur, data, section_offset, &algo)?
            }
        };

        let keytype = adjust_string_field(keytype, section_offset);
        let entry_end = cur.pos;
        keys.push(PrivateKeyEntry {
            full_span: Span {
                offset: section_offset + entry_start,
                length: entry_end - entry_start,
            },
            keytype,
            key_fields,
            comment,
        });
    }

    let actually_limited = multi_key && (keys.len() as u32) < nkeys;

    // Classify trailing bytes: only label as padding if the bytes actually
    // match the OpenSSH padding pattern (1, 2, 3, ...). Otherwise, treat
    // as unparsed/invalid remainder.
    let remaining = if cur.pos < data.len() {
        Some(Span {
            offset: section_offset + cur.pos,
            length: data.len() - cur.pos,
        })
    } else {
        None
    };
    let (padding_span, unparsed_remainder) = match remaining {
        None => (None, None),
        Some(span) if actually_limited => (None, Some(span)),
        Some(span) => {
            if looks_like_padding(&data[cur.pos..]) {
                (Some(span), None)
            } else {
                (None, Some(span))
            }
        }
    };

    Ok(ParsedPrivateSection {
        checkint1,
        checkint1_span: ci1_span,
        checkint2,
        checkint2_span: ci2_span,
        keys,
        padding_span,
        unparsed_remainder,
        checkints_match: checkint1 == checkint2,
        multi_key_limited: actually_limited,
    })
}

/// Parse Ed25519 private key fields: string pubkey(32), string combined(64), string comment.
fn parse_ed25519_fields(
    cur: &mut Cursor<'_>,
    section_offset: usize,
) -> Result<(KeyFields, StringField), ParseError> {
    let pubkey = cur.read_string()?;
    let combined = cur.read_string()?;
    let comment = cur.read_string()?;

    let key_fields = KeyFields::Ed25519 {
        pubkey: adjust_string_field(pubkey, section_offset),
        combined: adjust_string_field(combined, section_offset),
    };
    Ok((key_fields, adjust_string_field(comment, section_offset)))
}

/// Parse RSA private key fields: n, e, d, iqmp, p, q, comment.
fn parse_rsa_fields(
    cur: &mut Cursor<'_>,
    section_offset: usize,
) -> Result<(KeyFields, StringField), ParseError> {
    let n = cur.read_string()?;
    let e = cur.read_string()?;
    let d = cur.read_string()?;
    let iqmp = cur.read_string()?;
    let p = cur.read_string()?;
    let q = cur.read_string()?;
    let comment = cur.read_string()?;

    let key_fields = KeyFields::Rsa {
        n: adjust_string_field(n, section_offset),
        e: adjust_string_field(e, section_offset),
        d: adjust_string_field(d, section_offset),
        iqmp: adjust_string_field(iqmp, section_offset),
        p: adjust_string_field(p, section_offset),
        q: adjust_string_field(q, section_offset),
    };
    Ok((key_fields, adjust_string_field(comment, section_offset)))
}

/// Parse ECDSA private key fields: curve, pubkey, privkey, comment.
fn parse_ecdsa_fields(
    cur: &mut Cursor<'_>,
    section_offset: usize,
) -> Result<(KeyFields, StringField), ParseError> {
    let curve = cur.read_string()?;
    let pubkey = cur.read_string()?;
    let privkey = cur.read_string()?;
    let comment = cur.read_string()?;

    let key_fields = KeyFields::Ecdsa {
        curve: adjust_string_field(curve, section_offset),
        pubkey: adjust_string_field(pubkey, section_offset),
        privkey: adjust_string_field(privkey, section_offset),
    };
    Ok((key_fields, adjust_string_field(comment, section_offset)))
}

/// Fallback: scan forward using the padding heuristic (only safe for the last key).
fn parse_opaque_fields(
    cur: &mut Cursor<'_>,
    data: &[u8],
    section_offset: usize,
    algo: &str,
) -> Result<(KeyFields, StringField), ParseError> {
    let key_data_start = cur.pos;
    let mut last_string: Option<(usize, StringField)> = None;
    let mut probe_pos = cur.pos;

    loop {
        let save = cur.pos;
        match cur.read_string() {
            Ok(s) => {
                last_string = Some((save, s));
                probe_pos = cur.pos;
            }
            Err(_) => {
                cur.pos = save;
                break;
            }
        }
        if looks_like_padding(&data[cur.pos..]) {
            break;
        }
        if cur.remaining() < 4 {
            break;
        }
    }

    let (comment_start, comment) = match last_string {
        Some((off, s)) => (off, s),
        None => (cur.pos, empty_string_field_local(cur.pos)),
    };
    cur.pos = probe_pos;

    let data_span = Span {
        offset: section_offset + key_data_start,
        length: comment_start - key_data_start,
    };
    let key_fields = KeyFields::Opaque {
        data_span,
        algorithm: algo.to_string(),
    };
    Ok((key_fields, adjust_string_field(comment, section_offset)))
}

/// Adjust a StringField's spans from section-local to container-global coordinates.
fn adjust_string_field(f: StringField, section_offset: usize) -> StringField {
    StringField {
        full_span: Span {
            offset: section_offset + f.full_span.offset,
            length: f.full_span.length,
        },
        value_span: Span {
            offset: section_offset + f.value_span.offset,
            length: f.value_span.length,
        },
        value: f.value,
    }
}

/// Create an empty StringField at the given offset (container-global).
fn empty_string_field(offset: usize) -> StringField {
    StringField {
        full_span: Span { offset, length: 0 },
        value_span: Span { offset, length: 0 },
        value: Vec::new(),
    }
}

/// Create an empty StringField at a section-local offset (not yet adjusted).
fn empty_string_field_local(offset: usize) -> StringField {
    StringField {
        full_span: Span { offset, length: 0 },
        value_span: Span { offset, length: 0 },
        value: Vec::new(),
    }
}

/// Check if the remaining bytes look like OpenSSH padding (1, 2, 3, ...).
fn looks_like_padding(data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    // OpenSSH padding is 1, 2, 3, 4, 5, 6, 7, 1, 2, ... (mod block size).
    // We check the first few bytes.
    for (i, &b) in data.iter().enumerate() {
        let expected = ((i % 255) + 1) as u8;
        if b != expected {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_string(s: &[u8]) -> Vec<u8> {
        let mut v = (s.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(s);
        v
    }

    fn build_minimal_container(cipher: &str, nkeys: u32, pubkey: &[u8], private: &[u8]) -> Vec<u8> {
        let mut data = AUTH_MAGIC.to_vec();
        data.extend(build_string(cipher.as_bytes()));
        data.extend(build_string(b"none")); // kdfname
        data.extend(build_string(b"")); // kdfoptions
        data.extend(nkeys.to_be_bytes());
        data.extend(build_string(pubkey));
        data.extend(build_string(private));
        data
    }

    #[test]
    fn parses_minimal_unencrypted_container() {
        // Ed25519 private record: keytype, pubkey(32), combined(64), comment
        let fake_pubkey = [0xAA; 32];
        let fake_combined = [0xBB; 64]; // seed(32) || pubkey(32)
        let private_section = {
            let mut sec = Vec::new();
            sec.extend(42u32.to_be_bytes()); // checkint1
            sec.extend(42u32.to_be_bytes()); // checkint2
            sec.extend(build_string(b"ssh-ed25519")); // keytype
            sec.extend(build_string(&fake_pubkey)); // public key (32 bytes)
            sec.extend(build_string(&fake_combined)); // combined seed||pubkey (64 bytes)
            sec.extend(build_string(b"test comment")); // comment
            sec.extend([1, 2, 3]); // padding
            sec
        };
        let data = build_minimal_container("none", 1, b"fakepubkey", &private_section);

        let container = parse_container(&data).unwrap();
        assert!(!container.is_encrypted);
        assert_eq!(container.ciphername.as_str(), Some("none"));
        assert_eq!(container.kdfname.as_str(), Some("none"));
        assert_eq!(container.nkeys, 1);
        assert_eq!(container.public_keys.len(), 1);

        let priv_sec = parse_private_section(
            &container.private_section.value,
            container.nkeys,
            container.private_section.value_span.offset,
        )
        .unwrap();
        assert!(priv_sec.checkints_match);
        assert!(!priv_sec.multi_key_limited);
        assert_eq!(priv_sec.checkint1, 42);
        assert_eq!(priv_sec.keys.len(), 1);
        assert_eq!(priv_sec.keys[0].keytype.as_str(), Some("ssh-ed25519"));
        assert_eq!(priv_sec.keys[0].comment.as_str(), Some("test comment"));
        assert!(priv_sec.padding_span.is_some());
        assert!(priv_sec.unparsed_remainder.is_none());
        // Ed25519 fields should be decoded.
        match &priv_sec.keys[0].key_fields {
            KeyFields::Ed25519 { pubkey, combined } => {
                assert_eq!(pubkey.value.len(), 32);
                assert_eq!(combined.value.len(), 64);
            }
            other => panic!("expected Ed25519 fields, got {:?}", other),
        }
    }

    #[test]
    fn detects_encrypted_container() {
        let data = build_minimal_container("aes256-ctr", 1, b"pub", b"encrypted-blob");
        let container = parse_container(&data).unwrap();
        assert!(container.is_encrypted);
        assert_eq!(container.ciphername.as_str(), Some("aes256-ctr"));
    }

    #[test]
    fn rejects_bad_magic() {
        let data = b"not-openssh-key-data";
        assert!(matches!(parse_container(data), Err(ParseError::BadMagic)));
    }

    #[test]
    fn handles_truncated_data() {
        // Just the magic, nothing else.
        let data = AUTH_MAGIC;
        let err = parse_container(data).unwrap_err();
        assert!(matches!(err, ParseError::Truncated { .. }));
    }

    #[test]
    fn padding_detection() {
        assert!(looks_like_padding(&[]));
        assert!(looks_like_padding(&[1, 2, 3]));
        assert!(looks_like_padding(&[1, 2, 3, 4, 5, 6, 7]));
        assert!(!looks_like_padding(&[0]));
        assert!(!looks_like_padding(&[1, 2, 4]));
    }

    #[test]
    fn bad_trailing_bytes_not_labeled_as_padding() {
        // Valid Ed25519 key followed by junk instead of proper 1,2,3,... padding.
        let fake_pubkey = [0xAA; 32];
        let fake_combined = [0xBB; 64];
        let private_section = {
            let mut sec = Vec::new();
            sec.extend(42u32.to_be_bytes());
            sec.extend(42u32.to_be_bytes());
            sec.extend(build_string(b"ssh-ed25519"));
            sec.extend(build_string(&fake_pubkey));
            sec.extend(build_string(&fake_combined));
            sec.extend(build_string(b"comment"));
            sec.extend([0xFF, 0xFE, 0xFD]); // junk, not valid padding
            sec
        };
        let data = build_minimal_container("none", 1, b"fakepubkey", &private_section);

        let container = parse_container(&data).unwrap();
        let priv_sec = parse_private_section(
            &container.private_section.value,
            container.nkeys,
            container.private_section.value_span.offset,
        )
        .unwrap();

        assert_eq!(priv_sec.keys.len(), 1);
        assert!(
            priv_sec.padding_span.is_none(),
            "junk trailing bytes must not be labeled as padding"
        );
        assert!(
            priv_sec.unparsed_remainder.is_some(),
            "junk trailing bytes should be unparsed_remainder"
        );
    }

    #[test]
    fn multi_key_ed25519_both_parsed() {
        // Two Ed25519 keys — both should be parsed since Ed25519 has known field layout.
        let private_section = {
            let mut sec = Vec::new();
            sec.extend(99u32.to_be_bytes()); // checkint1
            sec.extend(99u32.to_be_bytes()); // checkint2
                                             // Key 0: Ed25519
            sec.extend(build_string(b"ssh-ed25519"));
            sec.extend(build_string(&[0xAA; 32])); // pubkey
            sec.extend(build_string(&[0xBB; 64])); // combined
            sec.extend(build_string(b"first key"));
            // Key 1: Ed25519
            sec.extend(build_string(b"ssh-ed25519"));
            sec.extend(build_string(&[0xCC; 32])); // pubkey
            sec.extend(build_string(&[0xDD; 64])); // combined
            sec.extend(build_string(b"second key"));
            sec.extend([1, 2, 3]); // padding
            sec
        };
        // Container advertises 2 public keys and nkeys=2.
        let mut data = AUTH_MAGIC.to_vec();
        data.extend(build_string(b"none"));
        data.extend(build_string(b"none"));
        data.extend(build_string(b""));
        data.extend(2u32.to_be_bytes());
        data.extend(build_string(b"pub0"));
        data.extend(build_string(b"pub1"));
        data.extend(build_string(&private_section));

        let container = parse_container(&data).unwrap();
        assert_eq!(container.nkeys, 2);
        assert_eq!(container.public_keys.len(), 2);

        let priv_sec = parse_private_section(
            &container.private_section.value,
            container.nkeys,
            container.private_section.value_span.offset,
        )
        .unwrap();

        // Both Ed25519 keys should be parsed (known field layout).
        assert_eq!(priv_sec.keys.len(), 2);
        assert_eq!(priv_sec.keys[0].keytype.as_str(), Some("ssh-ed25519"));
        assert_eq!(priv_sec.keys[0].comment.as_str(), Some("first key"));
        assert_eq!(priv_sec.keys[1].keytype.as_str(), Some("ssh-ed25519"));
        assert_eq!(priv_sec.keys[1].comment.as_str(), Some("second key"));
        assert!(
            !priv_sec.multi_key_limited,
            "both keys parsed — should not be limited"
        );
    }

    #[test]
    fn multi_key_opaque_second_key_heuristic() {
        // Ed25519 + unknown algo (last key) — heuristic fallback is safe for final key.
        let private_section = {
            let mut sec = Vec::new();
            sec.extend(99u32.to_be_bytes());
            sec.extend(99u32.to_be_bytes());
            // Key 0: Ed25519
            sec.extend(build_string(b"ssh-ed25519"));
            sec.extend(build_string(&[0xAA; 32]));
            sec.extend(build_string(&[0xBB; 64]));
            sec.extend(build_string(b"first key"));
            // Key 1: unknown algo
            sec.extend(build_string(b"ssh-dss"));
            sec.extend(build_string(b"opaque-data"));
            sec.extend(build_string(b"second key"));
            sec.extend([1, 2, 3]);
            sec
        };
        let mut data = AUTH_MAGIC.to_vec();
        data.extend(build_string(b"none"));
        data.extend(build_string(b"none"));
        data.extend(build_string(b""));
        data.extend(2u32.to_be_bytes());
        data.extend(build_string(b"pub0"));
        data.extend(build_string(b"pub1"));
        data.extend(build_string(&private_section));

        let container = parse_container(&data).unwrap();
        let priv_sec = parse_private_section(
            &container.private_section.value,
            container.nkeys,
            container.private_section.value_span.offset,
        )
        .unwrap();

        // First key parsed via Ed25519, second via opaque heuristic (it's the last key).
        assert_eq!(priv_sec.keys.len(), 2);
        assert_eq!(priv_sec.keys[0].keytype.as_str(), Some("ssh-ed25519"));
        assert_eq!(priv_sec.keys[0].comment.as_str(), Some("first key"));
        assert_eq!(priv_sec.keys[1].keytype.as_str(), Some("ssh-dss"));
        assert_eq!(priv_sec.keys[1].comment.as_str(), Some("second key"));
        // Not limited because the opaque key is the last one (heuristic is safe).
        assert!(!priv_sec.multi_key_limited);
        assert!(priv_sec.padding_span.is_some());
        assert!(priv_sec.unparsed_remainder.is_none());
    }

    #[test]
    fn multi_key_opaque_middle_key_stops_early() {
        // Ed25519 + dss (opaque, non-final) + ed25519 — dss can't be delimited mid-stream.
        let private_section = {
            let mut sec = Vec::new();
            sec.extend(99u32.to_be_bytes());
            sec.extend(99u32.to_be_bytes());
            // Key 0: Ed25519
            sec.extend(build_string(b"ssh-ed25519"));
            sec.extend(build_string(&[0xAA; 32]));
            sec.extend(build_string(&[0xBB; 64]));
            sec.extend(build_string(b"first"));
            // Key 1: unknown algo (non-final)
            sec.extend(build_string(b"ssh-dss"));
            sec.extend(build_string(b"data"));
            sec.extend(build_string(b"second"));
            // Key 2: Ed25519 (never reached)
            sec.extend(build_string(b"ssh-ed25519"));
            sec.extend(build_string(&[0xCC; 32]));
            sec.extend(build_string(&[0xDD; 64]));
            sec.extend(build_string(b"third"));
            sec.extend([1, 2, 3]);
            sec
        };
        let mut data = AUTH_MAGIC.to_vec();
        data.extend(build_string(b"none"));
        data.extend(build_string(b"none"));
        data.extend(build_string(b""));
        data.extend(3u32.to_be_bytes());
        data.extend(build_string(b"pub0"));
        data.extend(build_string(b"pub1"));
        data.extend(build_string(b"pub2"));
        data.extend(build_string(&private_section));

        let container = parse_container(&data).unwrap();
        let priv_sec = parse_private_section(
            &container.private_section.value,
            container.nkeys,
            container.private_section.value_span.offset,
        )
        .unwrap();

        // Ed25519 key 0 is parsed, then dss key 1 breaks early (opaque, non-final).
        assert_eq!(priv_sec.keys.len(), 2);
        assert_eq!(priv_sec.keys[0].comment.as_str(), Some("first"));
        assert_eq!(priv_sec.keys[1].keytype.as_str(), Some("ssh-dss"));
        assert!(
            priv_sec.multi_key_limited,
            "should flag limitation: opaque non-final key stopped parsing"
        );
        // Remainder must NOT be labeled as padding — it contains undecoded key material.
        assert!(
            priv_sec.padding_span.is_none(),
            "undecoded remainder must not be labeled as padding"
        );
        assert!(
            priv_sec.unparsed_remainder.is_some(),
            "should have unparsed_remainder for the undecoded bytes"
        );
    }
}
