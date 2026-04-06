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
    pub padding_span: Option<Span>,
    pub checkints_match: bool,
}

/// A single private key entry within the private section.
#[derive(Debug)]
pub struct PrivateKeyEntry {
    /// Span covering the entire key entry (keytype through comment).
    pub full_span: Span,
    pub keytype: StringField,
    /// Span covering the algorithm-specific data between keytype and comment.
    pub key_data_span: Span,
    pub comment: StringField,
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

    let mut keys = Vec::with_capacity(nkeys as usize);
    for _ in 0..nkeys {
        let entry_start = cur.pos;

        let keytype = cur.read_string()?;

        // Skip algorithm-specific fields until we find the comment.
        // Strategy: the comment is the last string before padding. We know
        // the key data is everything between keytype and comment.
        // We scan forward looking for plausible comment boundaries.
        //
        // Simpler approach: read strings until we find one that looks like a
        // comment (printable text, or empty) followed by padding or EOF.
        // Since we can't know the exact field count per algorithm, we use
        // a heuristic: keep reading strings and treat the last successful
        // one before padding as the comment.

        let key_data_start = cur.pos;
        let mut last_string_before_comment = None;
        let mut probe_pos = cur.pos;

        loop {
            let save = cur.pos;
            match cur.read_string() {
                Ok(s) => {
                    last_string_before_comment = Some((save, s));
                    probe_pos = cur.pos;
                }
                Err(_) => {
                    cur.pos = save;
                    break;
                }
            }
            // Check if remaining bytes look like padding (1..N repeating).
            if looks_like_padding(&data[cur.pos..]) {
                break;
            }
            // Safety valve: if we've consumed most of the data, stop.
            if cur.remaining() < 4 {
                break;
            }
        }

        let (comment_field_start, comment) = match last_string_before_comment {
            Some((off, s)) => (off, s),
            None => {
                // No strings found after keytype — treat as empty comment.
                let empty = StringField {
                    full_span: Span {
                        offset: section_offset + cur.pos,
                        length: 0,
                    },
                    value_span: Span {
                        offset: section_offset + cur.pos,
                        length: 0,
                    },
                    value: Vec::new(),
                };
                (cur.pos, empty)
            }
        };

        // Restore cursor to after the comment.
        cur.pos = probe_pos;

        let key_data_end = comment_field_start;
        let key_data_span = Span {
            offset: section_offset + key_data_start,
            length: key_data_end - key_data_start,
        };

        // Adjust comment spans to outer container coordinates.
        let comment = StringField {
            full_span: Span {
                offset: section_offset + comment.full_span.offset,
                length: comment.full_span.length,
            },
            value_span: Span {
                offset: section_offset + comment.value_span.offset,
                length: comment.value_span.length,
            },
            value: comment.value,
        };

        // Adjust keytype spans.
        let keytype = StringField {
            full_span: Span {
                offset: section_offset + keytype.full_span.offset,
                length: keytype.full_span.length,
            },
            value_span: Span {
                offset: section_offset + keytype.value_span.offset,
                length: keytype.value_span.length,
            },
            value: keytype.value,
        };

        let entry_end = cur.pos;
        keys.push(PrivateKeyEntry {
            full_span: Span {
                offset: section_offset + entry_start,
                length: entry_end - entry_start,
            },
            keytype,
            key_data_span,
            comment,
        });
    }

    // Remaining bytes are padding.
    let padding_span = if cur.pos < data.len() {
        Some(Span {
            offset: section_offset + cur.pos,
            length: data.len() - cur.pos,
        })
    } else {
        None
    };

    Ok(ParsedPrivateSection {
        checkint1,
        checkint1_span: ci1_span,
        checkint2,
        checkint2_span: ci2_span,
        keys,
        padding_span,
        checkints_match: checkint1 == checkint2,
    })
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
        let private_section = {
            let mut sec = Vec::new();
            sec.extend(42u32.to_be_bytes()); // checkint1
            sec.extend(42u32.to_be_bytes()); // checkint2
            sec.extend(build_string(b"ssh-ed25519")); // keytype
            sec.extend(build_string(b"\x00\x01\x02\x03")); // key data
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
        assert_eq!(priv_sec.checkint1, 42);
        assert_eq!(priv_sec.keys.len(), 1);
        assert_eq!(priv_sec.keys[0].keytype.as_str(), Some("ssh-ed25519"));
        assert_eq!(priv_sec.keys[0].comment.as_str(), Some("test comment"));
        assert!(priv_sec.padding_span.is_some());
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
}
