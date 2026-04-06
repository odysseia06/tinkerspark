use serde::{Deserialize, Serialize};
use std::fmt;

/// The detected kind of a binary file, determined by content sniffing first,
/// extension second.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectedKind {
    /// ASCII-armored OpenPGP data (detected by header content).
    OpenPgpArmored,
    /// Binary OpenPGP data (detected by content magic or extension).
    OpenPgpBinary,
    /// OpenPGP candidate detected by file extension only.
    OpenPgpByExtension,

    /// PEM-encoded X.509 certificate (detected by "-----BEGIN CERTIFICATE-----").
    X509Pem,
    /// DER-encoded X.509 certificate (detected by ASN.1 SEQUENCE tag + valid length).
    X509Der,

    /// OpenSSH private key (detected by "-----BEGIN OPENSSH PRIVATE KEY-----").
    SshPrivateKey,
    /// SSH public key (detected by "ssh-rsa ", "ssh-ed25519 ", etc.).
    SshPublicKey,

    /// age-encrypted file (detected by "age-encryption.org/" header).
    AgeEncrypted,
    /// age identity/key file (detected by "AGE-SECRET-KEY-" prefix).
    AgeKey,

    /// JSON Web Token (detected by "eyJ" base64url prefix).
    JsonWebToken,
    /// JSON Web Key (detected by JSON object with "kty" field).
    JsonWebKey,

    /// PEM-encoded data of unrecognized type (generic "-----BEGIN ...-----").
    Pem,

    /// Unknown binary data.
    Binary,
    /// Appears to be mostly text/ASCII content.
    Text,
    /// Empty file.
    Empty,
}

impl fmt::Display for DetectedKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OpenPgpArmored => write!(f, "OpenPGP (armored)"),
            Self::OpenPgpBinary => write!(f, "OpenPGP (binary)"),
            Self::OpenPgpByExtension => write!(f, "OpenPGP (by extension)"),
            Self::X509Pem => write!(f, "X.509 (PEM)"),
            Self::X509Der => write!(f, "X.509 (DER)"),
            Self::SshPrivateKey => write!(f, "SSH private key"),
            Self::SshPublicKey => write!(f, "SSH public key"),
            Self::AgeEncrypted => write!(f, "age (encrypted)"),
            Self::AgeKey => write!(f, "age (key)"),
            Self::JsonWebToken => write!(f, "JWT"),
            Self::JsonWebKey => write!(f, "JWK"),
            Self::Pem => write!(f, "PEM"),
            Self::Binary => write!(f, "Binary"),
            Self::Text => write!(f, "Text"),
            Self::Empty => write!(f, "Empty"),
        }
    }
}
