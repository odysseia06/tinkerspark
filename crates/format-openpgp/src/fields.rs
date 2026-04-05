use sequoia_openpgp::packet::prelude::*;
use sequoia_openpgp::packet::Packet;
use tinkerspark_core_analyze::FieldView;

/// Extract notable fields from a parsed packet.
pub fn extract_fields(packet: &Packet) -> Vec<FieldView> {
    let mut fields = vec![field("Tag", format!("{}", packet.tag()))];

    if let Some(version) = packet.version() {
        fields.push(field("Version", format!("{version}")));
    }

    match packet {
        Packet::PublicKey(ref key) => {
            extract_key_fields(key.parts_as_public(), &mut fields);
        }
        Packet::PublicSubkey(ref key) => {
            extract_key_fields(key.parts_as_public(), &mut fields);
        }
        Packet::SecretKey(ref key) => {
            extract_key_fields(key.parts_as_public(), &mut fields);
            fields.push(field("Secret key", "yes".to_string()));
        }
        Packet::SecretSubkey(ref key) => {
            extract_key_fields(key.parts_as_public(), &mut fields);
            fields.push(field("Secret key", "yes".to_string()));
        }
        Packet::UserID(ref uid) => {
            let value = String::from_utf8_lossy(uid.value()).into_owned();
            fields.push(field("User ID", value));
        }
        Packet::UserAttribute(_) => {
            fields.push(field("Type", "User Attribute".to_string()));
        }
        Packet::Signature(ref sig) => {
            extract_signature_fields(sig, &mut fields);
        }
        Packet::OnePassSig(ref ops) => {
            fields.push(field("Signature type", format!("{}", ops.typ())));
            fields.push(field("Hash algorithm", format!("{}", ops.hash_algo())));
            fields.push(field("PK algorithm", format!("{}", ops.pk_algo())));
        }
        Packet::Literal(ref lit) => {
            if let Some(filename) = lit.filename() {
                if let Ok(name) = std::str::from_utf8(filename) {
                    fields.push(field("Filename", name.to_string()));
                }
            }
            fields.push(field("Format", format!("{}", lit.format())));
            if let Some(date) = lit.date() {
                fields.push(field(
                    "Date",
                    format!(
                        "{}",
                        chrono::DateTime::<chrono::Utc>::from(date).format("%Y-%m-%d %H:%M:%S UTC")
                    ),
                ));
            }
        }
        Packet::CompressedData(ref cd) => {
            fields.push(field("Algorithm", format!("{}", cd.algo())));
        }
        Packet::PKESK(ref pkesk) => {
            if let Some(recipient) = pkesk.recipient() {
                fields.push(field("Recipient", format!("{recipient}")));
            }
            fields.push(field("PK algorithm", format!("{}", pkesk.pk_algo())));
        }
        Packet::SKESK(ref skesk) => {
            fields.push(field("Version", format!("{}", skesk.version())));
        }
        Packet::SEIP(ref seip) => {
            fields.push(field("Version", format!("{}", seip.version())));
        }
        Packet::Marker(_) => {
            fields.push(field("Type", "Marker (PGP 2.x)".to_string()));
        }
        Packet::Trust(_) => {
            fields.push(field("Type", "Trust".to_string()));
        }
        Packet::Unknown(ref unk) => {
            fields.push(field("Raw tag", format!("{}", unk.tag())));
        }
        _ => {}
    }

    fields
}

fn extract_key_fields<P, R>(key: &Key<P, R>, fields: &mut Vec<FieldView>)
where
    P: key::KeyParts,
    R: key::KeyRole,
{
    fields.push(field("Algorithm", format!("{}", key.pk_algo())));
    fields.push(field(
        "Key size",
        format!("{} bits", key.mpis().bits().unwrap_or(0)),
    ));
    fields.push(field("Fingerprint", key.fingerprint().to_hex()));
    fields.push(field("Key ID", format!("{}", key.keyid())));
    fields.push(field(
        "Creation time",
        format!(
            "{}",
            chrono::DateTime::<chrono::Utc>::from(key.creation_time())
                .format("%Y-%m-%d %H:%M:%S UTC")
        ),
    ));
}

fn extract_signature_fields(sig: &Signature, fields: &mut Vec<FieldView>) {
    fields.push(field("Signature type", format!("{}", sig.typ())));
    fields.push(field("Hash algorithm", format!("{}", sig.hash_algo())));
    fields.push(field("PK algorithm", format!("{}", sig.pk_algo())));
    if let Some(ct) = sig.signature_creation_time() {
        fields.push(field(
            "Creation time",
            format!(
                "{}",
                chrono::DateTime::<chrono::Utc>::from(ct).format("%Y-%m-%d %H:%M:%S UTC")
            ),
        ));
    }
    for issuer in sig.get_issuers() {
        fields.push(field("Issuer", format!("{issuer}")));
    }
}

fn field(name: &str, value: String) -> FieldView {
    FieldView {
        name: name.to_string(),
        value,
        range: None,
    }
}
