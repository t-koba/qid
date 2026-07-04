//! LDAP Data Interchange Format (RFC 2849).

use crate::error::QidResult;
use base64::Engine;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdifRecord {
    pub dn: String,
    pub attributes: BTreeMap<String, Vec<String>>,
    pub changetype: Option<String>,
}

pub fn parse_ldif(input: &str) -> QidResult<Vec<LdifRecord>> {
    let mut records = Vec::new();
    let mut current_dn = String::new();
    let mut current_attrs: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut current_changetype: Option<String> = None;
    let mut in_record = false;
    let mut last_attr: Option<String> = None;

    for line in input.lines() {
        if line.starts_with('#') || line.is_empty() {
            if in_record && !current_dn.is_empty() {
                flush_record(
                    &mut records,
                    &mut current_dn,
                    &mut current_attrs,
                    &mut current_changetype,
                    &mut in_record,
                );
            }
            last_attr = None;
            continue;
        }

        if (line.starts_with(' ') || line.starts_with('\t')) && last_attr.is_some() {
            if let Some(attr) = &last_attr
                && let Some(values) = current_attrs.get_mut(attr)
                && let Some(last_val) = values.last_mut()
            {
                last_val.push_str(line.trim());
            }
            continue;
        }

        if line.starts_with("dn:") || line.starts_with("dn ") {
            if in_record && !current_dn.is_empty() {
                flush_record(
                    &mut records,
                    &mut current_dn,
                    &mut current_attrs,
                    &mut current_changetype,
                    &mut in_record,
                );
            }
            current_dn = line[3..].trim().to_string();
            in_record = true;
            last_attr = None;
            continue;
        }

        if let Some(eq) = line.find(':') {
            let attr = line[..eq].trim().to_lowercase();
            if attr == "changetype" {
                current_changetype = Some(line[eq + 1..].trim().to_string());
                last_attr = None;
            } else {
                let sep = &line[eq..];
                let val = if sep.starts_with("::") {
                    let b64 = line[eq + 2..].trim();
                    let decoded = base64::engine::general_purpose::STANDARD
                        .decode(b64)
                        .unwrap_or_else(|_| b64.as_bytes().to_vec());
                    String::from_utf8_lossy(&decoded).to_string()
                } else if sep.starts_with(":") {
                    line[eq + 1..].trim().to_string()
                } else {
                    String::new()
                };
                current_attrs.entry(attr.clone()).or_default().push(val);
                last_attr = Some(attr);
            }
        }
    }

    if in_record && !current_dn.is_empty() {
        records.push(LdifRecord {
            dn: std::mem::take(&mut current_dn),
            attributes: std::mem::take(&mut current_attrs),
            changetype: current_changetype.take(),
        });
    }

    Ok(records)
}

fn flush_record(
    records: &mut Vec<LdifRecord>,
    dn: &mut String,
    attrs: &mut BTreeMap<String, Vec<String>>,
    changetype: &mut Option<String>,
    in_record: &mut bool,
) {
    if !dn.is_empty() {
        records.push(LdifRecord {
            dn: std::mem::take(dn),
            attributes: std::mem::take(attrs),
            changetype: changetype.take(),
        });
    }
    *in_record = false;
}

pub fn serialize_ldif(records: &[LdifRecord]) -> String {
    let mut out = String::new();
    for record in records {
        out.push_str(&format!("dn: {}\n", record.dn));
        if let Some(ref ct) = record.changetype {
            out.push_str(&format!("changetype: {ct}\n"));
        }
        for (attr, values) in &record.attributes {
            for value in values {
                if value.contains('\n') || value.contains('\0') || !value.is_ascii() {
                    let b64 = base64::engine::general_purpose::STANDARD.encode(value);
                    out.push_str(&format!("{attr}:: {b64}\n"));
                } else {
                    out.push_str(&format!("{attr}: {value}\n"));
                }
            }
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ldif_single_entry() {
        let input = "dn: cn=Alice,dc=example,dc=com\ncn: Alice\nsn: Doe\nmail: alice@example.com\n";
        let records = parse_ldif(input).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].dn, "cn=Alice,dc=example,dc=com");
        assert_eq!(
            records[0].attributes.get("mail").unwrap()[0],
            "alice@example.com"
        );
    }

    #[test]
    fn parse_ldif_multiple_entries() {
        let input =
            "dn: cn=Alice,dc=example,dc=com\ncn: Alice\n\ndn: cn=Bob,dc=example,dc=com\ncn: Bob\n";
        let records = parse_ldif(input).unwrap();
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn ldif_round_trip() {
        let records = vec![LdifRecord {
            dn: "cn=Test,dc=example,dc=com".to_string(),
            attributes: BTreeMap::from([
                ("cn".to_string(), vec!["Test".to_string()]),
                (
                    "objectClass".to_string(),
                    vec!["person".to_string(), "top".to_string()],
                ),
            ]),
            changetype: None,
        }];
        let ldif = serialize_ldif(&records);
        let parsed = parse_ldif(&ldif).unwrap();
        assert_eq!(parsed[0].dn, "cn=Test,dc=example,dc=com");
        assert_eq!(parsed[0].attributes.get("cn").unwrap()[0], "Test");
    }

    #[test]
    fn parse_ldif_base64_value() {
        let input = "dn: cn=test\njpegPhoto:: /9j/4AAQSkZJRg==\n";
        let records = parse_ldif(input).unwrap();
        assert!(records[0].attributes.contains_key("jpegphoto"));
    }
}
