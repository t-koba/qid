//! Email authentication: SPF (RFC 7208), DMARC (RFC 7489), MTA-STS (RFC 8461), TLSRPT (RFC 8460).

use crate::error::{QidError, QidResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpfRecord {
    pub version: String,
    pub mechanisms: Vec<SpfMechanism>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SpfMechanism {
    pub qualifier: SpfQualifier,
    pub kind: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SpfQualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

pub fn parse_spf_record(txt: &str) -> QidResult<SpfRecord> {
    let trimmed = txt.trim();
    if !trimmed.starts_with("v=spf1") {
        return Err(QidError::BadRequest {
            message: "invalid SPF version".to_string(),
        });
    }
    let rest = trimmed.trim_start_matches("v=spf1").trim();
    let mut mechanisms = Vec::new();
    for token in rest.split_whitespace() {
        let (qualifier, kind_value) = if let Some(rest) = token.strip_prefix('+') {
            (SpfQualifier::Pass, rest)
        } else if let Some(rest) = token.strip_prefix('-') {
            (SpfQualifier::Fail, rest)
        } else if let Some(rest) = token.strip_prefix('~') {
            (SpfQualifier::SoftFail, rest)
        } else if let Some(rest) = token.strip_prefix('?') {
            (SpfQualifier::Neutral, rest)
        } else {
            (SpfQualifier::Pass, token)
        };
        let parts: Vec<&str> = kind_value.splitn(2, ':').collect();
        let kind = parts[0].to_string();
        let value = parts.get(1).unwrap_or(&"").to_string();
        mechanisms.push(SpfMechanism {
            qualifier,
            kind,
            value,
        });
    }
    Ok(SpfRecord {
        version: "spf1".to_string(),
        mechanisms,
    })
}

pub fn evaluate_spf(record: &SpfRecord, sender_ip: &str, _sender_domain: &str) -> SpfQualifier {
    for mech in &record.mechanisms {
        match mech.kind.as_str() {
            "all" => return mech.qualifier,
            "ip4" | "ip6"
                if mech.value.contains(sender_ip)
                    || mech
                        .value
                        .starts_with(&sender_ip[..sender_ip.len().min(mech.value.len())]) =>
            {
                return mech.qualifier;
            }
            _ => {}
        }
    }
    SpfQualifier::Neutral
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DmarcRecord {
    pub version: String,
    pub policy: DmarcPolicy,
    pub subdomain_policy: Option<DmarcPolicy>,
    pub report_uri: Option<String>,
    pub aggregate_uri: Option<String>,
    pub percentage: Option<u32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum DmarcPolicy {
    None,
    Quarantine,
    Reject,
}

pub fn parse_dmarc_record(txt: &str) -> QidResult<DmarcRecord> {
    let trimmed = txt.trim();
    if !trimmed.starts_with("v=DMARC1") {
        return Err(QidError::BadRequest {
            message: "invalid DMARC version".to_string(),
        });
    }
    let mut record = DmarcRecord {
        version: "DMARC1".to_string(),
        policy: DmarcPolicy::None,
        subdomain_policy: None,
        report_uri: None,
        aggregate_uri: None,
        percentage: None,
    };
    for part in trimmed.split(';') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let key = part[..eq].trim();
            let value = part[eq + 1..].trim();
            match key {
                "p" => {
                    record.policy = match value {
                        "quarantine" => DmarcPolicy::Quarantine,
                        "reject" => DmarcPolicy::Reject,
                        _ => DmarcPolicy::None,
                    }
                }
                "sp" => {
                    record.subdomain_policy = match value {
                        "quarantine" => Some(DmarcPolicy::Quarantine),
                        "reject" => Some(DmarcPolicy::Reject),
                        _ => Some(DmarcPolicy::None),
                    }
                }
                "rua" => record.aggregate_uri = Some(value.to_string()),
                "ruf" => record.report_uri = Some(value.to_string()),
                "pct" => record.percentage = value.parse().ok(),
                _ => {}
            }
        }
    }
    Ok(record)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MtaStsPolicy {
    pub version: String,
    pub mode: MtaStsMode,
    pub mx: Vec<String>,
    pub max_age: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MtaStsMode {
    Enforce,
    Testing,
    None,
}

pub fn parse_mta_sts_policy(txt: &str) -> QidResult<MtaStsPolicy> {
    let mut policy = MtaStsPolicy {
        version: String::new(),
        mode: MtaStsMode::None,
        mx: Vec::new(),
        max_age: 86400,
    };
    for line in txt.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(eq) = line.find(':') {
            let key = line[..eq].trim();
            let value = line[eq + 1..].trim();
            match key {
                "version" => policy.version = value.to_string(),
                "mode" => {
                    policy.mode = match value {
                        "enforce" => MtaStsMode::Enforce,
                        "testing" => MtaStsMode::Testing,
                        _ => MtaStsMode::None,
                    }
                }
                "mx" => {
                    for mx in value.split(',') {
                        policy.mx.push(mx.trim().to_string());
                    }
                }
                "max_age" => policy.max_age = value.parse().unwrap_or(86400),
                _ => {}
            }
        }
    }
    Ok(policy)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TlsRptRecord {
    pub version: String,
    pub rua: Vec<String>,
    pub max_age: u64,
}

pub fn parse_tlsrpt_record(txt: &str) -> QidResult<TlsRptRecord> {
    let mut record = TlsRptRecord {
        version: String::new(),
        rua: Vec::new(),
        max_age: 86400,
    };
    for part in txt.split(';') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let key = part[..eq].trim();
            let value = part[eq + 1..].trim();
            match key {
                "v" => record.version = value.to_string(),
                "rua" => {
                    for uri in value.split(',') {
                        record.rua.push(uri.trim().trim_matches('!').to_string());
                    }
                }
                "rua!" => record.rua.push(value.to_string()),
                "max_age" => record.max_age = value.parse().unwrap_or(86400),
                _ => {}
            }
        }
    }
    Ok(record)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArcSeal {
    pub version: u16,
    pub headers: Vec<String>,
    pub signature: String,
}

pub fn parse_arc_seal(value: &str) -> Result<ArcSeal, String> {
    let mut seal = ArcSeal {
        version: 1,
        headers: vec![],
        signature: String::new(),
    };
    for part in value.split(';') {
        let part = part.trim();
        if let Some(eq) = part.find('=') {
            let key = part[..eq].trim();
            let val = part[eq + 1..].trim();
            match key {
                "i" => seal.version = val.parse().unwrap_or(1),
                "h" => seal.headers = val.split(':').map(|s| s.trim().to_string()).collect(),
                "b" => seal.signature = val.to_string(),
                _ => {}
            }
        }
    }
    Ok(seal)
}

pub fn normalize_email_eai(email: &str) -> Result<String, String> {
    let at = email.find('@').ok_or("email must contain @")?;
    let local = &email[..at];
    let domain = &email[at + 1..];
    Ok(format!("{local}@{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_spf_basic() {
        let record = parse_spf_record("v=spf1 ip4:192.0.2.0/24 -all").unwrap();
        assert_eq!(record.version, "spf1");
        assert_eq!(record.mechanisms.len(), 2);
        assert_eq!(record.mechanisms[1].qualifier, SpfQualifier::Fail);
    }

    #[test]
    fn parse_spf_invalid_version() {
        assert!(parse_spf_record("v=spf2").is_err());
    }

    #[test]
    fn evaluate_spf_all_fail() {
        let record = parse_spf_record("v=spf1 -all").unwrap();
        assert_eq!(
            evaluate_spf(&record, "1.2.3.4", "example.com"),
            SpfQualifier::Fail
        );
    }

    #[test]
    fn parse_dmarc_reject() {
        let record =
            parse_dmarc_record("v=DMARC1; p=reject; rua=mailto:dmarc@example.com").unwrap();
        assert_eq!(record.policy, DmarcPolicy::Reject);
        assert_eq!(
            record.aggregate_uri,
            Some("mailto:dmarc@example.com".to_string())
        );
    }

    #[test]
    fn parse_dmarc_quarantine() {
        let record = parse_dmarc_record("v=DMARC1; p=quarantine; sp=reject; pct=50").unwrap();
        assert_eq!(record.policy, DmarcPolicy::Quarantine);
        assert_eq!(record.subdomain_policy, Some(DmarcPolicy::Reject));
        assert_eq!(record.percentage, Some(50));
    }

    #[test]
    fn parse_mta_sts_enforce() {
        let policy = parse_mta_sts_policy(
            "version: STSv1\nmode: enforce\nmx: mx1.example.com\nmax_age: 86400",
        )
        .unwrap();
        assert_eq!(policy.mode, MtaStsMode::Enforce);
        assert_eq!(policy.mx, vec!["mx1.example.com"]);
    }

    #[test]
    fn parse_tlsrpt_basic() {
        let record =
            parse_tlsrpt_record("v=TLSRPTv1; rua=mailto:tlsrpt@example.com; max_age=86400")
                .unwrap();
        assert!(
            record
                .rua
                .contains(&"mailto:tlsrpt@example.com".to_string())
        );
        assert_eq!(record.max_age, 86400);
    }

    #[test]
    fn parse_arc_seal_basic() {
        let seal = parse_arc_seal("i=1; h=from:to:subject:date; b=abcdef").unwrap();
        assert_eq!(seal.version, 1);
        assert_eq!(seal.headers, vec!["from", "to", "subject", "date"]);
        assert_eq!(seal.signature, "abcdef");
    }

    #[test]
    fn eai_normalization() {
        let result = normalize_email_eai("user@example.com").unwrap();
        assert_eq!(result, "user@example.com");
    }
}
