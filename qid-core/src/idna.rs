use crate::error::{QidError, QidResult};

pub fn validate_idn_domain(domain: &str) -> QidResult<String> {
    match idna::domain_to_ascii(domain) {
        Ok(result) => Ok(result),
        Err(errors) => Err(QidError::BadRequest {
            message: format!("IDNA validation failed for domain: {domain}: {errors:?}"),
        }),
    }
}

pub fn validate_idn_email(email: &str) -> QidResult<String> {
    let at = email.find('@').ok_or_else(|| QidError::BadRequest {
        message: "email must contain @".to_string(),
    })?;
    let local = &email[..at];
    let domain = &email[at + 1..];
    let validated_domain = validate_idn_domain(domain)?;
    Ok(format!("{local}@{validated_domain}"))
}

pub fn validate_precis_username(username: &str) -> QidResult<String> {
    if username.is_empty() || username.len() > 64 {
        return Err(QidError::BadRequest {
            message: "username must be 1-64 characters".to_string(),
        });
    }
    let normalized: String = username.chars().flat_map(|c| c.to_lowercase()).collect();
    Ok(normalized)
}

pub fn validate_precis_password(password: &str) -> QidResult<String> {
    if password.len() < 8 {
        return Err(QidError::BadRequest {
            message: "password must be at least 8 characters".to_string(),
        });
    }
    Ok(password.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_domain() {
        assert!(validate_idn_domain("example.com").is_ok());
    }

    #[test]
    fn valid_email() {
        assert!(validate_idn_email("user@example.com").is_ok());
    }

    #[test]
    fn invalid_email_missing_at() {
        assert!(validate_idn_email("notanemail").is_err());
    }

    #[test]
    fn valid_username() {
        assert_eq!(validate_precis_username("Alice").unwrap(), "alice");
    }

    #[test]
    fn empty_username_fails() {
        assert!(validate_precis_username("").is_err());
    }

    #[test]
    fn password_min_length() {
        assert!(validate_precis_password("short").is_err());
        assert!(validate_precis_password("longenough123!").is_ok());
    }
}
