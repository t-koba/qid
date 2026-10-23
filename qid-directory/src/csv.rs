//! CSV HR source: the historical workforce export parsed into [`HrRecord`].
//!
//! The configured CSV keeps the historical HR columns `external_id`, `email`,
//! `display_name`, `department`, `manager_external_id` and `event`
//! (joiner/mover/leaver, case-insensitive header). An optional `username`
//! column is compatible: when present and non-blank it names the user,
//! otherwise `external_id` stays the username as before. Quoted fields follow
//! RFC 4180: commas inside quotes are data and `""` is an escaped quote.
//!
//! The whole file is validated before any record is returned, so the worker
//! never writes a prefix of a rejected batch; lifecycle, duplicate-ID
//! preflight and mover-clear semantics stay owned by [`crate::import_hr_records`].

use tokio::io::AsyncReadExt;

use qid_core::{
    config::MAX_DIRECTORY_SEARCH_ENTRIES,
    error::{QidError, QidResult},
};

use crate::types::{HrRecord, LifecycleEvent};

/// The most bytes a CSV HR source may hold, so one sync cannot allocate an
/// unbounded file into memory.
pub const MAX_CSV_HR_FILE_BYTES: usize = qid_core::config::MAX_HR_REQUEST_BYTES;

/// Read and parse the CSV HR source at `path`, bounding the source size and
/// the record count (`max_entries` is the configured ceiling, the default
/// search ceiling applies when it is unset).
pub async fn read_csv_hr_records(path: &str, max_entries: Option<u32>) -> QidResult<Vec<HrRecord>> {
    let read_error = |e| QidError::Internal {
        message: format!("failed to read CSV file {path}: {e}"),
    };
    let file = tokio::fs::File::open(path).await.map_err(read_error)?;
    let mut bytes = Vec::new();
    file.take((MAX_CSV_HR_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .map_err(read_error)?;
    check_csv_size(bytes.len())?;
    let content = std::str::from_utf8(&bytes).map_err(|e| QidError::BadRequest {
        message: format!("CSV file {path} is not valid UTF-8: {e}"),
    })?;
    let ceiling = max_entries.unwrap_or(MAX_DIRECTORY_SEARCH_ENTRIES) as usize;
    parse_csv_hr_records_with_limit(content, ceiling)
}

/// Parse CSV HR content with the default record ceiling.
pub fn parse_csv_hr_records(content: &str) -> QidResult<Vec<HrRecord>> {
    parse_csv_hr_records_with_limit(content, MAX_DIRECTORY_SEARCH_ENTRIES as usize)
}

fn check_csv_size(bytes: usize) -> QidResult<()> {
    if bytes > MAX_CSV_HR_FILE_BYTES {
        return Err(QidError::BadRequest {
            message: format!("CSV source holds more than {MAX_CSV_HR_FILE_BYTES} bytes"),
        });
    }
    Ok(())
}

fn parse_csv_hr_records_with_limit(content: &str, max_records: usize) -> QidResult<Vec<HrRecord>> {
    check_csv_size(content.len())?;
    if content.contains('\0') {
        return Err(QidError::BadRequest {
            message: "CSV content contains a NUL byte".to_string(),
        });
    }
    let mut header = None;
    let mut records = Vec::new();
    let mut lineno = 0;
    split_csv_rows(content.strip_prefix('\u{FEFF}').unwrap_or(content), |row| {
        lineno += 1;
        let Some((columns, width)) = &header else {
            header = Some((hr_columns(&row)?, row.len()));
            return Ok(());
        };
        if row.iter().all(|field| field.trim().is_empty()) {
            return Ok(());
        }
        if row.len() != *width {
            return Err(QidError::BadRequest {
                message: format!(
                    "CSV line {lineno} has {} columns, expected {width}",
                    row.len()
                ),
            });
        }
        let record = hr_record(&row, columns, lineno)?;
        if records.len() == max_records {
            return Err(QidError::BadRequest {
                message: format!("CSV file holds more than {max_records} records"),
            });
        }
        records.push(record);
        Ok(())
    })?;
    if header.is_none() {
        return Err(QidError::BadRequest {
            message: "CSV file is empty".to_string(),
        });
    }
    Ok(records)
}

/// A header column index set: the six historical columns plus the optional
/// compatible `username` column.
struct HrColumns {
    external_id: usize,
    email: usize,
    display_name: usize,
    department: usize,
    manager_external_id: usize,
    event: usize,
    username: Option<usize>,
}

fn hr_columns(header: &[String]) -> QidResult<HrColumns> {
    let mut seen = std::collections::HashSet::new();
    for name in header {
        if !seen.insert(name.trim().to_lowercase()) {
            return Err(QidError::BadRequest {
                message: format!("CSV header repeats column '{}'", name.trim()),
            });
        }
    }
    let find = |name: &str| {
        header
            .iter()
            .position(|h| h.trim().eq_ignore_ascii_case(name))
            .ok_or_else(|| QidError::BadRequest {
                message: format!("CSV missing required column '{name}'"),
            })
    };
    Ok(HrColumns {
        external_id: find("external_id")?,
        email: find("email")?,
        display_name: find("display_name")?,
        department: find("department")?,
        manager_external_id: find("manager_external_id")?,
        event: find("event")?,
        username: header
            .iter()
            .position(|h| h.trim().eq_ignore_ascii_case("username")),
    })
}

fn hr_record(row: &[String], columns: &HrColumns, lineno: usize) -> QidResult<HrRecord> {
    let external_id = row[columns.external_id].trim();
    if external_id.is_empty() {
        return Err(QidError::BadRequest {
            message: format!("CSV line {lineno} has empty external_id"),
        });
    }
    let event = match row[columns.event].trim().to_lowercase().as_str() {
        "joiner" => LifecycleEvent::Joiner,
        "mover" => LifecycleEvent::Mover,
        "leaver" => LifecycleEvent::Leaver,
        other => {
            return Err(QidError::BadRequest {
                message: format!(
                    "CSV line {lineno} has invalid event '{other}' (expected joiner/mover/leaver)"
                ),
            });
        }
    };
    let user_name = columns.username.map(|idx| row[idx].trim()).map_or_else(
        || external_id.to_string(),
        |name| {
            if name.is_empty() {
                external_id.to_string()
            } else {
                name.to_string()
            }
        },
    );
    Ok(HrRecord {
        external_id: external_id.to_string(),
        user_name,
        email: optional_field(&row[columns.email]),
        display_name: optional_field(&row[columns.display_name]),
        department: optional_field(&row[columns.department]),
        manager_external_id: optional_field(&row[columns.manager_external_id]),
        event,
    })
}

/// A directory attribute value: trimmed, and absent when it is empty.
fn optional_field(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

/// Read one row at a time, stopping as soon as the consumer rejects a row.
/// Quotes may only open at field start; after closing, only a delimiter or EOF
/// is legal. Quoted commas, escaped quotes and embedded line breaks are data.
fn split_csv_rows(
    content: &str,
    mut consume: impl FnMut(Vec<String>) -> QidResult<()>,
) -> QidResult<()> {
    #[derive(PartialEq)]
    enum FieldState {
        Start,
        Unquoted,
        Quoted,
        Closed,
    }
    use FieldState::*;
    let mut row = Vec::new();
    let mut field = String::new();
    let mut state = Start;
    let mut chars = content.chars().peekable();
    while let Some(ch) = chars.next() {
        if state == Quoted {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    field.push('"');
                    chars.next();
                } else {
                    state = Closed;
                }
            } else {
                field.push(ch);
            }
            continue;
        }
        match ch {
            '"' if state == Start => state = Quoted,
            ',' => {
                row.push(std::mem::take(&mut field));
                state = Start;
            }
            '\r' | '\n' => {
                if ch == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                }
                row.push(std::mem::take(&mut field));
                consume(std::mem::take(&mut row))?;
                state = Start;
            }
            _ if ch == '"' || state == Closed => {
                return Err(QidError::BadRequest {
                    message: "CSV has a malformed quoted field".to_string(),
                });
            }
            _ => {
                field.push(ch);
                state = Unquoted;
            }
        }
    }
    if state == Quoted {
        return Err(QidError::BadRequest {
            message: "CSV has an unterminated quoted field".to_string(),
        });
    }
    if state != Start || !row.is_empty() {
        row.push(field);
        consume(row)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "csv_tests.rs"]
mod tests;
