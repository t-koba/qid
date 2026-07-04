#![no_main]

use libfuzzer_sys::fuzz_target;

fn parse_eq_filter_value(value: &str) -> Result<(), ()> {
    if let Some(inner) = value.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        if !inner.is_empty() {
            return Ok(());
        }
    }
    match value {
        "true" | "false" => Ok(()),
        _ => Err(()),
    }
}

fn parse_eq_filter(input: &str) -> Result<(), ()> {
    let trimmed = input.trim();
    let (attribute, value) = trimmed.split_once(" eq ").ok_or(())?;
    if attribute.trim().is_empty() {
        return Err(());
    }
    parse_eq_filter_value(value.trim())
}

fuzz_target!(|data: &[u8]| {
    if let Ok(input) = std::str::from_utf8(data) {
        let _ = parse_eq_filter(input);
    }
});
