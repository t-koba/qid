use super::*;

const HEADER: &str = "external_id,email,display_name,department,manager_external_id,event\n";

#[test]
fn csv_hr_rejects_malformed_quotes() {
    for field in ["un\"quoted", "\"closed\"text", "\"closed\" ", " \"quoted\""] {
        let content = format!("{HEADER}hr-1,,{field},,,joiner\n");
        let err = parse_csv_hr_records(&content).expect_err("strict quoting");
        assert!(matches!(err, QidError::BadRequest { .. }));
        assert!(err.message().contains("malformed quoted field"));
    }
}

#[test]
fn csv_hr_keeps_quoted_line_breaks_and_accepts_closed_fields_at_eof() {
    let content = format!(
        "{}hr-1,,\"One\r\nTwo\nThree\",,,\"joiner\"\r\nhr-2,,,,,\"leaver\"",
        HEADER.replace('\n', "\r\n")
    );
    let records = parse_csv_hr_records(&content).expect("quoted CRLF and LF are data");
    assert_eq!(records.len(), 2);
    assert_eq!(
        records[0].display_name.as_deref(),
        Some("One\r\nTwo\nThree")
    );
    assert!(matches!(records[1].event, LifecycleEvent::Leaver));
}

#[test]
fn csv_hr_stops_at_the_record_ceiling_without_parsing_the_tail() {
    let one = format!("{HEADER}\nhr-1,,,,,joiner\n   \n");
    assert_eq!(parse_csv_hr_records_with_limit(&one, 1).unwrap().len(), 1);
    assert!(
        parse_csv_hr_records_with_limit(HEADER, 0)
            .unwrap()
            .is_empty()
    );
    for ending in ["", "\n", "\n\"unterminated"] {
        let content = format!("{one}hr-2,,,,,mover{ending}");
        let err = parse_csv_hr_records_with_limit(&content, 1).expect_err("record ceiling");
        assert!(matches!(err, QidError::BadRequest { .. }));
        assert!(err.message().contains("more than 1 records"));
    }
}

#[test]
fn csv_hr_public_parser_enforces_the_byte_ceiling() {
    let mut content = HEADER.to_string();
    content.push_str(&" ".repeat(MAX_CSV_HR_FILE_BYTES - content.len()));
    assert!(parse_csv_hr_records(&content).unwrap().is_empty());
    content.push(' ');
    let err = parse_csv_hr_records(&content).expect_err("one byte too many");
    assert!(matches!(err, QidError::BadRequest { .. }));
    assert!(err.message().contains("bytes"));
    let multibyte = "é".repeat(MAX_CSV_HR_FILE_BYTES / 2 + 1);
    assert!(
        parse_csv_hr_records(&multibyte)
            .unwrap_err()
            .message()
            .contains("bytes")
    );
}

#[tokio::test]
async fn csv_hr_file_reads_are_bounded_and_reject_invalid_utf8() {
    let path = std::env::temp_dir().join(format!("qid-csv-bounds-{}", ulid::Ulid::new()));
    let path_str = path.to_str().unwrap();
    // A sparse oversized file needs no large allocation by this test or the reader.
    let file = std::fs::File::create(&path).unwrap();
    file.set_len((2 * MAX_CSV_HR_FILE_BYTES) as u64).unwrap();
    drop(file);
    let err = read_csv_hr_records(path_str, None)
        .await
        .expect_err("bounded read");
    assert!(matches!(err, QidError::BadRequest { .. }));
    assert!(err.message().contains("bytes"));
    let mut content = HEADER.to_string();
    content.push_str(&" ".repeat(MAX_CSV_HR_FILE_BYTES - content.len()));
    std::fs::write(&path, &content).unwrap();
    assert!(
        read_csv_hr_records(path_str, None)
            .await
            .unwrap()
            .is_empty()
    );
    content.push(' ');
    std::fs::write(&path, &content).unwrap();
    let err = read_csv_hr_records(path_str, None)
        .await
        .expect_err("one byte too many");
    assert!(matches!(err, QidError::BadRequest { .. }));
    assert!(err.message().contains("bytes"));
    std::fs::write(&path, [0xff]).unwrap();
    let err = read_csv_hr_records(path_str, None)
        .await
        .expect_err("invalid UTF-8");
    assert!(matches!(err, QidError::BadRequest { .. }));
    assert!(err.message().contains("UTF-8"));
    std::fs::write(&path, format!("{HEADER}hr-1,,,,,joiner\nhr-2,,,,,mover")).unwrap();
    let err = read_csv_hr_records(path_str, Some(1))
        .await
        .expect_err("configured ceiling");
    assert!(err.message().contains("more than 1 records"));
    assert_eq!(
        read_csv_hr_records(path_str, Some(2)).await.unwrap().len(),
        2
    );
    std::fs::remove_file(&path).unwrap();
    assert!(matches!(
        read_csv_hr_records(path_str, None).await,
        Err(QidError::Internal { .. })
    ));
}
