use super::sqlite_deprovisioned_at;

#[test]
fn sqlite_deprovisioned_timestamp_rejects_overflow_without_wrapping() {
    assert_eq!(sqlite_deprovisioned_at(None).unwrap(), None);
    assert_eq!(sqlite_deprovisioned_at(Some(1_050)).unwrap(), Some(1_050));
    assert!(sqlite_deprovisioned_at(Some(u64::MAX)).is_err());
}
