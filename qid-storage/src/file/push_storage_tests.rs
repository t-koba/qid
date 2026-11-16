use super::select_oldest;

#[test]
fn cleanup_selection_is_bounded_and_deterministic() {
    let candidates = [(3, "c"), (1, "b"), (1, "a"), (2, "d")];
    for limit in 1..=4 {
        let expected: Vec<_> = ["a", "b", "d", "c"][..limit].to_vec();
        assert_eq!(select_oldest(candidates.into_iter(), limit), expected);
        assert_eq!(select_oldest(candidates.into_iter().rev(), limit), expected);
    }
}
