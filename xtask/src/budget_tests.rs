use super::*;

/// The product source stays inside the budget the workspace metadata sets.
/// The check belongs to the test suite so the cap is part of the accepted
/// verification and not only of a separate command.
#[test]
fn the_product_source_stays_within_the_budget() {
    let metadata = cargo_metadata().expect("the workspace metadata is readable");
    let config = BudgetConfig::from_metadata(&metadata).expect("the budget config is valid");
    let packages = packages_in_workspace_from_metadata(&metadata)
        .expect("the workspace packages are readable");
    let mut total = 0usize;
    for (name, manifest_path) in &packages {
        let dir = manifest_path.parent().expect("a manifest has a parent");
        let counts = count_rs_lines(dir, name).expect("the crate sources are readable");
        assert!(
            counts.product <= config.crate_limit(name),
            "{name} has {} product source lines, over its limit {}",
            counts.product,
            config.crate_limit(name)
        );
        total += counts.product;
    }
    assert!(
        total <= config.total,
        "the product source has {total} lines, over the limit {}",
        config.total
    );
}
