use xikomap::core::target::TargetResolver;

#[test]
fn test_target_resolver_cidr() {
    let resolver = TargetResolver::new(&["192.168.1.0/30".to_string()], &[]).unwrap();
    let targets = resolver.resolve(false);
    assert_eq!(targets.len(), 4);
}

#[test]
fn test_target_resolver_exclusion() {
    let resolver = TargetResolver::new(&["192.168.1.0/30".to_string()], &["192.168.1.1/32".to_string()]).unwrap();
    let targets = resolver.resolve(false);
    assert_eq!(targets.len(), 3);
    assert!(!targets.iter().any(|ip| ip.to_string() == "192.168.1.1"));
}

#[test]
fn test_target_resolver_range() {
    let resolver = TargetResolver::new(&["192.168.1.1-3".to_string()], &[]).unwrap();
    let targets = resolver.resolve(false);
    assert_eq!(targets.len(), 3);
}