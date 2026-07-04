//! RFC 8470 0-RTT gating.

pub enum ZeroRttPolicy {
    Allow,
    RejectWith425,
    RejectEarly,
}

pub fn zero_rtt_response(policy: ZeroRttPolicy) -> u16 {
    match policy {
        ZeroRttPolicy::RejectWith425 => 425,
        ZeroRttPolicy::RejectEarly => 400,
        ZeroRttPolicy::Allow => 200,
    }
}

pub fn zero_rtt_early_data_header() -> &'static str {
    "Early-Data: 1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_returns_425() {
        assert_eq!(zero_rtt_response(ZeroRttPolicy::RejectWith425), 425);
    }
}
