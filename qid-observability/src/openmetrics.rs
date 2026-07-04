//! OpenMetrics 1.0 exposition format.

pub fn metrics_to_openmetrics(metrics: &[MetricFamily]) -> String {
    let mut out = String::new();
    for family in metrics {
        out.push_str(&format!("# HELP {} {}\n", family.name, family.help));
        out.push_str(&format!(
            "# TYPE {} {}\n",
            family.name,
            family.r#type.as_str()
        ));
        for sample in &family.samples {
            let labels: String = sample
                .labels
                .iter()
                .map(|(k, v)| format!("{k}=\"{v}\""))
                .collect::<Vec<_>>()
                .join(",");
            if labels.is_empty() {
                out.push_str(&format!(
                    "{} {} {}\n",
                    family.name, sample.value, sample.timestamp
                ));
            } else {
                out.push_str(&format!(
                    "{}{{{}}} {} {}\n",
                    family.name, labels, sample.value, sample.timestamp
                ));
            }
        }
    }
    out.push_str("# EOF\n");
    out
}

#[derive(Debug, Clone)]
pub struct MetricFamily {
    pub name: String,
    pub help: String,
    pub r#type: MetricType,
    pub samples: Vec<MetricSample>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricType {
    Counter,
    Gauge,
    Histogram,
    Summary,
}

impl MetricType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
            Self::Summary => "summary",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MetricSample {
    pub value: f64,
    pub timestamp: u64,
    pub labels: Vec<(String, String)>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openmetrics_counter_output() {
        let metrics = vec![MetricFamily {
            name: "http_requests_total".to_string(),
            help: "Total HTTP requests".to_string(),
            r#type: MetricType::Counter,
            samples: vec![MetricSample {
                value: 42.0,
                timestamp: 1700000000,
                labels: vec![("method".to_string(), "GET".to_string())],
            }],
        }];
        let output = metrics_to_openmetrics(&metrics);
        assert!(output.contains("http_requests_total"));
        assert!(output.contains("42"));
        assert!(output.contains("method=\"GET\""));
        assert!(output.contains("# EOF"));
    }
}
