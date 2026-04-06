use crate::entropy::EntropyRegion;
use crate::magic::DetectedSignature;
use crate::strings::StringRegion;
use crate::tlv::TlvChain;

/// Combined confidence assessment from all heuristic passes.
#[derive(Debug, Clone)]
pub struct ConfidenceReport {
    /// Overall confidence score (0.0–1.0).
    pub score: f64,
    /// Human-readable summary of findings.
    pub summary: String,
    /// Individual evidence items.
    pub evidence: Vec<Evidence>,
}

/// A single piece of evidence contributing to the confidence score.
#[derive(Debug, Clone)]
pub struct Evidence {
    pub source: &'static str,
    pub weight: f64,
    pub description: String,
}

/// Merge evidence from all heuristic passes into a confidence report.
pub fn compute_confidence(
    file_size: u64,
    signatures: &[DetectedSignature],
    strings: &[StringRegion],
    entropy_regions: &[EntropyRegion],
    tlv_chains: &[TlvChain],
) -> ConfidenceReport {
    let mut evidence = Vec::new();
    let mut total_weight = 0.0;
    let mut weighted_sum = 0.0;

    // ── Magic signatures ──
    if !signatures.is_empty() {
        let sig_names: Vec<&str> = signatures.iter().map(|s| s.name).collect();
        let w = 0.3;
        let score = 0.8; // known signature is strong evidence
        evidence.push(Evidence {
            source: "magic",
            weight: w,
            description: format!("Detected signatures: {}", sig_names.join(", ")),
        });
        total_weight += w;
        weighted_sum += w * score;
    }

    // ── String content ──
    if !strings.is_empty() {
        let string_bytes: u64 = strings.iter().map(|s| s.length).sum();
        let string_ratio = string_bytes as f64 / file_size.max(1) as f64;
        let w = 0.15;
        let score = (string_ratio * 2.0).min(1.0); // more strings = more structure
        evidence.push(Evidence {
            source: "strings",
            weight: w,
            description: format!(
                "{} strings found ({:.1}% of file)",
                strings.len(),
                string_ratio * 100.0
            ),
        });
        total_weight += w;
        weighted_sum += w * score;
    }

    // ── Entropy analysis ──
    if !entropy_regions.is_empty() {
        let has_mixed = entropy_regions.len() > 1;
        let w = 0.2;
        let score = if has_mixed { 0.6 } else { 0.3 };
        let classes: Vec<&str> = entropy_regions.iter().map(|r| r.class.label()).collect();
        let unique: Vec<&&str> = {
            let mut v: Vec<&&str> = classes.iter().collect();
            v.dedup();
            v
        };
        evidence.push(Evidence {
            source: "entropy",
            weight: w,
            description: format!(
                "{} entropy regions, {} distinct classes",
                entropy_regions.len(),
                unique.len()
            ),
        });
        total_weight += w;
        weighted_sum += w * score;
    }

    // ── TLV chains ──
    if !tlv_chains.is_empty() {
        let best = &tlv_chains[0];
        let w = 0.35;
        let score = best.confidence;
        evidence.push(Evidence {
            source: "tlv",
            weight: w,
            description: format!(
                "TLV chain: {} elements ({} encoding, {:.0}% coverage)",
                best.elements.len(),
                best.encoding.label(),
                (best.length as f64 / file_size.max(1) as f64) * 100.0
            ),
        });
        total_weight += w;
        weighted_sum += w * score;
    }

    let overall = if total_weight > 0.0 {
        weighted_sum / total_weight
    } else {
        0.0
    };

    let summary = if overall > 0.7 {
        "High confidence: strong structural signals detected".into()
    } else if overall > 0.4 {
        "Moderate confidence: some structural patterns found".into()
    } else if overall > 0.1 {
        "Low confidence: weak structural signals".into()
    } else {
        "Minimal structure detected".into()
    };

    ConfidenceReport {
        score: overall,
        summary,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::EntropyClass;

    #[test]
    fn empty_input_gives_zero_confidence() {
        let report = compute_confidence(100, &[], &[], &[], &[]);
        assert_eq!(report.score, 0.0);
    }

    #[test]
    fn signature_boosts_confidence() {
        let sigs = vec![DetectedSignature {
            name: "PNG",
            offset: 0,
            length: 8,
        }];
        let report = compute_confidence(1000, &sigs, &[], &[], &[]);
        assert!(report.score > 0.0);
    }

    #[test]
    fn mixed_evidence_merges() {
        let sigs = vec![DetectedSignature {
            name: "ZIP",
            offset: 0,
            length: 4,
        }];
        let strings = vec![StringRegion {
            offset: 100,
            length: 20,
            content: "test string data".into(),
        }];
        let entropy = vec![EntropyRegion {
            offset: 0,
            length: 500,
            entropy: 3.5,
            class: EntropyClass::Low,
        }];
        let report = compute_confidence(500, &sigs, &strings, &entropy, &[]);
        assert!(report.score > 0.2);
        assert!(report.evidence.len() >= 3);
    }
}
