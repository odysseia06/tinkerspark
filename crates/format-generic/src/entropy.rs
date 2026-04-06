use tinkerspark_core_types::ByteRange;

/// Classification of entropy level for a block of data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyClass {
    /// Mostly zeros or repetitive data (entropy < 1.0).
    VeryLow,
    /// Structured data like text, code, headers (entropy 1.0–4.0).
    Low,
    /// Mixed or moderately structured data (entropy 4.0–6.5).
    Medium,
    /// Compressed or encrypted data (entropy 6.5–7.9).
    High,
    /// Near-random data (entropy >= 7.9).
    VeryHigh,
}

impl EntropyClass {
    pub fn label(&self) -> &'static str {
        match self {
            Self::VeryLow => "very low (repetitive/padding)",
            Self::Low => "low (structured)",
            Self::Medium => "medium (mixed)",
            Self::High => "high (compressed/encrypted)",
            Self::VeryHigh => "very high (near-random)",
        }
    }

    fn from_entropy(e: f64) -> Self {
        if e < 1.0 {
            Self::VeryLow
        } else if e < 4.0 {
            Self::Low
        } else if e < 6.5 {
            Self::Medium
        } else if e < 7.9 {
            Self::High
        } else {
            Self::VeryHigh
        }
    }
}

/// A region of data with computed entropy.
#[derive(Debug, Clone)]
pub struct EntropyRegion {
    pub offset: u64,
    pub length: u64,
    pub entropy: f64,
    pub class: EntropyClass,
}

impl EntropyRegion {
    pub fn range(&self) -> ByteRange {
        ByteRange::new(self.offset, self.length)
    }
}

/// Compute Shannon entropy of a byte slice (0.0–8.0 scale).
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Default block size for entropy analysis.
const DEFAULT_BLOCK_SIZE: usize = 256;

/// Analyze data in blocks and return entropy regions.
///
/// Adjacent blocks with the same entropy class are merged into a single region.
pub fn analyze_entropy(data: &[u8], base_offset: u64) -> Vec<EntropyRegion> {
    analyze_entropy_with_block_size(data, base_offset, DEFAULT_BLOCK_SIZE)
}

/// Analyze with a custom block size (useful for testing or tuning).
pub fn analyze_entropy_with_block_size(
    data: &[u8],
    base_offset: u64,
    block_size: usize,
) -> Vec<EntropyRegion> {
    if data.is_empty() {
        return Vec::new();
    }

    let block_size = block_size.max(16); // floor at 16 bytes

    // Compute per-block entropy.
    let mut blocks: Vec<(u64, u64, f64, EntropyClass)> = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let end = (pos + block_size).min(data.len());
        let block = &data[pos..end];
        let e = shannon_entropy(block);
        let class = EntropyClass::from_entropy(e);
        blocks.push((base_offset + pos as u64, (end - pos) as u64, e, class));
        pos = end;
    }

    // Merge adjacent blocks with the same class.
    let mut regions: Vec<EntropyRegion> = Vec::new();
    for (offset, length, entropy, class) in blocks {
        if let Some(last) = regions.last_mut() {
            if last.class == class {
                let merged_end = offset + length;
                let merged_len = merged_end - last.offset;
                // Weighted average entropy.
                let w1 = last.length as f64;
                let w2 = length as f64;
                last.entropy = (last.entropy * w1 + entropy * w2) / (w1 + w2);
                last.length = merged_len;
                continue;
            }
        }
        regions.push(EntropyRegion {
            offset,
            length,
            entropy,
            class,
        });
    }

    regions
}

/// Compute overall file entropy.
pub fn overall_entropy(data: &[u8]) -> f64 {
    shannon_entropy(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_entropy_for_uniform_data() {
        let data = vec![0xAA; 256];
        let e = shannon_entropy(&data);
        assert!(e < 0.01, "entropy of uniform data should be ~0, got {e}");
    }

    #[test]
    fn max_entropy_for_uniform_distribution() {
        // All 256 byte values equally distributed.
        let data: Vec<u8> = (0..=255).collect();
        let e = shannon_entropy(&data);
        assert!(
            (e - 8.0).abs() < 0.01,
            "entropy of uniform distribution should be ~8.0, got {e}"
        );
    }

    #[test]
    fn text_has_medium_entropy() {
        let data = b"The quick brown fox jumps over the lazy dog. 1234567890!";
        let e = shannon_entropy(data);
        assert!(
            e > 3.0 && e < 6.0,
            "text entropy should be moderate, got {e}"
        );
    }

    #[test]
    fn analyze_merges_adjacent_same_class() {
        // Uniform data → all blocks should merge into one VeryLow region.
        let data = vec![0x00; 1024];
        let regions = analyze_entropy(&data, 0);
        assert_eq!(regions.len(), 1);
        assert_eq!(regions[0].class, EntropyClass::VeryLow);
        assert_eq!(regions[0].length, 1024);
    }

    #[test]
    fn analyze_separates_different_classes() {
        let mut data = vec![0x00; 512]; // low entropy
        data.extend((0..=255).cycle().take(512)); // high entropy
        let regions = analyze_entropy(&data, 0);
        assert!(regions.len() >= 2, "should have at least 2 regions");
        assert_eq!(regions[0].class, EntropyClass::VeryLow);
    }

    #[test]
    fn empty_data() {
        let regions = analyze_entropy(&[], 0);
        assert!(regions.is_empty());
    }
}
