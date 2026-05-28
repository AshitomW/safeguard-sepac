//! Obfuscation detection analyser.
//!
//! Scans package source files for obfuscation patterns: high-entropy blobs,
//! base64-encoded payloads, eval() usage, and hex-encoded strings.

use std::fs;
use std::path::Path;

use crate::traits::Analyser;
use crate::types::{PackageArchive, Result, Signal};

/// Analyses package source files for obfuscation patterns.
///
/// # Detected signals
/// - `BinaryBlobInSource`: High-entropy binary files in the source tree.
/// - `ObfuscatedCode`: Code patterns indicating obfuscation (eval, hex, base64).
///
/// # Design
/// - Single responsibility: obfuscation detection only.
/// - Implements `Analyser` so it can be composed/chained.
/// - CPU-bound, synchronous — designed for rayon thread pool.
#[derive(Debug, Default)]
pub struct ObfuscationAnalyser {
    /// Minimum entropy threshold for binary blob detection (0.0–8.0).
    entropy_threshold: f64,
    /// Minimum file size to consider for binary blob detection.
    min_blob_size: usize,
}

impl ObfuscationAnalyser {
    /// Creates a new obfuscation analyser with default thresholds.
    pub fn new() -> Self {
        Self {
            entropy_threshold: 6.0,
            min_blob_size: 256,
        }
    }

    /// Creates an analyser with custom thresholds.
    pub fn with_thresholds(entropy_threshold: f64, min_blob_size: usize) -> Self {
        Self {
            entropy_threshold,
            min_blob_size,
        }
    }

    /// Calculates Shannon entropy of a byte slice.
    ///
    /// Returns a value in `[0.0, 8.0]` for byte data.
    /// Higher values indicate more random / compressed / encrypted data.
    fn shannon_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u64; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        counts
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }

    /// Scans a single file for obfuscation patterns.
    fn scan_file(&self, path: &Path, relative_path: &Path) -> Vec<Signal> {
        let mut signals = Vec::new();

        let data = match fs::read(path) {
            Ok(d) => d,
            Err(_) => return signals,
        };

        // Binary blob detection via entropy
        if data.len() >= self.min_blob_size {
            let entropy = Self::shannon_entropy(&data);
            if entropy >= self.entropy_threshold {
                signals.push(Signal::BinaryBlobInSource {
                    file: relative_path.to_path_buf(),
                    entropy,
                    size_bytes: data.len(),
                });
            }
        }

        // Text-based obfuscation patterns (only for text files)
        if let Ok(content) = std::str::from_utf8(&data) {
            signals.extend(self.scan_text_patterns(content, relative_path));
        }

        signals
    }

    /// Scans text content for obfuscation patterns.
    fn scan_text_patterns(&self, content: &str, path: &Path) -> Vec<Signal> {
        let mut signals = Vec::new();

        // Detect eval() usage
        if content.contains("eval(") {
            signals.push(Signal::ObfuscatedCode {
                file: path.to_path_buf(),
                pattern: "eval() usage detected".into(),
                confidence: 0.7,
            });
        }

        // Detect large base64 blocks (64+ chars of base64 alphabet)
        let base64_pattern_len = content
            .as_bytes()
            .windows(64)
            .filter(|window| {
                window
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
            })
            .count();

        if base64_pattern_len > 10 {
            signals.push(Signal::ObfuscatedCode {
                file: path.to_path_buf(),
                pattern: "large base64-encoded block detected".into(),
                confidence: 0.6,
            });
        }

        // Detect hex-encoded strings (\x41\x42...)
        let hex_escape_count = content.matches("\\x").count();
        if hex_escape_count > 20 {
            signals.push(Signal::ObfuscatedCode {
                file: path.to_path_buf(),
                pattern: format!("excessive hex escapes ({hex_escape_count} occurrences)"),
                confidence: 0.8,
            });
        }

        signals
    }
}

impl Analyser for ObfuscationAnalyser {
    fn analyse(&self, pkg: &PackageArchive) -> Result<Vec<Signal>> {
        let mut signals = Vec::new();
        let base_path = &pkg.extracted_path;

        if !base_path.exists() {
            return Ok(signals);
        }

        // Walk the extracted package directory
        let walker = walkdir(base_path);
        for entry in walker {
            let relative = entry.strip_prefix(base_path).unwrap_or(&entry);
            signals.extend(self.scan_file(&entry, relative));
        }

        Ok(signals)
    }
}

/// Simple recursive directory walker (avoids adding walkdir crate for this).
fn walkdir(path: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    if path.is_file() {
        files.push(path.to_path_buf());
    } else if path.is_dir()
        && let Ok(entries) = fs::read_dir(path)
    {
        for entry in entries.flatten() {
            files.extend(walkdir(&entry.path()));
        }
    }
    files
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_of_zeros_is_zero() {
        let data = vec![0u8; 1000];
        let entropy = ObfuscationAnalyser::shannon_entropy(&data);
        assert!((entropy - 0.0).abs() < 0.001);
    }

    #[test]
    fn entropy_of_uniform_distribution_is_eight() {
        // Perfectly uniform byte distribution
        let data: Vec<u8> = (0..=255).cycle().take(256 * 100).collect();
        let entropy = ObfuscationAnalyser::shannon_entropy(&data);
        assert!((entropy - 8.0).abs() < 0.01);
    }

    #[test]
    fn entropy_of_text_is_moderate() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let entropy = ObfuscationAnalyser::shannon_entropy(data);
        // English text typically has entropy around 3.5–4.5
        assert!(entropy > 3.0);
        assert!(entropy < 5.0);
    }

    #[test]
    fn empty_data_entropy_is_zero() {
        assert!((ObfuscationAnalyser::shannon_entropy(&[]) - 0.0).abs() < 0.001);
    }

    #[test]
    fn eval_detected() {
        let analyser = ObfuscationAnalyser::new();
        let path = Path::new("exploit.js");
        let signals = analyser.scan_text_patterns("var x = eval('malicious()')", path);
        assert!(signals.iter().any(|s| matches!(
            s,
            Signal::ObfuscatedCode { pattern, .. } if pattern.contains("eval")
        )));
    }

    #[test]
    fn hex_escapes_detected() {
        let analyser = ObfuscationAnalyser::new();
        let path = Path::new("payload.js");
        // 25 hex escapes — above threshold of 20
        let content = "\\x41".repeat(25);
        let signals = analyser.scan_text_patterns(&content, path);
        assert!(signals.iter().any(|s| matches!(
            s,
            Signal::ObfuscatedCode { pattern, .. } if pattern.contains("hex")
        )));
    }

    #[test]
    fn clean_text_no_signals() {
        let analyser = ObfuscationAnalyser::new();
        let path = Path::new("index.js");
        let signals = analyser.scan_text_patterns("console.log('hello world');", path);
        assert!(signals.is_empty());
    }
}
