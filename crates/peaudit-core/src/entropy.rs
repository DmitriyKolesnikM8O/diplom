//! Shannon entropy and sliding-window profiles.
//!
//! Entropy is a structural signal, not a verdict: packed or encrypted data has
//! high entropy, but so do legitimate compressed resources. Rules interpret the
//! numbers; this module only measures them.
//!
//! The sliding window is incremental: adding and removing one byte updates the
//! `Σ c·log₂c` term in constant time, so a full pass over a 10 MiB file costs
//! one log₂ per byte rather than 256.

/// Entropy value, in bits per byte, above which a region is usually considered
/// packed or encrypted.
///
/// Used as a default threshold for [`EntropyProfile::compute`]; rules may pass
/// their own.
pub const HIGH_ENTROPY_THRESHOLD: f64 = 7.0;

/// Shannon entropy of `data`, in bits per byte.
///
/// Returns `0.0` for an empty input and for a buffer of identical bytes.
/// The maximum, `8.0`, is reached when all 256 byte values occur equally often.
#[must_use]
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u64; 256];
    for &byte in data {
        if let Some(slot) = counts.get_mut(usize::from(byte)) {
            *slot = slot.saturating_add(1);
        }
    }

    entropy_from_counts(&counts, data.len())
}

/// Entropy summary of one buffer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EntropyProfile {
    /// Entropy of the whole buffer, in bits per byte.
    pub overall: f64,
    /// Highest entropy observed in any window; `0.0` if no window was evaluated.
    pub max_window: f64,
    /// Offset of the first window with [`EntropyProfile::max_window`].
    pub max_window_offset: usize,
    /// Number of windows whose entropy is at or above the threshold.
    pub windows_above_threshold: usize,
    /// Number of windows evaluated.
    pub windows: usize,
    /// Window size used for the profile; `0` means windows were disabled.
    pub window_size: usize,
}

impl EntropyProfile {
    /// Computes the overall entropy and a sliding-window profile.
    ///
    /// Windows are evaluated only when `window_size` is non-zero and does not
    /// exceed the input length. A window is counted as high-entropy when its
    /// value is greater than or equal to `threshold`.
    #[must_use]
    pub fn compute(data: &[u8], window_size: usize, threshold: f64) -> Self {
        let overall = shannon_entropy(data);

        if window_size == 0 || data.len() < window_size {
            return Self {
                overall,
                max_window: 0.0,
                max_window_offset: 0,
                windows_above_threshold: 0,
                windows: 0,
                window_size,
            };
        }

        let windows = data.len() - window_size + 1;
        let mut state = WindowState::new(window_size);

        if let Some(first) = data.get(..window_size) {
            for &byte in first {
                state.add(byte);
            }
        }

        let mut max_window = state.entropy();
        let mut max_window_offset = 0;
        let mut windows_above_threshold = usize::from(max_window >= threshold);

        for offset in 1..windows {
            let outgoing = data.get(offset.saturating_sub(1));
            let incoming = data.get(offset.saturating_add(window_size).saturating_sub(1));
            let (Some(&outgoing), Some(&incoming)) = (outgoing, incoming) else {
                continue;
            };

            state.remove(outgoing);
            state.add(incoming);

            let entropy = state.entropy();
            if entropy > max_window {
                max_window = entropy;
                max_window_offset = offset;
            }
            if entropy >= threshold {
                windows_above_threshold = windows_above_threshold.saturating_add(1);
            }
        }

        Self {
            overall,
            max_window,
            max_window_offset,
            windows_above_threshold,
            windows,
            window_size,
        }
    }

    /// Returns `true` if the overall entropy is at or above
    /// [`HIGH_ENTROPY_THRESHOLD`].
    #[must_use]
    pub fn is_high_entropy(&self) -> bool {
        self.overall >= HIGH_ENTROPY_THRESHOLD
    }
}

/// `c·log₂c`, with `0·log₂0` defined as `0`.
fn count_log_count(count: u64) -> f64 {
    if count == 0 {
        return 0.0;
    }
    let count = count as f64;
    count * count.log2()
}

fn entropy_from_counts(counts: &[u64; 256], len: usize) -> f64 {
    let len_f = len as f64;
    let sum: f64 = counts.iter().map(|&count| count_log_count(count)).sum();
    (len_f.log2() - sum / len_f).clamp(0.0, 8.0)
}

/// Mutable state of one sliding window.
///
/// `log2` dominates the cost of a window step, so for reasonable window sizes
/// the values of `c·log₂c` and `log₂n` are precomputed into lookup tables.
/// Larger windows fall back to computing logarithms directly instead of
/// allocating an oversized table.
struct WindowState {
    counts: [u64; 256],
    sum: f64,
    len: usize,
    log_counts: Option<Vec<f64>>,
    log_lengths: Option<Vec<f64>>,
}

/// Windows up to this size use lookup tables; the table costs 16 bytes per
/// entry and larger windows are rare in practice.
const MAX_LOG_TABLE_SIZE: usize = 1 << 16;

impl WindowState {
    fn new(window_size: usize) -> Self {
        let (log_counts, log_lengths) = if window_size <= MAX_LOG_TABLE_SIZE {
            let counts = (0..=window_size)
                .map(|count| count_log_count(count as u64))
                .collect();
            let lengths = (0..=window_size)
                .map(|len| if len == 0 { 0.0 } else { (len as f64).log2() })
                .collect();
            (Some(counts), Some(lengths))
        } else {
            (None, None)
        };

        Self {
            counts: [0u64; 256],
            sum: 0.0,
            len: 0,
            log_counts,
            log_lengths,
        }
    }

    fn count(&self, byte: u8) -> u64 {
        self.counts
            .get(usize::from(byte))
            .copied()
            .unwrap_or_default()
    }

    fn count_log(&self, count: u64) -> f64 {
        match self
            .log_counts
            .as_ref()
            .and_then(|table| table.get(count as usize))
        {
            Some(&value) => value,
            None => count_log_count(count),
        }
    }

    fn length_log(&self, len: usize) -> f64 {
        match self.log_lengths.as_ref().and_then(|table| table.get(len)) {
            Some(&value) => value,
            None if len == 0 => 0.0,
            None => (len as f64).log2(),
        }
    }

    fn add(&mut self, byte: u8) {
        let count = self.count(byte);
        self.sum += self.count_log(count.saturating_add(1)) - self.count_log(count);
        if let Some(slot) = self.counts.get_mut(usize::from(byte)) {
            *slot = slot.saturating_add(1);
        }
        self.len = self.len.saturating_add(1);
    }

    fn remove(&mut self, byte: u8) {
        let count = self.count(byte);
        let remaining = count.saturating_sub(1);
        self.sum += self.count_log(remaining) - self.count_log(count);
        if let Some(slot) = self.counts.get_mut(usize::from(byte)) {
            *slot = remaining;
        }
        self.len = self.len.saturating_sub(1);
    }

    fn entropy(&self) -> f64 {
        if self.len == 0 {
            return 0.0;
        }
        let len = self.len as f64;
        (self.length_log(self.len) - self.sum / len).clamp(0.0, 8.0)
    }
}

#[cfg(test)]
mod tests {
    use super::{EntropyProfile, WindowState, shannon_entropy};

    const EPSILON: f64 = 1e-9;

    fn assert_close(actual: f64, expected: f64) {
        assert!(
            (actual - expected).abs() < EPSILON,
            "expected {expected}, got {actual}"
        );
    }

    #[test]
    fn empty_input_has_zero_entropy() {
        assert_close(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn identical_bytes_have_zero_entropy() {
        assert_close(shannon_entropy(&[0u8; 1024]), 0.0);
        assert_close(shannon_entropy(&[0xAAu8; 512]), 0.0);
    }

    #[test]
    fn uniform_bytes_have_maximum_entropy() {
        let data: Vec<u8> = (0..=255u8).collect();
        assert_close(shannon_entropy(&data), 8.0);
    }

    #[test]
    fn two_equally_likely_symbols_have_one_bit() {
        let mut data = vec![0u8; 500];
        data.extend(vec![1u8; 500]);
        assert_close(shannon_entropy(&data), 1.0);
    }

    #[test]
    fn four_equally_likely_symbols_have_two_bits() {
        let mut data = Vec::new();
        for value in 0..4u8 {
            data.extend(vec![value; 250]);
        }
        assert_close(shannon_entropy(&data), 2.0);
    }

    #[test]
    fn single_byte_has_zero_entropy() {
        assert_close(shannon_entropy(&[42]), 0.0);
    }

    #[test]
    fn profile_of_uniform_data_reaches_eight() {
        let data: Vec<u8> = (0..=255u8).collect();
        let profile = EntropyProfile::compute(&data, 256, 7.0);
        assert_eq!(profile.windows, 1);
        assert_close(profile.overall, 8.0);
        assert_close(profile.max_window, 8.0);
        assert_eq!(profile.max_window_offset, 0);
        assert_eq!(profile.windows_above_threshold, 1);
    }

    #[test]
    fn profile_finds_the_highest_window() {
        let data = [0u8, 0, 0, 0, 1, 2, 3, 4];
        // Windows of four: [0,0,0,0] = 0, [0,0,0,1] ≈ 0.81, [0,0,1,2] = 1.5,
        // [0,1,2,3] = 2.0 and [1,2,3,4] = 2.0. The first maximum is reported.
        let profile = EntropyProfile::compute(&data, 4, 1.9);
        assert_eq!(profile.windows, 5);
        assert_eq!(profile.window_size, 4);
        assert_eq!(profile.max_window_offset, 3);
        assert_close(profile.max_window, 2.0);
        assert_eq!(profile.windows_above_threshold, 2);
    }

    #[test]
    fn profile_counts_every_window_above_zero_threshold() {
        let data = [0u8; 10];
        let profile = EntropyProfile::compute(&data, 4, 0.0);
        assert_eq!(profile.windows, 7);
        assert_eq!(profile.windows_above_threshold, 7);
        assert_close(profile.max_window, 0.0);
        assert_eq!(profile.max_window_offset, 0);
    }

    #[test]
    fn profile_of_short_input_has_no_windows() {
        let data = [1u8, 2, 3];
        let profile = EntropyProfile::compute(&data, 16, 7.0);
        assert_eq!(profile.windows, 0);
        assert_eq!(profile.window_size, 16);
        assert_close(profile.max_window, 0.0);
        assert_eq!(profile.windows_above_threshold, 0);
        assert!(profile.overall > 0.0);
    }

    #[test]
    fn zero_window_disables_windows() {
        let data = [1u8, 2, 3, 4];
        let profile = EntropyProfile::compute(&data, 0, 7.0);
        assert_eq!(profile.windows, 0);
        assert_eq!(profile.window_size, 0);
        assert_close(profile.max_window, 0.0);
        assert!(profile.overall > 0.0);
    }

    #[test]
    fn high_entropy_flag_uses_default_threshold() {
        let uniform: Vec<u8> = (0..=255u8).collect();
        assert!(EntropyProfile::compute(&uniform, 64, 7.0).is_high_entropy());
        assert!(!EntropyProfile::compute(&[0u8; 256], 64, 7.0).is_high_entropy());
    }

    /// Deterministic xorshift64* generator, as in `bytes.rs`: property tests
    /// stay repeatable and the core crate stays dependency-free.
    fn next_random(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    #[test]
    fn arbitrary_inputs_stay_within_bounds() {
        let mut state = 0xDEAD_BEEF_CAFE_F00D_u64;
        for _ in 0..2_000 {
            let len = (next_random(&mut state) % 512) as usize;
            let mut data = vec![0u8; len];
            for byte in &mut data {
                *byte = (next_random(&mut state) & 0xFF) as u8;
            }
            let window = (next_random(&mut state) % 64) as usize;
            let profile = EntropyProfile::compute(&data, window, 7.0);

            assert!((0.0..=8.0).contains(&profile.overall));
            assert!((0.0..=8.0).contains(&profile.max_window));
            assert!(profile.windows_above_threshold <= profile.windows);
            if profile.windows > 0 {
                assert!(profile.max_window_offset + window <= data.len());
            }
            let expected_windows = if window == 0 || len < window {
                0
            } else {
                len - window + 1
            };
            assert_eq!(profile.windows, expected_windows);
        }
    }

    #[test]
    fn incremental_window_matches_direct_entropy() {
        let mut state = 0x0BAD_F00D_1234_5678_u64;
        for _ in 0..64 {
            let len = 64 + (next_random(&mut state) % 960) as usize;
            let window = 8 + (next_random(&mut state) % 120) as usize;
            if window > len {
                continue;
            }

            let mut data = vec![0u8; len];
            for byte in &mut data {
                *byte = (next_random(&mut state) & 0xFF) as u8;
            }

            let mut window_state = WindowState::new(window);
            if let Some(initial) = data.get(..window) {
                for &byte in initial {
                    window_state.add(byte);
                }
            }

            for offset in 0..=(len - window) {
                let Some(slice) = data.get(offset..offset + window) else {
                    continue;
                };
                let direct = shannon_entropy(slice);
                let incremental = window_state.entropy();
                assert!(
                    (incremental - direct).abs() < 1e-6,
                    "offset {offset}: incremental {incremental} vs direct {direct}"
                );

                if offset + window < len {
                    if let (Some(outgoing), Some(incoming)) =
                        (data.get(offset), data.get(offset + window))
                    {
                        window_state.remove(*outgoing);
                        window_state.add(*incoming);
                    }
                }
            }
        }
    }

    #[test]
    fn profile_maximum_matches_direct_maximum() {
        let mut state = 0xFEED_FACE_CAFE_BEEF_u64;
        for _ in 0..32 {
            let len = 32 + (next_random(&mut state) % 256) as usize;
            let window = 4 + (next_random(&mut state) % 32) as usize;
            if window > len {
                continue;
            }

            let mut data = vec![0u8; len];
            for byte in &mut data {
                *byte = (next_random(&mut state) & 0xFF) as u8;
            }

            let profile = EntropyProfile::compute(&data, window, 7.0);
            let mut expected_max = 0.0_f64;
            for offset in 0..=(len - window) {
                let Some(slice) = data.get(offset..offset + window) else {
                    continue;
                };
                let direct = shannon_entropy(slice);
                if direct > expected_max {
                    expected_max = direct;
                }
            }

            assert!(
                (profile.max_window - expected_max).abs() < 1e-9,
                "profile {} vs direct {expected_max}",
                profile.max_window
            );
        }
    }

    #[test]
    #[ignore = "manual benchmark: cargo test -p peaudit-core --release bench_entropy_10mb -- --ignored --nocapture"]
    fn bench_entropy_10mb() {
        const SIZE: usize = 10 * 1024 * 1024;
        let mut state = 0x1234_5678_9ABC_DEF0_u64;
        let mut data = vec![0u8; SIZE];
        for byte in &mut data {
            *byte = (next_random(&mut state) & 0xFF) as u8;
        }

        let started = std::time::Instant::now();
        let profile = EntropyProfile::compute(&data, 4096, 7.0);
        let elapsed = started.elapsed();

        let millis = elapsed.as_secs_f64() * 1000.0;
        let throughput = (SIZE as f64 / (1024.0 * 1024.0)) / elapsed.as_secs_f64();
        println!(
            "entropy 10 MiB: {millis:.1} ms, {throughput:.1} MiB/s, overall {:.4}, windows {}",
            profile.overall, profile.windows
        );
        assert!(profile.overall > 0.0);
    }
}
