//! Bounds-checked, zero-copy reading over a borrowed byte slice.
//!
//! [`Reader`] is the only way the parser touches input bytes. Every read is
//! checked: a truncated or hostile file produces a [`ParseError`], never a
//! panic. On failure the cursor is left unchanged, so a caller can record a
//! diagnostic and continue with another strategy (partial parsing, ADR-0003).

use core::fmt;

use crate::error::ParseError;

/// A cursor over a borrowed byte slice.
///
/// The reader never copies or owns input data: [`Reader::take`] returns a
/// sub-slice of the original buffer, valid for the lifetime of the input.
///
/// ```
/// use peaudit_core::Reader;
///
/// let mut reader = Reader::new(b"PE\0\0");
/// assert_eq!(reader.read_u16().unwrap(), 0x4550);
/// assert_eq!(reader.read_u16().unwrap(), 0);
/// assert!(reader.is_exhausted());
/// ```
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the payload: it may be megabytes of hostile input.
        f.debug_struct("Reader")
            .field("len", &self.data.len())
            .field("offset", &self.offset)
            .finish()
    }
}

impl<'a> Reader<'a> {
    /// Creates a reader positioned at the start of `data`.
    #[must_use]
    pub const fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Returns the total length of the underlying buffer.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the underlying buffer is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Returns the current cursor position.
    #[must_use]
    pub const fn offset(&self) -> usize {
        self.offset
    }

    /// Returns the number of bytes left after the cursor.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.offset)
    }

    /// Returns `true` if the cursor is at the end of the buffer.
    #[must_use]
    pub const fn is_exhausted(&self) -> bool {
        self.offset == self.data.len()
    }

    /// Moves the cursor to an absolute position.
    ///
    /// Seeking to `len` is allowed and leaves the reader exhausted.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::OutOfBounds`](crate::ErrorKind::OutOfBounds) if
    /// `position` is past the end of the buffer.
    pub fn seek(&mut self, position: usize) -> Result<(), ParseError> {
        if position > self.data.len() {
            return Err(ParseError::out_of_bounds(position, "seek"));
        }
        self.offset = position;
        Ok(())
    }

    /// Advances the cursor by `count` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if `count` would move the cursor past the end of the
    /// buffer or if the addition overflows.
    pub fn skip(&mut self, count: usize) -> Result<(), ParseError> {
        let end = self.checked_end(count)?;
        if end > self.data.len() {
            return Err(ParseError::unexpected_eof(self.offset, "skip"));
        }
        self.offset = end;
        Ok(())
    }

    /// Returns the next `count` bytes and advances the cursor.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `count` bytes remain or if the addition
    /// overflows.
    pub fn take(&mut self, count: usize) -> Result<&'a [u8], ParseError> {
        self.take_with_context(count, "bytes")
    }

    /// Reads a fixed-size array and advances the cursor.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `N` bytes remain.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N], ParseError> {
        self.read_array_with_context("byte array")
    }

    /// Reads one unsigned byte.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is exhausted.
    pub fn read_u8(&mut self) -> Result<u8, ParseError> {
        self.read_array_with_context::<1>("u8")
            .map(u8::from_le_bytes)
    }

    /// Reads a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 2 bytes remain.
    pub fn read_u16(&mut self) -> Result<u16, ParseError> {
        self.read_array_with_context::<2>("u16")
            .map(u16::from_le_bytes)
    }

    /// Reads a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 4 bytes remain.
    pub fn read_u32(&mut self) -> Result<u32, ParseError> {
        self.read_array_with_context::<4>("u32")
            .map(u32::from_le_bytes)
    }

    /// Reads a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 8 bytes remain.
    pub fn read_u64(&mut self) -> Result<u64, ParseError> {
        self.read_array_with_context::<8>("u64")
            .map(u64::from_le_bytes)
    }

    /// Peeks at one unsigned byte without advancing the cursor.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is exhausted.
    pub fn peek_u8(&self) -> Result<u8, ParseError> {
        self.peek_array::<1>("u8").map(u8::from_le_bytes)
    }

    /// Peeks at a little-endian `u16` without advancing the cursor.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 2 bytes remain.
    pub fn peek_u16(&self) -> Result<u16, ParseError> {
        self.peek_array::<2>("u16").map(u16::from_le_bytes)
    }

    /// Peeks at a little-endian `u32` without advancing the cursor.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 4 bytes remain.
    pub fn peek_u32(&self) -> Result<u32, ParseError> {
        self.peek_array::<4>("u32").map(u32::from_le_bytes)
    }

    /// Compares the bytes at the cursor with `expected` without advancing.
    ///
    /// This is how signatures such as `MZ` and `PE\0\0` are checked: the cursor
    /// stays in place, so a failed check does not consume input.
    ///
    /// # Errors
    ///
    /// Returns `UnexpectedEof` if fewer than `expected.len()` bytes remain, or
    /// `InvalidValue` if the bytes differ.
    pub fn check_bytes(&self, expected: &[u8], context: &'static str) -> Result<(), ParseError> {
        let end = self
            .offset
            .checked_add(expected.len())
            .ok_or_else(|| ParseError::overflow(self.offset, context))?;
        let actual = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| ParseError::unexpected_eof(self.offset, context))?;
        if actual != expected {
            return Err(ParseError::invalid_value(self.offset, context));
        }
        Ok(())
    }

    /// Returns an absolute range of the input without moving the cursor.
    ///
    /// # Errors
    ///
    /// Returns `OutOfBounds` if `offset + len` exceeds the buffer, or
    /// `ArithmeticOverflow` if the sum overflows.
    pub fn slice(&self, offset: usize, len: usize) -> Result<&'a [u8], ParseError> {
        let end = offset
            .checked_add(len)
            .ok_or_else(|| ParseError::overflow(offset, "slice"))?;
        self.data
            .get(offset..end)
            .ok_or_else(|| ParseError::out_of_bounds(offset, "slice"))
    }

    /// Creates an independent reader over an absolute range of the input.
    ///
    /// Offsets inside the returned reader are relative to the start of the
    /// range, so a caller that needs absolute offsets must add the range start.
    /// This applies to errors too: a [`ParseError`] obtained from the
    /// sub-reader reports a relative offset. The parsers in [`crate::pe`] avoid
    /// the problem by bounding the whole structure with `sub_reader` first and
    /// then reading fields that are known to be present.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Reader::slice`].
    pub fn sub_reader(&self, offset: usize, len: usize) -> Result<Self, ParseError> {
        let bytes = self.slice(offset, len)?;
        Ok(Self::new(bytes))
    }

    /// Reads a NUL-terminated string without the terminator.
    ///
    /// The returned slice borrows the input; it is not validated as UTF-8.
    /// `max_len` bounds the string content, so a missing terminator cannot turn
    /// into an unbounded search: at most `max_len` bytes before the terminator
    /// are accepted.
    ///
    /// On success the cursor is placed right after the terminator. On failure
    /// the cursor does not move.
    ///
    /// # Errors
    ///
    /// - [`ErrorKind::LimitExceeded`](crate::ErrorKind::LimitExceeded) if no
    ///   terminator was found within `max_len` bytes;
    /// - [`ErrorKind::UnexpectedEof`](crate::ErrorKind::UnexpectedEof) if the
    ///   input ended before a terminator was found.
    pub fn read_cstr(&mut self, max_len: usize) -> Result<&'a [u8], ParseError> {
        let available = self.remaining();
        // One extra byte is scanned to see the terminator that follows a string
        // of exactly `max_len` bytes.
        let budget = max_len.saturating_add(1);
        let scan = budget.min(available);
        let end = self
            .offset
            .checked_add(scan)
            .ok_or_else(|| ParseError::overflow(self.offset, "cstring"))?;
        let window = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| ParseError::unexpected_eof(self.offset, "cstring"))?;

        let Some(index) = window.iter().position(|&byte| byte == 0) else {
            return if scan == budget {
                Err(ParseError::limit_exceeded(self.offset, "cstring"))
            } else {
                Err(ParseError::unexpected_eof(self.offset, "cstring"))
            };
        };

        let start = self.offset;
        let terminator = start
            .checked_add(index)
            .ok_or_else(|| ParseError::overflow(start, "cstring"))?;
        let string = window
            .get(..index)
            .ok_or_else(|| ParseError::out_of_bounds(start, "cstring"))?;
        self.offset = terminator
            .checked_add(1)
            .ok_or_else(|| ParseError::overflow(start, "cstring"))?;
        Ok(string)
    }

    /// Computes `offset + count`, reporting overflow instead of wrapping.
    fn checked_end(&self, count: usize) -> Result<usize, ParseError> {
        self.offset
            .checked_add(count)
            .ok_or_else(|| ParseError::overflow(self.offset, "offset"))
    }

    fn take_with_context(
        &mut self,
        count: usize,
        context: &'static str,
    ) -> Result<&'a [u8], ParseError> {
        let end = self.checked_end(count)?;
        let slice = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| ParseError::unexpected_eof(self.offset, context))?;
        self.offset = end;
        Ok(slice)
    }

    fn read_array_with_context<const N: usize>(
        &mut self,
        context: &'static str,
    ) -> Result<[u8; N], ParseError> {
        let array = self.peek_array::<N>(context)?;
        self.offset = self
            .offset
            .checked_add(N)
            .ok_or_else(|| ParseError::overflow(self.offset, context))?;
        Ok(array)
    }

    fn peek_array<const N: usize>(&self, context: &'static str) -> Result<[u8; N], ParseError> {
        let end = self
            .offset
            .checked_add(N)
            .ok_or_else(|| ParseError::overflow(self.offset, context))?;
        let bytes = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| ParseError::unexpected_eof(self.offset, context))?;
        let mut array = [0u8; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use super::Reader;
    use crate::ErrorKind;

    #[test]
    fn new_reader_starts_at_zero() {
        let reader = Reader::new(&[1, 2, 3]);
        assert_eq!(reader.len(), 3);
        assert_eq!(reader.offset(), 0);
        assert_eq!(reader.remaining(), 3);
        assert!(!reader.is_empty());
        assert!(!reader.is_exhausted());
    }

    #[test]
    fn empty_reader_is_exhausted() {
        let reader = Reader::new(&[]);
        assert_eq!(reader.len(), 0);
        assert_eq!(reader.remaining(), 0);
        assert!(reader.is_empty());
        assert!(reader.is_exhausted());
    }

    #[test]
    fn take_returns_slice_and_advances() {
        let data = [1u8, 2, 3, 4];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.take(2).unwrap(), &[1, 2]);
        assert_eq!(reader.offset(), 2);
        assert_eq!(reader.take(0).unwrap(), &[] as &[u8]);
        assert_eq!(reader.take(2).unwrap(), &[3, 4]);
        assert!(reader.is_exhausted());
    }

    #[test]
    fn take_past_end_fails_without_moving() {
        let mut reader = Reader::new(&[1, 2, 3]);
        let error = reader.take(4).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(error.offset(), 0);
        assert_eq!(reader.offset(), 0);
    }

    #[test]
    fn take_at_exact_end_succeeds() {
        let mut reader = Reader::new(&[1, 2, 3]);
        assert_eq!(reader.take(3).unwrap(), &[1, 2, 3]);
        assert!(reader.is_exhausted());
    }

    #[test]
    fn take_huge_count_reports_overflow() {
        let mut reader = Reader::new(&[1, 2, 3]);
        reader.skip(1).unwrap();
        let error = reader.take(usize::MAX).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArithmeticOverflow);
        assert_eq!(error.offset(), 1);
        assert_eq!(reader.offset(), 1);
    }

    #[test]
    fn take_zero_at_end_succeeds() {
        let mut reader = Reader::new(&[]);
        assert_eq!(reader.take(0).unwrap(), &[] as &[u8]);
        assert!(reader.is_exhausted());
    }

    #[test]
    fn skip_moves_cursor() {
        let mut reader = Reader::new(&[0u8; 8]);
        reader.skip(3).unwrap();
        assert_eq!(reader.offset(), 3);
        reader.skip(5).unwrap();
        assert!(reader.is_exhausted());
    }

    #[test]
    fn skip_past_end_fails_without_moving() {
        let mut reader = Reader::new(&[0u8; 4]);
        reader.skip(1).unwrap();
        let error = reader.skip(4).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(error.offset(), 1);
        assert_eq!(reader.offset(), 1);
    }

    #[test]
    fn skip_huge_count_reports_overflow() {
        let mut reader = Reader::new(&[0u8; 4]);
        reader.skip(1).unwrap();
        let error = reader.skip(usize::MAX).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::ArithmeticOverflow);
        assert_eq!(reader.offset(), 1);
    }

    #[test]
    fn seek_allows_end_and_rejects_beyond() {
        let mut reader = Reader::new(&[0u8; 4]);
        reader.seek(4).unwrap();
        assert!(reader.is_exhausted());

        let error = reader.seek(5).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::OutOfBounds);
        assert_eq!(error.offset(), 5);
        assert_eq!(reader.offset(), 4);
    }

    #[test]
    fn seek_backwards_works() {
        let mut reader = Reader::new(&[1, 2, 3]);
        reader.skip(3).unwrap();
        reader.seek(1).unwrap();
        assert_eq!(reader.read_u8().unwrap(), 2);
    }

    #[test]
    fn read_integers_is_little_endian() {
        let data = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
            0xFF,
        ];
        let mut reader = Reader::new(&data);
        assert_eq!(reader.read_u8().unwrap(), 0x11);
        assert_eq!(reader.read_u16().unwrap(), 0x3322);
        assert_eq!(reader.read_u32().unwrap(), 0x77665544);
        assert_eq!(reader.read_u64().unwrap(), 0xFFEEDDCCBBAA9988);
        assert!(reader.is_exhausted());
    }

    #[test]
    fn read_integer_at_boundary_succeeds() {
        let mut reader = Reader::new(&[0xAA, 0xBB]);
        assert_eq!(reader.read_u16().unwrap(), 0xBBAA);
        assert!(reader.is_exhausted());
    }

    #[test]
    fn read_u32_with_one_byte_left_fails() {
        let mut reader = Reader::new(&[1, 2, 3]);
        reader.skip(2).unwrap();
        let error = reader.read_u32().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(error.offset(), 2);
        assert_eq!(error.context(), "u32");
        assert_eq!(reader.offset(), 2);
    }

    #[test]
    fn read_array_returns_bytes() {
        let mut reader = Reader::new(&[1, 2, 3, 4]);
        assert_eq!(reader.read_array::<4>().unwrap(), [1, 2, 3, 4]);
        assert!(reader.is_exhausted());
    }

    #[test]
    fn peek_does_not_advance_cursor() {
        let mut reader = Reader::new(&[0x11, 0x22, 0x33, 0x44]);
        assert_eq!(reader.peek_u8().unwrap(), 0x11);
        assert_eq!(reader.peek_u16().unwrap(), 0x2211);
        assert_eq!(reader.peek_u32().unwrap(), 0x4433_2211);
        assert_eq!(reader.offset(), 0);
        assert_eq!(reader.read_u8().unwrap(), 0x11);
    }

    #[test]
    fn peek_at_end_fails_without_moving() {
        let reader = Reader::new(&[]);
        let error = reader.peek_u8().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(reader.offset(), 0);
    }

    #[test]
    fn peek_u32_with_insufficient_bytes_fails() {
        let reader = Reader::new(&[1, 2, 3]);
        assert_eq!(
            reader.peek_u32().unwrap_err().kind(),
            ErrorKind::UnexpectedEof
        );
        assert_eq!(reader.peek_u16().unwrap(), 0x0201);
    }

    #[test]
    fn check_bytes_compares_without_consuming() {
        let mut reader = Reader::new(b"PE\0\0rest");
        reader.check_bytes(b"PE\0\0", "PE signature").unwrap();
        assert_eq!(reader.offset(), 0);
        assert_eq!(reader.read_u32().unwrap(), 0x0000_4550);
    }

    #[test]
    fn check_bytes_reports_mismatch() {
        let reader = Reader::new(b"MZxx");
        let error = reader.check_bytes(b"PE\0\0", "PE signature").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidValue);
        assert_eq!(error.offset(), 0);
        assert_eq!(reader.offset(), 0);
    }

    #[test]
    fn check_bytes_reports_truncation() {
        let reader = Reader::new(b"PE");
        let error = reader.check_bytes(b"PE\0\0", "PE signature").unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn slice_returns_absolute_range() {
        let reader = Reader::new(&[0, 1, 2, 3, 4, 5]);
        assert_eq!(reader.slice(2, 3).unwrap(), &[2, 3, 4]);
        assert_eq!(reader.offset(), 0);
    }

    #[test]
    fn slice_rejects_out_of_bounds_and_overflow() {
        let reader = Reader::new(&[0, 1, 2]);
        assert_eq!(
            reader.slice(2, 2).unwrap_err().kind(),
            ErrorKind::OutOfBounds
        );
        assert_eq!(
            reader.slice(usize::MAX, 1).unwrap_err().kind(),
            ErrorKind::ArithmeticOverflow
        );
    }

    #[test]
    fn sub_reader_is_independent() {
        let mut reader = Reader::new(&[1, 2, 3, 4, 5, 6]);
        let mut sub = reader.sub_reader(2, 3).unwrap();
        assert_eq!(sub.len(), 3);
        assert_eq!(sub.read_u8().unwrap(), 3);
        assert_eq!(sub.read_u16().unwrap(), 0x0504);
        assert!(sub.is_exhausted());
        assert_eq!(reader.offset(), 0);
        assert_eq!(reader.read_u8().unwrap(), 1);
    }

    #[test]
    fn read_cstr_stops_at_terminator() {
        let data = b"abc\0def";
        let mut reader = Reader::new(data);
        assert_eq!(reader.read_cstr(16).unwrap(), b"abc");
        assert_eq!(reader.offset(), 4);
        assert_eq!(reader.read_u8().unwrap(), b'd');
    }

    #[test]
    fn read_cstr_accepts_empty_string() {
        let mut reader = Reader::new(b"\0tail");
        assert_eq!(reader.read_cstr(16).unwrap(), b"");
        assert_eq!(reader.offset(), 1);
    }

    #[test]
    fn read_cstr_without_terminator_reports_eof() {
        let mut reader = Reader::new(b"abc");
        let error = reader.read_cstr(16).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::UnexpectedEof);
        assert_eq!(reader.offset(), 0);
    }

    #[test]
    fn read_cstr_longer_than_limit_reports_limit() {
        let mut reader = Reader::new(b"abcdef\0");
        let error = reader.read_cstr(3).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
        assert_eq!(error.offset(), 0);
        assert_eq!(reader.offset(), 0);
    }

    #[test]
    fn read_cstr_zero_limit_on_non_empty_input_reports_limit() {
        let mut reader = Reader::new(b"a\0");
        let error = reader.read_cstr(0).unwrap_err();
        assert_eq!(error.kind(), ErrorKind::LimitExceeded);
    }

    #[test]
    fn read_cstr_at_exact_limit_succeeds() {
        let mut reader = Reader::new(b"abc\0rest");
        assert_eq!(reader.read_cstr(3).unwrap(), b"abc");
        assert_eq!(reader.offset(), 4);
    }

    #[test]
    fn read_cstr_accepts_non_utf8_bytes() {
        let mut reader = Reader::new(&[0xFF, 0xFE, 0x00]);
        assert_eq!(reader.read_cstr(8).unwrap(), &[0xFF, 0xFE]);
    }

    #[test]
    fn read_cstr_terminator_at_last_byte_of_buffer() {
        let mut reader = Reader::new(b"abc\0");
        assert_eq!(reader.read_cstr(64).unwrap(), b"abc");
        assert!(reader.is_exhausted());
    }

    #[test]
    fn debug_does_not_print_payload() {
        let reader = Reader::new(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let text = format!("{reader:?}");
        assert!(text.contains("len: 4"), "{text}");
        assert!(!text.contains("222"), "{text}");
    }

    /// Deterministic xorshift64* generator: property tests must be repeatable
    /// and must not pull a dependency into the core crate.
    fn next_random(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        *state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    #[test]
    fn arbitrary_bytes_and_operations_never_panic() {
        let mut state = 0x0123_4567_89AB_CDEF_u64;
        for _ in 0..10_000 {
            let len = (next_random(&mut state) % 257) as usize;
            let mut data = vec![0u8; len];
            for byte in &mut data {
                *byte = (next_random(&mut state) & 0xFF) as u8;
            }
            let mut reader = Reader::new(&data);

            for _ in 0..8 {
                let operand = match next_random(&mut state) % 5 {
                    0 => 0,
                    1 => 1,
                    2 => (next_random(&mut state) % 32) as usize,
                    3 => len,
                    _ => usize::MAX - (next_random(&mut state) % 8) as usize,
                };

                match next_random(&mut state) % 8 {
                    0 => {
                        let _ = reader.take(operand);
                    }
                    1 => {
                        let _ = reader.skip(operand);
                    }
                    2 => {
                        let _ = reader.seek(operand);
                    }
                    3 => {
                        let _ = reader.read_u8();
                    }
                    4 => {
                        let _ = reader.read_u16();
                    }
                    5 => {
                        let _ = reader.read_u32();
                    }
                    6 => {
                        let _ = reader.read_u64();
                    }
                    _ => {
                        let _ = reader.read_cstr(operand);
                    }
                }

                // The core invariant: the cursor never leaves the buffer.
                assert!(reader.offset() <= reader.len());
                assert_eq!(reader.remaining(), reader.len() - reader.offset());
            }
        }
    }
}
