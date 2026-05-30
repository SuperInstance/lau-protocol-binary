#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::pedantic)]
#![allow(
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

use std::fmt;

// ---------------------------------------------------------------------------
// ProtocolError
// ---------------------------------------------------------------------------

/// Errors that can occur while reading from a [`WireBuffer`].
#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolError {
    /// Not enough bytes left in the buffer to complete the read.
    UnexpectedEof,
    /// Attempted to decode invalid UTF-8 from a string field.
    InvalidUtf8,
    /// A length field exceeded an implementation-defined maximum.
    InvalidLength(u32),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEof => write!(f, "unexpected end of buffer"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 sequence"),
            Self::InvalidLength(n) => write!(f, "invalid length: {n}"),
        }
    }
}

impl std::error::Error for ProtocolError {}

/// Maximum number of bytes allowed in a single length-prefixed field.
/// Prevents malicious / malformed payloads from allocating huge vectors.
pub const MAX_PAYLOAD_BYTES: u32 = 64 * 1024 * 1024; // 64 MiB

/// Maximum string length in bytes (UTF-8 encoded).
pub const MAX_STRING_BYTES: u32 = 16 * 1024 * 1024; // 16 MiB

// ---------------------------------------------------------------------------
// WireBuffer
// ---------------------------------------------------------------------------

/// A compact, cursor-based buffer for reading and writing binary protocol data.
///
/// All multi-byte values are encoded **little-endian**.
/// Strings and raw byte slices are length-prefixed (u32 length + data).
#[derive(Debug, Clone, PartialEq)]
pub struct WireBuffer {
    /// The underlying byte storage.
    data: Vec<u8>,
    /// Current read cursor position.
    pos: usize,
}

impl WireBuffer {
    // ── construction -------------------------------------------------------

    /// Create an empty buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            pos: 0,
        }
    }

    /// Create an empty buffer with the given capacity (avoids re-allocation).
    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            data: Vec::with_capacity(n),
            pos: 0,
        }
    }

    // ── write methods ------------------------------------------------------

    /// Write a single byte.
    pub fn write_u8(&mut self, v: u8) {
        self.data.push(v);
    }

    /// Write a u16 in little-endian order.
    pub fn write_u16_le(&mut self, v: u16) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a u32 in little-endian order.
    pub fn write_u32_le(&mut self, v: u32) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a u64 in little-endian order.
    pub fn write_u64_le(&mut self, v: u64) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    /// Write an i64 in little-endian order.
    pub fn write_i64_le(&mut self, v: i64) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    /// Write an f64 in little-endian order.
    pub fn write_f64_le(&mut self, v: f64) {
        self.data.extend_from_slice(&v.to_le_bytes());
    }

    /// Write a boolean as a single byte (1 = true, 0 = false).
    pub fn write_bool(&mut self, v: bool) {
        self.data.push(u8::from(v));
    }

    /// Write a length-prefixed byte slice.
    ///
    /// Format: `[len: u32][data: len bytes]`
    /// Returns an error if `bytes` exceeds [`MAX_PAYLOAD_BYTES`].
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidLength`] if the slice is too long.
    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), ProtocolError> {
        let len = u32::try_from(bytes.len()).map_err(|_| ProtocolError::InvalidLength(u32::MAX))?;
        if len > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::InvalidLength(len));
        }
        self.write_u32_le(len);
        self.data.extend_from_slice(bytes);
        Ok(())
    }

    /// Write a length-prefixed UTF-8 string.
    ///
    /// Format: `[byte_len: u32][utf8 bytes]`
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidLength`] if the encoded string is too long.
    pub fn write_string(&mut self, s: &str) -> Result<(), ProtocolError> {
        self.write_bytes(s.as_bytes())
    }

    // ── read methods -------------------------------------------------------

    /// Read a single byte.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if no bytes remain.
    pub fn read_u8(&mut self) -> Result<u8, ProtocolError> {
        let b = self.data.get(self.pos).copied().ok_or(ProtocolError::UnexpectedEof)?;
        self.pos += 1;
        Ok(b)
    }

    /// Read a u16 in little-endian order.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if fewer than 2 bytes remain.
    pub fn read_u16_le(&mut self) -> Result<u16, ProtocolError> {
        let arr = self.read_arr::<2>()?;
        Ok(u16::from_le_bytes(arr))
    }

    /// Read a u32 in little-endian order.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if fewer than 4 bytes remain.
    pub fn read_u32_le(&mut self) -> Result<u32, ProtocolError> {
        let arr = self.read_arr::<4>()?;
        Ok(u32::from_le_bytes(arr))
    }

    /// Read a u64 in little-endian order.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if fewer than 8 bytes remain.
    pub fn read_u64_le(&mut self) -> Result<u64, ProtocolError> {
        let arr = self.read_arr::<8>()?;
        Ok(u64::from_le_bytes(arr))
    }

    /// Read an i64 in little-endian order.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if fewer than 8 bytes remain.
    pub fn read_i64_le(&mut self) -> Result<i64, ProtocolError> {
        let arr = self.read_arr::<8>()?;
        Ok(i64::from_le_bytes(arr))
    }

    /// Read an f64 in little-endian order.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if fewer than 8 bytes remain.
    pub fn read_f64_le(&mut self) -> Result<f64, ProtocolError> {
        let arr = self.read_arr::<8>()?;
        Ok(f64::from_le_bytes(arr))
    }

    /// Read a boolean (1 = true, 0 = false).
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if no bytes remain.
    pub fn read_bool(&mut self) -> Result<bool, ProtocolError> {
        self.read_u8().map(|b| b != 0)
    }

    /// Read a length-prefixed byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if the buffer is exhausted,
    /// [`ProtocolError::InvalidLength`] if the length exceeds [`MAX_PAYLOAD_BYTES`].
    pub fn read_bytes(&mut self) -> Result<Vec<u8>, ProtocolError> {
        let len = self.read_u32_le()?;
        if len > MAX_PAYLOAD_BYTES {
            return Err(ProtocolError::InvalidLength(len));
        }
        let end = self.pos.checked_add(len as usize).ok_or(ProtocolError::UnexpectedEof)?;
        if end > self.data.len() {
            return Err(ProtocolError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice.to_vec())
    }

    /// Read a length-prefixed UTF-8 string.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if the buffer is exhausted,
    /// [`ProtocolError::InvalidLength`] if the length exceeds [`MAX_STRING_BYTES`], or
    /// [`ProtocolError::InvalidUtf8`] if the bytes are not valid UTF-8.
    pub fn read_string(&mut self) -> Result<String, ProtocolError> {
        // Check length against the string-specific maximum before reading.
        let len = self.read_u32_le()?;
        if len > MAX_STRING_BYTES {
            return Err(ProtocolError::InvalidLength(len));
        }
        let end = self
            .pos
            .checked_add(len as usize)
            .ok_or(ProtocolError::UnexpectedEof)?;
        if end > self.data.len() {
            return Err(ProtocolError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        String::from_utf8(slice.to_vec()).map_err(|_| ProtocolError::InvalidUtf8)
    }

    // ── helpers ------------------------------------------------------------

    /// Number of unread bytes remaining.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    /// Reset the read cursor to the beginning.
    pub fn reset_read(&mut self) {
        self.pos = 0;
    }

    /// Consume the buffer and return the underlying bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Total number of bytes in the buffer (written data).
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Returns `true` if the buffer contains no data.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    // ── internal -----------------------------------------------------------

    /// Read exactly `n` bytes starting at the current cursor.
    fn read_arr<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let end = self.pos.checked_add(N).ok_or(ProtocolError::UnexpectedEof)?;
        if end > self.data.len() {
            return Err(ProtocolError::UnexpectedEof);
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(arr)
    }
}

impl Default for WireBuffer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MessageHeader
// ---------------------------------------------------------------------------

/// Fixed-size header included at the start of every PLATO protocol message.
///
/// Wire format: `[msg_type: u8][payload_len: u32 LE][tick: u64 LE]` — 13 bytes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MessageHeader {
    pub msg_type: u8,
    pub payload_len: u32,
    pub tick: u64,
}

impl MessageHeader {
    /// Encode the header into a 13-byte array.
    #[must_use]
    pub fn encode(&self) -> [u8; 13] {
        let mut buf = [0u8; 13];
        buf[0] = self.msg_type;
        buf[1..5].copy_from_slice(&self.payload_len.to_le_bytes());
        buf[5..13].copy_from_slice(&self.tick.to_le_bytes());
        buf
    }

    /// Decode a header from a 13-byte array.
    ///
    /// # Panics
    ///
    /// Panics if `src` is not exactly 13 bytes (it should always be, given the signature).
    #[must_use]
    pub fn decode(src: &[u8; 13]) -> Self {
        let msg_type = src[0];
        let payload_len = u32::from_le_bytes(src[1..5].try_into().unwrap());
        let tick = u64::from_le_bytes(src[5..13].try_into().unwrap());
        Self {
            msg_type,
            payload_len,
            tick,
        }
    }

    /// Header size in bytes (always 13).
    pub const SIZE: usize = 13;
}

// ---------------------------------------------------------------------------
// WireMessage
// ---------------------------------------------------------------------------

/// Message type identifiers (opcodes).
pub mod msg_type {
    pub const VIBE_UPDATE: u8 = 0x01;
    pub const CONSERVATION_CHECK: u8 = 0x02;
    pub const AGENT_ACTION: u8 = 0x03;
    pub const ROOM_EVENT: u8 = 0x04;
    pub const WORLD_SNAPSHOT: u8 = 0x05;
    pub const PING: u8 = 0x06;
    pub const PONG: u8 = 0x07;
}

/// All PLATO protocol message types with their encode/decode implementations.
#[derive(Debug, Clone, PartialEq)]
pub enum WireMessage {
    VibeUpdate {
        entity_id: u64,
        vibe: f64,
        tick: u64,
    },
    ConservationCheck {
        baseline: f64,
        actual: f64,
        error: f64,
    },
    AgentAction {
        agent_id: u64,
        action: u8,
        params: Vec<f64>,
    },
    RoomEvent {
        room_id: u64,
        event_type: u8,
        data: Vec<u8>,
    },
    WorldSnapshot {
        tick: u64,
        entity_count: u32,
        total_vibe: f64,
    },
    Ping {
        timestamp: u64,
    },
    Pong {
        timestamp: u64,
    },
}

impl WireMessage {
    /// Return the message-type opcode for this variant.
    #[must_use]
    pub fn msg_type_byte(&self) -> u8 {
        match self {
            Self::VibeUpdate { .. } => msg_type::VIBE_UPDATE,
            Self::ConservationCheck { .. } => msg_type::CONSERVATION_CHECK,
            Self::AgentAction { .. } => msg_type::AGENT_ACTION,
            Self::RoomEvent { .. } => msg_type::ROOM_EVENT,
            Self::WorldSnapshot { .. } => msg_type::WORLD_SNAPSHOT,
            Self::Ping { .. } => msg_type::PING,
            Self::Pong { .. } => msg_type::PONG,
        }
    }

    /// Encode the message into a `Vec<u8>`.
    ///
    /// Format: `[msg_type: u8][fields...]`
    ///
    /// # Panics
    ///
    /// Panics if `params` length in [`AgentAction`](Self::AgentAction) exceeds `u32::MAX`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = WireBuffer::new();
        buf.write_u8(self.msg_type_byte());
        match self {
            Self::VibeUpdate {
                entity_id,
                vibe,
                tick,
            } => {
                buf.write_u64_le(*entity_id);
                buf.write_f64_le(*vibe);
                buf.write_u64_le(*tick);
            }
            Self::ConservationCheck {
                baseline,
                actual,
                error,
            } => {
                buf.write_f64_le(*baseline);
                buf.write_f64_le(*actual);
                buf.write_f64_le(*error);
            }
            Self::AgentAction {
                agent_id,
                action,
                params,
            } => {
                buf.write_u64_le(*agent_id);
                buf.write_u8(*action);
                // Write params count + each f64
                let count =
                    u32::try_from(params.len()).expect("params vector too large for u32");
                buf.write_u32_le(count);
                for p in params {
                    buf.write_f64_le(*p);
                }
            }
            Self::RoomEvent {
                room_id,
                event_type,
                data,
            } => {
                buf.write_u64_le(*room_id);
                buf.write_u8(*event_type);
                buf.write_bytes(data).expect("room event data too large");
            }
            Self::WorldSnapshot {
                tick,
                entity_count,
                total_vibe,
            } => {
                buf.write_u64_le(*tick);
                buf.write_u32_le(*entity_count);
                buf.write_f64_le(*total_vibe);
            }
            Self::Ping { timestamp } | Self::Pong { timestamp } => {
                buf.write_u64_le(*timestamp);
            }
        }
        buf.into_bytes()
    }

    /// Decode a message from a [`WireBuffer`].
    ///
    /// The buffer must be positioned at the message-type byte.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::UnexpectedEof`] if the buffer is exhausted,
    /// or a variant-specific error for invalid data.
    pub fn decode(buf: &mut WireBuffer) -> Result<Self, ProtocolError> {
        let msg_type = buf.read_u8()?;
        match msg_type {
            msg_type::VIBE_UPDATE => {
                let entity_id = buf.read_u64_le()?;
                let vibe = buf.read_f64_le()?;
                let tick = buf.read_u64_le()?;
                Ok(Self::VibeUpdate {
                    entity_id,
                    vibe,
                    tick,
                })
            }
            msg_type::CONSERVATION_CHECK => {
                let baseline = buf.read_f64_le()?;
                let actual = buf.read_f64_le()?;
                let error = buf.read_f64_le()?;
                Ok(Self::ConservationCheck {
                    baseline,
                    actual,
                    error,
                })
            }
            msg_type::AGENT_ACTION => {
                let agent_id = buf.read_u64_le()?;
                let action = buf.read_u8()?;
                let count = buf.read_u32_le()?;
                let mut params = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    params.push(buf.read_f64_le()?);
                }
                Ok(Self::AgentAction {
                    agent_id,
                    action,
                    params,
                })
            }
            msg_type::ROOM_EVENT => {
                let room_id = buf.read_u64_le()?;
                let event_type = buf.read_u8()?;
                let data = buf.read_bytes()?;
                Ok(Self::RoomEvent {
                    room_id,
                    event_type,
                    data,
                })
            }
            msg_type::WORLD_SNAPSHOT => {
                let tick = buf.read_u64_le()?;
                let entity_count = buf.read_u32_le()?;
                let total_vibe = buf.read_f64_le()?;
                Ok(Self::WorldSnapshot {
                    tick,
                    entity_count,
                    total_vibe,
                })
            }
            msg_type::PING => {
                let timestamp = buf.read_u64_le()?;
                Ok(Self::Ping { timestamp })
            }
            msg_type::PONG => {
                let timestamp = buf.read_u64_le()?;
                Ok(Self::Pong { timestamp })
            }
            other => Err(ProtocolError::InvalidLength(u32::from(other))),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── WireBuffer: read / write basics ───────────────────────────────────

    #[test]
    fn test_write_read_u8() {
        let mut buf = WireBuffer::new();
        buf.write_u8(42);
        buf.write_u8(0);
        buf.write_u8(255);
        buf.reset_read();
        assert_eq!(buf.read_u8().unwrap(), 42);
        assert_eq!(buf.read_u8().unwrap(), 0);
        assert_eq!(buf.read_u8().unwrap(), 255);
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_write_read_u16_le() {
        let mut buf = WireBuffer::new();
        buf.write_u16_le(0xABCD);
        buf.reset_read();
        assert_eq!(buf.read_u16_le().unwrap(), 0xABCD);
    }

    #[test]
    fn test_write_read_u32_le() {
        let mut buf = WireBuffer::new();
        buf.write_u32_le(0xDEAD_BEEF);
        buf.reset_read();
        assert_eq!(buf.read_u32_le().unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn test_write_read_u64_le() {
        let mut buf = WireBuffer::new();
        buf.write_u64_le(u64::MAX);
        buf.reset_read();
        assert_eq!(buf.read_u64_le().unwrap(), u64::MAX);
    }

    #[test]
    fn test_write_read_i64_le() {
        let mut buf = WireBuffer::new();
        buf.write_i64_le(-42);
        buf.reset_read();
        assert_eq!(buf.read_i64_le().unwrap(), -42);
    }

    #[test]
    fn test_write_read_f64_le() {
        let mut buf = WireBuffer::new();
        buf.write_f64_le(std::f64::consts::PI);
        buf.reset_read();
        let v = buf.read_f64_le().unwrap();
        assert!((v - std::f64::consts::PI).abs() < 1e-15);
    }

    #[test]
    fn test_write_read_bool() {
        let mut buf = WireBuffer::new();
        buf.write_bool(true);
        buf.write_bool(false);
        buf.reset_read();
        assert!(buf.read_bool().unwrap());
        assert!(!buf.read_bool().unwrap());
    }

    #[test]
    fn test_write_read_bytes() {
        let mut buf = WireBuffer::new();
        let input = b"hello world";
        buf.write_bytes(input).unwrap();
        buf.reset_read();
        let out = buf.read_bytes().unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn test_write_read_string() {
        let mut buf = WireBuffer::new();
        let input = "héllo wörld 🌍";
        buf.write_string(input).unwrap();
        buf.reset_read();
        let out = buf.read_string().unwrap();
        assert_eq!(out, input);
    }

    #[test]
    fn test_empty_string() {
        let mut buf = WireBuffer::new();
        buf.write_string("").unwrap();
        buf.reset_read();
        let out = buf.read_string().unwrap();
        assert_eq!(out, "");
    }

    #[test]
    fn test_empty_bytes() {
        let mut buf = WireBuffer::new();
        buf.write_bytes(b"").unwrap();
        buf.reset_read();
        let out = buf.read_bytes().unwrap();
        assert!(out.is_empty());
    }

    // ── WireBuffer: error cases ───────────────────────────────────────────

    #[test]
    fn test_read_u8_eof() {
        let mut buf = WireBuffer::new();
        assert_eq!(buf.read_u8(), Err(ProtocolError::UnexpectedEof));
    }

    #[test]
    fn test_read_u16_le_eof() {
        let mut buf = WireBuffer::new();
        buf.write_u8(1); // only 1 byte
        buf.reset_read();
        assert_eq!(buf.read_u16_le(), Err(ProtocolError::UnexpectedEof));
    }

    #[test]
    fn test_read_u32_le_eof() {
        let mut buf = WireBuffer::new();
        buf.write_u32_le(100);
        // Don't write the actual payload
        buf.reset_read();
        assert_eq!(buf.read_u32_le().unwrap(), 100);
        assert_eq!(buf.read_bytes(), Err(ProtocolError::UnexpectedEof));
    }

    #[test]
    fn test_read_bytes_invalid_length() {
        // Manually craft a buffer with a huge length
        let mut raw = WireBuffer::new();
        raw.write_u32_le(MAX_PAYLOAD_BYTES + 1);
        let mut buf = WireBuffer {
            data: raw.into_bytes(),
            pos: 0,
        };
        assert_eq!(
            buf.read_bytes(),
            Err(ProtocolError::InvalidLength(MAX_PAYLOAD_BYTES + 1))
        );
    }

    #[test]
    fn test_read_string_invalid_utf8() {
        let mut buf = WireBuffer::new();
        // write length-prefixed invalid UTF-8 bytes
        buf.write_u32_le(2);
        buf.write_u8(0xFF);
        buf.write_u8(0xFE);
        buf.reset_read();
        assert_eq!(buf.read_string(), Err(ProtocolError::InvalidUtf8));
    }

    #[test]
    fn test_read_string_invalid_length() {
        let mut buf = WireBuffer::new();
        // write max string bytes + 1 as length prefix, then valid utf8 data after
        // actually, just use write_bytes directly with a too-large payload
        // Simpler: write the invalid length byte directly
        for &b in &(MAX_STRING_BYTES + 1).to_le_bytes() {
            buf.write_u8(b);
        }
        assert_eq!(
            buf.read_string(),
            Err(ProtocolError::InvalidLength(MAX_STRING_BYTES + 1))
        );
    }

    #[test]
    fn test_write_bytes_too_large() {
        let mut buf = WireBuffer::new();
        let huge = vec![0u8; MAX_PAYLOAD_BYTES as usize + 1];
        assert_eq!(
            buf.write_bytes(&huge),
            Err(ProtocolError::InvalidLength(MAX_PAYLOAD_BYTES + 1))
        );
    }

    // ── WireBuffer: utility methods ───────────────────────────────────────

    #[test]
    fn test_new_is_empty() {
        let buf = WireBuffer::new();
        assert!(buf.is_empty());
        assert_eq!(buf.len(), 0);
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_with_capacity() {
        let buf = WireBuffer::with_capacity(128);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_remaining() {
        let mut buf = WireBuffer::new();
        buf.write_u16_le(42);
        buf.write_u16_le(99);
        assert_eq!(buf.remaining(), 4); // wrote 4 bytes, pos=0
        buf.reset_read();
        assert_eq!(buf.remaining(), 4);
        buf.read_u16_le().unwrap();
        assert_eq!(buf.remaining(), 2);
    }

    #[test]
    fn test_into_bytes() {
        let mut buf = WireBuffer::new();
        buf.write_u8(1);
        buf.write_u8(2);
        let bytes = buf.into_bytes();
        assert_eq!(bytes, vec![1, 2]);
    }

    #[test]
    fn test_reset_read() {
        let mut buf = WireBuffer::new();
        buf.write_u8(10);
        buf.write_u8(20);
        buf.reset_read();
        assert_eq!(buf.read_u8().unwrap(), 10);
        assert_eq!(buf.read_u8().unwrap(), 20);
        // reset and re-read
        buf.reset_read();
        assert_eq!(buf.read_u8().unwrap(), 10);
    }

    // ── MessageHeader ─────────────────────────────────────────────────────

    #[test]
    fn test_message_header_roundtrip() {
        let h = MessageHeader {
            msg_type: 0x07,
            payload_len: 1234,
            tick: 999_999_999,
        };
        let encoded = h.encode();
        assert_eq!(encoded.len(), 13);
        let decoded = MessageHeader::decode(&encoded);
        assert_eq!(h, decoded);
    }

    #[test]
    fn test_message_header_edge_cases() {
        let h = MessageHeader {
            msg_type: 0,
            payload_len: 0,
            tick: 0,
        };
        assert_eq!(MessageHeader::decode(&h.encode()), h);

        let h = MessageHeader {
            msg_type: 255,
            payload_len: u32::MAX,
            tick: u64::MAX,
        };
        assert_eq!(MessageHeader::decode(&h.encode()), h);
    }

    // ── WireMessage: roundtrips ───────────────────────────────────────────

    #[test]
    fn test_vibe_update_roundtrip() {
        let msg = WireMessage::VibeUpdate {
            entity_id: 101,
            vibe: std::f64::consts::PI,
            tick: 42,
        };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn test_conservation_check_roundtrip() {
        let msg = WireMessage::ConservationCheck {
            baseline: 1.0,
            actual: 0.999,
            error: 0.001,
        };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_agent_action_roundtrip() {
        let msg = WireMessage::AgentAction {
            agent_id: 7,
            action: 3,
            params: vec![1.0, 2.5, -std::f64::consts::PI, 0.0],
        };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_agent_action_many_params() {
        let params: Vec<f64> = (0..100).map(|i| f64::from(i) * 1.5).collect();
        let msg = WireMessage::AgentAction {
            agent_id: 1,
            action: 2,
            params,
        };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_agent_action_no_params() {
        let msg = WireMessage::AgentAction {
            agent_id: 0,
            action: 0,
            params: vec![],
        };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_room_event_roundtrip() {
        let msg = WireMessage::RoomEvent {
            room_id: 42,
            event_type: 7,
            data: vec![0xCA, 0xFE, 0xBA, 0xBE],
        };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_room_event_empty_data() {
        let msg = WireMessage::RoomEvent {
            room_id: 0,
            event_type: 0,
            data: vec![],
        };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_world_snapshot_roundtrip() {
        let msg = WireMessage::WorldSnapshot {
            tick: 999,
            entity_count: 42,
            total_vibe: 100.0,
        };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_ping_roundtrip() {
        let msg = WireMessage::Ping { timestamp: 1_234_567 };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_pong_roundtrip() {
        let msg = WireMessage::Pong {
            timestamp: u64::MAX,
        };
        let encoded = msg.encode();
        let mut buf = WireBuffer {
            data: encoded,
            pos: 0,
        };
        let decoded = WireMessage::decode(&mut buf).unwrap();
        assert_eq!(msg, decoded);
    }

    // ── WireMessage: error cases ──────────────────────────────────────────

    #[test]
    fn test_decode_unknown_msg_type() {
        let mut buf = WireBuffer::new();
        buf.write_u8(0xFF); // unknown type
        assert_eq!(
            WireMessage::decode(&mut buf),
            Err(ProtocolError::InvalidLength(255))
        );
    }

    #[test]
    fn test_decode_empty_buffer() {
        let mut buf = WireBuffer::new();
        assert_eq!(
            WireMessage::decode(&mut buf),
            Err(ProtocolError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_truncated_message() {
        // Ping has message type (1) + timestamp (8) = 9 bytes
        let mut buf = WireBuffer::new();
        buf.write_u8(msg_type::PING);
        buf.write_u32_le(1234); // only 4 of 8 timestamp bytes
        buf.reset_read();
        assert_eq!(
            WireMessage::decode(&mut buf),
            Err(ProtocolError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_truncated_room_event_data() {
        let mut buf = WireBuffer::new();
        buf.write_u8(msg_type::ROOM_EVENT);
        buf.write_u64_le(1);
        buf.write_u8(5);
        buf.write_u32_le(100); // claim 100 bytes but provide none
        buf.reset_read();
        assert_eq!(
            WireMessage::decode(&mut buf),
            Err(ProtocolError::UnexpectedEof)
        );
    }

    #[test]
    fn test_decode_truncated_agent_action_params() {
        let mut buf = WireBuffer::new();
        buf.write_u8(msg_type::AGENT_ACTION);
        buf.write_u64_le(1);
        buf.write_u8(0);
        buf.write_u32_le(5); // claim 5 params but provide 0 f64s
        buf.reset_read();
        assert_eq!(
            WireMessage::decode(&mut buf),
            Err(ProtocolError::UnexpectedEof)
        );
    }

    // ── Determinism ───────────────────────────────────────────────────────

    #[test]
    fn test_deterministic_encoding() {
        let a = WireMessage::VibeUpdate {
            entity_id: 1,
            vibe: 2.0,
            tick: 3,
        };
        let b = WireMessage::VibeUpdate {
            entity_id: 1,
            vibe: 2.0,
            tick: 3,
        };
        assert_eq!(a.encode(), b.encode());
    }

    #[test]
    fn test_deterministic_header() {
        let h = MessageHeader {
            msg_type: 0x01,
            payload_len: 20,
            tick: 100,
        };
        assert_eq!(h.encode(), h.encode());
    }

    // ── Large payloads ────────────────────────────────────────────────────

    #[test]
    fn test_large_bytes_roundtrip() {
        let data: Vec<u8> = (0..65_535).map(|i| (i & 0xFF) as u8).collect();
        let mut buf = WireBuffer::new();
        buf.write_bytes(&data).unwrap();
        buf.reset_read();
        let out = buf.read_bytes().unwrap();
        assert_eq!(data, out);
    }

    #[test]
    fn test_large_string_roundtrip() {
        let s: String = (0..10_000).map(|_| 'A').collect();
        let mut buf = WireBuffer::new();
        buf.write_string(&s).unwrap();
        buf.reset_read();
        let out = buf.read_string().unwrap();
        assert_eq!(s.len(), out.len());
        assert_eq!(s, out);
    }

    #[test]
    fn test_max_payload_boundary() {
        let data = vec![0u8; MAX_PAYLOAD_BYTES as usize];
        let mut buf = WireBuffer::new();
        buf.write_bytes(&data).unwrap();
        buf.reset_read();
        let out = buf.read_bytes().unwrap();
        assert_eq!(out.len(), data.len());
    }

    #[test]
    fn test_write_string_too_large() {
        let mut buf = WireBuffer::new();
        // Exceeds MAX_STRING_BYTES (16 MiB) via MAX_PAYLOAD_BYTES check
        let huge = vec![b'x'; MAX_PAYLOAD_BYTES as usize + 1];
        // Convert to string for write_string — safe ASCII
        let s = std::str::from_utf8(&huge).unwrap();
        assert_eq!(
            buf.write_string(s),
            Err(ProtocolError::InvalidLength(MAX_PAYLOAD_BYTES + 1))
        );
    }
}