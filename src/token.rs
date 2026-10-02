//! Completion tokens: routing CQEs back to the operation that issued them.
//!
//! Layout (64 bits): `[ op: 8 | generation: 16 | slot: 24 | aux: 16 ]`.
//! The 16-bit generation guards against stale completions for a slot whose
//! session was closed and its slot reused.
//!
//! Extracted from vane-core's `token.rs`; the vane-specific
//! downstream/upstream operation split (proxy topology) was generalized to
//! direction-neutral `Read`/`Write` — callers distinguish sides via
//! `slot`/`aux`.

use std::fmt;

/// Operation kind encoded in a [`Token`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Op {
    /// Listener readiness (a new connection can be accepted).
    Accept = 1,
    /// Read from a connected socket (registered fixed buffer).
    Read = 2,
    /// Write to a connected socket (registered fixed buffer).
    Write = 3,
    /// Nonblocking connect completed.
    Connect = 4,
    /// Socket close completed.
    Close = 5,
    /// Splice pump progress (zero-copy passthrough).
    Splice = 6,
}

/// Uniquely identifies an in-flight engine operation.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Token(u64);

impl Token {
    const OP_BITS: u64 = 8;
    const GEN_BITS: u64 = 16;
    const SLOT_BITS: u64 = 24;
    const SLOT_SHIFT: u64 = Self::OP_BITS + Self::GEN_BITS;
    const AUX_SHIFT: u64 = Self::SLOT_SHIFT + Self::SLOT_BITS;

    /// Packs `op`, `slot`, `generation`, and an auxiliary value.
    #[must_use]
    #[inline]
    pub fn new(op: Op, slot: u32, generation: u16, aux: u16) -> Self {
        debug_assert!(slot < (1 << Self::SLOT_BITS), "slot overflows token");
        Self(
            (op as u64)
                | (u64::from(generation) << Self::OP_BITS)
                | (u64::from(slot) << Self::SLOT_SHIFT)
                | (u64::from(aux) << Self::AUX_SHIFT),
        )
    }

    /// Listener token (aux = listener index).
    #[must_use]
    #[inline]
    pub fn accept(listener: u16) -> Self {
        Self::new(Op::Accept, 0, 0, listener)
    }

    /// Decodes the operation kind.
    #[must_use]
    #[inline]
    pub fn op(self) -> Op {
        // All encoded discriminants 1..=6 map to their `Op`; any other
        // low byte (foreign bits, zero) falls back to `Splice` rather than
        // panicking — tokens are CQE routing hints, never trust anchors.
        match self.0 & ((1 << Self::OP_BITS) - 1) {
            1 => Op::Accept,
            2 => Op::Read,
            3 => Op::Write,
            4 => Op::Connect,
            5 => Op::Close,
            _ => Op::Splice,
        }
    }

    /// Decodes the session slot.
    #[must_use]
    #[inline]
    pub fn slot(self) -> u32 {
        ((self.0 >> Self::SLOT_SHIFT) & ((1 << Self::SLOT_BITS) - 1)) as u32
    }

    /// Decodes the session generation.
    #[must_use]
    #[inline]
    pub fn generation(self) -> u16 {
        ((self.0 >> Self::OP_BITS) & ((1 << Self::GEN_BITS) - 1)) as u16
    }

    /// Decodes the auxiliary payload.
    #[must_use]
    #[inline]
    pub fn aux(self) -> u16 {
        (self.0 >> Self::AUX_SHIFT) as u16
    }

    /// Raw bits (engine backends store tokens directly as `user_data`).
    #[must_use]
    #[inline]
    pub fn bits(self) -> u64 {
        self.0
    }

    /// Rebuilds a token from raw bits.
    #[must_use]
    #[inline]
    pub fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Token({:?}, slot {}, generation {}, aux {})",
            self.op(),
            self.slot(),
            self.generation(),
            self.aux()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let t = Token::new(Op::Read, 123_456, 0xBEEF, 7);
        assert_eq!(t.op(), Op::Read);
        assert_eq!(t.slot(), 123_456);
        assert_eq!(t.generation(), 0xBEEF);
        assert_eq!(t.aux(), 7);
    }

    #[test]
    fn accept_token() {
        let t = Token::accept(3);
        assert_eq!(t.op(), Op::Accept);
        assert_eq!(t.aux(), 3);
    }

    #[test]
    fn all_ops_roundtrip() {
        for (op, code) in [
            (Op::Accept, 1u64),
            (Op::Read, 2),
            (Op::Write, 3),
            (Op::Connect, 4),
            (Op::Close, 5),
            (Op::Splice, 6),
        ] {
            let t = Token::new(op, 1, 2, 3);
            assert_eq!(t.0 & 0xFF, code, "{op:?} discriminant drifted");
            assert_eq!(t.op(), op);
        }
    }

    #[test]
    fn foreign_bits_fall_back_to_splice() {
        // A token built from arbitrary bits never panics on decode.
        let t = Token::from_bits(0xDEAD_BEEF);
        assert_eq!(t.op(), Op::Splice);
    }

    #[test]
    fn debug_is_structured() {
        let t = Token::new(Op::Close, 9, 4, 1);
        let s = format!("{t:?}");
        assert!(s.contains("Close") && s.contains("slot 9"), "{s}");
    }
}
