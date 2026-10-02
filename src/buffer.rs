//! Fixed buffer pool (`IORING_REGISTER_BUFFERS` semantics).
//!
//! The owner pre-allocates `capacity` slots of `buf_size` bytes up front —
//! the hot path never calls `malloc`. Slots have *stable addresses*, which
//! is what allows [`UringEngine`](crate::uring::UringEngine) to register
//! them with the ring (`IORING_REGISTER_BUFFERS`) and read with
//! `buf_index = slot`: the kernel writes received bytes directly into the
//! slot, with zero per-op buffer mapping.
//!
//! Extracted from vane-core's `buffer.rs`. Genericization: vane pinned
//! `buf_size` to [`DEFAULT_BUF_SIZE`] because its engine assumed one
//! registration granularity; the pool here accepts any fixed `buf_size`
//! chosen at construction (all slots of one pool share the size, which is
//! what one `register_buffers` call requires).

/// Default per-slot buffer size (single read batch).
pub const DEFAULT_BUF_SIZE: usize = 4096;

/// Default slots per worker (power of two, `io_uring` registration-friendly).
pub const DEFAULT_POOL_SIZE: usize = 1024;

/// Pre-allocated, fixed-size buffer pool owned by one thread.
pub struct BufferPool {
    /// Stable-address slot storage: `slots[i]` is `buf_size` bytes.
    slots: Box<[Box<[u8]>]>,
    /// LIFO free list of slot indices (owner-local, single thread).
    free: Vec<u32>,
    /// Slot size in bytes.
    buf_size: usize,
}

impl BufferPool {
    /// Pre-allocates `capacity` slots of `buf_size` bytes.
    ///
    /// `buf_size` is fixed for the pool's lifetime (one registration
    /// granularity); power-of-two sizes and capacities are `io_uring`
    /// registration-friendly but not enforced.
    #[must_use]
    pub fn new(capacity: usize, buf_size: usize) -> Option<Self> {
        if capacity == 0 || buf_size == 0 {
            return None;
        }
        let mut slots = Vec::with_capacity(capacity);
        let mut free = Vec::with_capacity(capacity);
        for i in 0..capacity {
            slots.push(vec![0u8; buf_size].into_boxed_slice());
            free.push(i as u32);
        }
        Some(Self {
            slots: slots.into_boxed_slice(),
            free,
            buf_size,
        })
    }

    /// Slot size in bytes.
    #[must_use]
    #[inline]
    pub fn buf_size(&self) -> usize {
        self.buf_size
    }

    /// Number of slots.
    #[must_use]
    #[inline]
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }

    /// Free slot count.
    #[must_use]
    #[inline]
    pub fn free_slots(&self) -> usize {
        self.free.len()
    }

    /// Takes a slot, or `None` when the pool is exhausted (callers stop
    /// reading — TCP backpressure does the rest).
    #[inline]
    pub fn take(&mut self) -> Option<u32> {
        self.free.pop()
    }

    /// Returns a slot to the pool.
    ///
    /// # Panics
    /// Debug builds panic when `slot` is out of range (owner bug; release
    /// builds silently accept it back, matching the pool's contract that
    /// only valid slots are ever handed out).
    #[inline]
    pub fn release(&mut self, slot: u32) {
        debug_assert!((slot as usize) < self.slots.len(), "slot out of range");
        self.free.push(slot);
    }

    /// Reads the slot's bytes (stable address, safe to hand to the kernel).
    ///
    /// Out-of-range slots read as empty (the pool only ever hands out
    /// in-range indices; this is a defensive read path).
    #[must_use]
    #[inline]
    pub fn slot(&self, slot: u32) -> &[u8] {
        match self.slots.get(slot as usize) {
            Some(s) => s,
            None => &[],
        }
    }

    /// Mutable access to a slot's bytes (empty for out-of-range indices).
    #[inline]
    pub fn slot_mut(&mut self, slot: u32) -> &mut [u8] {
        match self.slots.get_mut(slot as usize) {
            Some(s) => s,
            None => &mut [],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_release() {
        let mut pool = BufferPool::new(4, DEFAULT_BUF_SIZE).expect("pool");
        assert_eq!(pool.free_slots(), 4);
        let a = pool.take().expect("slot");
        let b = pool.take().expect("slot");
        assert_eq!(pool.free_slots(), 2);
        pool.release(a);
        assert_eq!(pool.free_slots(), 3);
        let _c = pool.take();
        let d = pool.take();
        assert!(d.is_some());
        pool.release(b);
    }

    #[test]
    fn exhaustion() {
        let mut pool = BufferPool::new(2, DEFAULT_BUF_SIZE).expect("pool");
        let _ = pool.take();
        let _ = pool.take();
        assert!(pool.take().is_none(), "pool exhausted");
    }

    #[test]
    fn rejects_zero_capacity_and_size() {
        assert!(BufferPool::new(0, 64).is_none());
        assert!(BufferPool::new(4, 0).is_none());
    }

    #[test]
    fn arbitrary_slot_size_is_accepted() {
        // Genericized vs vane-core: any fixed size works, not just 4096.
        let mut pool = BufferPool::new(3, 16_384).expect("pool");
        assert_eq!(pool.buf_size(), 16_384);
        assert_eq!(pool.capacity(), 3);
        let s = pool.take().expect("slot");
        pool.slot_mut(s).fill(0xAB);
        assert!(pool.slot(s).iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn slots_have_distinct_stable_addresses() {
        let pool = BufferPool::new(4, 256).expect("pool");
        let a = pool.slot(0).as_ptr();
        let b = pool.slot(1).as_ptr();
        let a2 = pool.slot(0).as_ptr();
        assert_ne!(a, b);
        assert_eq!(a, a2, "slot addresses must be stable");
    }

    #[test]
    fn out_of_range_slot_reads_empty() {
        let pool = BufferPool::new(2, 64).expect("pool");
        assert!(pool.slot(99).is_empty());
    }
}
