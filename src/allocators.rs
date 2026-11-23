use std::alloc::{Allocator, Global};

/// A `len` long `Vec` of zeroes, allocated from `alloc`.
pub(crate) fn zeroed_in<A: Allocator>(len: usize, alloc: A) -> Vec<u8, A> {
    let mut v = Vec::with_capacity_in(len, alloc);
    v.resize(len, 0);
    v
}

/// A copy of `data`, allocated from `alloc`.
pub(crate) fn copied_in<T: Clone, A: Allocator>(data: &[T], alloc: A) -> Vec<T, A> {
    let mut v = Vec::with_capacity_in(data.len(), alloc);
    v.extend_from_slice(data);
    v
}

// TODO (Claue): This might be better as an Ext on Allocator
/// An allocator that can adopt bytes allocated from [`Global`], copying them when it must.
pub(crate) trait FromGlobal: Allocator + Copy {
    fn adopt(self, bytes: Vec<u8>) -> Vec<u8, Self>;
}

impl FromGlobal for Global {
    fn adopt(self, bytes: Vec<u8>) -> Vec<u8, Self> {
        bytes
    }
}

impl<S: Allocator> FromGlobal for &S {
    fn adopt(self, bytes: Vec<u8>) -> Vec<u8, Self> {
        copied_in(&bytes, self)
    }
}
