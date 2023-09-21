#![allow(unused)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::collapsible_else_if)]

pub trait Unsigned {
    const BITS: usize;
    fn convert(v: u64) -> Self;
}

pub trait Signed {
    const BITS: usize;
    fn convert(v: i64) -> Self;
}

macro_rules! impl_convert {
    ($trait: ty, $source: ty, $( $num_type: ty ),* ) => {
        $(
            impl $trait for $num_type {
                const BITS: usize = Self::BITS as usize;

                fn convert(v: $source) -> Self {
                    v.try_into().unwrap()
                }
            }
        )*
    }
}

impl_convert!(Unsigned, u64, u8, u16, u32, u64, usize);
impl_convert!(Signed, i64, i8, i16, i32, i64, isize);

pub struct BitStream<'a> {
    data: &'a [u8],
    idx: usize,
    remain: usize,
    tmp: u8,
    rbsp: u8,
}

impl<'a> BitStream<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BitStream {
            data,
            idx: 0,
            remain: 0,
            tmp: 0,
            rbsp: 0,
        }
    }

    #[inline(always)]
    pub fn read_bits(&mut self, mut num: usize) -> Option<u64> {
        let mut r = 0;

        while num > 0 {
            if self.remain == 0 {
                if self.idx >= self.data.len() {
                    return None;
                }
                self.tmp = self.data[self.idx];
                self.idx += 1;

                if self.rbsp > 0 && self.idx >= 2 && self.idx < self.data.len() {
                    if self.data[self.idx - 2..=self.idx] == [0, 0, 3] {
                        self.idx += 1;
                    }
                }
                self.remain = 8;
            }

            num -= 1;
            self.remain -= 1;
            if self.tmp & (1 << self.remain) > 0 {
                r |= 1 << num;
            }
        }

        Some(r)
    }

    /// Skip up to 64 bits.
    pub fn skip_bits(&mut self, num: usize) {
        self.read_bits(num);
    }

    /// Skip a given number of bytes.
    ///
    /// Panics if not called at a byte boundary.
    pub fn skip_bytes(&mut self, num: usize) {
        assert!(self.at_byte_boundary());
        let new_idx = self.idx + num;
        assert!(new_idx < self.data.len());
        self.idx = new_idx;
    }

    #[inline(always)]
    pub fn read_bits1(&mut self) -> Option<u64> {
        self.read_bits(1)
    }

    pub fn read_golomb_ue(&mut self) -> Option<u64> {
        let mut b = 0;
        let mut lzb = -1;

        loop {
            if b != 0 {
                break;
            }
            lzb += 1;
            b = self.read_bits1()?;

            if self.bits_left() == 0 {
                return if b == 1 { Some(0) } else { None };
            }
        }

        if lzb < 0 {
            return Some(0);
        }

        let rl = self.read_bits(lzb as usize)?;

        Some((1 << (lzb as usize)) - 1 + rl)
    }

    pub fn read_golomb_se(&mut self) -> Option<i64> {
        let mut r = self.read_golomb_ue()? as i64;

        if r == 0 {
            return Some(0);
        }

        let pos = r & 1;

        r = (r + 1) >> 1;

        Some(if pos > 0 { r } else { -r })
    }

    pub fn bits_left(&mut self) -> usize {
        self.remain + self.data.len() * 8
    }

    /// Read a single bit flag.
    pub fn read_bit_flag(&mut self) -> Option<bool> {
        self.read_bits1().map(|b| b == 1)
    }

    /// Read an unsigned number.
    pub fn read_unsigned<T: Unsigned>(&mut self) -> Option<T> {
        self.read_bits(T::BITS).map(T::convert)
    }

    /// Read an signed number.
    pub fn read_signed<T: Signed>(&mut self) -> Option<T> {
        self.read_bits(T::BITS).map(|v| v as i64).map(T::convert)
    }

    pub fn into_slice(self) -> &'a [u8] {
        self.as_slice()
    }

    pub fn as_slice(&self) -> &'a [u8] {
        if self.remain > 0 {
            &self.data[self.idx - 1..]
        } else {
            &self.data[self.idx..]
        }
    }

    pub fn idx(&self) -> usize {
        self.idx
    }

    pub fn at_byte_boundary(&self) -> bool {
        self.remain == 0
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_read_bits() {
        let mut bs = BitStream::new(&[0b10101010]);
        assert_eq!(bs.read_bits(1), Some(1));
        assert_eq!(bs.read_bits(1), Some(0));
        assert_eq!(bs.read_bits(1), Some(1));
        assert_eq!(bs.read_bits(1), Some(0));
        assert_eq!(bs.read_bits(1), Some(1));
        assert_eq!(bs.read_bits(1), Some(0));
        assert_eq!(bs.read_bits(1), Some(1));
        assert_eq!(bs.read_bits(1), Some(0));
        assert_eq!(bs.read_bits(1), None); // over reading
        assert_eq!(bs.read_bits(1), None);

        let mut bs = BitStream::new(&[0b10101010]);
        assert_eq!(bs.read_bits(3), Some(5));
        assert_eq!(bs.read_bits(3), Some(2));
        assert_eq!(bs.read_bits(3), None); // over reading
        assert_eq!(bs.read_bits(3), None);

        let mut bs = BitStream::new(&[0b10101010, 0b01010101]);
        assert_eq!(bs.read_bits(3), Some(5));
        assert_eq!(bs.read_bits(3), Some(2));
        assert_eq!(bs.read_bits(3), Some(4));
        assert_eq!(bs.read_bits(3), Some(5));
        assert_eq!(bs.read_bits(3), Some(2));
        assert_eq!(bs.read_bits(1), Some(1));
        assert_eq!(bs.read_bits(1), None); // over reading

        let mut bs = BitStream::new(&[0b10101010, 0b01010101]);
        assert_eq!(bs.read_bits(11), Some(1362));
        assert_eq!(bs.read_bits(5), Some(21));
    }

    #[test]
    fn test_golomb_ue() {
        let mut bs = BitStream::new(&[0b10000000]);
        assert_eq!(bs.read_golomb_ue(), Some(0));

        let mut bs = BitStream::new(&[0b01000000]);
        assert_eq!(bs.read_golomb_ue(), Some(1));

        let mut bs = BitStream::new(&[0b01100000]);
        assert_eq!(bs.read_golomb_ue(), Some(2));

        let mut bs = BitStream::new(&[0b00010000]);
        assert_eq!(bs.read_golomb_ue(), Some(7));

        let mut bs = BitStream::new(&[0b00010010]);
        assert_eq!(bs.read_golomb_ue(), Some(8));
    }

    #[test]
    fn test_golomb_se() {
        let mut bs = BitStream::new(&[0b10000000]);
        assert_eq!(bs.read_golomb_se(), Some(0));

        let mut bs = BitStream::new(&[0b01000000]);
        assert_eq!(bs.read_golomb_se(), Some(1));

        let mut bs = BitStream::new(&[0b01100000]);
        assert_eq!(bs.read_golomb_se(), Some(-1));

        let mut bs = BitStream::new(&[0b00010000]);
        assert_eq!(bs.read_golomb_se(), Some(4));

        let mut bs = BitStream::new(&[0b00010010]);
        assert_eq!(bs.read_golomb_se(), Some(-4));
    }

    #[test]
    fn test_read_signed_i64_high_bit_set() {
        let mut bs = BitStream::new(&[0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]);

        let value: i64 = bs
            .read_signed()
            .expect("Should be able to read i64 with high bit set");
        assert_eq!(value, i64::MIN);
    }
}
