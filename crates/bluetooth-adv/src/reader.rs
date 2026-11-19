//! A bounds-checked cursor over a byte slice. Every read returns `None`
//! instead of panicking when the data runs out.

#[derive(Debug, Clone)]
pub(crate) struct Reader<'a> {
    data: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    pub(crate) fn remaining(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        self.data
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.data.len() {
            return None;
        }
        let (head, tail) = self.data.split_at(n);
        self.data = tail;
        Some(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N).and_then(|s| s.try_into().ok())
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.array::<1>().map(|b| b[0])
    }

    pub(crate) fn i8(&mut self) -> Option<i8> {
        self.u8().map(|b| b as i8)
    }

    pub(crate) fn u16_le(&mut self) -> Option<u16> {
        self.array().map(u16::from_le_bytes)
    }

    pub(crate) fn u16_be(&mut self) -> Option<u16> {
        self.array().map(u16::from_be_bytes)
    }

    pub(crate) fn i16_be(&mut self) -> Option<i16> {
        self.array().map(i16::from_be_bytes)
    }

    pub(crate) fn u32_be(&mut self) -> Option<u32> {
        self.array().map(u32::from_be_bytes)
    }

    /// An unsigned little-endian integer of `n` bytes (1 to 4).
    pub(crate) fn uint_le(&mut self, n: usize) -> Option<u32> {
        let b = self.take(n)?;
        Some(
            b.iter()
                .rev()
                .fold(0u32, |acc, x| (acc << 8) | u32::from(*x)),
        )
    }

    /// A signed little-endian integer of `n` bytes (1 to 4).
    pub(crate) fn sint_le(&mut self, n: usize) -> Option<i32> {
        let v = self.uint_le(n)?;
        let shift = 32 - 8 * n as u32;
        Some(((v << shift) as i32) >> shift)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_and_runs_out() {
        let mut r = Reader::new(&[0x01, 0xff, 0x80, 0x00, 0x7f]);
        assert_eq!(r.u8(), Some(1));
        assert_eq!(r.sint_le(1), Some(-1));
        assert_eq!(r.sint_le(2), Some(0x0080));
        assert_eq!(r.u16_le(), None);
        assert_eq!(r.remaining(), 1);
        assert_eq!(Reader::new(&[0xff, 0xff, 0xff]).sint_le(3), Some(-1));
        assert_eq!(
            Reader::new(&[0x00, 0x00, 0x80]).sint_le(3),
            Some(-8_388_608)
        );
    }
}
