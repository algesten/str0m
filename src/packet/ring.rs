#[derive(Debug)]
pub struct RingBuf<T> {
    buffer: Vec<Option<T>>,
    max: u64,
    // This is an u64 since it is ever growing and used as an identifier.
    next: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd)]
pub struct Ident(u64);

impl Ident {
    pub fn increase(&self) -> Ident {
        Ident(self.0 + 1)
    }
}

impl<T> RingBuf<T> {
    pub fn new(max: usize) -> Self {
        // We don't want to require T: Clone.
        let mut buffer = Vec::with_capacity(max);
        for _ in 0..max {
            buffer.push(None);
        }

        Self {
            buffer,
            max: max as u64,
            next: 0,
        }
    }

    pub fn push(&mut self, t: T) -> (Ident, Option<T>) {
        let idx = (self.next % self.max) as usize;

        let prev = self.buffer[idx].take();
        self.buffer[idx] = Some(t);

        let ident = Ident(self.next);
        self.next += 1;

        (ident, prev)
    }

    fn in_scope(&self, i: Ident) -> Option<usize> {
        let range = (self.first_ident()?.0)..=(self.last_ident()?.0);
        if range.contains(&i.0) {
            Some((i.0 % self.max) as usize)
        } else {
            None
        }
    }

    pub fn get(&self, i: Ident) -> Option<&T> {
        let idx = self.in_scope(i)?;
        self.buffer[idx].as_ref()
    }

    pub fn get_mut(&mut self, i: Ident) -> Option<&mut T> {
        let idx = self.in_scope(i)?;
        self.buffer[idx].as_mut()
    }

    pub fn first_ident(&self) -> Option<Ident> {
        if self.next == 0 {
            return None;
        }

        let idx = self.next.saturating_sub(self.max);

        Some(Ident(idx))
    }

    pub fn last_ident(&self) -> Option<Ident> {
        if self.next == 0 {
            return None;
        }

        Some(Ident(self.next - 1))
    }

    pub fn first(&self) -> Option<&T> {
        let idx = self.first_ident()?.0 % self.max;
        self.buffer[idx as usize].as_ref()
    }

    pub fn last(&self) -> Option<&T> {
        let idx = self.last_ident()?.0 % self.max;
        self.buffer[idx as usize].as_ref()
    }

    pub fn len(&self) -> usize {
        let loop_c = (self.next - 1) / self.max;

        if loop_c == 0 {
            (self.next % self.max) as usize
        } else {
            self.max as usize
        }
    }

    pub fn remove(&mut self, i: Ident) -> Option<T> {
        let idx = self.in_scope(i)?;
        self.buffer[idx].take()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn before_full() {
        let mut rb = RingBuf::<u8>::new(5);

        let (id0, _) = rb.push(0);
        let (id1, _) = rb.push(1);
        let (id2, _) = rb.push(2);

        assert_eq!(rb.len(), 3);
        assert_eq!(rb.get(id0), Some(&0));
        assert_eq!(rb.get(id1), Some(&1));
        assert_eq!(rb.get(id2), Some(&2));
        assert_eq!(rb.first(), Some(&0));
        assert_eq!(rb.last(), Some(&2));
    }

    #[test]
    fn after_full() {
        let mut rb = RingBuf::<u8>::new(5);

        let (id0, _) = rb.push(0);
        let (id1, _) = rb.push(1);
        let (id2, _) = rb.push(2);
        let (id3, _) = rb.push(3);
        let (id4, _) = rb.push(4);
        let (id5, _) = rb.push(5);

        assert_eq!(rb.len(), 5);
        assert_eq!(rb.get(id0), None);
        assert_eq!(rb.get(id1), Some(&1));
        assert_eq!(rb.get(id2), Some(&2));
        assert_eq!(rb.get(id3), Some(&3));
        assert_eq!(rb.get(id4), Some(&4));
        assert_eq!(rb.get(id5), Some(&5));
    }
}
