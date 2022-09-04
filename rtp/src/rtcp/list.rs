use std::ops::Index;

/// List containing max 31 items.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportList<T>([Option<T>; 31]);

impl<T> ReportList<T> {
    pub fn len(&self) -> usize {
        self.0.iter().position(|i| i.is_none()).unwrap()
    }

    pub fn push(&mut self, v: T) {
        let pos = self.len();
        self.0[pos] = Some(v);
    }

    pub fn get(&self, i: usize) -> Option<&T> {
        self.0[i].as_ref()
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.into_iter()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub(crate) fn is_full(&self) -> bool {
        self.len() == 31
    }

    pub(crate) fn append_all_possible(&mut self, other: &mut Self, max: usize) -> usize {
        let pos = self.len();
        let to_move = (31 - pos).min(other.len()).min(max);

        for i in 0..to_move {
            self.0[pos + i] = other.0[i].take();
        }

        // shift down remaining in other
        for i in to_move..31 {
            other.0[i - to_move] = other.0[i].take();
        }

        // return number of appended items.
        to_move
    }
}

impl<T> Index<usize> for ReportList<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        self.0[index].as_ref().unwrap()
    }
}

impl<T> Default for ReportList<T> {
    fn default() -> Self {
        // We don't want to require T: Copy.
        ReportList([
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None, None, None, None, None, None, None, None, None, None, None, None,
            None, None, None,
        ])
    }
}

impl<'a, T> IntoIterator for &'a ReportList<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        Iter(self, 0)
    }
}

pub struct Iter<'a, T>(&'a ReportList<T>, usize);

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        let n = self.0 .0[self.1].as_ref();
        if n.is_some() {
            self.1 += 1;
        }
        n
    }
}

impl<T> From<T> for ReportList<T> {
    fn from(t: T) -> Self {
        let mut l = ReportList::default();
        l.push(t);
        l
    }
}
