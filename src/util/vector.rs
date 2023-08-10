use std::collections::VecDeque;

pub trait VecExtended<T> {
    fn push_get_last_mut(&mut self, item: T) -> &mut T;
    fn found_or_insert<F, C>(&mut self, compare: F, creator: C) -> &mut T
    where
        F: FnMut(&T) -> bool,
        C: FnMut() -> T;
}

impl<T> VecExtended<T> for Vec<T> {
    fn push_get_last_mut(&mut self, item: T) -> &mut T {
        self.push(item);
        self.last_mut()
            .expect("should get last because of just pushed")
    }

    fn found_or_insert<F, C>(&mut self, compare: F, mut creator: C) -> &mut T
    where
        F: FnMut(&T) -> bool,
        C: FnMut() -> T,
    {
        let idx = self.iter().position(compare);
        if let Some(idx) = idx {
            self.get_mut(idx).unwrap()
        } else {
            let e = creator();
            self.push_get_last_mut(e)
        }
    }
}
pub trait VecDequeExtended<T> {
    fn push_last_get_mut(&mut self, item: T) -> &mut T;
}

impl<T> VecDequeExtended<T> for VecDeque<T> {
    fn push_last_get_mut(&mut self, item: T) -> &mut T {
        self.push_back(item);
        self.back_mut()
            .expect("should get last because of just pushed")
    }
}
