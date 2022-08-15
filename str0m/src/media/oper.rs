use sdp::Sdp;

pub trait Oper {
    type Input;
    type Output;

    fn chain<B>(self, next: B) -> Chain<Self, B>
    where
        Self: Sized,
        B: Oper<Input = Self::Output>,
    {
        Chain(self, next)
    }

    fn configure(&mut self, sdp: &Sdp) {}

    fn run(&mut self, input: &Self::Input) -> Self::Output;
}

pub struct Chain<A, B>(A, B);

impl<A, B> Oper for Chain<A, B>
where
    A: Oper,
    B: Oper<Input = A::Output>,
{
    type Input = A::Input;
    type Output = B::Output;

    fn run(&mut self, input: &Self::Input) -> Self::Output {
        let a_out = self.0.run(input);
        self.1.run(&a_out)
    }
}

// pub struct OperState(AnyMap);

// impl OperState {
//     pub fn get<T: Default + Send + Sync + 'static>(&self) -> Option<&T> {
//         self.0
//             .get(&TypeId::of::<T>())
//             .and_then(|boxed| (&**boxed as &(dyn Any + 'static)).downcast_ref())
//     }

//     pub fn get_mut<T: Default + Send + Sync + 'static>(&mut self) -> &mut T {
//         (self
//             .0
//             .entry(TypeId::of::<T>())
//             .or_insert_with(|| Box::new(T::default())) as &mut (dyn Any + 'static))
//             .downcast_mut()
//             .expect("downcast_mut to be a value")
//     }
// }

// pub type AnyMap = HashMap<TypeId, Box<dyn Any + Send + Sync>, BuildHasherDefault<IdHasher>>;

// #[derive(Default)]
// struct IdHasher(u64);

// impl Hasher for IdHasher {
//     fn write(&mut self, _: &[u8]) {
//         unreachable!("TypeId is hashed with a u64");
//     }

//     #[inline]
//     fn write_u64(&mut self, id: u64) {
//         self.0 = id;
//     }

//     #[inline]
//     fn finish(&self) -> u64 {
//         self.0
//     }
// }
