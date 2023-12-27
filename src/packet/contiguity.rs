use super::vp8_contiguity::Vp8Contiguity;
use super::vp9_contiguity::Vp9Contiguity;
use super::CodecExtra;

#[derive(Debug)]
pub enum Contiguity {
    Vp8(Vp8Contiguity),
    Vp9(Vp9Contiguity),
    None,
}

impl Contiguity {
    pub fn check(&mut self, next: &CodecExtra, contiguous_seq: bool) -> (bool, bool) {
        match (self, next) {
            (Self::Vp8(contiguity), CodecExtra::Vp8(next)) => {
                contiguity.check(next, contiguous_seq)
            }
            (Self::Vp9(contiguity), CodecExtra::Vp9(next)) => {
                contiguity.check(next, contiguous_seq)
            }
            (Self::Vp8(_) | Self::Vp9(_) | Self::None, _) => (true, contiguous_seq),
        }
    }
}
