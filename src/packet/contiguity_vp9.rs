use super::contiguity::FrameContiguityState;
use super::Vp9CodecExtra;

#[derive(Debug, Default)]
pub struct Vp9Contiguity {
    /// last picture id of layer 0 that we allowed emitting
    last_tl0_picture_id: Option<u8>,

    /// last picture id of any layer that we allowed emitting
    last_picture_id: Option<u16>,
}

impl Vp9Contiguity {
    pub fn new() -> Self {
        Self::default()
    }

    /// Called when depacketizing a new frame is ready to be emitted
    ///
    /// Returns whether we can emit such frame and whether it's decodable with contiguity
    pub fn check(&mut self, next: &Vp9CodecExtra, contiguous_seq: bool) -> (bool, bool) {
        let mut frame_state: FrameContiguityState = self.into();
        let res = frame_state.next_frame(
            Some(next.pid.into()),
            next.tl0_picture_id.map(Into::into),
            next.tid.map(Into::into),
            contiguous_seq,
        );

        *self = frame_state.into();
        res
    }
}

impl From<&mut Vp9Contiguity> for FrameContiguityState {
    fn from(value: &mut Vp9Contiguity) -> Self {
        Self {
            last_picture_id: value.last_picture_id.map(Into::into),
            last_tl0_picture_id: value.last_tl0_picture_id.map(Into::into),
        }
    }
}

impl From<FrameContiguityState> for Vp9Contiguity {
    fn from(value: FrameContiguityState) -> Self {
        Self {
            last_picture_id: value.last_picture_id.and_then(|v| v.try_into().ok()),
            last_tl0_picture_id: value.last_tl0_picture_id.and_then(|v| v.try_into().ok()),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::packet::Vp9CodecExtra;

    use super::Vp9Contiguity;

    const L1T3_LAYERS: &[u64] = &[0, 2, 1, 2];
    const L1T2_LAYERS: &[u64] = &[0, 1, 0, 1];

    fn get_codec_extra(pid: u16, tid: u8, tl0_picture_id: u8) -> Vp9CodecExtra {
        Vp9CodecExtra {
            pid,
            tid: Some(tid),
            tl0_picture_id: Some(tl0_picture_id),
            ..Default::default()
        }
    }

    #[test]
    fn contiguous_l1t3() {
        let mut contiguity = Vp9Contiguity::new();

        for i in 0..100 {
            let next = get_codec_extra(i, L1T3_LAYERS[i as usize % 4] as u8, (i / 4) as u8);

            let res = contiguity.check(&next, true);
            assert_eq!(res, (true, true), "Failure at picture {} {:?}", i, next);
        }
    }

    #[test]
    fn contiguous_l1t3_no_l2_contig_l0() {
        const L1T3_LAYERS: &[u64] = &[0, 2, 1, 2];

        let mut contiguity = Vp9Contiguity::new();

        for i in 0..100 {
            let layer_index = L1T3_LAYERS[i as usize % 4] as u8;
            if layer_index == 2 {
                continue;
            }

            let next = get_codec_extra(i, layer_index, (i / 4) as u8);
            let (emit, contiguous) = contiguity.check(&next, true);

            // all layer 0 are contiguous therefore no discontinuity
            assert_eq!(emit, next.tid == Some(0));
            assert!(contiguous);

            if layer_index == 1 {
                // frames on layer 1 are not emitted (could be improved tracking more deps)
                // and we don't raise a discontinuity (stream still decodable)
                assert!(!emit);
                assert!(contiguous);
            }
        }
    }

    #[test]
    fn contiguous_l1t3_no_l2_discontig_l0() {
        const L1T3_LAYERS: &[u64] = &[0, 2, 1, 2];

        let mut contiguity = Vp9Contiguity::new();

        for i in 0..100 {
            let layer_index = L1T3_LAYERS[i as usize % 4] as u8;
            if layer_index == 2 {
                continue;
            }

            let next = get_codec_extra(i, layer_index, i as u8);
            let (emit, _) = contiguity.check(&next, true);

            assert!(emit == (next.tid == Some(0)));
        }
    }

    #[test]
    fn contiguous_l1t2() {
        let mut contiguity = Vp9Contiguity::new();

        for i in 0..100 {
            let next = get_codec_extra(i, L1T2_LAYERS[i as usize % 4] as u8, (i / 2) as u8);

            let res = contiguity.check(&next, true);
            assert_eq!(res, (true, true), "Failure at picture {} {:?}", i, next);
        }
    }

    #[test]
    fn contiguous_l1t1_no_l1_contig_l0() {
        let mut contiguity = Vp9Contiguity::new();

        for i in 0..100 {
            let layer_index = L1T2_LAYERS[i as usize % 4] as u8;
            if layer_index == 1 {
                continue;
            }

            let next = get_codec_extra(i, layer_index, (i / 2) as u8);
            let (emit, _) = contiguity.check(&next, true);

            // all layer 0 are contiguous therefore can be emitted
            assert_eq!(emit, next.tid == Some(0));
        }
    }
}
