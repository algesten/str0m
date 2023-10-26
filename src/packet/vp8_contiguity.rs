use super::Vp8CodecExtra;
use std::collections::VecDeque;

#[derive(Debug)]
pub struct Vp8Contiguity {
    /// last picture id of layer 0 that we allowed emitting
    last_tl0_picture_id: Option<u64>,
    /// last picture id of any layer that we allowed emitting
    last_picture_id: Option<u64>,
}

impl Vp8Contiguity {
    pub fn new() -> Self {
        Vp8Contiguity {
            last_tl0_picture_id: None,
            last_picture_id: None,
        }
    }

    /// Called when depacketizing a new frame is ready to be emitted
    ///
    /// Returns whether we can emit suchfameh and whether it's decodable with contiguity
    pub fn check(&mut self, next: &Vp8CodecExtra, contiguous_seq: bool) -> (bool, bool) {
        let Some(picture_id) = next.picture_id else {
            // picture id is not enabled or not progressing anyway
            return (true, contiguous_seq);
        };

        let Some(tl0_picture_id) = next.tl0_picture_id else {
            return (true, contiguous_seq);
        };

        let (Some(last_tl0_picture_id), Some(last_picture_id)) =
            (self.last_tl0_picture_id, self.last_picture_id)
        else {
            self.last_tl0_picture_id = Some(tl0_picture_id);
            self.last_picture_id = Some(picture_id);
            return (true, true);
        };

        // discard older pictures if any
        if picture_id <= last_picture_id {
            return (false, true);
        }

        if next.layer_index == 0 {
            if tl0_picture_id == last_tl0_picture_id {
                warn!("VP8: 2 subsequent frames on layer zero must have different tl0 picture id: encoding problem?")
            }

            // Frame on layer 0: always emit and report discontinuity if not subsequent
            let emit = true;
            // note: we use wrapping add because the encoder can restart if the
            // camera is closed / reopened and here we only care about
            // contiguity
            let contiguous = tl0_picture_id == last_tl0_picture_id.wrapping_add(1);

            self.last_tl0_picture_id = Some(tl0_picture_id);
            self.last_picture_id = Some(picture_id);

            return (emit, contiguous);
        }

        // Frame on layer 1 or 2: only emit if they refer to the current layer 0
        // and they are subsequent
        let emit =
            tl0_picture_id == last_tl0_picture_id && picture_id == last_picture_id.wrapping_add(1);

        if emit {
            self.last_picture_id = Some(picture_id);
            if !contiguous_seq {
                // this as happened in Safari + very lossy network (very rare)
                warn!("VP8: contiguous pictures implies contiguous seq numbers: encoding issue ?")
            }
        }

        (emit, true)
    }
}

#[cfg(test)]
mod test {
    use tracing_subscriber::layer;

    use super::Vp8Contiguity;
    const L1T3_LAYERS: &[u64] = &[0, 2, 1, 2];
    const L1T2_LAYERS: &[u64] = &[0, 1, 0, 1];

    #[test]
    fn contiguous_l1t3() {
        let mut contiguity = Vp8Contiguity::new();

        for i in 0..100 {
            let mut next = &crate::packet::Vp8CodecExtra {
                discardable: false,
                sync: true,
                layer_index: L1T3_LAYERS[i as usize % 4] as u8,
                picture_id: Some(i),
                tl0_picture_id: Some(i / 4),
            };

            let res = contiguity.check(next, true);
            assert_eq!(res, (true, true), "Failure at picture {} {:?}", i, next);
        }
    }

    #[test]
    fn contiguous_l1t3_no_l2_contig_l0() {
        const L1T3_LAYERS: &[u64] = &[0, 2, 1, 2];

        let mut contiguity = Vp8Contiguity::new();

        for i in 0..100 {
            let layer_index = L1T3_LAYERS[i as usize % 4] as u8;
            if layer_index == 2 {
                continue;
            }

            let mut next = &crate::packet::Vp8CodecExtra {
                discardable: false,
                sync: i % 8 == 0,
                layer_index,
                picture_id: Some(i),
                tl0_picture_id: Some(i / 4),
            };

            let (emit, contiguous) = contiguity.check(next, true);

            // all layer 0 are contiguous therefore no discontinuity
            assert_eq!(emit, next.layer_index == 0);
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

        let mut contiguity = Vp8Contiguity::new();

        for i in 0..100 {
            let layer_index = L1T3_LAYERS[i as usize % 4] as u8;
            if layer_index == 2 {
                continue;
            }

            let mut next = &crate::packet::Vp8CodecExtra {
                discardable: false,
                sync: i % 8 == 0,
                layer_index,
                picture_id: Some(i),
                tl0_picture_id: Some(i),
            };

            let (emit, contiguous) = contiguity.check(next, true);

            assert!(emit == (next.layer_index == 0));
        }
    }

    #[test]
    fn contiguous_l1t2() {
        let mut contiguity = Vp8Contiguity::new();

        for i in 0..100 {
            let mut next = &crate::packet::Vp8CodecExtra {
                discardable: false,
                sync: true,
                layer_index: L1T2_LAYERS[i as usize % 4] as u8,
                picture_id: Some(i),
                tl0_picture_id: Some(i / 2),
            };

            let res = contiguity.check(next, true);
            assert_eq!(res, (true, true), "Failure at picture {} {:?}", i, next);
        }
    }

    #[test]
    fn contiguous_l1t1_no_l1_contig_l0() {
        const L1T3_LAYERS: &[u64] = &[0, 2, 1, 2];

        let mut contiguity = Vp8Contiguity::new();

        for i in 0..100 {
            let layer_index = L1T2_LAYERS[i as usize % 4] as u8;
            if layer_index == 1 {
                continue;
            }

            let mut next = &crate::packet::Vp8CodecExtra {
                discardable: false,
                sync: i % 8 == 0,
                layer_index,
                picture_id: Some(i),
                tl0_picture_id: Some(i / 2),
            };

            let (emit, contiguous) = contiguity.check(next, true);

            // all layer 0 are contiguous therefore can be emitted
            assert_eq!(emit, next.layer_index == 0);
        }
    }
}
