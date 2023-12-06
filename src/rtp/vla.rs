use std::collections::VecDeque;

use super::{ExtensionSerializer, ExtensionValues};

#[allow(dead_code)]
/// URI for the Video Layers Allocation RTP Header Extension
pub const URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/video-layers-allocation00";

/// Top-level "allocation" for the Video Layers Allocation RTP Header Extension
/// Contains allocations for many simulcast streams, which contain many spatial layers.
/// In practice, there are either many simulcast streams with 1 spatial layer each (simulcast)
/// or 1 simulcast stream with many spatial layers (SVC)
/// or 1 simulcast stream with 1 spatial layer (only temporal layers used).
/// But theoretically, you could have N simulcast streams with M spatial layers each.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VideoLayersAllocation {
    /// The index of the current simulcast stream.
    /// AKA RTP stream index
    /// Set to 0 when everything is inactive (the special case of the header extension being just 0).
    /// Erroneously called "RID" in the spec.
    pub current_simulcast_stream_index: u8,

    /// AKA RTP streams
    pub simulcast_streams: Vec<SimulcastStreamAllocation>,
}

/// An allocation for a simulcast stream, which may contain many allocations for spatial layers.
/// There may be many of these per top-level allocation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SimulcastStreamAllocation {
    /// May contains many spatial layers, or none.
    pub spatial_layers: Vec<SpatialLayerAllocation>,
}

/// An allocation for a spatial layer, which may contain many allocations for temporal layers.
/// There may be many per simulcast stream.
/// Also contains an optional resolution and framerate.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SpatialLayerAllocation {
    /// Contains many temporal layers, or none.
    /// If empty, the spatial layer is not active.
    pub temporal_layers: Vec<TemporalLayerAllocation>,
    /// Contains an optional resolution and framerate
    pub resolution_and_framerate: Option<ResolutionAndFramerate>,
}

/// An allocation for a temporal layer.  There may be many per spatial layer.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TemporalLayerAllocation {
    /// Cumulative bitrate for this temporal layer and all below it within a spatial layer.
    pub cumulative_kbps: u64,
}

/// A resolution and a frame rate, tied together because that's how it's formed in
/// the header extension. Either they are both there or neither are there.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolutionAndFramerate {
    /// Width in number of pixels
    pub width: u16,
    /// Height in number of pixels
    pub height: u16,
    /// Framerate in frames per second
    pub framerate: u8,
}

impl VideoLayersAllocation {
    #[allow(dead_code)]
    fn parse(buf: &[u8]) -> Option<Self> {
        // First byte
        let (&b0, after_b0) = buf.split_first()?;
        if b0 == 0u8 && after_b0.is_empty() {
            // Special case when everything is inactive.
            return Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![],
            });
        }
        let current_simulcast_stream_index = read_bits(b0, 0..2);
        let simulcast_stream_count = read_bits(b0, 2..4) + 1;
        let shared_spatial_layer_bitmask = read_bits(b0, 4..8);

        // Spatial layer bitmasks, which can be either "shared" or not.
        // If shared, each simulcast stream as the same spatial layers active.
        // If not, each simulcast stream has its own 4 bits indicating which spatial layers are active.
        let (spatial_layer_active_bits, after_spatial_layer_bitmasks) =
            if shared_spatial_layer_bitmask > 0 {
                let shared_spatial_layer_active_bits =
                    read_lower_4bits_ignoring_leading_zeros(shared_spatial_layer_bitmask);
                let spatial_layer_active_bits =
                    vec![shared_spatial_layer_active_bits; simulcast_stream_count as usize];
                let after_spatial_layer_bitmasks = after_b0;
                (spatial_layer_active_bits, after_spatial_layer_bitmasks)
            } else {
                // 4 bits per simulcast stream
                let (spatial_layer_bitmasks, after_spatial_layer_bitmasks) =
                    split_at(after_b0, div_round_up(simulcast_stream_count as usize, 2))?;
                let spatial_layer_actives = spatial_layer_bitmasks
                    .iter()
                    .flat_map(|&byte| split_byte_in2(byte))
                    .take(simulcast_stream_count as usize)
                    .map(read_lower_4bits_ignoring_leading_zeros)
                    .collect();
                (spatial_layer_actives, after_spatial_layer_bitmasks)
            };
        // The number of active bits that are set across all simulcast streams,
        // which is the number of active spatial layers across all simulcast streams.
        let total_active_spatial_layer_count = spatial_layer_active_bits
            .iter()
            .flatten()
            .filter(|&&active| active)
            .count();

        // Temporal layer counts
        // 2 bits per temporal layer
        let (temporal_layer_counts, after_temporal_layer_counts) = split_at(
            after_spatial_layer_bitmasks,
            div_round_up(total_active_spatial_layer_count, 4),
        )?;
        let mut temporal_layer_counts: VecDeque<u8> = temporal_layer_counts
            .iter()
            .flat_map(|&byte| split_byte_in4(byte))
            .map(|count_minus_1| count_minus_1 + 1)
            .take(total_active_spatial_layer_count)
            .collect();
        let total_temporal_layer_count = temporal_layer_counts.iter().sum();

        // Temporal layer bitrates
        let mut next_temporal_layer_bitrate = after_temporal_layer_counts;
        let mut temporal_layer_cumulative_bitrates: VecDeque<u64> = (0..total_temporal_layer_count)
            .map(|_temporal_layer_index| {
                let (bitrate, after_temporal_layer_bitrate) =
                    parse_leb_u63(next_temporal_layer_bitrate);
                next_temporal_layer_bitrate = after_temporal_layer_bitrate;
                bitrate
            })
            .collect();
        // libwebrtc fails to parse at a value of 1_000_000 kbps.  We are a little more forgiving, 
        // but since we limit the LEB parse at 63 bits, we should be at least that strict.
        if temporal_layer_cumulative_bitrates.iter().any(|&kbps| kbps > (1u64 << 63)) {
            return None
        }

        // (Optional) resolutions and framerates
        let mut next_resolution_and_framerate = next_temporal_layer_bitrate;
        let mut resolutions_and_framerates: VecDeque<ResolutionAndFramerate> = (0
            ..total_active_spatial_layer_count)
            .filter_map(|_| {
                let (resolution_and_framerate, after_resolution_and_framerate) =
                    split_at(next_resolution_and_framerate, 5)?;
                next_resolution_and_framerate = after_resolution_and_framerate;
                Some(ResolutionAndFramerate {
                    width: u16::from_be_bytes(resolution_and_framerate[0..2].try_into().unwrap())
                        + 1,
                    height: u16::from_be_bytes(resolution_and_framerate[2..4].try_into().unwrap())
                        + 1,
                    framerate: resolution_and_framerate[4],
                })
            })
            .collect();

        let simulcast_streams = spatial_layer_active_bits
            .into_iter()
            .map(|spatial_layer_actives| {
                let spatial_layers = spatial_layer_actives
                    .into_iter()
                    .filter_map(|spatial_layer_active| {
                        let (temporal_layers, resolution_and_framerate) = if spatial_layer_active {
                            let temporal_layer_count = temporal_layer_counts.pop_front()?;
                            let temporal_layers = (0..temporal_layer_count)
                                .filter_map(|_temporal_layer_index| {
                                    Some(TemporalLayerAllocation {
                                        cumulative_kbps: temporal_layer_cumulative_bitrates.pop_front()?,
                                    })
                                })
                                .collect();
                            let resolution_and_framerate = resolutions_and_framerates.pop_front();
                            (temporal_layers, resolution_and_framerate)
                        } else {
                            (vec![], None)
                        };
                        Some(SpatialLayerAllocation {
                            temporal_layers,
                            resolution_and_framerate,
                        })
                    })
                    .collect();
                SimulcastStreamAllocation { spatial_layers }
            })
            .collect();
        Some(VideoLayersAllocation {
            current_simulcast_stream_index,
            simulcast_streams,
        })
    }
}

/// Serializer of the Video Layers Allocation Header Extension
#[derive(Debug)]
pub struct Serializer;

impl ExtensionSerializer for Serializer {
    fn write_to(&self, _buf: &mut [u8], ev: &ExtensionValues) -> usize {
        if ev.user_values.get::<VideoLayersAllocation>().is_some() {
            // Writing the VLA header extension is currently not supported.
            todo!();
        }
        0
    }

    fn parse_value(&self, buf: &[u8], ev: &mut ExtensionValues) -> bool {
        let Some(vla) = VideoLayersAllocation::parse(buf) else {
            return false;
        };
        ev.user_values.set(vla);
        true
    }

    fn is_video(&self) -> bool {
        true
    }

    fn is_audio(&self) -> bool {
        false
    }

    fn requires_two_byte_form(&self, _ev: &ExtensionValues) -> bool {
        // Writing isn't implemented yet
        false
    }
}

// See https://en.wikipedia.org/wiki/LEB128
// Reads out at most 9 bytes (63 bits) unsigned
// returns (value, rest)
// libwebrtc reads out all 64 bits, but then fails the parse if the value
// is over 1_000_000 anyway, so reading 63 bits should be enough as long as
// we throw away the parse if it's above 1_000_000.
#[allow(dead_code)]
fn parse_leb_u63(bytes: &[u8]) -> (u64, &[u8]) {
    let mut result = 0;
    for (index, &byte) in bytes.iter().enumerate() {
        let is_last = !read_bit(byte, 0);
        let chunk = read_bits(byte, 1..8);
        result |= (chunk as u64) << (7 * index);
        if is_last || index == 8 {
            return (result, &bytes[(index + 1)..]);
        }
    }
    (0, bytes)
}

// If successful, the size of the left will be mid,
// and the size of the right while be buf.len()-mid.
#[allow(dead_code)]
fn split_at(buf: &[u8], mid: usize) -> Option<(&[u8], &[u8])> {
    if mid > buf.len() {
        return None;
    }
    Some(buf.split_at(mid))
}

#[allow(dead_code)]
fn div_round_up(top: usize, bottom: usize) -> usize {
    if top == 0 {
        0
    } else {
        ((top - 1) / bottom) + 1
    }
}

// Into 2 chunks of 4 bits
#[allow(dead_code)]
fn split_byte_in2(byte: u8) -> [u8; 2] {
    [read_bits(byte, 0..4), read_bits(byte, 4..8)]
}

// Into 4 chunks of 2 bits
#[allow(dead_code)]
fn split_byte_in4(byte: u8) -> [u8; 4] {
    [
        read_bits(byte, 0..2),
        read_bits(byte, 2..4),
        read_bits(byte, 4..6),
        read_bits(byte, 6..8),
    ]
}

// Ignore top 4 bits and leading zeros.  Then split into a Vec<bool>ca
fn read_lower_4bits_ignoring_leading_zeros(bits: u8) -> Vec<bool> {
    let mut count = 0;
    let mut bools: Vec<bool> = (0..=3u8)
        .map(|index| {
            let bit = read_bit(bits, 7 - index);
            if bit {
                count = index + 1;
            }
            bit
        })
        .collect();
    bools.truncate(count as usize);
    bools
}

#[allow(dead_code)]
fn read_bit(bits: u8, index: u8) -> bool {
    read_bits(bits, index..(index + 1)) > 0
}

#[allow(dead_code)]
fn read_bits(bits: u8, range: std::ops::Range<u8>) -> u8 {
    assert!(range.end <= 8);
    (bits >> (8 - range.end)) & (0b1111_1111 >> (8 - range.len()))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_read_bits() {
        assert_eq!(read_bits(0b1100_0000, 0..2), 0b0000_0011);
        assert_eq!(read_bits(0b1001_0101, 0..2), 0b0000_0010);
        assert_eq!(read_bits(0b0110_1010, 0..2), 0b0000_0001);
        assert_eq!(read_bits(0b0011_1111, 0..2), 0b0000_0000);
        assert_eq!(read_bits(0b0011_0000, 2..4), 0b0000_0011);
        assert_eq!(read_bits(0b0110_0101, 2..4), 0b0000_0010);
        assert_eq!(read_bits(0b1001_1010, 2..4), 0b0000_0001);
        assert_eq!(read_bits(0b1100_1111, 2..4), 0b0000_0000);
    }

    #[test]
    fn test_parse_leb_u63() {
        let (value, rest) = parse_leb_u63(&[0b0000_0000, 5]);
        assert_eq!(0, value);
        assert_eq!(&[5], rest);

        let (value, rest) = parse_leb_u63(&[0b0000_0001, 5]);
        assert_eq!(1, value);
        assert_eq!(&[5], rest);

        let (value, rest) = parse_leb_u63(&[0b1000_0000, 0b0000_0001, 5]);
        assert_eq!(128, value);
        assert_eq!(&[5], rest);

        let (value, rest) = parse_leb_u63(&[0b1000_0000, 0b1000_0000, 0b0000_0001, 5]);
        assert_eq!(16384, value);
        assert_eq!(&[5], rest);

        let (value, rest) = parse_leb_u63(&[0b1000_0000, 0b1000_0000, 0b1000_0000, 0b0000_0001, 5]);
        assert_eq!(2097152, value);
        assert_eq!(&[5], rest);

        let (value, rest) = parse_leb_u63(&[0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b0000_0001, 5]);
        assert_eq!(72057594037927936, value);
        assert_eq!(&[5], rest);

        // Too many bytes, so stop early.
        let (value, rest) = parse_leb_u63(&[0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0000, 0b1000_0001, 5]);
        assert_eq!(72057594037927936, value);
        assert_eq!(&[5], rest);
    }

    #[test]
    fn test_parse_vla_empty_buffer() {
        assert_eq!(VideoLayersAllocation::parse(&[]), None);
    }

    #[test]
    fn test_parse_vla_empty() {
        assert_eq!(
            VideoLayersAllocation::parse(&[0b0000_0000]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![],
            })
        );
    }

    #[test]
    fn test_parse_vla_missing_spatial_layer_bitmasks() {
        assert_eq!(VideoLayersAllocation::parse(&[0b0110_0000]), None);
    }

    #[test]
    fn test_parse_vla_1_simulcast_stream_with_no_active_layers() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0100_0000,
                // 1 bitmask
                0b0000_0000,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 1,
                simulcast_streams: vec![SimulcastStreamAllocation {
                    spatial_layers: vec![],
                }],
            })
        );
    }

    #[test]
    fn test_parse_vla_3_simulcast_streams_with_no_active_layers() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0110_0000,
                // 3 active spatial layer bitmasks, 4 bits each
                0b0000_0000,
                0b0000_1111,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 1,
                simulcast_streams: vec![
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    }
                ],
            })
        );
    }

    #[test]
    fn test_parse_vla_3_simulcast_streams_with_1_active_spatial_layers_and_2_temporal_layers() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0110_0001,
                // 3 temporal layer counts (minus 1), 2 bits each
                0b0101_0100,
                // 6 temporal layer bitrates
                0b0000_0001,
                0b0000_0010,
                0b0000_0100,
                0b0000_1000,
                0b0001_0000,
                0b0010_0000,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 1,
                simulcast_streams: vec![
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation { cumulative_kbps: 1 },
                                TemporalLayerAllocation { cumulative_kbps: 2 }
                            ],
                            resolution_and_framerate: None,
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation { cumulative_kbps: 4 },
                                TemporalLayerAllocation { cumulative_kbps: 8 }
                            ],
                            resolution_and_framerate: None,
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 16
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 32
                                }
                            ],
                            resolution_and_framerate: None,
                        }],
                    }
                ],
            })
        );
    }

    #[test]
    fn test_parse_vla_3_simulcast_streams_with_1_active_spatial_layers_and_2_temporal_layers_with_resolutions(
    ) {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0110_0001,
                // 3 temporal layer counts (minus 1), 2 bits each
                0b0101_0100,
                // 6 temporal layer bitrates
                100,
                101,
                110,
                111,
                120,
                121,
                // 3 resolutions + framerates (5 bytes each)
                // 320x180x15
                1,
                63,
                0,
                179,
                15,
                // 640x360x30
                2,
                127,
                1,
                103,
                30,
                // 1280x720x60
                4,
                255,
                2,
                207,
                60,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 1,
                simulcast_streams: vec![
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 100
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 101
                                }
                            ],
                            resolution_and_framerate: Some(ResolutionAndFramerate {
                                width: 320,
                                height: 180,
                                framerate: 15,
                            }),
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 110
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 111
                                }
                            ],
                            resolution_and_framerate: Some(ResolutionAndFramerate {
                                width: 640,
                                height: 360,
                                framerate: 30,
                            }),
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 120
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 121
                                }
                            ],
                            resolution_and_framerate: Some(ResolutionAndFramerate {
                                width: 1280,
                                height: 720,
                                framerate: 60,
                            }),
                        }],
                    }
                ],
            })
        );
    }

    #[test]
    fn test_parse_vla_3_simulcast_streams_with_differing_active_spatial_layers_with_resolutions() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0010_0000,
                // 3 active spatial layer bitmasks, 4 bits each; only the base layer is active
                0b0001_0000,
                0b0000_1111,
                // 1 temporal layer counts (minus 1), 2 bits each
                0b0100_0000,
                // 2 temporal layer bitrates
                100,
                101,
                // 1 resolutions + framerates (5 bytes)
                // 320x180x15
                1,
                63,
                0,
                179,
                15,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![
                    SimulcastStreamAllocation {
                        spatial_layers: vec![SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 100
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 101
                                }
                            ],
                            resolution_and_framerate: Some(ResolutionAndFramerate {
                                width: 320,
                                height: 180,
                                framerate: 15,
                            }),
                        }],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    },
                    SimulcastStreamAllocation {
                        spatial_layers: vec![],
                    }
                ],
            })
        );
    }

    #[test]
    fn test_parse_vla_1_simulcast_streams_with_3_spatial_layers() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0000_0111,
                // 3 temporal layer counts (minus 1), 2 bits each
                0b0101_0100,
                // 6 temporal layer bitrates
                100,
                101,
                110,
                111,
                120,
                121,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![SimulcastStreamAllocation {
                    spatial_layers: vec![
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 100
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 101
                                }
                            ],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 110
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 111
                                }
                            ],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 120
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 121
                                }
                            ],
                            resolution_and_framerate: None,
                        }
                    ],
                },],
            })
        );
    }

    #[test]
    fn test_parse_vla_1_simulcast_streams_with_4_spatial_layers_1_inactive() {
        assert_eq!(
            VideoLayersAllocation::parse(&[
                0b0000_1011,
                // 3 temporal layer counts (minus 1), 2 bits each
                0b0101_0100,
                // 6 temporal layer bitrates
                100,
                101,
                110,
                111,
                120,
                121,
            ]),
            Some(VideoLayersAllocation {
                current_simulcast_stream_index: 0,
                simulcast_streams: vec![SimulcastStreamAllocation {
                    spatial_layers: vec![
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 100
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 101
                                }
                            ],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 110
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 111
                                }
                            ],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![],
                            resolution_and_framerate: None,
                        },
                        SpatialLayerAllocation {
                            temporal_layers: vec![
                                TemporalLayerAllocation {
                                    cumulative_kbps: 120
                                },
                                TemporalLayerAllocation {
                                    cumulative_kbps: 121
                                }
                            ],
                            resolution_and_framerate: None,
                        }
                    ],
                },],
            })
        );
    }
}
