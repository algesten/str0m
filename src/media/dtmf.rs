//! Telephone events (DTMF), RFC 4733.
//!
//! Telephone events carry named signals such as DTMF digits over RTP using a
//! dedicated `telephone-event` payload type, negotiated inside an audio m-line.
//! Each event is reported by a small, fixed-size RTP payload (4 bytes) that is
//! resent across several packets: packets in one segment share an RTP timestamp
//! and carry a growing duration, while events longer than the 16-bit duration
//! field are split into contiguous segments. Final segment reports are repeated
//! for robustness (RFC 4733 §2.5).
//!
//! Sending is done with [`Writer::write_dtmf`][crate::media::Writer::write_dtmf]
//! and received tones are surfaced as [`Event::DtmfEvent`][crate::Event::DtmfEvent].

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::rtp_::{ExtensionValues, Frequency, MediaTime, Mid, Pt, Rid};

use super::ToPayload;

/// Number of times the final packet of an event (with the end bit set) is sent.
///
/// RFC 4733 §2.5.1.4 recommends resending the final packet for robustness.
const END_PACKET_REPEATS: u8 = 3;

/// Default per-packet interval for a DTMF tone (its ptime).
const DEFAULT_PACKET_INTERVAL: Duration = Duration::from_millis(20);

/// Maximum silence after an unfinished incoming event before best-effort completion.
const RECEIVE_EVENT_TIMEOUT: Duration = Duration::from_millis(150);

/// Default volume for a DTMF tone, in -dBm0 (RFC 4733 §2.5.2.1).
const DEFAULT_VOLUME: u8 = 10;

const NANOS_PER_SECOND: u128 = 1_000_000_000;

fn samples_from_duration(duration: Duration, clock_rate: Frequency) -> u64 {
    ((duration.as_nanos() * clock_rate.get() as u128) / NANOS_PER_SECOND).min(u64::MAX as u128)
        as u64
}

fn duration_from_samples(samples: u64, clock_rate: Frequency) -> Duration {
    let nanos = (samples as u128 * NANOS_PER_SECOND).div_ceil(clock_rate.get() as u128);
    Duration::new(
        (nanos / NANOS_PER_SECOND) as u64,
        (nanos % NANOS_PER_SECOND) as u32,
    )
}

/// A DTMF keypad symbol or supported legacy telephone event carried by RFC 4733.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Dtmf {
    D0,
    D1,
    D2,
    D3,
    D4,
    D5,
    D6,
    D7,
    D8,
    D9,
    /// The `*` key.
    Star,
    /// The `#` key.
    Pound,
    /// The `A` key from the fourth column of a 16-key DTMF keypad.
    ///
    /// `A`–`D` are uncommon on consumer phones, but remain part of DTMF for
    /// military, network-control, and other specialized telephone systems.
    A,
    /// The specialized `B` key from a 16-key DTMF keypad. See [`Dtmf::A`].
    B,
    /// The specialized `C` key from a 16-key DTMF keypad. See [`Dtmf::A`].
    C,
    /// The specialized `D` key from a 16-key DTMF keypad. See [`Dtmf::A`].
    D,
    /// Briefly interrupts the phone line without ending the call.
    ///
    /// Traditional phone systems call this a *hook flash* and use it for
    /// features such as call waiting, call transfer, and three-way calling.
    /// This is legacy telephone event 16, not a DTMF keypad tone.
    Flash,
}

impl Dtmf {
    /// The RFC 4733 event code for this event.
    pub fn event_code(&self) -> u8 {
        use Dtmf::*;
        match self {
            D0 => 0,
            D1 => 1,
            D2 => 2,
            D3 => 3,
            D4 => 4,
            D5 => 5,
            D6 => 6,
            D7 => 7,
            D8 => 8,
            D9 => 9,
            Star => 10,
            Pound => 11,
            A => 12,
            B => 13,
            C => 14,
            D => 15,
            Flash => 16,
        }
    }

    /// Creates a [`Dtmf`] from an RFC 4733 event code, if it is a known event.
    pub fn from_event_code(code: u8) -> Option<Dtmf> {
        use Dtmf::*;
        Some(match code {
            0 => D0,
            1 => D1,
            2 => D2,
            3 => D3,
            4 => D4,
            5 => D5,
            6 => D6,
            7 => D7,
            8 => D8,
            9 => D9,
            10 => Star,
            11 => Pound,
            12 => A,
            13 => B,
            14 => C,
            15 => D,
            16 => Flash,
            _ => return None,
        })
    }

    /// The dialpad character for this event, if any.
    pub fn to_char(&self) -> Option<char> {
        use Dtmf::*;
        Some(match self {
            D0 => '0',
            D1 => '1',
            D2 => '2',
            D3 => '3',
            D4 => '4',
            D5 => '5',
            D6 => '6',
            D7 => '7',
            D8 => '8',
            D9 => '9',
            Star => '*',
            Pound => '#',
            A => 'A',
            B => 'B',
            C => 'C',
            D => 'D',
            Flash => return None,
        })
    }

    /// Parses a dialpad character (`0`–`9`, `*`, `#`, `A`–`D`) into an event.
    pub fn from_char(c: char) -> Option<Dtmf> {
        use Dtmf::*;
        Some(match c.to_ascii_uppercase() {
            '0' => D0,
            '1' => D1,
            '2' => D2,
            '3' => D3,
            '4' => D4,
            '5' => D5,
            '6' => D6,
            '7' => D7,
            '8' => D8,
            '9' => D9,
            '*' => Star,
            '#' => Pound,
            'A' => A,
            'B' => B,
            'C' => C,
            'D' => D,
            _ => return None,
        })
    }
}

/// A single telephone-event (RFC 4733) RTP payload.
///
/// This is the 4-byte payload carried by one `telephone-event` RTP packet. Use
/// it to build or inspect raw telephone-event packets; for sending DTMF tones at
/// a higher level, use [`Writer::write_dtmf`][crate::media::Writer::write_dtmf].
///
/// ```text
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |     event     |E|R| volume    |          duration             |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TelephoneEventPayload {
    /// The event code (RFC 4733 §2.5.1.1). See [`Dtmf::from_event_code`].
    pub event: u8,

    /// The end bit: set on the final packet(s) of an event (RFC 4733 §2.5.1.3).
    pub end: bool,

    /// The volume of the event, in -dBm0 (0–63, RFC 4733 §2.5.1.4).
    ///
    /// Only meaningful for DTMF events. Higher values are quieter.
    pub volume: u8,

    /// The duration of the current event segment, in RTP timestamp units
    /// (samples at the payload clock rate).
    pub duration: u16,
}

impl TelephoneEventPayload {
    /// Parses a telephone-event payload from the 4 payload bytes of an RTP packet.
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 4 {
            return None;
        }
        Some(TelephoneEventPayload {
            event: buf[0],
            end: buf[1] & 0x80 != 0,
            volume: buf[1] & 0x3f,
            duration: u16::from_be_bytes([buf[2], buf[3]]),
        })
    }

    /// Parses every consecutive telephone event in an RTP payload.
    ///
    /// RFC 4733 permits multiple contiguous events in one packet. The payload
    /// must therefore be a non-empty multiple of four bytes.
    pub fn parse_all(buf: &[u8]) -> Option<impl Iterator<Item = Self> + '_> {
        if buf.is_empty() || buf.len() % 4 != 0 {
            return None;
        }

        Some(buf.chunks_exact(4).map(|chunk| {
            // unwrap: chunks_exact guarantees a four-byte chunk.
            Self::parse(chunk).unwrap()
        }))
    }

    /// Serializes this payload to its 4 wire bytes.
    pub fn to_bytes(&self) -> [u8; 4] {
        let [d0, d1] = self.duration.to_be_bytes();
        let end = if self.end { 0x80 } else { 0x00 };
        [self.event, end | (self.volume & 0x3f), d0, d1]
    }
}

/// A received telephone event (DTMF), surfaced by
/// [`Event::DtmfEvent`][crate::Event::DtmfEvent].
///
/// One `DtmfEvent` is emitted per completed tone, once its final (end) packet
/// has been received or an unfinished event has timed out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DtmfEvent {
    /// The media (m-line) the event was received on.
    pub mid: Mid,

    /// The raw RFC 4733 event code.
    pub event: u8,

    /// The decoded DTMF digit, if the event code is a known DTMF event.
    pub dtmf: Option<Dtmf>,

    /// The reported volume, in -dBm0 (0–63).
    pub volume: u8,

    /// The total duration of the tone, in the payload clock rate.
    pub duration: MediaTime,
}

/// A request to queue a tone for sending by [`DtmfSender`].
#[derive(Debug)]
pub(crate) struct DtmfTone {
    pub pt: Pt,
    pub rid: Option<Rid>,
    pub rtp_time: MediaTime,
    pub wallclock: Instant,
    pub event: u8,
    pub volume: u8,
    pub duration: Duration,
    pub clock_rate: crate::rtp_::Frequency,
}

/// A tone queued for sending by [`DtmfSender`].
#[derive(Debug)]
struct QueuedTone {
    pt: Pt,
    rid: Option<Rid>,
    event: u8,
    volume: u8,
    /// The full duration of the tone in samples at `clock_rate`.
    total_samples: u64,
    /// The number of samples each packet advances the duration.
    step_samples: u64,
    /// RTP timestamp at which this tone starts.
    rtp_time: MediaTime,
    /// Wallclock corresponding to `rtp_time`.
    start: Instant,
    clock_rate: crate::rtp_::Frequency,
    /// The per-packet interval.
    interval: Duration,
}

impl QueuedTone {
    fn end_at(&self) -> Option<Instant> {
        self.start
            .checked_add(duration_from_samples(self.total_samples, self.clock_rate))
    }

    fn end_rtp_time(&self) -> MediaTime {
        self.rtp_time + MediaTime::new(self.total_samples, self.clock_rate)
    }

    fn first_report_at(&self) -> Instant {
        self.start
            + duration_from_samples(self.step_samples.min(self.total_samples), self.clock_rate)
    }
}

/// The tone currently being transmitted by [`DtmfSender`].
#[derive(Debug)]
struct ActiveTone {
    tone: QueuedTone,
    /// Total number of packets emitted so far (for the marker on the first).
    packets: u32,
    /// Sample offset at which the current segment starts.
    segment_start: u64,
    /// Current duration within the segment.
    segment_duration: u64,
    /// Whether the current segment reached its full duration.
    segment_complete: bool,
    /// Number of final reports emitted for the current segment.
    final_reports: u8,
    /// When the next packet is due.
    next_at: Instant,
}

/// Generates the RTP packet series for outgoing DTMF tones (RFC 4733).
///
/// Tones are played back-to-back in the order they are queued. Packets within a
/// segment share an RTP timestamp and carry a growing duration. Long tones are
/// split into contiguous segments, with the marker bit only on the first packet
/// and each segment's final report repeated for robustness.
#[derive(Debug, Default)]
pub(crate) struct DtmfSender {
    queue: VecDeque<QueuedTone>,
    active: Option<ActiveTone>,
}

impl DtmfSender {
    /// Queues a DTMF tone for sending.
    pub fn push(&mut self, tone: DtmfTone) {
        let DtmfTone {
            pt,
            rid,
            mut rtp_time,
            wallclock,
            event,
            volume,
            duration,
            clock_rate,
        } = tone;
        let total_samples = samples_from_duration(duration, clock_rate).max(1);

        let interval = DEFAULT_PACKET_INTERVAL;
        let step_samples = samples_from_duration(interval, clock_rate).max(1);

        let mut start = wallclock;
        let previous = self
            .queue
            .back()
            .or_else(|| self.active.as_ref().map(|active| &active.tone));
        if let Some(previous) = previous {
            if let Some(previous_end) = previous.end_at() {
                // Preserve caller-supplied gaps while preventing FIFO tones from overlapping.
                start = start.max(previous_end);
                let earliest_rtp_time = previous.end_rtp_time()
                    + MediaTime::from(start.saturating_duration_since(previous_end));
                rtp_time = rtp_time.max(earliest_rtp_time);
            }
        }

        self.queue.push_back(QueuedTone {
            pt,
            rid,
            event,
            volume: volume.min(0x3f),
            total_samples,
            step_samples,
            rtp_time,
            start,
            clock_rate,
            interval,
        });
    }

    /// The next time [`DtmfSender::poll`] should be called, if any packet is
    /// pending.
    pub fn poll_timeout(&self) -> Option<Instant> {
        if let Some(active) = &self.active {
            return Some(active.next_at);
        }
        self.queue.front().map(QueuedTone::first_report_at)
    }

    /// Produces the next due telephone-event payload, if one is ready at `now`.
    ///
    /// Returns `None` when nothing is due yet or there are no pending tones.
    pub fn poll(&mut self, now: Instant) -> Option<ToPayload> {
        // Activate the next queued tone if nothing is playing.
        if self.active.is_none() {
            let tone = self.queue.pop_front()?;
            let next_at = tone.first_report_at();
            self.active = Some(ActiveTone {
                tone,
                packets: 0,
                segment_start: 0,
                segment_duration: 0,
                segment_complete: false,
                final_reports: 0,
                next_at,
            });
        }

        // unwrap: set just above if it was None.
        let active = self.active.as_mut().unwrap();

        if now < active.next_at {
            return None;
        }

        let first = active.packets == 0;

        let segment_target =
            (active.tone.total_samples - active.segment_start).min(u16::MAX as u64);
        let final_segment = active.segment_start + segment_target >= active.tone.total_samples;

        // Each segment boundary is reported three times. Only the final segment
        // sets E; intermediate segments finish at 0xffff with E clear.
        let (end, segment_done, last) = if !active.segment_complete {
            let elapsed = now.saturating_duration_since(active.tone.start);
            let elapsed_samples = samples_from_duration(elapsed, active.tone.clock_rate)
                .min(active.tone.total_samples);
            active.segment_duration = active
                .segment_duration
                .max(elapsed_samples.saturating_sub(active.segment_start))
                .min(segment_target);

            if active.segment_duration >= segment_target {
                active.segment_complete = true;
                active.final_reports = 1;
                let segment_done = END_PACKET_REPEATS <= 1;
                (final_segment, segment_done, final_segment && segment_done)
            } else {
                (false, false, false)
            }
        } else {
            active.final_reports = active.final_reports.saturating_add(1);
            let segment_done = active.final_reports >= END_PACKET_REPEATS;
            (final_segment, segment_done, final_segment && segment_done)
        };

        let payload = TelephoneEventPayload {
            event: active.tone.event,
            end,
            volume: active.tone.volume,
            duration: active.segment_duration as u16,
        };

        let data: Arc<[u8]> = Arc::from(payload.to_bytes().as_slice());

        let segment_offset = MediaTime::new(active.segment_start, active.tone.clock_rate);
        let to_payload = ToPayload {
            pt: active.tone.pt,
            rid: active.tone.rid,
            wallclock: active.tone.start + segment_offset,
            rtp_time: active.tone.rtp_time + segment_offset,
            start_of_talk_spurt: first,
            data,
            ext_vals: ExtensionValues::default(),
        };

        // Advance schedule.
        active.packets = active.packets.saturating_add(1);
        active.next_at = now + active.tone.interval;

        if last {
            self.active = None;
        } else if segment_done {
            active.segment_start += segment_target;
            active.segment_duration = 0;
            active.segment_complete = false;
            active.final_reports = 0;
        }

        Some(to_payload)
    }
}

/// Reassembles incoming telephone-event (RFC 4733) packets into completed
/// [`DtmfEvent`]s.
#[derive(Debug, Default)]
pub(crate) struct DtmfReceiver {
    current: Option<InProgress>,
    ready: VecDeque<DtmfEvent>,
    recent: VecDeque<EventKey>,
}

const RECENT_EVENT_COUNT: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EventKey {
    time: MediaTime,
    event: u8,
}

/// State for the telephone event currently being received.
#[derive(Debug)]
struct InProgress {
    /// RTP timestamp identifying the complete event.
    start: MediaTime,
    /// RTP timestamp identifying the current long-event segment.
    segment_start: MediaTime,
    event: u8,
    volume: u8,
    /// Duration represented by complete preceding segments.
    completed_duration: u64,
    /// Largest duration seen for the current segment.
    segment_duration: u16,
    /// Arrival time of the most recent report for this event.
    last_report_at: Instant,
    /// Whether a completed `DtmfEvent` has already been emitted for this event.
    emitted: bool,
}

impl DtmfReceiver {
    /// Feeds one depacketized telephone-event payload into the aggregator.
    ///
    /// `time` is the RTP timestamp of the packet (which identifies the event).
    pub fn feed(
        &mut self,
        mid: Mid,
        time: MediaTime,
        received_at: Instant,
        payload: TelephoneEventPayload,
    ) {
        let key = EventKey {
            time,
            event: payload.event,
        };
        if self.recent.contains(&key) {
            return;
        }

        enum Relation {
            SameSegment,
            NextSegment,
            Stale,
            NewEvent,
        }

        let relation = self.current.as_ref().map_or(Relation::NewEvent, |current| {
            if current.segment_start == time && current.event == payload.event {
                Relation::SameSegment
            } else if current.is_next_segment(time, payload.event) {
                Relation::NextSegment
            } else if time <= current.segment_start {
                Relation::Stale
            } else {
                Relation::NewEvent
            }
        });

        match relation {
            Relation::SameSegment => {
                let current = self.current.as_mut().unwrap();
                current.segment_duration = current.segment_duration.max(payload.duration);
                current.volume = payload.volume;
                current.last_report_at = received_at;
            }
            Relation::NextSegment => {
                let current = self.current.as_mut().unwrap();
                current.completed_duration += u16::MAX as u64;
                current.segment_start = time;
                current.segment_duration = payload.duration;
                current.volume = payload.volume;
                current.last_report_at = received_at;
            }
            Relation::Stale => return,
            Relation::NewEvent => {
                // If every end packet was lost, emit the previous event as a
                // best effort when a newer event begins.
                self.flush_current(mid);
                self.current = Some(InProgress::new(time, received_at, payload));
            }
        }

        let completed = self.current.as_mut().and_then(|current| {
            if payload.end && !current.emitted {
                current.emitted = true;
                Some((current.to_event(mid), current.key()))
            } else {
                None
            }
        });
        if let Some((event, key)) = completed {
            self.ready.push_back(event);
            self.remember(key);
        }
    }

    /// Pops the next completed [`DtmfEvent`], if any.
    pub fn poll(&mut self) -> Option<DtmfEvent> {
        self.ready.pop_front()
    }

    /// The best-effort completion deadline for an unfinished event.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.current
            .as_ref()
            .filter(|current| !current.emitted)
            .map(|current| current.last_report_at + RECEIVE_EVENT_TIMEOUT)
    }

    /// Completes an unfinished event after reports have stopped arriving.
    pub fn handle_timeout(&mut self, mid: Mid, now: Instant) {
        if self.poll_timeout().is_some_and(|deadline| now >= deadline) {
            self.flush_current(mid);
        }
    }

    /// Resets stream-specific ordering state, preserving events ready for polling.
    pub fn reset(&mut self, mid: Mid) {
        self.flush_current(mid);
        self.recent.clear();
    }

    fn flush_current(&mut self, mid: Mid) {
        if let Some(current) = self.current.take() {
            if !current.emitted {
                let ev = current.to_event(mid);
                self.ready.push_back(ev);
            }
            self.remember(current.key());
        }
    }

    fn remember(&mut self, key: EventKey) {
        if self.recent.contains(&key) {
            return;
        }
        self.recent.push_back(key);
        while self.recent.len() > RECENT_EVENT_COUNT {
            self.recent.pop_front();
        }
    }
}

impl InProgress {
    fn new(time: MediaTime, received_at: Instant, payload: TelephoneEventPayload) -> Self {
        Self {
            start: time,
            segment_start: time,
            event: payload.event,
            volume: payload.volume,
            completed_duration: 0,
            segment_duration: payload.duration,
            last_report_at: received_at,
            emitted: false,
        }
    }

    fn key(&self) -> EventKey {
        EventKey {
            time: self.start,
            event: self.event,
        }
    }

    fn is_next_segment(&self, time: MediaTime, event: u8) -> bool {
        let segment_duration = MediaTime::new(u16::MAX as u64, self.segment_start.frequency());
        !self.emitted && self.event == event && self.segment_start + segment_duration == time
    }

    fn to_event(&self, mid: Mid) -> DtmfEvent {
        DtmfEvent {
            mid,
            event: self.event,
            dtmf: Dtmf::from_event_code(self.event),
            volume: self.volume,
            duration: MediaTime::new(
                self.completed_duration + self.segment_duration as u64,
                self.start.frequency(),
            ),
        }
    }
}

/// Default volume used by the high-level DTMF sending API.
pub(crate) const fn default_volume(event: Dtmf) -> u8 {
    match event {
        Dtmf::Flash => 0,
        _ => DEFAULT_VOLUME,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::rtp_::Frequency;

    #[test]
    fn payload_roundtrip() {
        let p = TelephoneEventPayload {
            event: 5,
            end: true,
            volume: 10,
            duration: 1600,
        };
        let bytes = p.to_bytes();
        assert_eq!(bytes, [0x05, 0x8a, 0x06, 0x40]);
        assert_eq!(TelephoneEventPayload::parse(&bytes), Some(p));
    }

    #[test]
    fn payload_parse_all() {
        let first = TelephoneEventPayload {
            event: 1,
            end: true,
            volume: 10,
            duration: 160,
        };
        let second = TelephoneEventPayload {
            event: 2,
            end: true,
            volume: 10,
            duration: 320,
        };
        let bytes = [first.to_bytes(), second.to_bytes()].concat();

        let mut payloads = TelephoneEventPayload::parse_all(&bytes).unwrap();
        assert_eq!(payloads.next(), Some(first));
        assert_eq!(payloads.next(), Some(second));
        assert_eq!(payloads.next(), None);
        assert!(TelephoneEventPayload::parse_all(&bytes[..7]).is_none());
    }

    #[test]
    fn dtmf_char_roundtrip() {
        for c in "0123456789*#ABCD".chars() {
            let d = Dtmf::from_char(c).unwrap();
            assert_eq!(d.to_char(), Some(c));
            assert_eq!(Dtmf::from_event_code(d.event_code()), Some(d));
        }
    }

    #[test]
    fn flash_uses_zero_volume() {
        assert_eq!(default_volume(Dtmf::D5), DEFAULT_VOLUME);
        assert_eq!(default_volume(Dtmf::Flash), 0);
    }

    #[test]
    fn sender_emits_series_with_marker_and_end_repeats() {
        let mut s = DtmfSender::default();
        let start = Instant::now();
        // 100 ms tone at 8 kHz, 20 ms packets => 5 reports + two retransmissions.
        s.push(DtmfTone {
            pt: 101.into(),
            rid: None,
            rtp_time: MediaTime::new(0, Frequency::EIGHT_KHZ),
            wallclock: start,
            event: 5,
            volume: 10,
            duration: Duration::from_millis(100),
            clock_rate: Frequency::EIGHT_KHZ,
        });

        let mut now = start;
        let mut payloads = vec![];
        for _ in 0..20 {
            while let Some(tp) = s.poll(now) {
                payloads.push((now, tp));
            }
            now += Duration::from_millis(20);
        }

        // First packet has the marker (start of talkspurt).
        assert_eq!(payloads[0].0, start + Duration::from_millis(20));
        assert!(payloads[0].1.start_of_talk_spurt);
        assert!(!payloads[1].1.start_of_talk_spurt);

        // All packets share the same RTP timestamp.
        for (_, p) in &payloads {
            assert_eq!(p.rtp_time.numer(), 0);
            assert_eq!(p.wallclock, start);
        }

        // The final three packets carry the end bit and full duration.
        let parsed: Vec<_> = payloads
            .iter()
            .map(|(_, p)| TelephoneEventPayload::parse(&p.data).unwrap())
            .collect();
        let end_count = parsed.iter().filter(|p| p.end).count();
        assert_eq!(end_count, END_PACKET_REPEATS as usize);
        assert_eq!(parsed.last().unwrap().duration, 800); // 100 ms @ 8 kHz
        let first_end = payloads
            .iter()
            .find(|(_, p)| TelephoneEventPayload::parse(&p.data).unwrap().end)
            .unwrap();
        assert_eq!(first_end.0, start + Duration::from_millis(100));
    }

    #[test]
    fn sender_preserves_rid() {
        let mut sender = DtmfSender::default();
        let start = Instant::now();
        let rid: Rid = "audio".into();
        sender.push(DtmfTone {
            pt: 101.into(),
            rid: Some(rid),
            rtp_time: MediaTime::new(0, Frequency::EIGHT_KHZ),
            wallclock: start,
            event: 5,
            volume: 10,
            duration: Duration::from_millis(20),
            clock_rate: Frequency::EIGHT_KHZ,
        });

        assert!(sender.poll(start).is_none());
        let payload = sender.poll(start + Duration::from_millis(20)).unwrap();
        assert_eq!(payload.rid, Some(rid));
    }

    #[test]
    fn sender_segments_long_tones() {
        let mut sender = DtmfSender::default();
        let start = Instant::now();
        sender.push(DtmfTone {
            pt: 126.into(),
            rid: None,
            rtp_time: MediaTime::new(0, Frequency::EIGHT_KHZ),
            wallclock: start,
            event: 5,
            volume: 10,
            duration: Duration::from_secs(9),
            clock_rate: Frequency::EIGHT_KHZ,
        });

        let mut payloads = vec![];
        let mut now = start;
        for _ in 0..600 {
            while let Some(payload) = sender.poll(now) {
                payloads.push(payload);
            }
            now += Duration::from_millis(20);
        }

        let segment_offset = MediaTime::new(u16::MAX as u64, Frequency::EIGHT_KHZ);
        let first_segment: Vec<_> = payloads
            .iter()
            .filter(|payload| payload.rtp_time.numer() == 0)
            .collect();
        let second_segment: Vec<_> = payloads
            .iter()
            .filter(|payload| payload.rtp_time.numer() == u16::MAX as u64)
            .collect();

        assert!(!first_segment.is_empty());
        assert!(!second_segment.is_empty());
        assert!(
            first_segment
                .iter()
                .all(|payload| payload.wallclock == start)
        );
        assert!(
            second_segment
                .iter()
                .all(|payload| payload.wallclock == start + segment_offset)
        );

        let first_final: Vec<_> = first_segment
            .iter()
            .filter_map(|payload| TelephoneEventPayload::parse(&payload.data))
            .filter(|payload| payload.duration == u16::MAX)
            .collect();
        assert_eq!(first_final.len(), END_PACKET_REPEATS as usize);
        assert!(first_final.iter().all(|payload| !payload.end));

        let second_final: Vec<_> = second_segment
            .iter()
            .filter_map(|payload| TelephoneEventPayload::parse(&payload.data))
            .filter(|payload| payload.end)
            .collect();
        assert_eq!(second_final.len(), END_PACKET_REPEATS as usize);
        assert!(second_final.iter().all(|payload| payload.duration == 6465));
    }

    #[test]
    fn receiver_aggregates_to_single_event() {
        let mut r = DtmfReceiver::default();
        let mid = Mid::from("audio");
        let freq = Frequency::EIGHT_KHZ;
        let received_at = Instant::now();

        // Playing packets (growing duration, no end bit).
        for d in [160u16, 320, 480, 640, 800] {
            r.feed(
                mid,
                MediaTime::new(1000, freq),
                received_at,
                TelephoneEventPayload {
                    event: 5,
                    end: false,
                    volume: 10,
                    duration: d,
                },
            );
            assert!(r.poll().is_none());
        }

        // Three end packets — only the first should produce an event.
        for _ in 0..3 {
            r.feed(
                mid,
                MediaTime::new(1000, freq),
                received_at,
                TelephoneEventPayload {
                    event: 5,
                    end: true,
                    volume: 10,
                    duration: 800,
                },
            );
        }

        let ev = r.poll().unwrap();
        assert_eq!(ev.event, 5);
        assert_eq!(ev.dtmf, Some(Dtmf::D5));
        assert_eq!(ev.duration.numer(), 800);
        assert!(r.poll().is_none());
    }

    #[test]
    fn receiver_ignores_late_end_repeat_after_next_event_starts() {
        let mut r = DtmfReceiver::default();
        let mid = Mid::from("audio");
        let freq = Frequency::EIGHT_KHZ;
        let received_at = Instant::now();
        let event = |event, end, duration| TelephoneEventPayload {
            event,
            end,
            volume: 10,
            duration,
        };

        r.feed(
            mid,
            MediaTime::new(1000, freq),
            received_at,
            event(1, true, 800),
        );
        assert_eq!(r.poll().unwrap().dtmf, Some(Dtmf::D1));

        r.feed(
            mid,
            MediaTime::new(2000, freq),
            received_at,
            event(2, false, 160),
        );
        r.feed(
            mid,
            MediaTime::new(1000, freq),
            received_at,
            event(1, true, 800),
        );
        assert!(r.poll().is_none());

        r.feed(
            mid,
            MediaTime::new(2000, freq),
            received_at,
            event(2, true, 800),
        );
        assert_eq!(r.poll().unwrap().dtmf, Some(Dtmf::D2));
        assert!(r.poll().is_none());
    }

    #[test]
    fn receiver_combines_long_event_segments() {
        let mut r = DtmfReceiver::default();
        let mid = Mid::from("audio");
        let freq = Frequency::EIGHT_KHZ;
        let received_at = Instant::now();

        r.feed(
            mid,
            MediaTime::new(1000, freq),
            received_at,
            TelephoneEventPayload {
                event: 5,
                end: false,
                volume: 10,
                duration: u16::MAX,
            },
        );
        r.feed(
            mid,
            MediaTime::new(1000 + u16::MAX as u64, freq),
            received_at,
            TelephoneEventPayload {
                event: 5,
                end: true,
                volume: 10,
                duration: 6465,
            },
        );

        let event = r.poll().unwrap();
        assert_eq!(event.dtmf, Some(Dtmf::D5));
        assert_eq!(event.duration, MediaTime::new(72_000, freq));
        assert!(r.poll().is_none());
    }

    #[test]
    fn receiver_flushes_unfinished_event_after_inactivity() {
        let mut receiver = DtmfReceiver::default();
        let mid = Mid::from("audio");
        let received_at = Instant::now();

        receiver.feed(
            mid,
            MediaTime::new(1000, Frequency::EIGHT_KHZ),
            received_at,
            TelephoneEventPayload {
                event: 5,
                end: false,
                volume: 10,
                duration: 800,
            },
        );

        let deadline = received_at + RECEIVE_EVENT_TIMEOUT;
        assert_eq!(receiver.poll_timeout(), Some(deadline));
        receiver.handle_timeout(mid, deadline - Duration::from_millis(1));
        assert!(receiver.poll().is_none());

        receiver.handle_timeout(mid, deadline);
        assert_eq!(receiver.poll().unwrap().dtmf, Some(Dtmf::D5));
        assert_eq!(receiver.poll_timeout(), None);
    }

    #[test]
    fn receiver_reset_accepts_lower_timestamp_from_new_source() {
        let mut receiver = DtmfReceiver::default();
        let mid = Mid::from("audio");
        let received_at = Instant::now();
        let event = |event| TelephoneEventPayload {
            event,
            end: true,
            volume: 10,
            duration: 800,
        };

        receiver.feed(
            mid,
            MediaTime::new(3_000_000, Frequency::EIGHT_KHZ),
            received_at,
            event(1),
        );
        assert_eq!(receiver.poll().unwrap().dtmf, Some(Dtmf::D1));

        receiver.reset(mid);
        receiver.feed(
            mid,
            MediaTime::new(1_000_000, Frequency::EIGHT_KHZ),
            received_at + Duration::from_secs(1),
            event(2),
        );
        assert_eq!(receiver.poll().unwrap().dtmf, Some(Dtmf::D2));
    }
}
