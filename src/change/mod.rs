//! Ways of changing the Rtc session

use std::ops::Deref;

use crate::io::Id;
use crate::rtp::{ChannelId, Direction, Mid, Ssrc};
use crate::sctp::{DcepOpen, ReliabilityType};
use crate::sdp::Msid;

use crate::media::{MediaKind, PayloadParams};
use crate::Rtc;

pub(crate) struct Changes(pub Vec<Change>);

mod sdp;
pub use sdp::{SdpAnswer, SdpOffer, SdpPendingOffer, SdpStrategy};

/// Strategy for changing the [`Rtc`][crate::Rtc] session.
///
/// One common strategy is [`SdpStrategy`][crate::change::SdpStrategy].
pub trait ChangeStrategy: Sized {
    /// The type [`ChangeSet::apply`] produces.
    type Apply;

    #[doc(hidden)]
    fn apply(&self, change_id: usize, rtc: &mut Rtc, changes: ChangesWrapper) -> Self::Apply;
}

#[doc(hidden)]
pub struct ChangesWrapper(Changes);

#[derive(Debug)]
pub(crate) enum Change {
    AddMedia(AddMedia),
    AddApp(Mid),
    AddChannel(ChannelId, DcepOpen),
    Direction(Mid, Direction),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AddMedia {
    pub mid: Mid,
    pub cname: String,
    pub msid: Msid,
    pub kind: MediaKind,
    pub dir: Direction,
    pub ssrcs: Vec<(Ssrc, Option<Ssrc>)>,

    // These are filled in when creating a Media from AddMedia
    pub params: Vec<PayloadParams>,
    pub index: usize,
}

/// Changes to apply to the WebRTC session.
///
/// Get this by calling [`Rtc::create_change_set`][crate::Rtc::create_change_set()].
///
/// For [`SdpStrategy`]: No changes are made without calling [`ChangeSet::apply()`], followed
/// by sending the offer to the remote peer, receiving an answer and completing the changes using
/// [`SdpPendingOffer`].
pub struct ChangeSet<'a, Strategy>
where
    Strategy: ChangeStrategy,
{
    pub(crate) rtc: &'a mut Rtc,
    pub(crate) changes: Changes,
    strategy: Strategy,
}

impl<'a, Strategy: ChangeStrategy> ChangeSet<'a, Strategy> {
    pub(crate) fn new(rtc: &'a mut Rtc, strategy: Strategy) -> Self {
        ChangeSet {
            rtc,
            strategy,
            changes: Changes(vec![]),
        }
    }

    /// Test if this change set has any changes.
    ///
    /// ```
    /// # use str0m::{Rtc, media::MediaKind, media::Direction};
    /// # use str0m::change::SdpStrategy;
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.create_change_set(SdpStrategy);
    /// assert!(!changes.has_changes());
    ///
    /// let mid = changes.add_media(MediaKind::Audio, Direction::SendRecv, None);
    /// assert!(changes.has_changes());
    /// ```
    pub fn has_changes(&self) -> bool {
        !self.changes.is_empty()
    }

    /// Add audio or video media and get the `mid` that will be used.
    ///
    /// For [`SdpStrategy`]: Each call will result in a new m-line in the offer identifed by the [`Mid`].
    ///
    /// The mid is not valid to use until the SDP offer-answer dance is complete and
    /// the mid been advertised via [`Event::MediaAdded`][crate::Event::MediaAdded].
    ///
    /// ```
    /// # use str0m::{Rtc, media::MediaKind, media::Direction};
    /// # use str0m::change::SdpStrategy;
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.create_change_set(SdpStrategy);
    ///
    /// let mid = changes.add_media(MediaKind::Audio, Direction::SendRecv, None);
    /// ```
    pub fn add_media(&mut self, kind: MediaKind, dir: Direction, cname: Option<String>) -> Mid {
        let mid = self.rtc.new_mid();

        let cname = if let Some(cname) = cname {
            fn is_token_char(c: &char) -> bool {
                // token-char = %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39
                // / %x41-5A / %x5E-7E
                let u = *c as u32;
                u == 0x21
                    || (0x23..=0x27).contains(&u)
                    || (0x2a..=0x2b).contains(&u)
                    || (0x2d..=0x2e).contains(&u)
                    || (0x30..=0x39).contains(&u)
                    || (0x41..=0x5a).contains(&u)
                    || (0x5e..0x7e).contains(&u)
            }
            // https://www.rfc-editor.org/rfc/rfc8830
            // msid-id = 1*64token-char
            cname.chars().filter(is_token_char).take(64).collect()
        } else {
            Id::<20>::random().to_string()
        };

        let ssrcs = {
            // For video we do RTX channels.
            let has_rtx = kind == MediaKind::Video;

            let ssrc_base = if has_rtx { 2 } else { 1 };

            // TODO: allow configuring simulcast
            let simulcast_count = 1;

            let ssrc_count = ssrc_base * simulcast_count;
            let mut v = Vec::with_capacity(ssrc_count);

            let mut prev = 0.into();
            for i in 0..ssrc_count {
                // Allocate SSRC that are not in use in the session already.
                let new_ssrc = self.rtc.new_ssrc();
                let is_rtx = has_rtx && i % 2 == 1;
                let repairs = if is_rtx { Some(prev) } else { None };
                v.push((new_ssrc, repairs));
                prev = new_ssrc;
            }

            v
        };

        // TODO: let user configure stream/track name.
        let msid = Msid {
            stream_id: cname.clone(),
            track_id: Id::<30>::random().to_string(),
        };

        let add = AddMedia {
            mid,
            cname,
            msid,
            kind,
            dir,
            ssrcs,

            // Added later
            params: vec![],
            index: 0,
        };

        self.changes.0.push(Change::AddMedia(add));
        mid
    }

    /// Change the direction of an already existing media.
    ///
    /// All media have a direction. The media can be added by this side via
    /// [`ChangeSet::add_media()`] or by the remote peer. Either way, the direction
    /// of the line can be changed at any time.
    ///
    /// It's possible to set the direction [`Direction::Inactive`] for media that
    /// will not be used by the session anymore.
    ///
    /// If the direction is set for media that doesn't exist, or if the direction is
    /// the same that's already set [`ChangeSet::apply()`] not require a negotiation.
    pub fn set_direction(&mut self, mid: Mid, dir: Direction) {
        let Some(media) = self.rtc.session.media_by_mid_mut(mid) else {
            return;
        };

        if media.direction() == dir {
            return;
        }

        self.changes.0.push(Change::Direction(mid, dir));
    }

    /// Add a new data channel and get the `id` that will be used.
    ///
    /// For [`SdpStrategy`]: The first ever data channel added to a WebRTC session results in a media
    /// of a special "application" type in the SDP. The m-line is for a SCTP association over
    /// DTLS, and all data channels are multiplexed over this single association.
    ///
    /// That means only the first ever `add_channel` will result in an [`SdpOffer`].
    /// Consecutive channels will be opened without needing a negotiation.
    ///
    /// The label is used to identify the data channel to the remote peer. This is mostly
    /// useful whe multiple channels are in use at the same time.
    ///
    /// ```
    /// # use str0m::Rtc;
    /// # use str0m::change::SdpStrategy;
    /// let mut rtc = Rtc::new();
    ///
    /// let mut changes = rtc.create_change_set(SdpStrategy);
    ///
    /// let cid = changes.add_channel("my special channel".to_string());
    /// ```
    pub fn add_channel(&mut self, label: String) -> ChannelId {
        let has_media = self.rtc.session.app().is_some();

        if !has_media {
            let mid = self.rtc.new_mid();
            self.changes.0.push(Change::AddApp(mid));
        }

        let id = self.rtc.new_sctp_channel();

        let dcep = DcepOpen {
            unordered: false,
            channel_type: ReliabilityType::Reliable,
            reliability_parameter: 0,
            label,
            priority: 0,
            protocol: String::new(),
        };

        self.changes.0.push(Change::AddChannel(id, dcep));

        id
    }

    /// Attempt to apply the changes made in the change set. What that means depends on the
    /// used [`ChangeStrategy`].
    ///
    /// For [`SdpStrategy`]: If this returns [`SdpOffer`], the caller the changes are
    /// not happening straight away, and the caller is expected to do a negotiation with the remote
    /// peer and apply the answer using [`SdpPendingOffer`].
    ///
    /// In case this returns `None`, there either were no changes, or the changes could be applied
    /// without doing a negotiation. Specifically for additional [`ChangeSet::add_channel()`]
    /// after the first, there is no negotiation needed.
    ///
    /// The [`SdpPendingOffer`] is valid until the next time we call this function, at which
    /// point using it will raise an error. Using [`SdpStrategy::accept_offer()`] will also invalidate
    /// the current [`SdpPendingOffer`].
    ///
    /// ```
    /// # use str0m::Rtc;
    /// # use str0m::change::SdpStrategy;
    /// let mut rtc = Rtc::new();
    ///
    /// let changes = rtc.create_change_set(SdpStrategy);
    /// assert!(changes.apply().is_none());
    /// ```
    pub fn apply(self) -> Strategy::Apply {
        let change_id = self.rtc.next_change_id();
        self.strategy
            .apply(change_id, self.rtc, ChangesWrapper(self.changes))
    }
}

impl Deref for Changes {
    type Target = [Change];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
