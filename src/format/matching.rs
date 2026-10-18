use super::FormatParams;
use crate::sdp::FormatParam;

/// Declarative defaults and constraints used by the shared matcher.
pub(crate) struct MatchingRules {
    pub default_channels: Option<u8>,
    pub max_channels: Option<u8>,
    /// Compare only these parameters, or all stored fields when absent.
    pub format: Option<&'static [FormatRule]>,
}

pub(crate) struct FormatRule {
    pub value: fn(&FormatParams) -> Option<FormatParam>,
    pub default: Option<FormatParam>,
    /// An omitted value can accept the peer's constraint, with a lower score.
    pub allow_unspecified: bool,
}

impl MatchingRules {
    pub fn supports_channels(&self, channels: Option<u8>) -> bool {
        self.max_channels
            .map(|max| (1..=max).contains(&channels.unwrap_or(1)))
            .unwrap_or(true)
    }

    pub fn format_penalty(&self, left: &FormatParams, right: &FormatParams) -> Option<usize> {
        let Some(rules) = self.format else {
            return (left == right).then_some(0);
        };

        rules.iter().try_fold(0, |penalty, rule| {
            let left = (rule.value)(left).or(rule.default);
            let right = (rule.value)(right).or(rule.default);
            if left == right {
                Some(penalty)
            } else if rule.allow_unspecified && (left.is_none() || right.is_none()) {
                Some(penalty + 1)
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const RULES: MatchingRules = MatchingRules {
        default_channels: Some(2),
        max_channels: Some(2),
        format: Some(&[
            FormatRule {
                value: |p| p.stereo.map(FormatParam::Stereo),
                default: Some(FormatParam::Stereo(false)),
                allow_unspecified: false,
            },
            FormatRule {
                value: |p| p.min_p_time.map(FormatParam::MinPTime),
                default: None,
                allow_unspecified: true,
            },
        ]),
    };

    #[test]
    fn defaults_compare_without_filling_input_fields() {
        let omitted = FormatParams::default();
        let explicit = FormatParams {
            stereo: Some(false),
            ..Default::default()
        };
        assert_eq!(RULES.format_penalty(&omitted, &explicit), Some(0));

        let different = FormatParams {
            stereo: Some(true),
            ..Default::default()
        };
        assert_eq!(RULES.format_penalty(&omitted, &different), None);
        assert_eq!(RULES.format_penalty(&different, &different), Some(0));
    }

    #[test]
    fn unspecified_constraint_can_adopt_the_peer_value() {
        let restricted = FormatParams {
            min_p_time: Some(10),
            ..Default::default()
        };
        let different = FormatParams {
            min_p_time: Some(20),
            ..Default::default()
        };
        let omitted = FormatParams::default();
        assert_eq!(RULES.format_penalty(&restricted, &omitted), Some(1));
        assert_eq!(RULES.format_penalty(&omitted, &restricted), Some(1));
        assert_eq!(RULES.format_penalty(&restricted, &different), None);
    }

    #[test]
    fn channel_limits_are_data() {
        assert!(RULES.supports_channels(Some(1)));
        assert!(RULES.supports_channels(Some(2)));
        assert!(!RULES.supports_channels(Some(0)));
        assert!(!RULES.supports_channels(Some(3)));
    }
}
