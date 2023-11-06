use std::fmt;
use std::ops::Deref;

use serde::ser::SerializeStruct;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

mod data;
pub(crate) use data::{FormatParam, Sdp, Session, SessionAttribute, Setup};
pub(crate) use data::{MediaAttribute, MediaLine, MediaType, Msid, Proto};
pub(crate) use data::{Simulcast, SimulcastGroups};
pub(crate) use parser::parse_candidate;

#[cfg(test)]
pub(crate) use data::RtpMap;

mod parser;

/// Errors from parsing and serializing SDP.
#[derive(Debug, Error)]
#[allow(missing_docs)]
pub enum SdpError {
    #[error("SDP parse: {0}")]
    ParseError(String),

    #[error("SDP inconsistent: {0}")]
    Inconsistent(String),
}

#[derive(Debug, PartialEq, Eq)]
/// SDP offer. Offers can be serialized via serde.
pub struct SdpOffer(Sdp);

impl SdpOffer {
    /// Takes the SDP string without any JSON wrapping and makes an `Offer`.
    pub fn from_sdp_string(input: &str) -> Result<Self, SdpError> {
        let sdp = Sdp::parse(input)?;
        Ok(SdpOffer(sdp))
    }

    /// Turns this offer into an SDP string, without any JSON wrapping.
    pub fn to_sdp_string(&self) -> String {
        self.0.to_string()
    }
}

#[derive(Debug, PartialEq, Eq)]
/// SDP answer. Answers can be serialized via serde.
pub struct SdpAnswer(Sdp);

impl SdpAnswer {
    /// Takes the SDP string without any JSON wrapping and makes an `Answer`.
    pub fn from_sdp_string(input: &str) -> Result<Self, SdpError> {
        let sdp = Sdp::parse(input)?;
        Ok(SdpAnswer(sdp))
    }

    /// Turns this answer into an SDP string, without any JSON wrapping.
    pub fn to_sdp_string(&self) -> String {
        self.0.to_string()
    }
}

impl Deref for SdpOffer {
    type Target = Sdp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for SdpAnswer {
    type Target = Sdp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Sdp> for SdpOffer {
    fn from(v: Sdp) -> Self {
        SdpOffer(v)
    }
}

impl From<Sdp> for SdpAnswer {
    fn from(v: Sdp) -> Self {
        SdpAnswer(v)
    }
}

impl fmt::Display for SdpOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", **self)
    }
}

impl fmt::Display for SdpAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", **self)
    }
}

macro_rules! sdp_ser {
    ($Struct:tt, $Name:literal, $LCName:literal) => {
        impl Serialize for $Struct {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                let mut o = s.serialize_struct($Name, 2)?;
                o.serialize_field("type", $LCName)?;
                o.serialize_field("sdp", &self.0.to_string())?;
                o.end()
            }
        }

        impl<'de> Deserialize<'de> for $Struct {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                #[derive(Debug)]
                enum Field {
                    Typ,
                    Sdp,
                }

                impl<'de> Deserialize<'de> for Field {
                    fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
                    where
                        D: Deserializer<'de>,
                    {
                        struct FieldVisitor;
                        impl<'de> de::Visitor<'de> for FieldVisitor {
                            type Value = Field;

                            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                                formatter.write_str("`type` or `sdp`")
                            }

                            fn visit_str<E>(self, value: &str) -> Result<Field, E>
                            where
                                E: de::Error,
                            {
                                match value {
                                    "type" => Ok(Field::Typ),
                                    "sdp" => Ok(Field::Sdp),
                                    _ => Err(de::Error::unknown_field(value, FIELDS)),
                                }
                            }
                        }
                        deserializer.deserialize_identifier(FieldVisitor)
                    }
                }

                struct StructVisitor;

                impl<'de> de::Visitor<'de> for StructVisitor {
                    type Value = $Struct;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        formatter.write_str($Name)
                    }

                    fn visit_seq<V>(self, mut seq: V) -> Result<$Struct, V::Error>
                    where
                        V: de::SeqAccess<'de>,
                    {
                        let typ: &'de str = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
                        if typ != $LCName {
                            return Err(de::Error::custom(format!(
                                "{} type field is '{}'",
                                $Name, typ
                            )));
                        }
                        let sdp: &'de str = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(1, &self))?;
                        let sdp = Sdp::parse(sdp)
                            .map_err(|_ph| de::Error::custom("Failed to parse SDP"))?;
                        Ok($Struct(sdp))
                    }

                    fn visit_map<V>(self, mut map: V) -> Result<$Struct, V::Error>
                    where
                        V: de::MapAccess<'de>,
                    {
                        let mut typ: Option<String> = None;
                        let mut sdp: Option<String> = None;
                        while let Some(key) = map.next_key()? {
                            match key {
                                Field::Typ => {
                                    if typ.is_some() {
                                        return Err(de::Error::duplicate_field("type"));
                                    }
                                    let value = map.next_value()?;
                                    if value != $LCName {
                                        return Err(de::Error::custom(format!(
                                            "{} type field is '{}'",
                                            $Name, value
                                        )));
                                    }
                                    typ = Some(value);
                                }
                                Field::Sdp => {
                                    if sdp.is_some() {
                                        return Err(de::Error::duplicate_field("sdp"));
                                    }
                                    sdp = Some(map.next_value()?);
                                }
                            }
                        }
                        let sdp = sdp.ok_or_else(|| de::Error::missing_field("sdp"))?;
                        let sdp = Sdp::parse(&sdp).map_err(|ph| {
                            de::Error::custom(format!("Failed to parse SDP: {:?}", ph))
                        })?;
                        Ok($Struct(sdp))
                    }
                }

                const FIELDS: &'static [&'static str] = &["type", "sdp"];
                d.deserialize_struct($Name, FIELDS, StructVisitor)
            }
        }
    };
}

sdp_ser!(SdpOffer, "Offer", "offer");
sdp_ser!(SdpAnswer, "Answer", "answer");

#[cfg(test)]
mod test {
    use crate::rtp_::SessionId;
    use crate::VERSION;

    use super::*;

    fn sdp() -> Sdp {
        Sdp {
            session: Session {
                id: SessionId::from(123_u64),
                attrs: vec![],
                bw: None,
            },
            media_lines: vec![],
        }
    }

    #[test]
    fn serialize_deserialize_offer() {
        let offer = SdpOffer(sdp());
        let json = serde_json::to_string(&offer).unwrap();

        assert_eq!(json, format!("{{\"type\":\"offer\",\"sdp\":\"v=0\\r\\no=str0m-{VERSION} 123 2 IN IP4 0.0.0.0\\r\\ns=-\\r\\nt=0 0\\r\\n\"}}"));

        let offer2: SdpOffer = serde_json::from_str(&json).unwrap();

        assert_eq!(offer, offer2);
    }

    #[test]
    fn serialize_deserialize_answer() {
        let answer = SdpAnswer(sdp());
        let json = serde_json::to_string(&answer).unwrap();

        assert_eq!(json, format!("{{\"type\":\"answer\",\"sdp\":\"v=0\\r\\no=str0m-{VERSION} 123 2 IN IP4 0.0.0.0\\r\\ns=-\\r\\nt=0 0\\r\\n\"}}"));

        let answer2: SdpAnswer = serde_json::from_str(&json).unwrap();

        assert_eq!(answer, answer2);
    }
}
