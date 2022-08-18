#[macro_use]
extern crate tracing;

use std::fmt;
use std::ops::Deref;

use combine::error::StringStreamError;
use serde::ser::SerializeStruct;
use thiserror::Error;

mod data;
pub use data::{MediaLine, MediaType, Sdp};

mod parser;

#[derive(Debug, Error)]
pub enum SdpError {
    #[error("SDP parse: {0}")]
    Parse(#[from] StringStreamError),

    #[error("SDP inconsistent: {0}")]
    Inconsistent(String),
}

/// SDP offer.
pub struct Offer(Sdp);

/// SDP answer.
pub struct Answer(Sdp);

impl Deref for Offer {
    type Target = Sdp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deref for Answer {
    type Target = Sdp;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

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
                        let _typ = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
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
                        let mut typ = None;
                        let mut sdp = None;
                        while let Some(key) = map.next_key()? {
                            match key {
                                Field::Typ => {
                                    if typ.is_some() {
                                        return Err(de::Error::duplicate_field("type"));
                                    }
                                    typ = Some(map.next_value()?);
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
                        let sdp = Sdp::parse(sdp)
                            .map_err(|_ph| de::Error::custom("Failed to parse SDP"))?;
                        Ok($Struct(sdp))
                    }
                }

                const FIELDS: &'static [&'static str] = &["type", "sdp"];
                d.deserialize_struct($Name, FIELDS, StructVisitor)
            }
        }
    };
}

sdp_ser!(Offer, "Offer", "offer");
sdp_ser!(Answer, "Answer", "answer");
