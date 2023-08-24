//! `CAA` RDATA definition.

use std::fmt::Display;
use std::io::{Read, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};
use url::Url;

use crate::error::{EncodeError, ParseError};
use crate::name::Name;

use super::{encode_string_into, Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// The type of [`Value`] stored in a [`CAA`] record.
/// [\[RFC 6844\]](https://www.rfc-editor.org/rfc/rfc6844)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Property {
    /// The issue property entry authorizes the holder of the domain name stored in [`CAA`]'s value
    /// or a party acting under the explicit authority of the holder of that domain name to issue
    /// certificates for the domain in which the property is published.
    Issue,
    /// The issuewild property entry authorizes the holder of the domain name stored in [`CAA`]'s
    /// value or a party acting under the explicit authority of the holder of that domain name to
    /// issue wildcard certificates for the domain in which the property is published.
    IssueWild,
    /// [`CAA`]'s value specifies a URL to which an issuer MAY report certificate issue requests
    /// that are inconsistent with the issuer's Certification Practices or Certificate Policy, or
    /// that a Certificate Evaluator may use to report observation of a possible policy violation.
    /// The Incident Object Description Exchange Format (IODEF) format is used (see
    /// [RFC 5070](https://www.rfc-editor.org/rfc/rfc5070)).
    Iodef,
    Unknown(String),
}

/// The value stored in a [`CAA`] record.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Value {
    /// See [`Property::Issue`] and [`Property::IssueWild`].
    Issuer {
        /// If [`None`], indicates that no certificates are to be issued for the domain in question.
        name: Option<Name>,
        parameters: Vec<(String, String)>,
    },
    /// See [`Property::Iodef`].
    IodefUrl(Url),
    /// For [`Property::Unknown`].
    Unknown(String),
}

/// This record allows a DNS domain name holder to specify one or more Certification Authorities
/// (CAs) authorized to issue certificates for that domain. CAA Resource Records allow a public
/// Certification Authority to implement additional controls to reduce the risk of unintended
/// certificate mis-issue. [\[RFC 6844\]](https://www.rfc-editor.org/rfc/rfc6844)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CAA {
    /// If true, indicates that the corresponding property tag MUST be understood if the semantics
    /// of the `CAA` record are to be correctly interpreted by an issuer.
    ///
    /// Issuers MUST NOT issue certificates for a domain if the relevant CAA Resource Record set
    /// contains unknown property tags that have this set to true.
    pub issuer_critical: bool,
    /// The type of [`Self::value`] stored in this record.
    ///
    /// This is private to prevent constructing invalid `CAA` records (mismatch between tag and
    /// value).
    tag: Property,
    /// The value stored in this record, as defined by [`Self::tag`].
    ///
    /// This is private to prevent constructing invalid `CAA` records (mismatch between tag and
    /// value).
    value: Value,
}

impl Property {
    /// Encodes the `Property` into the given `buf`, preceded by the tag length. No spaces are
    /// written to `buf`.
    ///
    /// Returns the number of bytes written on success.
    pub(crate) fn encode_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        encode_string_into(self.to_string(), buf)
    }
}

impl Display for Property {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Iodef => write!(f, "iodef"),
            Self::Issue => write!(f, "issue"),
            Self::IssueWild => write!(f, "iodef"),
            Self::Unknown(unknown) => write!(f, "{}", unknown),
        }
    }
}

impl Value {
    /// Encodes the `Value` into the given `buf`, preceded by the value length. No spaces are
    /// written to `buf`.
    ///
    /// Returns the number of bytes written on success.
    pub(crate) fn encode_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        encode_string_into(self.to_string(), buf)
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Issuer { name, parameters } => {
                if parameters.is_empty() {
                    if let Some(name) = name {
                        write!(f, "{}", name)
                    } else {
                        write!(f, ";")
                    }
                } else {
                    let parameters = parameters
                        .iter()
                        .map(|(tag, value)| format!("{}={}", tag, value))
                        .collect::<Vec<_>>()
                        .join(" ");
                    let name = name.as_ref().map(|n| n.to_string()).unwrap_or_default();
                    write!(f, "{}; {}", name, parameters)
                }
            }
            Self::IodefUrl(url) => write!(f, "{}", url),

            Self::Unknown(unknown) => write!(f, "{}", unknown),
        }
    }
}

impl From<&str> for Property {
    fn from(value: &str) -> Self {
        match value.to_ascii_lowercase().as_str() {
            "issue" => Self::Issue,
            "issuewild" => Self::IssueWild,
            "iodef" => Self::Iodef,
            _ => Self::Unknown(value.to_string()),
        }
    }
}

impl CAA {
    /// Creates a new `CAA` record with tag [`Property::Issue`].
    pub fn issue(
        issuer_critical: bool,
        name: Option<Name>,
        parameters: Vec<(String, String)>,
    ) -> Self {
        Self {
            issuer_critical,
            tag: Property::Issue,
            value: Value::Issuer { name, parameters },
        }
    }

    /// Creates a new `CAA` record with tag [`Property::IssueWild`].
    pub fn issue_wild(
        issuer_critical: bool,
        name: Option<Name>,
        parameters: Vec<(String, String)>,
    ) -> Self {
        Self {
            issuer_critical,
            tag: Property::IssueWild,
            value: Value::Issuer { name, parameters },
        }
    }

    /// Creates a new `CAA` record with tag [`Property::Iodef`].
    pub fn iodef(issuer_critical: bool, url: Url) -> Self {
        Self {
            issuer_critical,
            tag: Property::Iodef,
            value: Value::IodefUrl(url),
        }
    }

    /// The type of [`Self::value()`] stored in this record.
    pub fn tag(&self) -> &Property {
        &self.tag
    }

    /// The value stored in this record, as defined by [`Self::tag()`].
    pub fn value(&self) -> &Value {
        &self.value
    }
}

impl RdataTrait for CAA {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let flags = rdata.read_u8()?;
        let issuer_critical = (flags & (1 << 7)) != 0;
        let tag_length = rdata.read_u8()?;
        let mut tag = vec![0; tag_length as usize];
        rdata.read_exact(&mut tag)?;
        // we already read: u8 (1) + u8 (1) + tag_length = 2 + tag_length bytes
        let bytes_read = 2 + tag_length;
        let value_length = rdlength - bytes_read as u16;
        let mut value = vec![0; value_length as usize];
        rdata.read_exact(&mut value)?;

        let tag = String::from_utf8_lossy(&tag);
        if !tag.is_ascii() {
            return Err(ParseError::NonAsciiCaa(tag.into_owned()));
        }
        let value_cow = String::from_utf8_lossy(&value);
        let tag = Property::from(&*tag);
        let caa = match &tag {
            Property::Unknown(_) => Self {
                issuer_critical,
                tag,
                value: Value::Unknown(value_cow.into_owned()),
            },
            Property::Iodef => {
                let url = Url::parse(&value_cow)?;
                Self {
                    issuer_critical,
                    tag,
                    value: Value::IodefUrl(url),
                }
            }
            Property::Issue | Property::IssueWild => {
                let value = value_cow.trim();
                // check if we have issue/issuewild tag first
                let (name, parameters) = if let Some((name, parameters)) = value.split_once(';') {
                    let name = name.trim();
                    let name = if name.is_empty() {
                        None
                    } else {
                        Some(
                            Name::from_ascii(name)
                                .map_err(|_| ParseError::InvalidCaaIssueName(name.to_string()))?,
                        )
                    };
                    let parameters = parameters.trim();
                    let tag_values: Result<Vec<_>, _> = parameters
                        .split(&[' ', '\t'])
                        // may be separated by multiple spaces/tabs
                        .filter(|s| !s.is_empty())
                        .map(|tag_value| {
                            tag_value.split_once('=').ok_or_else(|| {
                                ParseError::InvalidCaaParameter(parameters.to_string())
                            })
                        })
                        .collect();
                    let tag_values: Vec<_> = tag_values?
                        .iter()
                        .map(|(tag, value)| (tag.to_string(), value.to_string()))
                        .collect();
                    (name, tag_values)
                } else {
                    let name = Name::from_ascii(value)
                        .map_err(|_| ParseError::InvalidCaaIssueName(value_cow.into_owned()))?;
                    (Some(name), vec![])
                };
                Self {
                    issuer_critical,
                    tag,
                    value: Value::Issuer { name, parameters },
                }
            }
        };

        Ok(Rdata::CAA(caa))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        let flags = if self.issuer_critical { 1 << 7 } else { 0 };
        buf.write_u8(flags)?;
        let tag_byte_count = self.tag.encode_into(buf)?;
        let value_byte_count = self.value.encode_into(buf)?;

        Ok(1 + tag_byte_count + value_byte_count)
    }
}

impl Display for CAA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.issuer_critical {
            write!(f, "1 ")?;
        } else {
            write!(f, "0 ")?;
        }
        write!(f, "{} \"{}\"", self.tag, self.value)
    }
}
