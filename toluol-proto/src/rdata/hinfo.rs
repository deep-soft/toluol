//! `HINFO` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use crate::error::{EncodeError, ParseError};

use super::{encode_string_into, parse_string, Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record containing mailbox or mail list information.
/// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
///
/// May also be used as a response to queries with type `ANY`.
/// [\[RFC 8482\]](https://www.rfc-editor.org/rfc/rfc8482)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct HINFO {
    /// A string which specifies the CPU type.
    ///
    /// Set to `"RFC8482"` in a reply to a query with type `ANY`.
    pub cpu: String,
    /// A string which specifies the operating system type.
    ///
    /// Set to `""` in a reply to a query with type `ANY`.
    pub os: String,
}

impl RdataTrait for HINFO {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let cpu = parse_string(rdata)?.0;
        let os = parse_string(rdata)?.0;
        Ok(Rdata::HINFO(Self { cpu, os }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        Ok(encode_string_into(&self.cpu, buf)? + encode_string_into(&self.os, buf)?)
    }
}

impl Display for HINFO {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.cpu, self.os)
    }
}
