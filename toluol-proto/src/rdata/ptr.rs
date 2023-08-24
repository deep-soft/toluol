//! `PTR` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record containing a domain name pointer.
/// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
///
/// These records are used in special domains to point to some other location in the domain space.
/// These records are simple data, and don't imply any special processing similar to that performed
/// by [`CNAME`](super::cname::CNAME), which identifies aliases. See the description of the
/// IN-ADDR.ARPA domain for an example (Section 3.5 of
/// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)).
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct PTR {
    /// A domain name which points to some location in the domain name space.
    pub location: Name,
}

impl RdataTrait for PTR {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        Ok(Rdata::PTR(Self {
            location: Name::parse(rdata, Compression::Allowed)?,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        self.location.encode_into(buf)
    }

    fn canonicalize(&mut self) {
        self.location.canonicalize();
    }
}

impl Display for PTR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.location)
    }
}
