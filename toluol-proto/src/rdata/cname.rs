//! `CNAME` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record containing the canonical name for an alias.
/// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CNAME {
    /// A domain name which specifies the canonical or primary name for the owner. The owner name is
    /// an alias.
    pub cname: Name,
}

impl RdataTrait for CNAME {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        Ok(Rdata::CNAME(Self {
            cname: Name::parse(rdata, Compression::Allowed)?,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        self.cname.encode_into(buf)
    }

    fn canonicalize(&mut self) {
        self.cname.canonicalize();
    }
}

impl Display for CNAME {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.cname)
    }
}
