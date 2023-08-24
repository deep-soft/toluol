//! `NS` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record containing the name of an authoritative name server.
/// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct NS {
    /// A domain name which specifies a host which should be authoritative for the specified class
    /// and domain.
    pub name: Name,
}

impl RdataTrait for NS {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        Ok(Rdata::NS(Self {
            name: Name::parse(rdata, Compression::Allowed)?,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        self.name.encode_into(buf)
    }

    fn canonicalize(&mut self) {
        self.name.canonicalize();
    }
}

impl Display for NS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}
