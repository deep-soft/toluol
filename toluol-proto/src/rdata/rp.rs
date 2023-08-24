//! `RP` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record for associating responsible person identification to any name in the DNS.
/// [\[RFC 1183\]](https://www.rfc-editor.org/rfc/rfc1183)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct RP {
    /// A domain name that specifies the mailbox for the responsible person.
    pub mbox: Name,
    /// A domain name for which `TXT` records exist.
    ///
    /// This may be "." to indicate that no associated `TXT` record exists.
    pub txt: Name,
}

impl RdataTrait for RP {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let mbox = Name::parse(rdata, Compression::Allowed)?;
        let txt = Name::parse(rdata, Compression::Allowed)?;
        Ok(Rdata::RP(Self { mbox, txt }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        Ok(self.mbox.encode_into(buf)? + self.txt.encode_into(buf)?)
    }

    fn canonicalize(&mut self) {
        self.mbox.canonicalize();
        self.txt.canonicalize();
    }
}

impl Display for RP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.mbox, self.txt)
    }
}
