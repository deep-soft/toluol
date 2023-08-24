//! `MX` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record containing mail exchange information.
/// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct MX {
    /// An integer which specifies the preference given to this record among others at the same
    /// owner. Lower values are preferred.
    pub preference: i16,
    /// A domain name which specifies a host willing to act as a mail exchange for the owner name.
    ///
    /// If this is ".", the record's domain does not accept mail.
    /// [\[RFC 7505\]](https://www.rfc-editor.org/rfc/rfc7505)
    pub exchange: Name,
}

impl RdataTrait for MX {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let preference = rdata.read_i16::<NetworkEndian>()?;
        let exchange = Name::parse(rdata, Compression::Allowed)?;
        Ok(Rdata::MX(Self {
            preference,
            exchange,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_i16::<NetworkEndian>(self.preference)?;
        self.exchange
            .encode_into(buf)
            .map(|bytes_written| bytes_written + 2)
    }

    fn canonicalize(&mut self) {
        self.exchange.canonicalize();
    }
}

impl Display for MX {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.preference, self.exchange)
    }
}
