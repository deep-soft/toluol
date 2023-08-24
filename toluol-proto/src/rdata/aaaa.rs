//! `AAAA` RDATA definition.

use std::fmt::Display;
use std::io::Write;
use std::net::Ipv6Addr;

use byteorder::{NetworkEndian, ReadBytesExt};

use crate::error::{EncodeError, ParseError};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record containing an IPv6 host address.
/// [\[RFC 3596\]](https://www.rfc-editor.org/rfc/rfc3596)
///
/// Hosts that have multiple Internet addresses will have multiple `AAAA` records.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct AAAA {
    /// The host's address.
    pub address: Ipv6Addr,
}

impl RdataTrait for AAAA {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let address = Ipv6Addr::new(
            rdata.read_u16::<NetworkEndian>()?,
            rdata.read_u16::<NetworkEndian>()?,
            rdata.read_u16::<NetworkEndian>()?,
            rdata.read_u16::<NetworkEndian>()?,
            rdata.read_u16::<NetworkEndian>()?,
            rdata.read_u16::<NetworkEndian>()?,
            rdata.read_u16::<NetworkEndian>()?,
            rdata.read_u16::<NetworkEndian>()?,
        );
        Ok(Rdata::AAAA(Self { address }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_all(&self.address.octets())?;
        // an IPv6 address has 16 bytes
        Ok(16)
    }
}

impl Display for AAAA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}
