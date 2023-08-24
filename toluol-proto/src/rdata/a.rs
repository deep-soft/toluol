//! `A` RDATA definition.

use std::fmt::Display;
use std::io::Write;
use std::net::Ipv4Addr;

use byteorder::ReadBytesExt;

use crate::error::{EncodeError, ParseError};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record containing an IPv4 host address. [\[RFC 1035\]](https://tools.ietf.org/pdf/rfc1035.pdf)
///
/// Hosts that have multiple Internet addresses will have multiple `A` records.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct A {
    /// The host's address.
    pub address: Ipv4Addr,
}

impl RdataTrait for A {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let address = Ipv4Addr::new(
            rdata.read_u8()?,
            rdata.read_u8()?,
            rdata.read_u8()?,
            rdata.read_u8()?,
        );
        Ok(Rdata::A(Self { address }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_all(&self.address.octets())?;
        // an IPv4 address has 4 bytes
        Ok(4)
    }
}

impl Display for A {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}
