//! `SOA` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record that marks the start of a zone of authority.
/// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SOA {
    /// The domain name of the name server that was the original or primary source of data for this
    /// zone.
    pub mname: Name,
    /// A domain name which specifies the mailbox of the person responsible for this zone.
    pub rname: Name,
    /// The version number of the original copy of the zone. Zone transfers preserve this value.
    /// This value wraps and should be compared using sequence space arithmetic.
    pub serial: u32,
    /// A time interval before the zone should be refreshed.
    pub refresh: u32,
    /// A time interval that should elapse before a failed refresh should be retried.
    pub retry: u32,
    /// A time value that specifies the upper limit on the time interval that can elapse before
    /// the zone is no longer authoritative.
    pub expire: u32,
    /// The TTL to be used for negative (NXDOMAIN) responses.
    /// [\[RFC 2308\]](https://www.rfc-editor.org/rfc/rfc2308)
    ///
    /// There also exists this obsolete definition:
    /// The minimum TTL field that should be exported with any record from this zone.
    pub minimum: u32,
}

impl RdataTrait for SOA {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let mname = Name::parse(rdata, Compression::Allowed)?;
        let rname = Name::parse(rdata, Compression::Allowed)?;
        let serial = rdata.read_u32::<NetworkEndian>()?;
        let refresh = rdata.read_u32::<NetworkEndian>()?;
        let retry = rdata.read_u32::<NetworkEndian>()?;
        let expire = rdata.read_u32::<NetworkEndian>()?;
        let minimum = rdata.read_u32::<NetworkEndian>()?;

        Ok(Rdata::SOA(Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        let mut bytes_written = self.mname.encode_into(buf)?;
        bytes_written += self.rname.encode_into(buf)?;
        buf.write_u32::<NetworkEndian>(self.serial)?;
        buf.write_u32::<NetworkEndian>(self.refresh)?;
        buf.write_u32::<NetworkEndian>(self.retry)?;
        buf.write_u32::<NetworkEndian>(self.expire)?;
        buf.write_u32::<NetworkEndian>(self.minimum)?;

        Ok(bytes_written + 4 + 4 + 4 + 4 + 4)
    }

    fn canonicalize(&mut self) {
        self.mname.canonicalize();
        self.rname.canonicalize();
    }
}

impl Display for SOA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {} {} {} {}",
            self.mname,
            self.rname,
            self.serial,
            self.refresh,
            self.retry,
            self.expire,
            self.minimum
        )
    }
}
