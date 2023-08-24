//! `SRV` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record which specifies the location of the server(s) for a specific protocol and domain.
/// [\[RFC 2782\]](https://www.rfc-editor.org/rfc/rfc2782)
///
/// The name this record is for must be of the format "_Service._Proto.Name", where:
/// - Service is the symbolic name of the desired service, as defined by the IANA or locally. This
///   is case insensitive.
/// - Proto is the symbolic name of the desired protocol, as defined by the IANA or locally. This is
///   case insensitive.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SRV {
    /// The priority of this target host. A client MUST attempt to contact the target host with the
    /// lowest-numbered priority it can reach; target hosts with the same priority SHOULD be tried
    /// in an order defined by [`Self::weight`].
    pub priority: u16,
    /// A server selection mechanism. The weight field specifies a relative weight for entries with
    /// the same priority. Larger weights SHOULD be given a proportionately higher probability of
    /// being selected. Domain administrators SHOULD use Weight 0 when there isn't any server
    /// selection to do, to make the record easier to read for humans (less noisy). In the presence
    /// of records containing weights greater than 0, records with weight 0 should have a very small
    /// chance of being selected.
    pub weight: u16,
    /// The port on this target host of this service. This is often as specified in Assigned Numbers
    /// but need not be.
    pub port: u16,
    /// The domain name of the target host. There MUST be one or more address records for this name,
    /// the name MUST NOT be an alias (in the sense of
    /// [RFC 1034](https://www.rfc-editor.org/rfc/rfc4034) or
    /// [RFC 2181](https://www.rfc-editor.org/rfc/rfc2181)). Implementors are urged, but not
    /// required, to return the address record(s) in the Additional Data section. Name compression
    /// is not to be used for this field.
    pub target: Name,
}

impl RdataTrait for SRV {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let priority = rdata.read_u16::<NetworkEndian>()?;
        let weight = rdata.read_u16::<NetworkEndian>()?;
        let port = rdata.read_u16::<NetworkEndian>()?;
        let target = Name::parse(rdata, Compression::Prohibited)?;
        Ok(Rdata::SRV(Self {
            priority,
            weight,
            port,
            target,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_u16::<NetworkEndian>(self.priority)?;
        buf.write_u16::<NetworkEndian>(self.weight)?;
        buf.write_u16::<NetworkEndian>(self.port)?;
        self.target
            .encode_into(buf)
            .map(|bytes_written| bytes_written + 2 + 2 + 2)
    }

    fn canonicalize(&mut self) {
        self.target.canonicalize();
    }
}

impl Display for SRV {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {} {}",
            self.priority, self.weight, self.port, self.target
        )
    }
}
