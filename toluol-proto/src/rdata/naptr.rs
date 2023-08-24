//! `NAPTR` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};

use super::{encode_string_into, parse_string, Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record containing a rule for Dynamic Delegation Discovery System.
/// [\[RFC 3403\]](https://www.rfc-editor.org/rfc/rfc3403)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct NAPTR {
    /// An integer specifying the order in which the `NAPTR` records MUST be processed in order to
    /// accurately represent the ordered list of Rules. The ordering is from lowest to highest. If
    /// two records have the same order value then they are considered to be the same rule and
    /// should be selected based on the combination of the Preference values and Services offered.
    pub order: u16,
    /// An unsigned integer that specifies the order in which `NAPTR` records with equal Order
    /// values SHOULD be processed, low numbers being processed before high numbers. A client MAY
    /// look at records with higher preference values if it has a good reason to do so such as not
    /// supporting some protocol or service very well.
    pub preference: u16,
    /// A string containing flags to control aspects of the rewriting and interpretation of the
    /// fields in the record. Flags are single characters from the set A-Z and 0-9. The case of the
    /// alphabetic characters is not significant. The field can be empty.
    pub flags: String,
    /// A string that specifies the Service Parameters applicable to this this delegation path. It
    /// is up to the Application Specification to specify the values found in this field.
    pub services: String,
    /// A string containing a substitution expression that is applied to the original string held by
    /// the client in order to construct the next domain name to lookup.
    pub regexp: String,
    /// A domain name which is the next domain-name to query for depending on the potential values
    /// found in the flags field. This field is used when the regular expression is a simple
    /// replacement operation. Any value in this field MUST be a fully qualified domain name. Name
    /// compression is not to be used for this field.
    pub replacement: Name,
}

impl RdataTrait for NAPTR {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let order = rdata.read_u16::<NetworkEndian>()?;
        let preference = rdata.read_u16::<NetworkEndian>()?;
        let flags = parse_string(rdata)?.0;
        let services = parse_string(rdata)?.0;
        let regexp = parse_string(rdata)?.0;
        let replacement = Name::parse(rdata, Compression::Prohibited)?;
        Ok(Rdata::NAPTR(Self {
            order,
            preference,
            flags,
            services,
            regexp,
            replacement,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_u16::<NetworkEndian>(self.order)?;
        buf.write_u16::<NetworkEndian>(self.preference)?;
        let mut bytes_read = 2 + 2;
        bytes_read += encode_string_into(&self.flags, buf)?;
        bytes_read += encode_string_into(&self.services, buf)?;
        bytes_read += encode_string_into(&self.regexp, buf)?;
        bytes_read += self.replacement.encode_into(buf)?;

        Ok(bytes_read)
    }

    fn canonicalize(&mut self) {
        self.replacement.canonicalize();
    }
}

impl Display for NAPTR {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} \"{}\" \"{}\" \"{}\" {}",
            self.order, self.preference, self.flags, self.services, self.regexp, self.replacement
        )
    }
}
