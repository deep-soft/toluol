//! `OPT` RDATA definition.

use std::collections::HashMap;
use std::fmt::Display;
use std::io::{Read, Write};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use repr_with_fallback::repr_with_fallback;

use crate::error::{EncodeError, ParseError};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

repr_with_fallback! {
    /// The type of option as per [the IANA assignment](
    /// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11).
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug, Hash)]
    #[non_exhaustive]
    pub enum OptionCode {
        /// "A lightweight DNS transaction security mechanism that provides limited protection to
        /// DNS servers and clients against a variety of increasingly common denial-of-service and
        /// amplification/forgery or cache poisoning attacks by off-path attackers."
        /// [\[RFC 7873\]](https://www.rfc-editor.org/rfc/rfc7873.html)
        Cookie = 10,
        /// "Allows DNS clients and servers to pad request and response messages by a variable
        /// number of octets." [\[RFC 7830\]](https://www.rfc-editor.org/rfc/rfc7830.html)
        Padding = 12,
        Unknown(u16),
    }
}

impl OptionCode {
    fn format_rdata(&self, rdata: &[u8]) -> String {
        match self {
            OptionCode::Cookie => data_encoding::HEXLOWER.encode(rdata),
            OptionCode::Padding => "<padding>".into(),
            OptionCode::Unknown(_) => data_encoding::HEXLOWER.encode(rdata),
        }
    }
}

impl Display for OptionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptionCode::Cookie => write!(f, "COOKIE"),
            OptionCode::Padding => write!(f, "PADDING"),
            OptionCode::Unknown(u) => write!(f, "CODE{u}"),
        }
    }
}

/// A pseudo-record (i.e. not containing any real DNS data) containing control information
/// pertaining to the question-and-answer sequence of a specific transaction.
/// [\[RFC 6891\]](https://www.rfc-editor.org/rfc/rfc6891)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct OPT {
    /// A map of different EDNS options and their respective values.
    pub options: HashMap<OptionCode, Vec<u8>>,
}

impl RdataTrait for OPT {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let mut len = 0;
        let mut options = HashMap::new();
        while len < rdlength {
            let option_code = rdata.read_u16::<NetworkEndian>()?.into();
            let option_len = rdata.read_u16::<NetworkEndian>()?;
            let mut option_value = vec![0; option_len as usize];
            rdata.read_exact(&mut option_value)?;
            options.insert(option_code, option_value);
            len += option_len + 4;
        }
        Ok(Rdata::OPT(Self { options }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        let mut bytes_written = 0;
        for (option_code, option_value) in self.options.iter() {
            buf.write_u16::<NetworkEndian>((*option_code).into())?;
            buf.write_u16::<NetworkEndian>(option_value.len() as u16)?;
            buf.write_all(option_value)?;
            bytes_written += 2 + 2 + option_value.len() as u16;
        }
        Ok(bytes_written)
    }
}

impl Display for OPT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, (option_code, option_data)) in self.options.iter().enumerate() {
            write!(
                f,
                "{}: {}",
                option_code,
                option_code.format_rdata(option_data)
            )?;
            if i < self.options.len() - 1 {
                write!(f, ", ")?;
            }
        }
        Ok(())
    }
}
