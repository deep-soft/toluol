//! `TXT` RDATA definition.
//!
use std::fmt::Display;
use std::io::Write;

use crate::error::{EncodeError, ParseError};

use super::{encode_string_into, parse_string, Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record containing text strings. [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
///
/// `TXT` records are used to hold descriptive text. The semantics of the text depends on the
/// domain where it is found.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct TXT {
    /// One or more strings.
    pub text: Vec<String>,
}

impl RdataTrait for TXT {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let rdlength = rdlength as usize;
        let mut text = Vec::new();
        let mut bytes_read = 0;

        // according to RFC1035, it is possible that one TXT entry holds multiple character strings
        while bytes_read < rdlength {
            let (s, len) = parse_string(rdata)?;
            bytes_read += len; // also count the length byte before the actual string
            text.push(s);
        }

        Ok(Rdata::TXT(Self { text }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        let mut bytes_written = 0;
        for string in &self.text {
            bytes_written += encode_string_into(string, buf)?;
        }
        Ok(bytes_written)
    }
}

impl Display for TXT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let texts: Vec<_> = self
            .text
            .iter()
            .map(|text| {
                // we need to escape any eventual quotes in the string if we want to print the
                // strings quoted
                let text = text.replace('"', "\\\"");
                format!("\"{}\"", text)
            })
            .collect();
        let texts = texts.join(" ");
        write!(f, "{}", texts)
    }
}
