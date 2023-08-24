//! `DNAME` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record providing redirection for a subtree of the domain name tree in the DNS. That is, all
/// names that end with a particular suffix are redirected to another part of the DNS.
/// [\[RFC 6672\]](https://www.rfc-editor.org/rfc/rfc6672)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DNAME {
    /// The effect of the `DNAME` record is the substitution of [`Self::target`] for its owner name,
    /// as a suffix of a domain name. This substitution is to be applied for all names below the
    /// owner name of the `DNAME` record. This substitution has to be applied for every `DNAME`
    /// record found in the resolution process, which allows fairly lengthy valid chains of `DNAME`
    /// records.
    pub target: Name,
}

impl RdataTrait for DNAME {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        Ok(Rdata::DNAME(Self {
            target: Name::parse(rdata, Compression::Allowed)?,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        self.target.encode_into(buf)
    }

    fn canonicalize(&mut self) {
        self.target.canonicalize();
    }
}

impl Display for DNAME {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.target)
    }
}
