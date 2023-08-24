//! `OPENPGPKEY` RDATA definition.

use std::fmt::Display;
use std::io::{Read, Write};

use crate::error::{EncodeError, ParseError};
use data_encoding::BASE64;

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record used to associate an end entity OpenPGP Transferable Public Key (see [Section 11.1 of
/// RFC 4880](https://www.rfc-editor.org/rfc/rfc4880#section-11.1)) with an email address, thus
/// forming an "OpenPGP public key association".
/// [\[RFC 7929\]](https://www.rfc-editor.org/rfc/rfc7929)
///
/// A user that wishes to specify more than one OpenPGP key, for example, because they are
/// transitioning to a newer stronger key, can do so by adding multiple `OPENPGPKEY` records. A
/// single `OPENPGPKEY` record MUST only contain one OpenPGP key.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct OPENPGPKEY {
    /// A Transferable Public Key formatted as specified in
    /// [RFC 4880](https://www.rfc-editor.org/rfc/rfc4880).
    pub key: Vec<u8>,
}

impl RdataTrait for OPENPGPKEY {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let mut key = vec![0; rdlength as usize];
        rdata.read_exact(&mut key)?;
        Ok(Rdata::OPENPGPKEY(Self { key }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_all(&self.key)?;

        Ok(self.key.len() as u16)
    }
}

impl Display for OPENPGPKEY {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = BASE64.encode(&self.key);
        write!(f, "{}", key)
    }
}
