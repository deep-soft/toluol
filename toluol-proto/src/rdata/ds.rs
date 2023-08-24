//! `DS` RDATA definition.

use std::fmt::Display;
use std::io::{Read, Write};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use data_encoding::HEXUPPER;
use repr_with_fallback::repr_with_fallback;

use crate::error::{EncodeError, ParseError};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

// import DNSKEY for easier rustdoc links
#[allow(unused_imports)]
use super::dnskey::{Algorithm, DNSKEY};

repr_with_fallback! {
    /// Digest algorithms for the [`DS`] record.
    ///
    /// See <https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml> for the official list.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[non_exhaustive]
    pub enum DigestType {
        /// [RFC 3658](https://www.rfc-editor.org/rfc/rfc3658)
        SHA1 = 1,
        /// [RFC 4509](https://www.rfc-editor.org/rfc/rfc4509)
        SHA256 = 2,
        /// GOST R 34.11-94 [\[RFC 5933\]](https://www.rfc-editor.org/rfc/rfc5933)
        GOST = 3,
        /// [RFC 6605](https://www.rfc-editor.org/rfc/rfc6605)
        SHA384 = 4,
        Unassigned(u8), // 0, 5-255 (technically, 0 is Reserved, but we treat it as Unassigned)
    }
}

/// A record referring to a [`DNSKEY`] record by storing the key tag, algorithm number, and a digest
/// of the [`DNSKEY`] record. [\[RFC 4034\]](https://www.rfc-editor.org/rfc/rfc4034)
///
/// The `DS` record and its corresponding [`DNSKEY`] record have the same owner name, but they are
/// stored in different locations. The `DS` record appears only on the upper (parental) side of a
/// delegation, and is authoritative data in the parent zone. For example, the `DS` record for
/// "example.com" is stored in the "com" zone (the parent zone) rather than in the "example.com"
/// zone (the child zone). The corresponding [`DNSKEY`] record is stored in the "example.com" zone
/// (the child zone).
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DS {
    /// The key tag of the corresponding [`DNSKEY`] record.
    ///
    /// See [`DNSKEY::key_tag()`].
    pub key_tag: u16,
    /// The algorithm used by the corresponding [`DNSKEY`] record.
    pub algorithm: Algorithm,
    /// The type of digest stored in [`Self::digest`].
    pub digest_type: DigestType,
    /// The digest of the corresponding [`DNSKEY`] record.
    pub digest: Vec<u8>,
}

impl RdataTrait for DS {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let key_tag = rdata.read_u16::<NetworkEndian>()?;
        let algorithm: Algorithm = rdata.read_u8()?.into();
        let digest_type: DigestType = rdata.read_u8()?.into();
        // we already read: u16 (2) + u8 (1) + u8 (1) = 4 bytes
        let mut digest = vec![0; (rdlength - 4) as usize];
        rdata.read_exact(&mut digest)?;

        Ok(Rdata::DS(Self {
            key_tag,
            algorithm,
            digest_type,
            digest,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_u16::<NetworkEndian>(self.key_tag)?;
        buf.write_u8(self.algorithm.into())?;
        buf.write_u8(self.digest_type.into())?;
        buf.write_all(&self.digest)?;

        Ok(self.digest.len() as u16 + 2 + 1 + 1)
    }
}

impl Display for DS {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let digest_type: u8 = self.digest_type.into();
        let digest = HEXUPPER.encode(&self.digest);
        write!(
            f,
            "{} {:?} {} {}",
            self.key_tag, self.algorithm, digest_type, digest
        )
    }
}
