//! `CERT` RDATA definition.

use std::fmt::Display;
use std::io::{Read, Write};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use data_encoding::BASE64;
use repr_with_fallback::repr_with_fallback;

use crate::error::{EncodeError, ParseError};

use super::dnskey::Algorithm;
use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

repr_with_fallback! {
    /// The types of certificates that can be stored in a [`CERT`] record.
    /// [\[RFC 4398\]](https://www.rfc-editor.org/rfc/rfc4398)
    ///
    /// See <https://www.iana.org/assignments/cert-rr-types/cert-rr-types.xhtml> for the official list.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[non_exhaustive]
    pub enum CertificateType {
        /// X.509 as per PKIX
        PKIX = 1,
        /// SPKI certificate
        SPKI = 2,
        /// OpenPGP packet
        PGP = 3,
        /// The URL of an X.509 data object
        IPKIX = 4,
        /// The URL of an SPKI certificate
        ISPKI = 5,
        /// The URL of an OpenPGP packet
        IPGP = 6,
        /// Attribute Certificate
        ACPKIX = 7,
        /// The URL of an Attribute Certificate
        IACPKIX = 8,
        /// URI private
        URI = 253,
        /// OID private
        OID = 254,
        Unassigned(u16), // 0, 9-252, 255-65535 (technically, 0, 255, and 65535 are Reserved and
                        // 65280-65534 are Experimental, but we treat these values as Unassigned)
    }
}

/// A record containing a certificate or certificate revocation list.
/// [\[RFC 4398\]](https://www.rfc-editor.org/rfc/rfc4398)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CERT {
    /// The type of certificate that is stored in this record.
    pub ctype: CertificateType,
    /// Value computed for the key embedded in the certificate, using the
    /// [`RRSIG`](super::rrsig::RRSIG) key tag algorithm.
    ///
    /// See [`DNSKEY::key_tag()`](super::dnskey::DNSKEY::key_tag()).
    pub key_tag: u16,
    /// The used cryptographic algorithm.
    pub algorithm: Algorithm,
    /// The binary certificate data.
    pub data: Vec<u8>,
}

impl RdataTrait for CERT {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let ctype: CertificateType = rdata.read_u16::<NetworkEndian>()?.into();
        let key_tag = rdata.read_u16::<NetworkEndian>()?;
        let algorithm: Algorithm = rdata.read_u8()?.into();
        // we already read: u16 (2) + u16 (2) + u8 (1) = 5 bytes
        let mut data = vec![0; (rdlength - 5) as usize];
        rdata.read_exact(&mut data)?;

        Ok(Rdata::CERT(Self {
            ctype,
            key_tag,
            algorithm,
            data,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_u16::<NetworkEndian>(self.ctype.into())?;
        buf.write_u16::<NetworkEndian>(self.key_tag)?;
        buf.write_u8(self.algorithm.into())?;
        buf.write_all(&self.data)?;

        Ok(self.data.len() as u16 + 2 + 2 + 1)
    }
}

impl Display for CERT {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = BASE64.encode(&self.data);
        write!(
            f,
            "{:?} {} {:?} {}",
            self.ctype, self.key_tag, self.algorithm, data
        )
    }
}
