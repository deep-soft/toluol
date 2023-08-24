//! `SSHFP` RDATA definition.

use std::fmt::Display;
use std::io::{Read, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};
use data_encoding::HEXUPPER;
use repr_with_fallback::repr_with_fallback;

use crate::error::{EncodeError, ParseError};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

repr_with_fallback! {
    /// The public key algorithms for [`SSHFP`] records.
    /// [\[RFC 4255\]](https://www.rfc-editor.org/rfc/rfc4255)
    ///
    /// See <https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml> for
    /// the official list.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[non_exhaustive]
    pub enum Algorithm {
        RSA = 1,
        DSA = 2,
        ECDSA = 3,
        ED25519 = 4,
        ED448 = 6,
        Unassigned(u8), // 0, 5, 7-255 (technically, 0 is Reserved, but we treat it as Unassigned)
    }
}

repr_with_fallback! {
    /// The message-digest algorithms for fingerprints in [`SSHFP`] records.
    /// [\[RFC 4255\]](https://www.rfc-editor.org/rfc/rfc4255)
    ///
    /// See <https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xhtml> for
    /// the official list.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[non_exhaustive]
    pub enum FingerprintType {
        SHA1 = 1,
        SHA256 = 2,
        Unassigned(u8), // 0, 3-255 (technically, 0 is Reserved, but we treat it as Unassigned)
    }
}

/// A record containg a fingerprint of an SSH public host key that is associated with a DNS name.
/// [\[RFC 4255\]](https://www.rfc-editor.org/rfc/rfc4255)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct SSHFP {
    /// The algorithm of the public key.
    pub algorithm: Algorithm,
    /// The message-digest algorithm used to calculate the fingerprint of the public key.
    pub fingerprint_type: FingerprintType,
    /// The fingerprint, calculated over the public key blob as described in
    /// [RFC 4253](https://www.rfc-editor.org/rfc/rfc4253).
    pub fingerprint: Vec<u8>,
}

impl RdataTrait for SSHFP {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let algorithm: Algorithm = rdata.read_u8()?.into();
        let fingerprint_type: FingerprintType = rdata.read_u8()?.into();
        // we already read: u8 (2) + u8 (1) = 2 bytes
        let mut fingerprint = vec![0; (rdlength - 2) as usize];
        rdata.read_exact(&mut fingerprint)?;

        Ok(Rdata::SSHFP(Self {
            algorithm,
            fingerprint_type,
            fingerprint,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_u8(self.algorithm.into())?;
        buf.write_u8(self.fingerprint_type.into())?;
        buf.write_all(&self.fingerprint)?;

        Ok(self.fingerprint.len() as u16 + 1 + 1)
    }
}

impl Display for SSHFP {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let algorithm: u8 = self.algorithm.into();
        let fingerprint_type: u8 = self.fingerprint_type.into();
        let fingerprint = HEXUPPER.encode(&self.fingerprint);
        write!(f, "{} {} {}", algorithm, fingerprint_type, fingerprint)
    }
}
