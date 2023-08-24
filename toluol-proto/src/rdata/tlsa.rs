//! `TLSA` RDATA definition.

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
    /// The usage of a certificate stored in a [`TLSA`] record.
    /// [\[RFC 6698\]](https://www.rfc-editor.org/rfc/rfc6698)
    ///
    /// See <https://www.iana.org/assignments/dane-parameters/dane-parameters.xhtml> for the
    /// official list.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[non_exhaustive]
    pub enum CertUsage {
        CA = 0,
        Service = 1,
        TrustAnchor = 2,
        DomainIssued = 3,
        Unassigned(u8), // 4-254
        Private = 255,
    }
}

repr_with_fallback! {
    /// Which part of a server's TLS certificate to match against the data stored in a [`TLSA`]
    /// record. [\[RFC 6698\]](https://www.rfc-editor.org/rfc/rfc6698)
    ///
    /// See <https://www.iana.org/assignments/dane-parameters/dane-parameters.xhtml> for the
    /// official list.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[non_exhaustive]
    pub enum Selector {
        /// The Certificate binary structure as defined in
        /// [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).
        Full = 0,
        /// DER-encoded binary structure as defined in
        /// [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280).
        SPKI = 1,
        Unassigned(u8), // 2-254
        Private = 255,
    }
}

repr_with_fallback! {
    /// How the certificate association stored in a [`TLSA`] record is presented.
    /// [\[RFC 6698\]](https://www.rfc-editor.org/rfc/rfc6698)
    ///
    /// See <https://www.iana.org/assignments/dane-parameters/dane-parameters.xhtml> for the
    /// official list.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[non_exhaustive]
    pub enum Matching {
        /// Exact match on selected content.
        Full = 0,
        /// SHA-256 hash of selected content.
        SHA256 = 1,
        /// SHA-512 hash of selected content.
        SHA512 = 2,
        Unassigned(u8), // 3-254
        Private = 255,
    }
}

/// A record used to associate a TLS server certificate or public key with the domain name where the
/// record is found, thus forming a "TLSA certificate association".
/// [\[RFC 6698\]](https://www.rfc-editor.org/rfc/rfc6698)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct TLSA {
    /// The provided association that will be used to match the certificate presented in the TLS
    /// handshake.
    pub cert_usage: CertUsage,
    /// Which part of the TLS certificate presented by the server will be matched against the
    /// association data.
    pub selector: Selector,
    /// How the certificate association is presented.
    pub matching: Matching,
    /// The "certificate association data" to be matched. These bytes are either raw data (that is,
    /// the full certificate or its SubjectPublicKeyInfo, depending on the selector), or the hash of
    /// the raw data. The data refers to the certificate in the association, not to the TLS ASN.1
    /// Certificate object.
    pub cert_data: Vec<u8>,
}

impl RdataTrait for TLSA {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let cert_usage: CertUsage = rdata.read_u8()?.into();
        let selector: Selector = rdata.read_u8()?.into();
        let matching: Matching = rdata.read_u8()?.into();
        // we already read: u8 (1) + u8 (1) + u8 (1) = 3 bytes
        let mut cert_data = vec![0; (rdlength - 3) as usize];
        rdata.read_exact(&mut cert_data)?;

        Ok(Rdata::TLSA(Self {
            cert_usage,
            selector,
            matching,
            cert_data,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_u8(self.cert_usage.into())?;
        buf.write_u8(self.selector.into())?;
        buf.write_u8(self.matching.into())?;
        buf.write_all(&self.cert_data)?;

        Ok(self.cert_data.len() as u16 + 1 + 1 + 1)
    }
}

impl Display for TLSA {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cert_usage: u8 = self.cert_usage.into();
        let selector: u8 = self.selector.into();
        let matching: u8 = self.matching.into();
        let cert_data = HEXUPPER.encode(&self.cert_data);
        write!(f, "{} {} {} {}", cert_usage, selector, matching, cert_data)
    }
}
