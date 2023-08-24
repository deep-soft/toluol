//! `RRSIG` RDATA definition.

use std::fmt::Display;
use std::io::{Read, Write};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use chrono::{TimeZone, Utc};
use data_encoding::BASE64;

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};
use crate::RecordType;

use super::dnskey::Algorithm;
use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

// for easier rustdoc links
#[allow(unused_imports)]
use super::dnskey::DNSKEY;

/// A record storing the digital signature for a resource record set with a particular name, class,
/// and type. This signature can be verified  using the public key stored in the matching [`DNSKEY`]
/// record. [\[RFC 4034\]](https://www.rfc-editor.org/rfc/rfc4034)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct RRSIG {
    /// The type of the record set covered by this record.
    pub type_covered: RecordType,
    /// The cryptographic algorithm used to create the signature.
    pub algorithm: Algorithm,
    /// The number of labels in the original `RRSIG` record owner name.
    ///
    /// The significance of this field is that a validator uses it to determine whether the answer
    /// was synthesized from a wildcard. If so, it can be used to determine what owner name was used
    /// in generating the signature. [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035) describes
    /// how to use this field to reconstruct the original owner name.
    ///
    /// The value of this field MUST NOT count either the null (root) label that terminates the
    /// owner name or the wildcard label (if present). The value of this field MUST be less than or
    /// equal to the number of labels in the `RRSIG` owner name. For example, "www.example.com" has
    /// a value of 3, and "*.example.com." has a value of 2. Root (".") has a value of 0.
    pub labels: u8,
    /// The TTL of the covered record set as it appears in the authoritative zone.
    ///
    /// This field is necessary because a caching resolver decrements the TTL value of a cached
    /// record set. In order to validate a signature, a validator requires the original TTL.
    pub original_ttl: u32,
    /// The end of the validity period for the signature, in the form of a 32-bit unsigned number of
    /// seconds elapsed since 1 January 1970 00:00:00 UTC, ignoring leap seconds.
    ///
    /// The longest interval that can be expressed by this format without wrapping is approximately
    /// 136 years. An `RRSIG` record can have an [`Self::signature_expiration`] value that is
    /// numerically smaller than the [`Self::signature_inception`] value if the expiration field
    /// value is near the 32-bit wrap-around point or if the signature is long lived. Because of
    /// this, all comparisons involving these fields MUST use "Serial number arithmetic", as defined
    /// in [RFC 1982](https://www.rfc-editor.org/rfc/rfc1982). As a direct consequence, the values
    /// contained in these fields cannot refer to dates more than 68 years in either the past or the
    /// future.
    pub signature_expiration: u32,
    /// The start of the validity period for the signature. See [Self::signature_expiration] for
    /// details.
    pub signature_inception: u32,
    /// The key tag of the [`DNSKEY`] record that validates this signature.
    ///
    /// See [`DNSKEY::key_tag()`].
    pub key_tag: u16,
    /// The owner name of the [`DNSKEY`] record that a validator is supposed to use to validate this
    /// signature.
    ///
    /// This MUST contain the name of the zone of the covered record set.
    ///
    /// A sender MUST NOT use DNS name compression on this field when transmitting an `RRSIG`
    /// record.
    pub signer_name: Name,
    /// The cryptographic signature that covers the `RRSIG` RDATA (excluding [`Self::signature`])
    /// and the record set specified by the record's owner name and class, and
    /// [`Self::type_covered`].
    ///
    /// The format of this field depends on the algorithm in use.
    pub signature: Vec<u8>,
}

impl RRSIG {
    /// The same as [`RdataTrait::encode_into()`], but skips [`Self::signature`] during encoding.
    ///
    /// This is useful for verifying DNSSEC signatures.
    pub(crate) fn encode_into_without_signature(
        &self,
        buf: &mut impl Write,
    ) -> Result<u16, EncodeError> {
        buf.write_u16::<NetworkEndian>(self.type_covered.into())?;
        buf.write_u8(self.algorithm.into())?;
        buf.write_u8(self.labels)?;
        buf.write_u32::<NetworkEndian>(self.original_ttl)?;
        buf.write_u32::<NetworkEndian>(self.signature_expiration)?;
        buf.write_u32::<NetworkEndian>(self.signature_inception)?;
        buf.write_u16::<NetworkEndian>(self.key_tag)?;
        let mut bytes_written = 2 + 1 + 1 + 4 + 4 + 4 + 2;
        bytes_written += self.signer_name.encode_into(buf)?;

        Ok(bytes_written)
    }
}

impl RdataTrait for RRSIG {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        // used to calculate how many bytes were read later on
        let rdata_pos_before = rdata.position();

        let type_covered: RecordType = rdata.read_u16::<NetworkEndian>()?.into();
        let algorithm: Algorithm = rdata.read_u8()?.into();
        let labels = rdata.read_u8()?;
        let original_ttl = rdata.read_u32::<NetworkEndian>()?;
        let signature_expiration = rdata.read_u32::<NetworkEndian>()?;
        let signature_inception = rdata.read_u32::<NetworkEndian>()?;
        let key_tag = rdata.read_u16::<NetworkEndian>()?;
        let signer_name = Name::parse(rdata, Compression::Prohibited)?;

        let rdata_pos_after = rdata.position();
        let bytes_read = (rdata_pos_after - rdata_pos_before) as usize;
        let mut signature = vec![0; rdlength as usize - bytes_read];
        rdata.read_exact(&mut signature)?;

        Ok(Rdata::RRSIG(Self {
            type_covered,
            algorithm,
            labels,
            original_ttl,
            signature_expiration,
            signature_inception,
            key_tag,
            signer_name,
            signature,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_u16::<NetworkEndian>(self.type_covered.into())?;
        buf.write_u8(self.algorithm.into())?;
        buf.write_u8(self.labels)?;
        buf.write_u32::<NetworkEndian>(self.original_ttl)?;
        buf.write_u32::<NetworkEndian>(self.signature_expiration)?;
        buf.write_u32::<NetworkEndian>(self.signature_inception)?;
        buf.write_u16::<NetworkEndian>(self.key_tag)?;
        let mut bytes_written = 2 + 1 + 1 + 4 + 4 + 4 + 2;
        bytes_written += self.signer_name.encode_into(buf)?;
        buf.write_all(&self.signature)?;

        Ok(bytes_written + self.signature.len() as u16)
    }

    fn canonicalize(&mut self) {
        self.signer_name.canonicalize();
    }
}

impl Display for RRSIG {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let signature_expiration = Utc
            .timestamp(self.signature_expiration as i64, 0)
            .format("%Y%m%d%H%M%S")
            .to_string();
        let signature_inception = Utc
            .timestamp(self.signature_inception as i64, 0)
            .format("%Y%m%d%H%M%S")
            .to_string();
        let signature = BASE64.encode(&self.signature);
        write!(
            f,
            "{} {:?} {} {} {} {} {} {} {}",
            self.type_covered,
            self.algorithm,
            self.labels,
            self.original_ttl,
            signature_expiration,
            signature_inception,
            self.key_tag,
            self.signer_name,
            signature
        )
    }
}
