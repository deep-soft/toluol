//! `DNSKEY` RDATA definition.

use std::{
    fmt::Display,
    io::{Read, Write},
};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use data_encoding::BASE64;
use ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use repr_with_fallback::repr_with_fallback;

use crate::error::{DnssecError, EncodeError, ParseError};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

repr_with_fallback! {
    /// Algorithms for use in zone signing (see [`DNSKEY`]) and storing certificates in the DNS (see
    /// [`CERT`](super::cert::CERT)).
    ///
    /// See <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml> for the
    /// official list.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[non_exhaustive]
    #[allow(non_camel_case_types)]
    pub enum Algorithm {
        /// DON'T USE THIS! DSA is not considered secure anymore, and this is only provided for
        /// compatibility.
        DSA = 3,
        /// DON'T USE THIS! SHA1 is not considered secure anymore, and this is only provided for
        /// compatibility.
        RSASHA1 = 5,
        /// DON'T USE THIS! DSA and SHA1 are not considered secure anymore, and this is only provided
        /// for compatibility.
        DSA_NSEC3_SHA1 = 6,
        /// DON'T USE THIS! SHA1 is not considered secure anymore, and this is only provided for
        /// compatibility.
        RSASHA1_NSEC3_SHA1 = 7,
        /// RSA with SHA256 [\[RFC 5702\]](https://www.rfc-editor.org/rfc/rfc5702)
        RSASHA256 = 8,
        /// RSA with SHA512 [\[RFC 5702\]](https://www.rfc-editor.org/rfc/rfc5702)
        RSASHA512 = 10,
        /// GOST R 34.10-2001 [\[RFC 5933\]](https://www.rfc-editor.org/rfc/rfc5933)
        ECC_GOST = 12,
        /// ECDSA Curve P-256 with SHA-256 [\[RFC 6605\]](https://www.rfc-editor.org/rfc/rfc6605)
        ECDSAP256SHA256 = 13,
        /// ECDSA Curve P-384 with SHA-384 [\[RFC 6605\]](https://www.rfc-editor.org/rfc/rfc6605)
        ECDSAP384SHA384 = 14,
        /// Ed25519 [\[RFC 8080\]](https://www.rfc-editor.org/rfc/rfc8080)
        ED25519 = 15,
        /// Ed448 [\[RFC 8080\]](https://www.rfc-editor.org/rfc/rfc8080)
        ED448 = 16,
        Unassigned(u8), // 0-2, 4, 9, 11, 17-255 (technically, some of these values have been assigned
                        // to algorithms that cannot be used for zone signing or are Reserved/Private,
                        // but we treat them as Unassigned)
    }
}

/// A record containing the public key used to sign record sets of the zone.
/// [\[RFC 4034\]](https://www.rfc-editor.org/rfc/rfc4034)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct DNSKEY {
    /// Indicates whether this key is used to sign record sets.
    pub zone: bool,
    /// A key is considered revoked when the resolver sees the key in a self-signed record set and
    /// the key has this set to true. [\[RFC 5011\]](https://www.rfc-editor.org/rfc/rfc5011)
    pub revoked: bool,
    /// Indicates whether this key is a key signing key, i.e. used to sign the key(s) that sign
    /// record sets.
    pub secure_entry_point: bool,

    // the wire format also contains a "Protocol" field, but that must always be 3 (see
    // https://www.iana.org/assignments/dns-key-rr/dns-key-rr.xhtml), so we don't store it
    // explicitly
    /// The public key's cryptographic algorithm and determines the format of
    /// [`Self::key`].
    pub algorithm: Algorithm,
    pub key: Vec<u8>,
}

impl DNSKEY {
    /// Calculates this key's key tag. Key tags are used in [`RRSIG`](super::RRSIG) and
    /// [`DS`](super::DS) records to "help select the corresponding `DNSKEY` record efficiently when
    /// more than one candidate `DNSKEY` record is available."
    /// [\[RFC 4034\]](https://www.rfc-editor.org/rfc/rfc4034)
    ///
    /// # Note from [RFC 4034](https://www.rfc-editor.org/rfc/rfc4034)
    /// However, it is essential to note that the key tag is not a unique identifier. It is
    /// theoretically possible for two distinct `DNSKEY` records to have the same owner name, the
    /// same algorithm, and the same key tag. The key tag is used to limit the possible candidate
    /// keys, but it does not uniquely identify a `DNSKEY` record. Implementations MUST NOT assume
    /// that the key tag uniquely identifies a `DNSKEY` record.
    pub fn key_tag(&self) -> u16 {
        // This is a translation of the C reference code from RFC 4034, Appendix B
        let mut key_data = vec![0; self.key.len() + 4];
        self.encode_rdata_into(&mut key_data)
            .expect("encoding DNSKEY into vector failed");
        let mut ac = 0u32;
        for (i, byte) in key_data.iter().enumerate() {
            let byte = *byte as u32;
            ac += if (i & 1) != 0 { byte } else { byte << 8 };
        }
        ac += (ac >> 16) & 0xFFFF;
        (ac & 0xFFFF) as u16
    }

    /// Validates the given signature of the specified data using the public key stored in this
    /// `DNSKEY`.
    ///
    /// Returns `Ok(())` if the signature is valid and and error if the signature in invalid.
    ///
    /// This may fail if verification using the algorithm specified by [`Self::algorithm`] has not
    /// been implemented (yet).
    pub fn validate(&self, data: &[u8], signature: &[u8]) -> Result<(), DnssecError> {
        // TODO move the actual signature validation somewhere else?
        match self.algorithm {
            Algorithm::ECDSAP256SHA256 => {
                if signature.len() != 64 {
                    return Err(DnssecError::ParseSignature);
                }

                // see https://docs.rs/sec1/0.2.1/sec1/point/struct.EncodedPoint.html#method.from_untagged_bytes
                let mut encoded_key = vec![0x04; self.key.len() + 1];
                encoded_key[1..].copy_from_slice(&self.key);
                let key = match VerifyingKey::from_sec1_bytes(&encoded_key) {
                    Ok(key) => key,
                    Err(_) => return Err(DnssecError::ParseKey),
                };

                let mut point_r = [0; 32];
                point_r.copy_from_slice(&signature[..32]);
                let mut point_s = [0; 32];
                point_s.copy_from_slice(&signature[32..]);
                let signature = match Signature::from_scalars(point_r, point_s) {
                    Ok(sig) => sig,
                    Err(_) => return Err(DnssecError::ParseSignature),
                };

                match key.verify(data, &signature) {
                    Ok(()) => Ok(()),
                    Err(_) => Err(DnssecError::InvalidSignature),
                }
            }
            // TODO: support more DNSSEC algorithms (e.g. RSASHA256, used for example.com)
            _ => Err(DnssecError::UnsupportedAlgorithm),
        }
    }

    fn encode_flags(&self) -> u16 {
        let zone = if self.zone { 1 << 8 } else { 0 };
        let revoked = if self.revoked { 1 << 7 } else { 0 };
        let secure_entry_point = if self.secure_entry_point { 1 } else { 0 };
        zone | revoked | secure_entry_point
    }
}

impl RdataTrait for DNSKEY {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let flags = rdata.read_u16::<NetworkEndian>()?;
        let zone = (flags & (1 << 8)) != 0;
        let revoked = (flags & (1 << 7)) != 0;
        let secure_entry_point = (flags & 1) != 0;

        let protocol = rdata.read_u8()?;
        if protocol != 3 {
            return Err(ParseError::InvalidDnskeyProtocol(protocol));
        }

        let algorithm: Algorithm = rdata.read_u8()?.into();

        // we already read: u16 (2) + u8 (1) + u8 (1) = 4 bytes
        let mut key = vec![0; (rdlength - 4) as usize];
        rdata.read_exact(&mut key)?;

        Ok(Rdata::DNSKEY(Self {
            zone,
            revoked,
            secure_entry_point,
            algorithm,
            key,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        let flags = self.encode_flags();

        buf.write_u16::<NetworkEndian>(flags)?;
        // protocol must always be 3
        buf.write_u8(3)?;
        buf.write_u8(self.algorithm.into())?;
        buf.write_all(&self.key)?;

        Ok(self.key.len() as u16 + 2 + 1 + 1)
    }
}

impl Display for DNSKEY {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let key = BASE64.encode(&self.key);
        write!(f, "{} 3 {:?} {}", self.encode_flags(), self.algorithm, key)
    }
}
