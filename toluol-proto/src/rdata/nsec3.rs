//! `NSEC3` and `NSEC3PARAM` RDATA definition.

use std::fmt::Display;
use std::io::{Read, Write};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use data_encoding::{BASE32_DNSSEC, HEXUPPER};
use repr_with_fallback::repr_with_fallback;

use crate::error::{EncodeError, ParseError};
use crate::RecordType;

use super::nsec::NSEC;
use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

repr_with_fallback! {
    /// Hashing algorithms for use in [`NSEC3`] records.
    ///
    /// See <https://www.iana.org/assignments/dnssec-nsec3-parameters/dnssec-nsec3-parameters.xhtml> for
    /// the official list.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, Debug)]
    #[non_exhaustive]
    pub enum HashAlgorithm {
        SHA1 = 1,
        Unassigned(u8), // 0, 2-255 (technically, 0 is Reserved, but we treat it as Unassigned)
    }
}

/// A record providing authenticated denial of existence for DNS Resource Record Sets.
/// [\[RFC 5155\]](https://www.rfc-editor.org/rfc/rfc5155)
///
/// This serves the same purpose as an [`NSEC`][super::nsec::NSEC] record, but makes it harder to
/// enumerate all records in the zone by only containing a hash of the next owner name.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct NSEC3 {
    /// The cryptographic hash algorithm used to construct the hash-value.
    pub hash_algorithm: HashAlgorithm,
    /// Indicates whether this `NSEC3` record may cover unsigned delegations: if true, the record
    /// covers zero or more unsigned delegations; if false, the record covers zero unsigned
    /// delegations.
    pub opt_out: bool,
    /// The number of additional times the hash function has been performed. More iterations result
    /// in greater resiliency of the hash value against dictionary attacks, but at a higher
    /// computational cost for both the server and resolver.
    pub iterations: u16,
    /// If not [`None`], this is appended to the original owner name before hashing in order to
    /// defend against pre-calculated dictionary attacks.
    ///
    /// See [Section 5 of RFC 5155](https://www.rfc-editor.org/rfc/rfc5155#section-5) for details.
    pub salt: Option<Vec<u8>>,
    /// The next hashed owner name in hash order.
    ///
    /// Given the ordered set of all hashed owner names, this field contains the hash of an owner
    /// name that immediately follows the owner name of the given `NSEC3` record. The value of this
    /// field in the last `NSEC3` record in the zone is the same as the hashed owner name of the
    /// first `NSEC3` record in the zone in hash order.
    ///
    /// This is not base32 encoded, unlike the owner name of the `NSEC3` record. It is the
    /// unmodified binary hash value. It does not include the name of the containing zone.
    pub next_hashed_owner: Vec<u8>,
    /// The record set types that exist at the original owner name of the `NSEC3` record.
    pub types: Vec<RecordType>,
}

/// A record containing the [`NSEC3`] parameters (hash algorithm, flags, iterations, and salt)
/// needed by authoritative servers to calculate hashed owner names. [RFC 5155]
///
/// The owner name for the `NSEC3PARAM` record is the name of the zone apex.
///
/// The presence of an `NSEC3PARAM` record at a zone apex indicates that the specified parameters
/// may be used by authoritative servers to choose an appropriate set of [`NSEC3`] records for
/// negative responses. The `NSEC3PARAM` record is not used by validators or resolvers.
///
/// If an `NSEC3PARAM` record is present at the apex of a zone, then there MUST be an [`NSEC3`]
/// record using the same hash algorithm, iterations, and salt parameters present at every hashed
/// owner name in the zone. That is, the zone MUST contain a complete set of [`NSEC3`] records with
/// the same hash algorithm, iterations, and salt parameters.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct NSEC3PARAM {
    /// See [`NSEC3::hash_algorithm`].
    pub hash_algorithm: HashAlgorithm,
    /// This must be 0. If it is not, this record is not to be used.
    pub flags: u8,
    /// See [`NSEC3::iterations`].
    pub iterations: u16,
    /// See [`NSEC3::salt`].
    pub salt: Option<Vec<u8>>,
}

impl NSEC3 {
    fn encode_flags(&self) -> u8 {
        if self.opt_out {
            1
        } else {
            0
        }
    }
}

impl RdataTrait for NSEC3 {
    fn parse_rdata(rdata: &mut std::io::Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        let hash_algorithm: HashAlgorithm = rdata.read_u8()?.into();
        let flags = rdata.read_u8()?;
        let opt_out = (flags & 1) != 0;
        let iterations = rdata.read_u16::<NetworkEndian>()?;
        let salt_length = rdata.read_u8()?;
        let salt = if salt_length != 0 {
            let mut salt = vec![0; salt_length as usize];
            rdata.read_exact(&mut salt)?;
            Some(salt)
        } else {
            None
        };
        let hash_length = rdata.read_u8()?;
        let mut next_hashed_owner = vec![0; hash_length as usize];
        rdata.read_exact(&mut next_hashed_owner)?;
        // we already read: u8 (1) + u8 (1) + u16 (2) + u8 (1) + salt_length + u8 (1) + hash_length = 6 + salt_length + hash_length bytes
        let bytes_read = 6 + salt_length as u16 + hash_length as u16;
        let types = NSEC::parse_type_bitmap(rdata, bytes_read, rdlength)?;

        Ok(Rdata::NSEC3(Self {
            hash_algorithm,
            opt_out,
            iterations,
            salt,
            next_hashed_owner,
            types,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_u8(self.hash_algorithm.into())?;

        let flags = if self.opt_out { 1 } else { 0 };
        buf.write_u8(flags)?;
        buf.write_u16::<NetworkEndian>(self.iterations)?;

        if let Some(salt) = &self.salt {
            buf.write_u8(salt.len() as u8)?;
            buf.write_all(salt)?;
        } else {
            buf.write_u8(0)?;
        }

        buf.write_u8(self.next_hashed_owner.len() as u8)?;
        buf.write_all(&self.next_hashed_owner)?;

        let bytes_written = 1
            + 1
            + 2
            + 1
            + self.salt.as_ref().map(|s| s.len()).unwrap_or_default()
            + 1
            + self.next_hashed_owner.len();

        Ok(bytes_written as u16 + NSEC::encode_type_bitmap_into(&self.types, buf)?)
    }
}

impl Display for NSEC3 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash_algorithm: u8 = self.hash_algorithm.into();
        let salt = match &self.salt {
            None => "-".into(),
            Some(salt) => HEXUPPER.encode(salt),
        };
        let next_hashed_owner = BASE32_DNSSEC.encode(&self.next_hashed_owner);
        let types: Vec<_> = self.types.iter().map(ToString::to_string).collect();
        let types = types.join(" ");
        write!(
            f,
            "{} {} {} {} {} {}",
            hash_algorithm,
            self.encode_flags(),
            self.iterations,
            salt,
            next_hashed_owner,
            types,
        )
    }
}

impl RdataTrait for NSEC3PARAM {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let hash_algorithm: HashAlgorithm = rdata.read_u8()?.into();
        let flags = rdata.read_u8()?;
        let iterations = rdata.read_u16::<NetworkEndian>()?;
        let salt_length = rdata.read_u8()?;
        let salt = if salt_length != 0 {
            let mut salt = vec![0; salt_length as usize];
            rdata.read_exact(&mut salt)?;
            Some(salt)
        } else {
            None
        };
        Ok(Rdata::NSEC3PARAM(Self {
            hash_algorithm,
            flags,
            iterations,
            salt,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        buf.write_u8(self.hash_algorithm.into())?;
        buf.write_u8(self.flags)?;
        buf.write_u16::<NetworkEndian>(self.iterations)?;

        if let Some(salt) = &self.salt {
            buf.write_u8(salt.len() as u8)?;
            buf.write_all(salt)?;
        } else {
            buf.write_u8(0)?;
        }

        Ok(1 + 1 + 2 + 1 + self.salt.as_ref().map(|s| s.len()).unwrap_or_default() as u16)
    }
}

impl Display for NSEC3PARAM {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash_algorithm: u8 = self.hash_algorithm.into();
        let salt = match &self.salt {
            None => "-".into(),
            Some(salt) => HEXUPPER.encode(salt),
        };
        write!(f, "{} 0 {} {}", hash_algorithm, self.iterations, salt,)
    }
}
