//! `NSEC` RDATA definition.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::{Cursor, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};

use crate::error::{EncodeError, ParseError};
use crate::name::{Compression, Name};
use crate::RecordType;

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record listing two separate things: the next owner name (in the canonical ordering of the
/// zone) that contains authoritative data or a delegation point `NS` record set, and the set of
/// record types present at the `NSEC` record's owner name (see
/// [RFC 3845](https://www.rfc-editor.org/rfc/rfc3845)). The complete set of `NSEC` records in a
/// zone indicates which authoritative record sets exist in a zone and also form a chain of
/// authoritative owner names in the zone. This information is used to provide authenticated denial
/// of existence for DNS data, as described in [RFC 4035](https://www.rfc-editor.org/rfc/rfc4035).
/// [\[RFC 4034\]](https://www.rfc-editor.org/rfc/rfc4034)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct NSEC {
    /// The next owner name (in the canonical ordering of the zone, see
    /// [Section 6.1 of RFC 4034](https://www.rfc-editor.org/rfc/rfc4034#section-6.1)) that has
    /// authoritative data or contains a delegation point [`NS`](super::ns::NS) record set.
    ///
    /// The value of this field in the last `NSEC` record in the zone is the name of the zone apex
    /// (the owner name of the zone's [`SOA`](super::soa::SOA) record). This indicates that the
    /// owner name of the `NSEC` record is the last name in the canonical ordering of the zone.
    ///
    /// A sender MUST NOT use DNS name compression on the Next Domain Name field when transmitting
    /// an `NSEC` record.
    ///
    /// Owner names of record sets for which the given zone is not authoritative (such as glue
    /// records) MUST NOT be listed in the Next Domain Name unless at least one authoritative record
    /// set exists at the same owner name.
    pub next_domain_name: Name,
    /// The record set types that exist at the `NSEC` record's owner name.
    pub types: Vec<RecordType>,
}

impl NSEC {
    /// Parses the type bitmap in the RDATA section of an NSEC or NSEC3 record.
    ///
    /// `bytes_read` is the count of the bytes already read from the rdata. `rdlength` is the total
    /// length of the rdata.
    ///
    /// Returns an error if reading from `msg` fails.
    pub fn parse_type_bitmap(
        msg: &mut Cursor<&[u8]>,
        bytes_read: u16,
        rdlength: u16,
    ) -> Result<Vec<RecordType>, ParseError> {
        let mut len_read = bytes_read;
        let mut available_types = Vec::new();
        while len_read < rdlength {
            let window_number = msg.read_u8()?;
            let bitmap_len = msg.read_u8()?;
            for i in 0..bitmap_len {
                let byte = msg.read_u8()?;
                for j in 0..8 {
                    if (byte & (0b10000000 >> j)) != 0 {
                        let type_num = ((window_number as u16) << 8) + (i * 8 + j) as u16;
                        available_types.push(type_num.into());
                    }
                }
            }
            len_read += (2 + bitmap_len) as u16;
        }
        Ok(available_types)
    }

    /// Generates and writes the type bitmap representing the members of `types` into the given
    /// `buf`.
    ///
    /// Returns the number of written bytes on success.
    pub fn encode_type_bitmap_into(
        types: &[RecordType],
        buf: &mut impl Write,
    ) -> Result<u16, EncodeError> {
        // key: window block number; value: the window block.
        // we need to iterate over the blocks from lowest to highest block number, which is why we
        // use a BTreeMap and not a HashMap
        let mut window_blocks: BTreeMap<_, [u8; 32]> = BTreeMap::new();
        let mut bytes_written = 0;

        for rtype in types {
            let rtype: u16 = (*rtype).into();
            let block_idx = rtype / 256;
            let type_offset = rtype % 256;

            let block = window_blocks.entry(block_idx).or_default();
            let type_index = type_offset / 8;
            let type_shift = type_offset % 8;
            // the offset is counted from left to right, so we need to shift right
            block[type_index as usize] |= 0b10000000 >> type_shift;
        }

        for (block_number, block) in window_blocks {
            // we know there must be at least one bit set to one (else the block number wouldn't
            // be in the map) and therefore at least one non-zero octet, i.e. we can unwrap
            let last_nonzero_idx = block
                .iter()
                .enumerate()
                .rfind(|(_, byte)| **byte != 0)
                .unwrap()
                .0;
            let block_length = last_nonzero_idx + 1;

            buf.write_u8(block_number as u8)?;
            buf.write_u8(block_length as u8)?;
            buf.write_all(&block[..=last_nonzero_idx])?;

            bytes_written += 1 + 1 + block_length as u16;
        }

        Ok(bytes_written)
    }
}

impl RdataTrait for NSEC {
    fn parse_rdata(rdata: &mut Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError> {
        // used to calculate how many bytes were read later on
        let rdata_pos_before = rdata.position();

        let next_domain_name = Name::parse(rdata, Compression::Prohibited)?;

        let rdata_pos_after = rdata.position();
        let bytes_read = (rdata_pos_after - rdata_pos_before) as u16;

        let types = NSEC::parse_type_bitmap(rdata, bytes_read, rdlength)?;

        Ok(Rdata::NSEC(Self {
            next_domain_name,
            types,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        Ok(self.next_domain_name.encode_into(buf)?
            + Self::encode_type_bitmap_into(&self.types, buf)?)
    }

    fn canonicalize(&mut self) {
        self.next_domain_name.canonicalize();
    }
}

impl Display for NSEC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let types: Vec<_> = self.types.iter().map(ToString::to_string).collect();
        let types = types.join(" ");
        write!(f, "{} {}", self.next_domain_name, types)
    }
}
