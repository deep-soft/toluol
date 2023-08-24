//! `LOC` RDATA definition.

use std::fmt::Display;
use std::io::Write;

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};

use crate::error::{EncodeError, ParseError};

use super::{Rdata, RdataTrait};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A record carrying location information about hosts, networks, and subnets. This is experimental.
/// [RFC 1876](https://www.rfc-editor.org/rfc/rfc1876)
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct LOC {
    // the wire format also contains a "Version" field, but that must always be 0 (see RFC 1876)
    /// The diameter of a sphere enclosing the described entity, in centimeters, expressed as a pair
    /// of four-bit unsigned integers, each ranging from zero to nine, with the most significant
    /// four bits representing the base and the second number representing the power of ten by which
    /// to multiply the base.
    pub size: u8,
    /// The horizontal precision of the data, in centimeters, expressed using the same
    /// representation as [`Self::size`]. This is the diameter of the horizontal "circle of error",
    /// rather than a "plus or minus" value.
    pub horizontal_precision: u8,
    /// The vertical precision of the data, in centimeters, expressed using the sane representation
    /// as for [`Self::size`]. This is the total potential vertical error, rather than a "plus or
    /// minus" value.
    pub vertical_precision: u8,
    /// The latitude of the center of the sphere described by [`Self::size`], in thousandths of a
    /// second of arc. 2^31 represents the equator; numbers above that are north latitude.
    pub latitude: u32,
    /// The longitude of the center of the sphere described by [`Self::size`], in thousandths of a
    /// second of arc, rounded away from the prime meridian. 2^31 represents the prime meridian;
    /// numbers above that are east longitude.
    pub longitude: u32,
    /// The altitude of the center of the sphere described by the [`Self::size`] field, in
    /// centimeters, from a base of 100,000m below the [WGS 84] reference spheroid used by GPS.
    pub altitude: u32,
}

impl RdataTrait for LOC {
    fn parse_rdata(
        rdata: &mut std::io::Cursor<&[u8]>,
        _rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        let version = rdata.read_u8()?;
        if version != 0 {
            return Err(ParseError::InvalidLocVersion(version));
        }

        let size = rdata.read_u8()?;
        let horizontal_precision = rdata.read_u8()?;
        let vertical_precision = rdata.read_u8()?;
        let latitude = rdata.read_u32::<NetworkEndian>()?;
        let longitude = rdata.read_u32::<NetworkEndian>()?;
        let altitude = rdata.read_u32::<NetworkEndian>()?;
        Ok(Rdata::LOC(Self {
            size,
            horizontal_precision,
            vertical_precision,
            latitude,
            longitude,
            altitude,
        }))
    }

    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        // version must be 0
        buf.write_u8(0)?;
        buf.write_u8(self.size)?;
        buf.write_u8(self.horizontal_precision)?;
        buf.write_u8(self.vertical_precision)?;
        buf.write_u32::<NetworkEndian>(self.latitude)?;
        buf.write_u32::<NetworkEndian>(self.longitude)?;
        buf.write_u32::<NetworkEndian>(self.altitude)?;
        Ok(1 + 1 + 1 + 1 + 4 + 4 + 4)
    }
}

fn decode_size(size: u8) -> u32 {
    let decoded = ((size & 0xF0) >> 4) as u32; // base
    decoded * 10u32.pow((size & 0x0F) as u32) // exponent
}

fn decode_lat_long(mut val: u32) -> (u32, u32, u32, u32) {
    // uses the algorithm from RFC 1876, Appendix A to avoid floating point problems
    val = (val as i64 - (1i64 << 31)).unsigned_abs() as u32;
    let secfrac = val % 1000;
    val /= 1000;
    let sec = val % 60;
    val /= 60;
    let min = val % 60;
    val /= 60;
    let deg = val;
    (deg, min, sec, secfrac)
}

impl Display for LOC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let size = decode_size(self.size);
        // horizontal and vertical precision use the same encoding as size
        let horizontal_precision = decode_size(self.horizontal_precision);
        let vertical_precision = decode_size(self.vertical_precision);

        let north_south = if self.latitude >= 1u32 << 31 {
            "N"
        } else {
            "S"
        };
        let (lat_deg, lat_min, lat_sec, lat_secfrac) = decode_lat_long(self.latitude);

        let east_west = if self.longitude >= 1u32 << 31 {
            "E"
        } else {
            "W"
        };
        let (long_deg, long_min, long_sec, long_secfrac) = decode_lat_long(self.longitude);

        let altitude = self.altitude as f64 / 100.0 - 100_000.0;

        write!(
            f,
            "{} {} {}.{:03} {} {} {} {}.{:03} {} {:.2}m {:.2}m {:.2}m {:.2}m",
            lat_deg,
            lat_min,
            lat_sec,
            lat_secfrac,
            north_south,
            long_deg,
            long_min,
            long_sec,
            long_secfrac,
            east_west,
            altitude,
            size as f64,
            horizontal_precision as f64,
            vertical_precision as f64
        )
    }
}
