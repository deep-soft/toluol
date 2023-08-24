//! RDATA type definitions.

use std::fmt::Display;
use std::io::{Cursor, Read, Write};

use byteorder::ReadBytesExt;
use data_encoding::HEXUPPER;

use crate::error::{EncodeError, ParseError};
use crate::RecordType;

#[cfg(feature = "serde")]
use serde::Serialize;

pub mod a;
pub mod aaaa;
pub mod caa;
pub mod cert;
pub mod cname;
pub mod dname;
pub mod dnskey;
pub mod ds;
pub mod hinfo;
pub mod loc;
pub mod mx;
pub mod naptr;
pub mod ns;
pub mod nsec;
pub mod nsec3;
pub mod openpgpkey;
pub mod opt;
pub mod ptr;
pub mod rp;
pub mod rrsig;
pub mod soa;
pub mod srv;
pub mod sshfp;
pub mod tlsa;
pub mod txt;

pub use a::A;
pub use aaaa::AAAA;
pub use caa::CAA;
pub use cert::CERT;
pub use cname::CNAME;
pub use dname::DNAME;
pub use dnskey::DNSKEY;
pub use ds::DS;
pub use hinfo::HINFO;
pub use loc::LOC;
pub use mx::MX;
pub use naptr::NAPTR;
pub use ns::NS;
pub use nsec::NSEC;
pub use nsec3::{NSEC3, NSEC3PARAM};
pub use openpgpkey::OPENPGPKEY;
pub use opt::OPT;
pub use ptr::PTR;
pub use rp::RP;
pub use rrsig::RRSIG;
pub use soa::SOA;
pub use srv::SRV;
pub use sshfp::SSHFP;
pub use tlsa::TLSA;
pub use txt::TXT;

// TODO think about serde representation for nice JSON output
/// The record data (RDATA) for a [`Record`][super::Record].
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
#[non_exhaustive]
pub enum Rdata {
    A(A),
    NS(NS),
    CNAME(CNAME),
    SOA(SOA),
    PTR(PTR),
    HINFO(HINFO),
    MX(MX),
    TXT(TXT),
    RP(RP),
    AAAA(AAAA),
    LOC(LOC),
    SRV(SRV),
    NAPTR(NAPTR),
    CERT(CERT),
    DNAME(DNAME),
    OPT(OPT),
    DS(DS),
    SSHFP(SSHFP),
    RRSIG(RRSIG),
    NSEC(NSEC),
    DNSKEY(DNSKEY),
    NSEC3(NSEC3),
    NSEC3PARAM(NSEC3PARAM),
    TLSA(TLSA),
    OPENPGPKEY(OPENPGPKEY),
    CAA(CAA),

    /// Unknown RDATA, containing the raw RDATA bytes.
    Unknown(Vec<u8>),
}

/// A trait for working with the different RDATA variants.
pub trait RdataTrait: Sized + Display {
    /// Parses the RDATA from the encoded bytes, starting at `rdata`'s current position in the
    /// slice.
    ///
    /// `rdata` is a [`Cursor`] wrapping the complete DNS message that contains the RDATA. It is
    /// important that the slice contains the complete message, as this is needed for handling DNS
    /// message compression: it is necessary to be able to jump to a specific byte position in the
    /// message. This is also the reason for using [`Cursor`], as the [`Seek`][std::io::Seek] impl
    /// provided by this type makes these jumps easier.
    ///
    /// `rdata` is the byte count of the encoded RDATA that will be parsed.
    fn parse_rdata(rdata: &mut Cursor<&[u8]>, rdlength: u16) -> Result<Rdata, ParseError>;

    /// Encodes the RDATA into the given `buf` and returns the number of written bytes on success.
    ///
    /// If an error is returned, no guarantees for the state of `buf` are given.
    fn encode_rdata_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError>;

    /// Ensures the RDATA is in canonical format, as defined in
    /// [RFC 4034, Section 6.2](https://www.rfc-editor.org/rfc/rfc4034#section-6.2).
    ///
    /// Canonical format means that for [`NS`], [`CNAME`], [`SOA`], [`PTR`], [`MX`], [`RP`],
    /// [`NAPTR`], [`SRV`], [`DNAME`], [`RRSIG`], and [`NSEC`], all [`Name`](crate::Name)s contained
    /// within the RDATA are in canonical format (see
    /// [`Name::canonicalize()`](crate::Name::canonicalize)).
    fn canonicalize(&mut self) {}

    /// Encodes the RDATA and returns the encoded bytes.
    fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut rdata = Vec::new();
        self.encode_rdata_into(&mut rdata)?;
        Ok(rdata)
    }
}

#[doc(hidden)]
macro_rules! impl_from_rtype {
    ($variant:ident) => {
        impl From<$variant> for Rdata {
            fn from(rdata: $variant) -> Self {
                Self::$variant(rdata)
            }
        }
    };
}

#[doc(hidden)]
macro_rules! impl_as_rtype {
    // shoutout to https://stackoverflow.com/a/43353854 for the idea to use a recursive macro and
    // stringify! to put $variant inside the doc comment
    ($method:ident, $method_mut:ident, $variant:ident, $doc:expr) => {
        #[doc = "Returns a reference to the inner [`"]
        #[doc = $doc]
        #[doc = "`] when called on the `"]
        #[doc = $doc]
        #[doc = "` variant. For all other variants, returns [`None`]."]
        pub fn $method(&self) -> Option<&$variant> {
            if let Self::$variant(inner) = self {
                Some(inner)
            } else {
                None
            }
        }

        #[doc = "Returns a mutable reference to the inner [`"]
        #[doc = $doc]
        #[doc = "`] when called on the `"]
        #[doc = $doc]
        #[doc = "` variant. For all other variants, returns [`None`]."]
        pub fn $method_mut(&mut self) -> Option<&mut $variant> {
            if let Self::$variant(ref mut inner) = self {
                Some(inner)
            } else {
                None
            }
        }
    };

    ($method:ident, $method_mut:ident, $variant:ident) => {
        impl_as_rtype!($method, $method_mut, $variant, stringify!($variant));
    };
}

/// Match on every [`Rdata`] variant and execute a block for it.
///
/// Matches $self, using $arm as the match arm for the non-[`Rdata::Unknown`] variants and
/// $unknown_arm as the match arm for the [`Rdata::Unknown`] variant. $inner and $inner_unknown are
/// what the identifiers for the inner field that can be used in $arm and $unknown_arm,
/// respectively.
///
/// # Examples
/// This is how [`Rdata::canonicalize()`] is implemented:
/// ```ignore
/// pub fn canonicalize(&mut self) {
///     match_rdata!(self, rdata, { rdata.canonicalize() }, _rdata, {})
/// }
/// ```
///
/// And this is how the [`Display`] impl for [`Rdata`] is done:
/// ```ignore
/// fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
///     match_rdata!(self, rdata, { write!(f, "{}", rdata) }, data, {
///         write!(f, "\\# {} {}", data.len(), HEXUPPER.encode(data))
///     })
/// }
/// ```
#[macro_export]
macro_rules! match_rdata {
    ($self:ident, $inner:ident, $arm:block, $inner_unknown:ident, $unknown_arm:block) => {
        match $self {
            Rdata::A($inner) => $arm,
            Rdata::NS($inner) => $arm,
            Rdata::CNAME($inner) => $arm,
            Rdata::SOA($inner) => $arm,
            Rdata::PTR($inner) => $arm,
            Rdata::HINFO($inner) => $arm,
            Rdata::MX($inner) => $arm,
            Rdata::TXT($inner) => $arm,
            Rdata::RP($inner) => $arm,
            Rdata::AAAA($inner) => $arm,
            Rdata::LOC($inner) => $arm,
            Rdata::SRV($inner) => $arm,
            Rdata::NAPTR($inner) => $arm,
            Rdata::CERT($inner) => $arm,
            Rdata::DNAME($inner) => $arm,
            Rdata::OPT($inner) => $arm,
            Rdata::DS($inner) => $arm,
            Rdata::SSHFP($inner) => $arm,
            Rdata::RRSIG($inner) => $arm,
            Rdata::NSEC($inner) => $arm,
            Rdata::DNSKEY($inner) => $arm,
            Rdata::NSEC3($inner) => $arm,
            Rdata::NSEC3PARAM($inner) => $arm,
            Rdata::TLSA($inner) => $arm,
            Rdata::OPENPGPKEY($inner) => $arm,
            Rdata::CAA($inner) => $arm,
            Rdata::Unknown($inner_unknown) => $unknown_arm,
        }
    };
}

impl Rdata {
    /// See [`RdataTrait::canonicalize()`].
    pub fn canonicalize(&mut self) {
        match_rdata!(self, rdata, { rdata.canonicalize() }, _rdata, {})
    }

    /// See [`RdataTrait::encode()`].
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        match_rdata!(self, rdata, { rdata.encode() }, unknown_rdata, {
            Ok(unknown_rdata.clone())
        })
    }

    /// See [`RdataTrait::encode_rdata_into()`].
    pub fn encode_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        match_rdata!(
            self,
            rdata,
            { rdata.encode_rdata_into(buf) },
            unknown_rdata,
            {
                buf.write_all(unknown_rdata)?;
                Ok(unknown_rdata.len() as u16)
            }
        )
    }

    /// Returns the [`RecordType`] that matches this `RDATA`.
    ///
    /// # Note
    /// As [`Rdata::Unknown`] does not know its type, calling this method on it will return
    /// [`RecordType::Unknown(0)`].
    pub fn rtype(&self) -> RecordType {
        match self {
            Rdata::A(_) => RecordType::A,
            Rdata::NS(_) => RecordType::NS,
            Rdata::CNAME(_) => RecordType::CNAME,
            Rdata::SOA(_) => RecordType::SOA,
            Rdata::PTR(_) => RecordType::PTR,
            Rdata::HINFO(_) => RecordType::HINFO,
            Rdata::MX(_) => RecordType::MX,
            Rdata::TXT(_) => RecordType::TXT,
            Rdata::RP(_) => RecordType::RP,
            Rdata::AAAA(_) => RecordType::AAAA,
            Rdata::LOC(_) => RecordType::LOC,
            Rdata::SRV(_) => RecordType::SRV,
            Rdata::NAPTR(_) => RecordType::NAPTR,
            Rdata::CERT(_) => RecordType::CERT,
            Rdata::DNAME(_) => RecordType::DNAME,
            Rdata::OPT(_) => RecordType::OPT,
            Rdata::DS(_) => RecordType::DS,
            Rdata::SSHFP(_) => RecordType::SSHFP,
            Rdata::RRSIG(_) => RecordType::RRSIG,
            Rdata::NSEC(_) => RecordType::NSEC,
            Rdata::DNSKEY(_) => RecordType::DNSKEY,
            Rdata::NSEC3(_) => RecordType::NSEC3,
            Rdata::NSEC3PARAM(_) => RecordType::NSEC3PARAM,
            Rdata::TLSA(_) => RecordType::TLSA,
            Rdata::OPENPGPKEY(_) => RecordType::OPENPGPKEY,
            Rdata::CAA(_) => RecordType::CAA,
            Rdata::Unknown(_) => RecordType::Unknown(0),
        }
    }

    impl_as_rtype!(as_a, as_mut_a, A);
    impl_as_rtype!(as_ns, as_mut_ns, NS);
    impl_as_rtype!(as_cname, as_mut_cname, CNAME);
    impl_as_rtype!(as_soa, as_mut_soa, SOA);
    impl_as_rtype!(as_ptr, as_mut_ptr, PTR);
    impl_as_rtype!(as_hinfo, as_mut_hinfo, HINFO);
    impl_as_rtype!(as_mx, as_mut_mx, MX);
    impl_as_rtype!(as_txt, as_mut_txt, TXT);
    impl_as_rtype!(as_rp, as_mut_rp, RP);
    impl_as_rtype!(as_aaaa, as_mut_aaaa, AAAA);
    impl_as_rtype!(as_loc, as_mut_loc, LOC);
    impl_as_rtype!(as_srv, as_mut_srv, SRV);
    impl_as_rtype!(as_naptr, as_mut_naptr, NAPTR);
    impl_as_rtype!(as_cert, as_mut_cert, CERT);
    impl_as_rtype!(as_dname, as_mut_dname, DNAME);
    impl_as_rtype!(as_opt, as_mut_opt, OPT);
    impl_as_rtype!(as_ds, as_mut_ds, DS);
    impl_as_rtype!(as_sshfp, as_mut_sshfp, SSHFP);
    impl_as_rtype!(as_rrsig, as_mut_rrsig, RRSIG);
    impl_as_rtype!(as_nsec, as_mut_nsec, NSEC);
    impl_as_rtype!(as_dnskey, as_mut_dnskey, DNSKEY);
    impl_as_rtype!(as_nsec3, as_mut_nsec3, NSEC3);
    impl_as_rtype!(as_nsec3param, as_mut_nsec3param, NSEC3PARAM);
    impl_as_rtype!(as_tlsa, as_mut_tlsa, TLSA);
    impl_as_rtype!(as_openpgpkey, as_mut_openpgpkey, OPENPGPKEY);
    impl_as_rtype!(as_caa, as_mut_caa, CAA);
}

impl_from_rtype!(A);
impl_from_rtype!(NS);
impl_from_rtype!(CNAME);
impl_from_rtype!(SOA);
impl_from_rtype!(PTR);
impl_from_rtype!(HINFO);
impl_from_rtype!(MX);
impl_from_rtype!(TXT);
impl_from_rtype!(RP);
impl_from_rtype!(AAAA);
impl_from_rtype!(LOC);
impl_from_rtype!(SRV);
impl_from_rtype!(NAPTR);
impl_from_rtype!(CERT);
impl_from_rtype!(DNAME);
impl_from_rtype!(OPT);
impl_from_rtype!(DS);
impl_from_rtype!(SSHFP);
impl_from_rtype!(RRSIG);
impl_from_rtype!(NSEC);
impl_from_rtype!(DNSKEY);
impl_from_rtype!(NSEC3);
impl_from_rtype!(NSEC3PARAM);
impl_from_rtype!(TLSA);
impl_from_rtype!(OPENPGPKEY);
impl_from_rtype!(CAA);

impl Display for Rdata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match_rdata!(self, rdata, { write!(f, "{}", rdata) }, data, {
            write!(f, "\\# {} {}", data.len(), HEXUPPER.encode(data))
        })
    }
}

/// Parses a character string as defined in [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035),
/// i.e. reads a length byte and then the number of ASCII characters specified by the length byte.
///
/// Returns the parsed string and the number of bytes read.
///
/// Returns an error if reading from the [`Cursor`] fails (i.e. unexpected EOF) or the read string
/// was not all ASCII.
pub fn parse_string(msg: &mut Cursor<&[u8]>) -> Result<(String, usize), ParseError> {
    let length = msg.read_u8()?;
    let mut string = vec![0; length as usize];
    msg.read_exact(&mut string)?;

    let string = String::from_utf8_lossy(&string).into_owned();
    if !string.is_ascii() {
        return Err(ParseError::NonAsciiString(string));
    }

    // + 1 because we also need to count the length byte
    let bytes_read = string.len() + 1;
    Ok((string, bytes_read))
}

/// Encodes a string as a character string as defined in
/// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035), i.e. writes the length of the string as a
/// byte and then the string bytes, into the given `buf`.
///
/// `string` must consist of only ASCII characters.
///
/// Returns the number of bytes written on success.
pub fn encode_string_into(
    string: impl AsRef<str>,
    buf: &mut impl Write,
) -> Result<u16, EncodeError> {
    let string = string.as_ref();

    if !string.is_ascii() {
        return Err(EncodeError::NonAsciiString(string.to_string()));
    }

    let len = string.len();
    buf.write_all(&(len as u8).to_be_bytes())?;
    write!(buf, "{}", string)?;
    Ok(1 + len as u16)
}
