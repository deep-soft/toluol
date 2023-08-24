//! `toluol-proto` provides the definition of the DNS protocol's data types as well as the means to
//! de-/serialize them from/to the wire format. In simpler terms, you can construct, encode, and
//! decode DNS queries and responses with it.
//!
//! It is used as the backend for [`toluol`], a DNS client that aims to
//! replace `dig`, but you can use this library on its own as well. It is possible to compile it to
//! WASM, so you can even make DNS queries from the browser with it (using DNS over HTTPS).
//!
//! # Basic usage example
//! ```rust
//! use toluol_proto::{EdnsConfig, HeaderFlags, Message, Name, Opcode, RecordType};
//!
//! let flags = HeaderFlags { aa: false, tc: false, rd: true, ra: false, ad: true, cd: true };
//! let msg = Message::new_query(
//!     Name::from_ascii("example.com").unwrap(),
//!     RecordType::A,
//!     Opcode::QUERY,
//!     flags,
//!     Some(EdnsConfig {
//!         do_flag: false,
//!         bufsize: 4096,
//!         client_cookie: None,
//!     }),
//! ).unwrap();
//! let _encoded = msg.encode().unwrap();
//! ```
//!
//! If you're also looking for utilities to actually send and receive DNS queries and responses,
//! please take a look at [`toluol`].
//!
//! # Usage note
//! You can construct most structs directly, without using any `new()` method. In some cases, this
//! can lead to inconsistencies, e.g. manually creating a [`Message`] where the record counts in the
//! header don't match the actual number of records.
//!
//! In these cases, you should prefer using the appropriate constructor of the struct (if there is
//! none, please file a bug). However, this library does not force you to do so, so that you have
//! as much freedom using it as possible. It won't stop you if you really want to create
//! inconsistent messages, for whatever reason.
//!
//! [`toluol`]: https://docs.rs/toluol

use std::cmp::max;
use std::collections::HashMap;
use std::fmt::{self, Display};
use std::io::{Cursor, Read, Write};

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use owo_colors::OwoColorize;
use rand::Rng;
use rdata::opt::OptionCode;
use repr_with_fallback::repr_with_fallback;
#[cfg(feature = "serde")]
use serde::Serialize;
use strum_macros::EnumString;

// TODO put the dnssec module behind a feature?
pub mod dnssec;
pub mod error;
pub mod name;
pub mod rdata;

use error::{DnssecError, EncodeError, ParseError, ToluolError};
use rdata::{RdataTrait, OPT};

pub use name::Name;
pub use rdata::Rdata;

/// Represents a DNS OpCode.
///
/// See [here](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5) for
/// further information.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Opcode {
    QUERY,
    IQUERY,
    STATUS,
    NOTIFY,
    UPDATE,
    DSO,
}

/// Represents a DNS RCODE, including those introduced by EDNS.
///
/// See
/// [here](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6)
/// for further information.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
#[non_exhaustive]
pub enum RCode {
    NOERROR,
    FORMERR,
    SERVFAIL,
    NXDOMAIN,
    NOTIMP,
    REFUSED,
    YXDOMAIN,
    YXRRSET,
    NXRRSET,
    NOTAUTH,
    NOTZONE,
    DSOTYPENI,
    BADVERSBADSIG,
    BADKEY,
    BADTIME,
    BADMODE,
    BADNAME,
    BADALG,
    BADTRUNC,
    BADCOOKIE,
    // TODO Unknown(u16) ?
}

repr_with_fallback! {
    /// Represents a DNS TYPE.
    ///
    /// See the documentation in the [`rdata`] module for explanations of the different types.
    ///
    /// This enum is non-exhaustive, see
    /// [here](https://en.wikipedia.org/wiki/List_of_DNS_record_types) for a more comprehensive
    /// overview.
    #[cfg_attr(feature = "serde", derive(Serialize))]
    #[derive(PartialEq, Eq, Copy, Clone, EnumString, Debug)]
    #[non_exhaustive]
    pub enum RecordType {
        A = 1,
        NS = 2,
        CNAME = 5,
        SOA = 6,
        PTR = 12,
        HINFO = 13,
        MX = 15,
        TXT = 16,
        RP = 17,
        // TODO: SIG (24) (should have the same wire format as RRSIG)
        // TODO: KEY (25) (should have the same wire format as DNSKEY)
        AAAA = 28,
        LOC = 29,
        SRV = 33,
        NAPTR = 35,
        CERT = 37,
        DNAME = 39,
        OPT = 41,
        DS = 43,
        SSHFP = 44,
        // TODO: IPSECKEY (45)
        RRSIG = 46,
        NSEC = 47,
        DNSKEY = 48,
        // TODO: DHCID (49)
        NSEC3 = 50,
        NSEC3PARAM = 51,
        TLSA = 52,
        // TODO: SMIMEA (53)
        // TODO: HIP (55)
        // TODO: CDNSKEY (60)
        OPENPGPKEY = 61,
        // TODO: HTTPS (65)
        // TODO: TKEY (249)
        // TODO: TSIG (250)
        CAA = 257,
        // TODO: TA (32768)
        // TODO: DLV (32769)
        Unknown(u16),
    }
}

/// Represents a DNS CLASS.
///
/// Other classes than `IN` and `ANY` are included only for completeness and historical reasons.
///
/// See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) for further information.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum Class {
    IN,
    CH,
    HS,
    NONE,
    /// See also [RFC 8482](https://www.rfc-editor.org/rfc/rfc8482).
    ANY,
}

/// Represents the flags of a [`Header`].
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub struct HeaderFlags {
    /// authoritative answer (valid in responses only)
    /// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
    pub aa: bool,
    /// truncated (set on all truncated messages except last one)
    /// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
    pub tc: bool,
    /// recursion desired (copied in answer if supported and accepted)
    /// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
    pub rd: bool,
    /// valid in responses, indicating recursive query support in the name server
    /// [\[RFC 1035\]](https://www.rfc-editor.org/rfc/rfc1035)
    pub ra: bool,
    /// For queries: indicates interest in the `ad` bit of the upcoming response; for responses:
    /// indicates that the resolver side considers all resource records in the Answer section and
    /// relevant negative response resource records in the Authority section to be authentic.
    /// [\[RFC 4035\]](https://www.rfc-editor.org/rfc/rfc4035),
    /// [\[RFC 6840\]](https://www.rfc-editor.org/rfc/rfc6840)
    pub ad: bool,
    /// disable signature validation in a security-aware name server's processing of a particular query
    /// [\[RFC 4035\]](https://www.rfc-editor.org/rfc/rfc4035),
    /// [\[RFC 6840\]](https://www.rfc-editor.org/rfc/rfc6840)
    pub cd: bool,
}

/// Represents a DNS header.
///
/// The general format of a header is defined in [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035).
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Header {
    /// Supplied by questioner and reflected back unchanged by responder.
    pub msg_id: u16,
    /// False for queries, true for responses.
    pub qr: bool,
    /// The [`Opcode`] of the message.
    pub opcode: Opcode,
    /// The [`HeaderFlags`] of the message.
    pub flags: HeaderFlags,
    /// For queries: [`None`]. For responses: the return/status code of the server.
    pub rcode: Option<RCode>,
    /// The number of questions.
    pub qdcount: u16,
    /// The number of resource records.
    pub ancount: u16,
    /// The number of name server resource records.
    pub nscount: u16,
    /// The number of additional resource records.
    pub arcount: u16,
}

/// Represents a DNS question, i.e. an entry in the question section of a DNS message.
///
/// See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) for further information.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Question {
    /// The [`Name`] to query for.
    pub qname: Name,
    /// The [`RecordType`] to query for.
    pub qtype: RecordType,
    /// The query [`Class`].
    pub qclass: Class,
}

/// Represents a DNS record, i.e. an entry in the answer, authority or additional section of a DNS
/// message.
///
/// See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) for further information.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[cfg_attr(feature = "serde", serde(untagged))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum Record {
    OPT(OptRecord),
    NONOPT(NonOptRecord),
}

/// Flags for an [`OptRecord`].
///
/// See [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891#section-6) as well as
/// <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13> for
/// further information.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Copy, Clone, Debug)]
pub enum OptFlags {
    /// Indicates to the server that the resolver is able to accept DNSSEC security records.
    /// [\[RFC 3225\]](https://www.rfc-editor.org/rfc/rfc3225)
    DO,
}

/// EDNS parameters.
pub struct EdnsConfig {
    /// Indicates DNSSEC support, i.e. whether the server should send appropiate DNSSEC records.
    pub do_flag: bool,
    /// The payload size that gets sent in the `OPT` record.
    pub bufsize: u16,
    /// May be [`None`] to indicate no client cookie should be set.
    ///
    /// See [RFC 7873](https://www.rfc-editor.org/rfc/rfc7873.html) for more.
    pub client_cookie: Option<[u8; 8]>,
    // TODO: support padding?
}

/// The `OPT` variant of [`Record`].
///
/// See [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891#section-6) for further information.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct OptRecord {
    /// Must be [`Name::root()`].
    pub owner: Name,
    /// The number of octets of the largest UDP payload that can be reassembled and delivered in the
    /// requestor's network stack.
    pub payload_size: u16,
    /// `None` for queries. For responses, this is always the correct [`RCode`], i.e. the lower four
    /// bits from the header are included.
    pub rcode: Option<RCode>,
    /// Almost always zero.
    pub edns_version: u8,
    /// A list of [`OptFlags`] (may be empty).
    pub flags: Vec<OptFlags>,
    // rdlength omitted as rdata knows its own length
    #[cfg_attr(feature = "serde", serde(skip))]
    encoded_rdata: Vec<u8>, // needed for encoding
    rdata: Rdata, // this is of type Rdata and not OPT so that it nicely mirrors NonOptRecord
}

/// The `NONOPT` variant of [`Record`].
///
/// See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) for further information.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct NonOptRecord {
    /// The [`Name`] that this record is for.
    pub owner: Name,
    /// The type of this record.
    pub rtype: RecordType,
    /// The class of this record (will almost always be [`Class::IN`]).
    pub class: Class,
    /// The amount of seconds this record may be cached for.
    pub ttl: u32,
    // rdlength omitted as rdata knows its own length
    #[cfg_attr(feature = "serde", serde(skip))]
    encoded_rdata: Vec<u8>, // needed for encoding and DNSSEC
    rdata: Rdata,
}

/// Represents a DNS message.
///
/// See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) for further information.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Message {
    /// The message header.
    pub header: Header,
    /// The list of questions.
    pub questions: Vec<Question>,
    /// The list of resource records.
    pub answers: Vec<Record>,
    /// The list of name server resource records.
    pub authoritative_answers: Vec<Record>,
    /// The list of additional resource records.
    pub additional_answers: Vec<Record>,
}

impl Opcode {
    /// Encodes a `Opcode` as a byte.
    pub fn encode(&self) -> u8 {
        match self {
            Opcode::QUERY => 0,
            Opcode::IQUERY => 1,
            Opcode::STATUS => 2,
            Opcode::NOTIFY => 4,
            Opcode::UPDATE => 5,
            Opcode::DSO => 6,
        }
    }

    /// Parses an encoded `Opcode` from a byte.
    ///
    /// Returns an error if the given byte does not represent a valid DNS OpCode.
    pub fn parse(val: u8) -> Result<Opcode, ParseError> {
        Ok(match val {
            0 => Opcode::QUERY,
            1 => Opcode::IQUERY,
            2 => Opcode::STATUS,
            4 => Opcode::NOTIFY,
            5 => Opcode::UPDATE,
            6 => Opcode::DSO,
            x => return Err(ParseError::InvalidOpcode(x)),
        })
    }
}

impl Display for Opcode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl RCode {
    /// Encodes an `RCode` as a byte (actually only the lower four bits are used).
    ///
    /// Note that for RCODEs `BADVERSBADSIG` and following only the lower four bits are encoded;
    /// the upper eight bits need to be encoded in an OPT record in the additional section of the
    /// DNS message.
    pub fn encode(&self) -> u8 {
        match self {
            RCode::NOERROR => 0,
            RCode::FORMERR => 1,
            RCode::SERVFAIL => 2,
            RCode::NXDOMAIN => 3,
            RCode::NOTIMP => 4,
            RCode::REFUSED => 5,
            RCode::YXDOMAIN => 6,
            RCode::YXRRSET => 7,
            RCode::NXRRSET => 8,
            RCode::NOTAUTH => 9,
            RCode::NOTZONE => 10,
            RCode::DSOTYPENI => 11,
            RCode::BADVERSBADSIG => 16 & 0b1111,
            RCode::BADKEY => 17 & 0b1111,
            RCode::BADTIME => 18 & 0b1111,
            RCode::BADMODE => 19 & 0b1111,
            RCode::BADNAME => 20 & 0b1111,
            RCode::BADALG => 21 & 0b1111,
            RCode::BADTRUNC => 22 & 0b1111,
            RCode::BADCOOKIE => 23 & 0b1111,
        }
    }

    /// Parses an encoded `RCode` from a twelve bit value. If EDNS is used, the upper eight bits
    /// are stored in the OPT entry of the additional section and the lower four bits are stored in
    /// the [`Header`].
    ///
    /// Returns an error if the given value does not represent a valid DNS RCODE.
    pub fn parse(val: u16) -> Result<RCode, ParseError> {
        Ok(match val {
            0 => RCode::NOERROR,
            1 => RCode::FORMERR,
            2 => RCode::SERVFAIL,
            3 => RCode::NXDOMAIN,
            4 => RCode::NOTIMP,
            5 => RCode::REFUSED,
            6 => RCode::YXDOMAIN,
            7 => RCode::YXRRSET,
            8 => RCode::NXRRSET,
            9 => RCode::NOTAUTH,
            10 => RCode::NOTZONE,
            11 => RCode::DSOTYPENI,
            16 => RCode::BADVERSBADSIG,
            17 => RCode::BADKEY,
            18 => RCode::BADTIME,
            19 => RCode::BADMODE,
            20 => RCode::BADNAME,
            21 => RCode::BADALG,
            22 => RCode::BADTRUNC,
            23 => RCode::BADCOOKIE,
            x => return Err(ParseError::InvalidRcode(x)),
        })
    }
}

impl Display for RCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::Unknown(x) => write!(f, "TYPE{}", x),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl Class {
    /// Encodes a `Class` as a two-byte value.
    pub fn encode(&self) -> u16 {
        match self {
            Class::IN => 1,
            Class::CH => 3,
            Class::HS => 4,
            Class::NONE => 254,
            Class::ANY => 255,
        }
    }

    /// Parses an encoded `Class` from a two-byte value.
    ///
    /// Returns an error if the given value does not represent a valid DNS CLASS.
    pub fn parse(val: u16) -> Result<Class, ParseError> {
        Ok(match val {
            1 => Class::IN,
            3 => Class::CH,
            4 => Class::HS,
            254 => Class::NONE,
            255 => Class::ANY,
            x => return Err(ParseError::InvalidClass(x)),
        })
    }
}

impl Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl HeaderFlags {
    /// Creates a `HeaderFlags` struct from bitflags as they would appear in the second 16-octet
    /// line of a [`Header`].
    pub fn from_flags(flags: u16) -> Self {
        Self {
            aa: (flags & (1 << 10)) != 0,
            tc: (flags & (1 << 9)) != 0,
            rd: (flags & (1 << 8)) != 0,
            ra: (flags & (1 << 8)) != 0,
            ad: (flags & (1 << 5)) != 0,
            cd: (flags & (1 << 4)) != 0,
        }
    }

    /// Returns a u16 representing bitflags as they would appear in the second 16-octet line of a
    /// [`Header`].
    pub fn as_flags(&self) -> u16 {
        let aa = if self.aa { 1 } else { 0 };
        let tc = if self.tc { 1 } else { 0 };
        let rd = if self.rd { 1 } else { 0 };
        let ra = if self.ra { 1 } else { 0 };
        let ad = if self.ad { 1 } else { 0 };
        let cd = if self.cd { 1 } else { 0 };
        (aa << 10) + (tc << 9) + (rd << 8) + (ra << 7) + (ad << 5) + (cd << 4)
    }
}

impl Header {
    /// Creates a header for a DNS response message.
    ///
    /// See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) and
    /// [here](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12) for
    /// information about the parameters.
    ///
    /// `qdcount`, `ancount`, `nscount` and `arcount` are grouped in that order in the `counts` parameter.
    pub fn new_response_header(
        msg_id: u16,
        opcode: Opcode,
        flags: HeaderFlags,
        rcode: RCode,
        counts: [u16; 4],
    ) -> Self {
        Header {
            msg_id,
            qr: true,
            opcode,
            flags,
            rcode: Some(rcode),
            qdcount: counts[0],
            ancount: counts[1],
            nscount: counts[2],
            arcount: counts[3],
        }
    }

    /// Creates a header for a DNS query message.
    ///
    /// If the query includes an [`OPT`](rdata::opt::OPT) record, `edns` must be `true`.
    ///
    /// See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) and
    /// [here](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12) for
    /// information about the other parameters.
    pub fn new_query_header(
        msg_id: u16,
        opcode: Opcode,
        flags: HeaderFlags,
        edns: bool,
        qdcount: u16,
    ) -> Result<Self, EncodeError> {
        if flags.aa || flags.ra {
            Err(EncodeError::AaOrRaInQuery)
        } else {
            Ok(Header {
                msg_id,
                qr: false,
                opcode,
                flags,
                rcode: None,
                qdcount,
                ancount: 0,
                nscount: 0,
                arcount: if edns { 1 } else { 0 },
            })
        }
    }

    /// Encodes a `Header` as a series of bytes.
    ///
    /// Returns an error if a method defined in [`byteorder::WriteBytesExt`] returns an error.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// The same as [`encode()`](Self::encode()), but encoded bytes are appended to the given writer
    /// instead of to a newly allocated one.
    pub fn encode_into(&self, buf: &mut impl Write) -> Result<(), EncodeError> {
        let qr = if self.qr { 1u16 } else { 0u16 };
        let opcode = self.opcode.encode() as u16;
        let rcode = match &self.rcode {
            Some(val) => val.encode() as u16,
            None => 0u16,
        };

        let line_two = (qr << 15) + (opcode << 11) + self.flags.as_flags() + rcode;
        buf.write_u16::<NetworkEndian>(self.msg_id)?;
        buf.write_u16::<NetworkEndian>(line_two)?;
        buf.write_u16::<NetworkEndian>(self.qdcount)?;
        buf.write_u16::<NetworkEndian>(self.ancount)?;
        buf.write_u16::<NetworkEndian>(self.nscount)?;
        buf.write_u16::<NetworkEndian>(self.arcount)?;

        Ok(())
    }

    /// Parses an encoded `Header` from a series of bytes.
    ///
    /// Returns an error if [`Opcode::parse()`], [`RCode::parse()`] or a method defined in
    /// [`byteorder::ReadBytesExt`] return an error.
    pub fn parse(header: &mut Cursor<&[u8]>) -> Result<Self, ParseError> {
        let msg_id = header.read_u16::<NetworkEndian>()?;
        let line_two = header.read_u16::<NetworkEndian>()?;
        let qr = (line_two & (1 << 15)) >> 15;
        let opcode = Opcode::parse(((line_two & (0b1111 << 11)) >> 11) as u8)?;
        let flags = HeaderFlags::from_flags(line_two & 0b0000011110110000);
        let rcode = RCode::parse(line_two & 0b1111)?;

        Ok(Header {
            msg_id,
            qr: qr != 0,
            opcode,
            flags,
            rcode: if qr != 0 { Some(rcode) } else { None },
            qdcount: header.read_u16::<NetworkEndian>()?,
            ancount: header.read_u16::<NetworkEndian>()?,
            nscount: header.read_u16::<NetworkEndian>()?,
            arcount: header.read_u16::<NetworkEndian>()?,
        })
    }

    /// Creates a string containing information (id, opcode, rcode if applicable, flags) about the
    /// header.
    pub fn info_str(&self) -> String {
        let mut s = String::new();
        if let Some(rcode) = self.rcode {
            s.push_str(
                format!(
                    "id: {}, opcode: {}, rcode: {}, flags: ",
                    self.msg_id, self.opcode, rcode
                )
                .as_str(),
            );
        } else {
            s.push_str(format!("id: {}, opcode: {}, flags: ", self.msg_id, self.opcode).as_str());
        }
        if self.flags.aa {
            s.push_str("aa ")
        }
        if self.flags.tc {
            s.push_str("tc ")
        }
        if self.flags.rd {
            s.push_str("rd ")
        }
        if self.flags.ra {
            s.push_str("ra ")
        }
        if self.flags.ad {
            s.push_str("ad ")
        }
        if self.flags.cd {
            s.push_str("cd ")
        }
        s.remove(s.len() - 1); // remove last ' '
        s
    }
}

impl Display for Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::new();
        if self.qr {
            s.push_str("DNS Response (");
        } else {
            s.push_str("DNS Query (");
        }
        s.push_str(&self.info_str());
        s.push(')');
        write!(f, "{}", s)
    }
}

impl Question {
    /// Creates a DNS question.
    pub fn new(name: Name, qtype: RecordType, qclass: Class) -> Self {
        Question {
            qname: name,
            qtype,
            qclass,
        }
    }

    /// Encodes a `Question` as a series of bytes.
    ///
    /// Returns an error if a method defined in [`byteorder::WriteBytesExt`] returns an error.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// The same as [`encode()`](Self::encode()), but encoded bytes are appended to the given writer
    /// instead of to a newly allocated one.
    pub fn encode_into(&self, buf: &mut impl Write) -> Result<(), EncodeError> {
        self.qname.encode_into(buf)?;
        buf.write_u16::<NetworkEndian>(self.qtype.into())?;
        buf.write_u16::<NetworkEndian>(self.qclass.encode())?;
        Ok(())
    }

    /// Parses an encoded `Question` from a series of bytes.
    ///
    /// Returns an error if [`Name::parse()`], [`Class::parse()`] or a method defined in
    /// [`byteorder::ReadBytesExt`] return an error.
    pub fn parse(msg: &mut Cursor<&[u8]>) -> Result<Self, ParseError> {
        let qname = Name::parse(msg, name::Compression::Allowed)?;
        let qtype: RecordType = msg.read_u16::<NetworkEndian>()?.into();
        let qclass = Class::parse(msg.read_u16::<NetworkEndian>()?)?;

        Ok(Question {
            qname,
            qtype,
            qclass,
        })
    }

    /// Returns a string representing the record in the canonical format, with the owner padded to
    /// the given length.
    ///
    /// If `output` is [`Some`] and the specified output stream supports colours, the output will be
    /// colourized.
    pub fn as_padded_string(&self, owner_len: usize, output: Option<owo_colors::Stream>) -> String {
        let mut res = String::new();

        let mut owner = self.qname.to_string();
        while owner.len() < owner_len {
            owner.push(' ');
        }

        let mut qtype = self.qtype.to_string();
        if let Some(stream) = output {
            owner = owner.if_supports_color(stream, |s| s.green()).to_string();
            qtype = qtype.if_supports_color(stream, |s| s.purple()).to_string();
        }

        res.push_str(format!("{}          {}", owner, qtype).as_str());

        res
    }
}

impl Display for Question {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DNS Question for '{}' (type: {}, class: {})",
            self.qname, self.qtype, self.qclass
        )
    }
}

impl Record {
    /// Encodes a `Record` as a series of bytes.
    ///
    /// Returns an error if a method defined in [`byteorder::WriteBytesExt`] returns an error.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// The same as [`encode()`](Self::encode()), but encoded bytes are appended to the given writer
    /// instead of to a newly allocated one.
    pub fn encode_into(&self, buf: &mut impl Write) -> Result<(), EncodeError> {
        match self {
            Record::NONOPT(nonopt) => nonopt.encode_into(buf),
            Record::OPT(opt) => opt.encode_into(buf),
        }
    }

    /// Parses an encoded `Record` from a series of bytes.
    ///
    /// Returns an error if [`Name::parse()`], [`Class::parse()`],
    /// [`parse_rdata()`](Self::parse_rdata()) or a method defined in [`byteorder::ReadBytesExt`]
    /// return an error, or if an `OPT` record has a name other than `"."`.
    pub fn parse(msg: &mut Cursor<&[u8]>, rcode: Option<RCode>) -> Result<Self, ParseError> {
        let owner = Name::parse(msg, name::Compression::Allowed)?;
        let atype: RecordType = msg.read_u16::<NetworkEndian>()?.into();
        if atype == RecordType::OPT {
            return OptRecord::parse(msg, owner, rcode);
        }
        let class = Class::parse(msg.read_u16::<NetworkEndian>()?)?;
        let ttl = msg.read_u32::<NetworkEndian>()?;
        let rdlength = msg.read_u16::<NetworkEndian>()?;

        let mut encoded_rdata = vec![0; rdlength as usize];
        let pos_rdata_start = msg.position();
        msg.read_exact(&mut encoded_rdata)?;
        // reset position to the start of rdata for parse_rdata()
        msg.set_position(pos_rdata_start);
        let rdata = Record::parse_rdata(&atype, msg, rdlength)?;

        Ok(Record::NONOPT(NonOptRecord {
            owner,
            rtype: atype,
            class,
            ttl,
            encoded_rdata,
            rdata,
        }))
    }

    /// Parses encoded rdata into a vector of strings (canonical format).
    ///
    /// `atype` is the type of the record containing the rdata. `msg` is the complete response
    /// message, which is needed for message compression. `rdlength` is the length of the RDATA in
    /// bytes.
    ///
    /// Returns an error if any of the `parse_rdata()` methods in [`rdata`] or a method defined in
    /// [`byteorder::ReadBytesExt`] return an error.
    pub fn parse_rdata(
        atype: &RecordType,
        msg: &mut Cursor<&[u8]>,
        rdlength: u16,
    ) -> Result<Rdata, ParseError> {
        match atype {
            RecordType::A => rdata::A::parse_rdata(msg, rdlength),
            RecordType::NS => rdata::NS::parse_rdata(msg, rdlength),
            RecordType::CNAME => rdata::CNAME::parse_rdata(msg, rdlength),
            RecordType::SOA => rdata::SOA::parse_rdata(msg, rdlength),
            RecordType::PTR => rdata::PTR::parse_rdata(msg, rdlength),
            RecordType::HINFO => rdata::HINFO::parse_rdata(msg, rdlength),
            RecordType::MX => rdata::MX::parse_rdata(msg, rdlength),
            RecordType::TXT => rdata::TXT::parse_rdata(msg, rdlength),
            RecordType::RP => rdata::RP::parse_rdata(msg, rdlength),
            RecordType::AAAA => rdata::AAAA::parse_rdata(msg, rdlength),
            RecordType::LOC => rdata::LOC::parse_rdata(msg, rdlength),
            RecordType::SRV => rdata::SRV::parse_rdata(msg, rdlength),
            RecordType::NAPTR => rdata::NAPTR::parse_rdata(msg, rdlength),
            RecordType::CERT => rdata::CERT::parse_rdata(msg, rdlength),
            RecordType::DNAME => rdata::DNAME::parse_rdata(msg, rdlength),
            RecordType::OPT => rdata::OPT::parse_rdata(msg, rdlength),
            RecordType::DS => rdata::DS::parse_rdata(msg, rdlength),
            RecordType::SSHFP => rdata::SSHFP::parse_rdata(msg, rdlength),
            RecordType::RRSIG => rdata::RRSIG::parse_rdata(msg, rdlength),
            RecordType::NSEC => rdata::NSEC::parse_rdata(msg, rdlength),
            RecordType::DNSKEY => rdata::DNSKEY::parse_rdata(msg, rdlength),
            RecordType::NSEC3 => rdata::NSEC3::parse_rdata(msg, rdlength),
            RecordType::NSEC3PARAM => rdata::NSEC3PARAM::parse_rdata(msg, rdlength),
            RecordType::TLSA => rdata::TLSA::parse_rdata(msg, rdlength),
            RecordType::OPENPGPKEY => rdata::OPENPGPKEY::parse_rdata(msg, rdlength),
            RecordType::CAA => rdata::CAA::parse_rdata(msg, rdlength),
            RecordType::Unknown(_) => {
                let mut rdata = vec![0; rdlength as usize];
                msg.read_exact(&mut rdata)?;
                Ok(Rdata::Unknown(rdata))
            }
        }
    }

    /// Returns a reference to the inner [`OptRecord`]. [`None`] for the `NONOPT` variant.
    pub fn as_opt(&self) -> Option<&OptRecord> {
        match self {
            Self::OPT(opt) => Some(opt),
            Self::NONOPT(_) => None,
        }
    }

    /// Returns a reference to the inner [`NonOptRecord`]. [`None`] for the `OPT` variant.
    pub fn as_nonopt(&self) -> Option<&NonOptRecord> {
        match self {
            Self::NONOPT(nonopt) => Some(nonopt),
            Self::OPT(_) => None,
        }
    }

    /// Returns the inner [`OptRecord`]. Panics if the variant is not `OPT`.
    pub fn into_opt(self) -> OptRecord {
        match self {
            Self::OPT(opt) => opt,
            Self::NONOPT(_) => panic!("Record::into_opt() called on NONOPT variant"),
        }
    }

    /// Returns the inner [`NonOptRecord`]. Panics if the variant is not `NONOPT`.
    pub fn into_nonopt(self) -> NonOptRecord {
        match self {
            Self::NONOPT(nonopt) => nonopt,
            Self::OPT(_) => panic!("Record::into_nonopt() called on OPT variant"),
        }
    }

    /// Returns a reference to the contained [`Rdata`].
    pub fn rdata(&self) -> &Rdata {
        match self {
            Self::OPT(opt) => opt.rdata(),
            Self::NONOPT(nonopt) => nonopt.rdata(),
        }
    }

    /// Returns a mutable reference to the contained [`Rdata`].
    pub fn rdata_mut(&mut self) -> &mut Rdata {
        match self {
            Self::OPT(opt) => opt.rdata_mut(),
            Self::NONOPT(nonopt) => nonopt.rdata_mut(),
        }
    }
}

impl NonOptRecord {
    /// Creates a new `NonOptRecord` from [`Rdata`].
    ///
    /// Returns an error if `rdata` is [`Rdata::OPT`] or if `rdata` could not be encoded.
    pub fn new(owner: Name, class: Class, ttl: u32, rdata: Rdata) -> Result<Self, ToluolError> {
        if rdata.as_opt().is_some() {
            return Err(ToluolError::OptRdataForNonOptRecord);
        }

        let rtype = rdata.rtype();
        let encoded_rdata = rdata.encode()?;

        Ok(Self {
            owner,
            rtype,
            class,
            ttl,
            rdata,
            encoded_rdata,
        })
    }

    /// Encodes a `NonOptRecord` as a series of bytes.
    ///
    /// Returns an error if a method defined in [`byteorder::WriteBytesExt`] returns an error.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// The same as [`encode()`](Self::encode()), but encoded bytes are appended to the given writer
    /// instead of to a newly allocated one.
    pub fn encode_into(&self, buf: &mut impl Write) -> Result<(), EncodeError> {
        self.owner.encode_into(buf)?;
        buf.write_u16::<NetworkEndian>(self.rtype.into())?;
        buf.write_u16::<NetworkEndian>(self.class.encode())?;
        buf.write_u32::<NetworkEndian>(self.ttl)?;
        buf.write_u16::<NetworkEndian>(self.encoded_rdata.len() as u16)?;
        buf.write_all(&self.encoded_rdata)?;
        Ok(())
    }

    /// Ensures the record is in canonical format, as defined in
    /// [RFC 4034, Section 6.2](https://www.rfc-editor.org/rfc/rfc4034#section-6.2).
    ///
    /// `rrsig_labels` and `original_ttl` should be the values of
    /// [`RRSIG::labels`](rdata::RRSIG::labels) and
    /// [`RRSIG::original_ttl`](rdata::RRSIG::original_ttl), respectively, from a
    /// [`RRSIG`](rdata::RRSIG) record that covers this record.
    ///
    /// Canonical format means that
    /// - [`Self::owner`] is in canonical format (see
    ///   [`Name::canonicalize()`](Name::canonicalize())).
    /// - [`Self::rdata`] is in canonical format (see [`Rdata::canonicalize()`]).
    /// - If [`Self::owner`] was originally a wildcard name, the wildcard substitution is undone.
    ///   For example, imagine a record for a.example.com that was generated from *.example.com.
    ///   Canonicalizing it would (among possibly other things) set its owner to *.example.com.
    ///   This is what the `rrsig_labels` parameter is needed for.
    /// - [`Self::ttl`] is set to the value of `original_ttl`.
    pub fn canonicalize(&mut self, rrsig_labels: u8, original_ttl: u32) -> Result<(), DnssecError> {
        if self.owner.label_count() < rrsig_labels {
            return Err(DnssecError::InvalidRrsigLabelCount(
                self.owner.label_count(),
                rrsig_labels,
            ));
        }

        self.owner.canonicalize();
        self.rdata.canonicalize();
        self.ttl = original_ttl;

        // see RFC 4035, Section 5.3.2
        let mut popped_label = None;
        while self.owner.label_count() > rrsig_labels {
            popped_label = self.owner.pop_front_label();
        }

        // if we popped a label, we still need to make `self.owner` into a wildcard name
        if popped_label.is_some() {
            self.owner.make_wildcard();
        }

        // ensure that any changes of the canonicalization are also reflected in the encoded rdata
        self.encoded_rdata.clear();
        self.rdata.encode_into(&mut self.encoded_rdata)?;

        Ok(())
    }

    /// Returns a reference to the contained [`Rdata`].
    pub fn rdata(&self) -> &Rdata {
        &self.rdata
    }

    /// Returns a mutable reference to the contained [`Rdata`].
    pub fn rdata_mut(&mut self) -> &mut Rdata {
        &mut self.rdata
    }

    /// Returns a string representing the record in the format used in zone files, but without the
    /// redundant IN class and without trailing dots for domain names.
    ///
    /// If `separate_with_single_space` is true, the different fields of the record are always
    /// separated by a single space. If it is false, all fields are separated by two spaces, and the
    /// TTL field is always six characters long (not including separators).
    ///
    /// If `owner_len`/`atype_len` is [`Some`], the `owner`/`atype` field is padded to the specified
    /// length.
    ///
    /// If `output` is [`Some`] and the specified output stream supports colours, the output will
    /// be colourized.
    pub fn as_string(
        &self,
        separate_with_single_space: bool,
        owner_len: Option<usize>,
        atype_len: Option<usize>,
        output: Option<owo_colors::Stream>,
    ) -> String {
        let mut owner = self.owner.to_string();
        if let Some(len) = owner_len {
            while owner.len() < len {
                owner.push(' ');
            }
        }

        let mut atype = self.rtype.to_string();
        if let Some(len) = atype_len {
            while atype.len() < len {
                atype.push(' ');
            }
        }

        if let Some(stream) = output {
            owner = owner.if_supports_color(stream, |s| s.green()).to_string();
            atype = atype.if_supports_color(stream, |s| s.purple()).to_string();
        }

        if separate_with_single_space {
            format!("{} {} {} {}", owner, self.ttl, atype, self.rdata,)
        } else {
            format!("{}  {:>6}  {}  {}", owner, self.ttl, atype, &self.rdata,)
        }
    }
}

impl Display for NonOptRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_string(true, None, None, None))
    }
}

impl Display for OptFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let flag = format!("{:?}", self);
        write!(f, "{}", flag.to_ascii_lowercase())
    }
}

impl OptRecord {
    /// Creates a new `OPT` record.
    ///
    /// For the `rcode` parameter, see [`Self::rcode`].
    pub fn new(rcode: Option<RCode>, edns_config: EdnsConfig) -> Result<Self, EncodeError> {
        let mut flags = vec![];
        if edns_config.do_flag {
            flags.push(OptFlags::DO);
        }
        let mut options = HashMap::new();
        if let Some(cookie) = edns_config.client_cookie {
            options.insert(OptionCode::Cookie, cookie.to_vec());
        }
        let rdata = Rdata::OPT(OPT { options });
        Ok(Self {
            owner: Name::root(),
            payload_size: edns_config.bufsize,
            rcode,
            edns_version: 0,
            flags,
            encoded_rdata: rdata.encode()?,
            rdata,
        })
    }

    /// Encodes a `OptRecord` as a series of bytes.
    ///
    /// Returns an error if a method defined in [`byteorder::WriteBytesExt`] returns an error.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// The same as [`encode()`](Self::encode()), but encoded bytes are appended to the given writer
    /// instead of to a newly allocated one.
    pub fn encode_into(&self, buf: &mut impl Write) -> Result<(), EncodeError> {
        self.owner.encode_into(buf)?;
        buf.write_u16::<NetworkEndian>(RecordType::OPT.into())?;
        buf.write_u16::<NetworkEndian>(self.payload_size)?;
        let rcode = self.rcode.unwrap_or(RCode::NOERROR);
        let rcode = (((rcode.encode() as u16) & 0b111111110000) >> 4) as u8;
        buf.write_u8(rcode)?;
        buf.write_u8(self.edns_version)?;
        if self.flags.contains(&OptFlags::DO) {
            buf.write_u16::<NetworkEndian>(1 << 15)?;
        } else {
            buf.write_u16::<NetworkEndian>(0)?;
        }
        buf.write_u16::<NetworkEndian>(self.encoded_rdata.len() as u16)?;
        buf.write_all(&self.encoded_rdata)?;
        Ok(())
    }

    /// Returns a string describing the `OPT` record, with the given `prefix` prepended to each
    /// line.
    ///
    /// If `output` is [`Some`] and the specified output stream supports colours, the output will be
    /// colourized.
    pub fn as_padded_string(&self, prefix: &str, _output: Option<owo_colors::Stream>) -> String {
        let mut s = prefix.to_string();

        s.push_str(&self.to_string());

        // TODO: don't ignore output so we get coloured output

        if !self.opt_rdata().options.is_empty() {
            let options = self.rdata.to_string();
            let options_iter: Vec<_> = options.split(", ").collect();
            let options_str = options_iter.join("\n");
            s.push('\n');
            s.push_str(prefix);
            s.push_str(&options_str);
        }

        s
    }

    /// Returns a reference to the contained [`Rdata`].
    pub fn rdata(&self) -> &Rdata {
        &self.rdata
    }

    /// Returns a mutable reference to the contained [`Rdata`].
    pub fn rdata_mut(&mut self) -> &mut Rdata {
        &mut self.rdata
    }

    /// Returns a reference to the contained [`Rdata`].
    pub fn opt_rdata(&self) -> &OPT {
        self.rdata.as_opt().expect("OPT record had non-OPT RDATA")
    }

    /// Returns a mutable reference to the contained [`Rdata`].
    pub fn opt_rdata_mut(&mut self) -> &mut OPT {
        self.rdata
            .as_mut_opt()
            .expect("OPT record had non-OPT RDATA")
    }

    /// Generates and returns the string used for our `Display` impl.
    fn info_str(&self) -> Result<String, fmt::Error> {
        use fmt::Write;
        let mut s = String::new();
        write!(&mut s, "EDNS: Version {}, flags: ", self.edns_version)?;
        let mut wrote_flag = false;
        for (i, flag) in self.flags.iter().enumerate() {
            wrote_flag = true;
            write!(&mut s, "{}", flag)?;
            if i < self.flags.len() - 1 {
                write!(&mut s, " ")?;
            }
        }
        if !wrote_flag {
            write!(&mut s, "<none>, ")?;
        } else {
            write!(&mut s, ", ")?;
        }
        write!(&mut s, "payload size: {}", self.payload_size)?;
        Ok(s)
    }

    /// Parses an encoded `OptRecord` from a series of bytes.
    ///
    /// See [`DnsRecord::parse()`] for further information.
    fn parse(
        msg: &mut Cursor<&[u8]>,
        owner: Name,
        rcode: Option<RCode>,
    ) -> Result<Record, ParseError> {
        if !owner.is_root() {
            return Err(ParseError::InvalidOptName(owner));
        }

        let payload_size = msg.read_u16::<NetworkEndian>()?;
        let ext_rcode = msg.read_u8()?;
        let rcode = if rcode.is_some() {
            match ext_rcode {
                0 => rcode,
                x => Some(RCode::parse(
                    ((x as u16) << 4) + (rcode.unwrap().encode() as u16),
                )?),
            }
        } else {
            rcode
        };
        let edns_version = msg.read_u8()?;
        let mut flags = vec![];
        let do_flag = msg.read_u16::<NetworkEndian>()? & (1 << 15) != 0;
        if do_flag {
            flags.push(OptFlags::DO);
        }

        let rdlength = msg.read_u16::<NetworkEndian>()?;
        let mut encoded_rdata = vec![0; rdlength as usize];
        let pos_rdata_start = msg.position();
        msg.read_exact(&mut encoded_rdata)?;
        // reset position to the start of rdata for parse_rdata()
        msg.set_position(pos_rdata_start);
        let rdata = Record::parse_rdata(&RecordType::OPT, msg, rdlength)?;

        Ok(Record::OPT(OptRecord {
            owner,
            payload_size,
            rcode,
            edns_version,
            flags,
            encoded_rdata,
            rdata,
        }))
    }
}

impl Display for OptRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.info_str()?)
    }
}

impl Display for Record {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Record::NONOPT(nonopt) => write!(f, "{}", nonopt),
            Record::OPT(opt) => write!(f, "{}", opt),
        }
    }
}

impl Message {
    /// Creates a DNS query.
    ///
    /// If `edns` is [`Some`], the query will contain an `OPT` record.
    ///
    /// See [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) and the documentation of [`Header`]
    /// for information about the remaining parameters.
    ///
    /// Returns an error if `aa` or `ra` are set in `flags`.
    pub fn new_query(
        domain: Name,
        qtype: RecordType,
        opcode: Opcode,
        flags: HeaderFlags,
        edns: Option<EdnsConfig>,
    ) -> Result<Self, EncodeError> {
        if flags.aa || flags.ra {
            return Err(EncodeError::AaOrRaInQuery);
        }

        let msg_id = rand::thread_rng().gen_range(0..(1u32 << 16)) as u16;

        let header = Header::new_query_header(msg_id, opcode, flags, edns.is_some(), 1)?;

        let mut additional_answers = Vec::new();
        if let Some(edns_config) = edns {
            additional_answers.push(Record::OPT(OptRecord::new(None, edns_config)?));
        }

        Ok(Message {
            header,
            questions: vec![Question::new(domain, qtype, Class::IN)],
            answers: Vec::new(),
            authoritative_answers: Vec::new(),
            additional_answers,
        })
    }

    /// Creates a DNS response.
    ///
    /// See the documentation of [`Header`] for information about the parameters.
    ///
    /// `answers`, `authoritative_answers`, `additional_answers` are grouped in that order in the `records` parameter.
    pub fn new_response(
        msg_id: u16,
        opcode: Opcode,
        flags: HeaderFlags,
        rcode: RCode,
        questions: Vec<Question>,
        records: [Vec<Record>; 3],
    ) -> Self {
        Message {
            header: Header::new_response_header(
                msg_id,
                opcode,
                flags,
                rcode,
                [
                    questions.len() as u16,
                    records[0].len() as u16,
                    records[1].len() as u16,
                    records[2].len() as u16,
                ],
            ),
            questions,
            answers: records[0].clone(),
            authoritative_answers: records[1].clone(),
            additional_answers: records[2].clone(),
        }
    }

    /// Encodes a `Message` as a series of bytes.
    ///
    /// Returns an error if [`Header::encode()`], [`Question::encode()`] or [`Record::encode()`]
    /// return an error.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        let mut buf = Vec::new();
        self.encode_into(&mut buf)?;
        Ok(buf)
    }

    /// The same as [`encode()`](Self::encode()), but encoded bytes are appended to the given writer
    /// instead of to a newly allocated one.
    pub fn encode_into(&self, buf: &mut impl Write) -> Result<(), EncodeError> {
        self.header.encode_into(buf)?;
        for question in &self.questions {
            question.encode_into(buf)?;
        }
        for record in &self.answers {
            record.encode_into(buf)?;
        }
        for record in &self.authoritative_answers {
            record.encode_into(buf)?;
        }
        for record in &self.additional_answers {
            record.encode_into(buf)?;
        }

        Ok(())
    }

    /// Parses an encoded `Message` from a series of bytes.
    ///
    /// Returns an error if [`Header::parse()`], [`Question::parse()`] or [`Record::parse()`] return
    /// an error or a truncated message is received.
    pub fn parse(msg: &mut Cursor<&[u8]>) -> Result<Self, ParseError> {
        let mut header = Header::parse(msg)?;

        if header.flags.tc {
            return Err(ParseError::TruncatedMessage);
        }

        let qdcount = header.qdcount;
        let ancount = header.ancount;
        let nscount = header.nscount;
        let arcount = header.arcount;
        let questions = Message::parse_questions(msg, qdcount)?;
        let mut answers = Vec::new();
        let mut authoritative_answers = Vec::new();
        let mut additional_answers = Vec::new();
        if ancount > 0 {
            answers = Message::parse_records(msg, ancount, header.rcode)?;
        }
        if nscount > 0 {
            authoritative_answers = Message::parse_records(msg, nscount, header.rcode)?;
        }
        if arcount > 0 {
            additional_answers = Message::parse_records(msg, arcount, header.rcode)?;
        }

        for answer in &additional_answers {
            if let Record::OPT(OptRecord { rcode, .. }) = answer {
                header.rcode = *rcode;
            }
        }

        Ok(Message {
            header,
            questions,
            answers,
            authoritative_answers,
            additional_answers,
        })
    }

    /// Returns a string verbosely describing the message (i.e. header and all the other sections).
    ///
    /// If `output` is [`Some`] and the specified output stream supports colours, the output will
    /// be colourized.
    pub fn as_string(&self, output: Option<owo_colors::Stream>) -> String {
        let section_name = |s: &str, o: Option<owo_colors::Stream>| {
            let mut s = s.to_string();
            if let Some(stream) = o {
                s = s.if_supports_color(stream, |s| s.yellow()).to_string();
            }
            s
        };

        let mut res = String::new();

        let mut additional_answers = self.additional_answers.clone();
        let mut opt_index = None;

        let mut max_owner_len = 0;
        let mut max_type_len = 0;

        for q in &self.questions {
            max_owner_len = max(max_owner_len, q.qname.string_len());
            max_type_len = max(max_type_len, q.qtype.to_string().len());
        }

        let answers = [
            &self.answers,
            &self.authoritative_answers,
            &self.additional_answers,
        ];
        let answers_iter = answers.iter().flat_map(|a| a.iter());
        for (i, answer) in answers_iter.enumerate() {
            match answer {
                Record::OPT(_) => {
                    // the iterator runs over self.answers, self.authoritative_answers and self.additional_answers,
                    // but we want the index of answer with respect to self.additional_answers
                    opt_index = Some(i - self.answers.len() - self.authoritative_answers.len());
                }
                Record::NONOPT(NonOptRecord {
                    owner: name,
                    rtype: atype,
                    ..
                }) => {
                    max_owner_len = max(max_owner_len, name.string_len());
                    max_type_len = max(max_type_len, atype.to_string().len());
                }
            }
        }

        // Header
        // TODO: coloured header output?
        res.push_str(section_name("Header:\n\t", output).as_str());
        res.push_str(format!("{}\n\n", self.header.info_str()).as_str());

        // OPT Pseudosection (if present)
        if let Some(idx) = opt_index {
            let opt = additional_answers.remove(idx);
            let opt = opt
                .as_opt()
                .expect("Calculated incorrect index for OPT record");
            res.push_str(section_name("OPT Pseudosection:\n", output).as_str());
            res.push_str(&opt.as_padded_string("\t", output));
            res.push_str("\n\n");
        }

        res.push_str(section_name("Question Section:\n", output).as_str());
        for question in &self.questions {
            res.push('\t');
            // question doesn't need max_type_len because nothing gets printed after its qtype
            res.push_str(question.as_padded_string(max_owner_len, output).as_str());
            res.push('\n');
        }
        res.push('\n');

        if !self.answers.is_empty() {
            res.push_str(section_name("Answer Section:\n", output).as_str());
            for answer in &self.answers {
                res.push('\t');
                res.push_str(
                    answer
                        .as_nonopt()
                        .expect("Unexpected OPT record")
                        .as_string(false, Some(max_owner_len), Some(max_type_len), output)
                        .as_str(),
                );
                res.push('\n');
            }
            res.push('\n');
        }

        if !self.authoritative_answers.is_empty() {
            res.push_str(section_name("Authoritative Section:\n", output).as_str());
            for answer in &self.authoritative_answers {
                res.push('\t');
                res.push_str(
                    answer
                        .as_nonopt()
                        .expect("Unexpected OPT record")
                        .as_string(false, Some(max_owner_len), Some(max_type_len), output)
                        .as_str(),
                );
                res.push('\n');
            }
            res.push('\n');
        }

        if !additional_answers.is_empty() {
            res.push_str(section_name("Additional Section:\n", output).as_str());
            for answer in &additional_answers {
                res.push('\t');
                res.push_str(
                    answer
                        .as_nonopt()
                        .expect("Unexpected OPT record")
                        .as_string(false, Some(max_owner_len), Some(max_type_len), output)
                        .as_str(),
                );
                res.push('\n');
            }
        }

        // remove trailing '\n's
        while res.chars().nth(res.len() - 1).unwrap() == '\n' {
            res.remove(res.len() - 1);
        }

        res
    }

    /// Parses the question section of a DNS message.
    fn parse_questions(msg: &mut Cursor<&[u8]>, qdcount: u16) -> Result<Vec<Question>, ParseError> {
        let mut questions = Vec::with_capacity(qdcount as usize);
        for _i in 0..qdcount {
            questions.push(Question::parse(msg)?);
        }

        Ok(questions)
    }

    /// Parses an answer section (i. e. answer, authoritative or additional) of a DNS message.
    fn parse_records(
        msg: &mut Cursor<&[u8]>,
        ancount: u16,
        rcode: Option<RCode>,
    ) -> Result<Vec<Record>, ParseError> {
        let mut answers = Vec::with_capacity(ancount as usize);
        for _i in 0..ancount {
            answers.push(Record::parse(msg, rcode)?);
        }

        Ok(answers)
    }
}
