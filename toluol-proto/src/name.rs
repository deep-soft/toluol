//! Definition and implementation of the [`Name`] type.

use std::cmp::Ordering;
use std::collections::VecDeque;
use std::fmt::Display;
use std::io::{Cursor, Seek, SeekFrom, Write};

use byteorder::{ReadBytesExt, WriteBytesExt};
use smartstring::SmartString;

use crate::error::{EncodeError, ParseError};

#[cfg(feature = "serde")]
use serde::Serialize;

/// A DNS domain name.
///
/// `Name`s can be sorted according to the canonical ordering, as defined in
/// [RFC 4034, Section 6.1](https://www.rfc-editor.org/rfc/rfc4034#section-6.1),
/// thanks to the [`Ord`] impl (see below for an example).
///
/// Note that the string representation omits the dot at the end of the name that is sometimes seen.
/// The only exception is the DNS root's name, which is represented as `"."`.
#[cfg_attr(feature = "serde", derive(Serialize))]
#[derive(Eq, Clone, Debug)]
pub struct Name {
    // does not contain the root label, as that would be the empty string
    labels: VecDeque<SmartString<smartstring::LazyCompact>>,
}

/// Whether DNS message/name compression is allowed when parsing a [`Name`].
///
/// For example, the [`RRSIG::signer_name`](crate::rdata::rrsig::RRSIG::signer_name) field must not
/// be compressed, according to the RFC.
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
pub enum Compression {
    /// Message compression is allowed.
    Allowed,
    /// Message compression is prohibited.
    Prohibited,
}

impl Name {
    /// Returns a `Name` representing the DNS root (`"."`).
    ///
    /// Do not create this solely for comparisons with other `Name`s, as this method allocates.
    /// [`Name::is_root()`] is allocation-free.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// assert_eq!(Name::from_ascii(".").ok(), Some(Name::root()));
    /// ```
    pub fn root() -> Self {
        Self {
            labels: VecDeque::new(),
        }
    }

    /// Parses a `Name` encoded as a DNS QNAME from the given cursor.
    ///
    /// If `allow_compression` is true, message compression is supported.
    ///
    /// If `allow_compression` is false, trying to parse a compressed name will return an error.
    /// For example, the [`RRSIG::signer_name`](crate::rdata::rrsig::RRSIG::signer_name) field must
    /// not be compressed, according to the RFC.
    ///
    /// # Examples
    /// ```rust
    /// use std::io::Cursor;
    /// use toluol_proto::name::{Compression, Name};
    ///
    /// // "sub.example.com" encoded via the "sub" label followed by a pointer to "example.com"
    /// let bytes = b"\x07example\x03com\0\x03sub\xc0";
    /// let mut cursor = Cursor::new(bytes as &[u8]);
    /// let name = Name::parse(&mut cursor, Compression::Allowed);
    /// assert_eq!(name.ok(), Some(Name::from_ascii("example.com").unwrap()));
    ///
    /// let name = Name::parse(&mut cursor, Compression::Prohibited);
    /// assert!(name.is_err());
    /// ```
    pub fn parse(msg: &mut Cursor<&[u8]>, compression: Compression) -> Result<Self, ParseError> {
        let mut labels = VecDeque::new();
        let mut c = msg.read_u8()?; // length of next label

        while c != 0 {
            if (c & 0b11000000) != 0 {
                if compression == Compression::Prohibited {
                    return Err(ParseError::CompressionProhibited);
                }

                // after this comes a pointer for message compression
                c &= 0b00111111; // erase upper two bits of c for offset calculation
                let offset = ((c as u16) << 8) + (msg.read_u8()? as u16);
                // save position after pointer
                let pos_after_pointer = msg.position() as i64;
                msg.seek(SeekFrom::Start(offset as u64))?;
                // recursion is the easiest way to handle recursive message compression
                // (i've seen that being used... looking at you, a.gtld-servers.net)
                // TODO do this iteratively to avoid unnecessary allocations
                labels.append(&mut Name::parse(msg, compression)?.labels);

                // move cursor to byte after pointer
                msg.seek(SeekFrom::Start(pos_after_pointer as u64))?;
                return Ok(Name { labels });
            } else if (c & 0b01000000) != 0 || (c & 0b10000000) != 0 {
                return Err(ParseError::InvalidLabelType(c));
            }
            let mut label = SmartString::new();
            for _ in 0..c {
                label.push(msg.read_u8()? as char);
            }
            labels.push_back(label);
            c = msg.read_u8()?;
        }

        Ok(Name { labels })
    }

    /// Constructs a `Name` from an ASCII domain string.
    ///
    /// The rules for allowed names are as follows:
    /// - Every label (except for the first, see next item) must consist of the following
    ///   characters: `a-z`, `A-Z`, `0-9`, `_`, `-`. The label's first and last character must not
    ///   be `-`.
    /// - The first label may also be a wildcard (i.e. `"*"`).
    /// - Every label must contain at least one character, except for the DNS root's name.
    /// - A trailing dot is allowed, but not necessary.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// assert_eq!(Name::from_ascii(".").ok(), Some(Name::root()));
    /// assert_eq!(Name::from_ascii("").ok(), Some(Name::root()));
    ///
    /// assert!(Name::from_ascii("example.com").is_ok());
    /// assert!(Name::from_ascii("example.com.").is_ok());
    /// assert!(Name::from_ascii("*.example.com").is_ok());
    /// assert!(Name::from_ascii("_th1s-1s-an.example.com").is_ok());
    ///
    /// assert!(Name::from_ascii("**.example.com").is_err());
    /// assert!(Name::from_ascii("a*.example.com").is_err());
    /// assert!(Name::from_ascii("exa-mple-.com").is_err());
    /// assert!(Name::from_ascii("-exa-mple_.com").is_err());
    /// assert!(Name::from_ascii("example.com-").is_err());
    /// assert!(Name::from_ascii("exämple.com").is_err());
    /// ```
    pub fn from_ascii(name: impl AsRef<str>) -> Result<Self, ParseError> {
        let name = name.as_ref();

        // without this special case, we would later return `Err(EmptyLabel)`, because splitting "."
        // on '.' gives two empty labels
        if name == "." {
            return Ok(Self::root());
        }

        if name.bytes().len() > 255 {
            return Err(ParseError::NameTooLong(name.bytes().len()));
        }

        let labels_iter = name.split('.');
        let mut labels = VecDeque::new();
        let mut root_label_found = false;
        for (idx, label) in labels_iter.enumerate() {
            if root_label_found {
                return Err(ParseError::EmptyLabel);
            }
            if label.bytes().len() > 63 {
                return Err(ParseError::LabelTooLong(label.bytes().len()));
            }
            if label.is_empty() {
                root_label_found = true;
            } else {
                // only the first label may be a wildcard
                let is_valid_wildcard = (idx == 0) && (label == "*");

                if !is_valid_wildcard {
                    Name::check_label(label)?;
                }
                labels.push_back(label.into());
            }
        }

        Ok(Name { labels })
    }

    /// Encodes this name as a DNS QNAME into the given buffer. Does not use message compression.
    ///
    /// Returns the number of bytes written on success.
    ///
    /// Returns an error if writing to the buffer fails.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let mut buf = Vec::new();
    /// let name = Name::from_ascii("example.com").unwrap();
    /// name.encode_into(&mut buf).ok();
    /// assert_eq!(buf, b"\x07example\x03com\0");
    /// ```
    pub fn encode_into(&self, buf: &mut impl Write) -> Result<u16, EncodeError> {
        let mut bytes_written = 0;
        for label in &self.labels {
            buf.write_u8(label.len() as u8)?;
            buf.write_all(label.as_bytes())?;
            bytes_written += 1 + label.as_bytes().len();
        }
        buf.write_u8(0)?;
        Ok(bytes_written as u16 + 1)
    }

    /// Appends the given `Name` to this `Name`.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let mut base = Name::from_ascii("a").unwrap();
    /// let name = Name::from_ascii("example.com").unwrap();
    /// base.append_name(name);
    ///
    /// let complete = Name::from_ascii("a.example.com").unwrap();
    /// assert_eq!(base, complete);
    /// ```
    pub fn append_name(&mut self, mut other: Name) {
        self.labels.append(&mut other.labels)
    }

    /// Appends the given label to this `Name`.
    ///
    /// Returns an error if the given label is invalid (see [`Name::from_ascii()`] for what a valid
    /// label is).
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let mut base = Name::from_ascii("a.example").unwrap();
    /// assert!(base.append_label("com").is_ok());
    ///
    /// let complete = Name::from_ascii("a.example.com").unwrap();
    /// assert_eq!(base, complete);
    /// ```
    pub fn append_label(&mut self, label: impl AsRef<str>) -> Result<(), ParseError> {
        Name::check_label(label.as_ref())?;
        let label = SmartString::from(label.as_ref());
        self.labels.push_back(label);
        Ok(())
    }

    /// Prepends the given `Name` to this `Name`.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let name = Name::from_ascii("a").unwrap();
    /// let mut base = Name::from_ascii("example.com").unwrap();
    /// base.prepend_name(name);
    ///
    /// let complete = Name::from_ascii("a.example.com").unwrap();
    /// assert_eq!(base, complete);
    /// ```
    pub fn prepend_name(&mut self, mut other: Name) {
        other.labels.append(&mut self.labels);
        self.labels = other.labels;
    }

    /// Prepends the given label to this `Name`.
    ///
    /// This cannot be used to prepend a wildcard label; please use [`Name::prepend_wildcard()`] for
    /// that.
    ///
    /// Returns an error if the given label is invalid (see [`Name::from_ascii()`] for what a valid
    /// label is).
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let mut base = Name::from_ascii("example.com").unwrap();
    /// assert!(base.prepend_label("a").is_ok());
    ///
    /// let complete = Name::from_ascii("a.example.com").unwrap();
    /// assert_eq!(base, complete);
    /// ```
    pub fn prepend_label(&mut self, label: impl AsRef<str>) -> Result<(), ParseError> {
        Name::check_label(label.as_ref())?;
        self.labels.push_front(label.as_ref().into());
        Ok(())
    }

    /// Removes and returns the first label of this `Name`, if it exists.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let mut name = Name::from_ascii("a.example.com").unwrap();
    ///
    /// let label = name.pop_front_label().unwrap();
    /// assert_eq!(label, "a");
    ///
    /// assert!(name.pop_front_label().is_some());
    /// assert!(name.pop_front_label().is_some());
    /// assert!(name.pop_front_label().is_none());
    ///
    /// assert!(name.is_root());
    /// ```
    pub fn pop_front_label(&mut self) -> Option<SmartString<smartstring::LazyCompact>> {
        self.labels.pop_front()
    }

    /// Removes and returns the last label of this `Name`, if it exists.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let mut name = Name::from_ascii("a.example.com").unwrap();
    ///
    /// let label = name.pop_back_label().unwrap();
    /// assert_eq!(label, "com");
    ///
    /// assert!(name.pop_back_label().is_some());
    /// assert!(name.pop_back_label().is_some());
    /// assert!(name.pop_back_label().is_none());
    ///
    /// assert!(name.is_root());
    /// ```
    pub fn pop_back_label(&mut self) -> Option<SmartString<smartstring::LazyCompact>> {
        self.labels.pop_back()
    }

    /// Prepends a wildcard label (`"*"`) to this `Name`.
    ///
    /// This is does nothing for a `Name` that already has a wildcard label.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let mut name = Name::from_ascii("example.com").unwrap();
    /// name.prepend_wildcard();
    ///
    /// let complete = Name::from_ascii("*.example.com").unwrap();
    /// assert_eq!(name, complete);
    ///
    /// // this does nothing
    /// name.prepend_wildcard();
    /// assert_eq!(name, complete);
    /// ```
    pub fn prepend_wildcard(&mut self) {
        if !self.is_wildcard() {
            self.labels.push_front("*".into());
        }
    }

    /// Transforms this `Name` into a wildcard name by replacing the first label with `"*"`.
    ///
    /// This does nothing for `Name` that already has a wildcard label or represents the DNS root's
    /// name.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let mut name = Name::from_ascii("a.example.com").unwrap();
    /// name.make_wildcard();
    ///
    /// let complete = Name::from_ascii("*.example.com").unwrap();
    /// assert_eq!(name, complete);
    ///
    /// // this does nothing
    /// name.make_wildcard();
    /// assert_eq!(name, complete);
    /// ```
    pub fn make_wildcard(&mut self) {
        if !self.is_root() && !self.is_wildcard() {
            self.pop_front_label();
            self.prepend_wildcard();
        }
    }

    /// Ensures this `Name` is in canonical format, i.e. all uppercase letters are replaced with
    /// their lowercase counterparts.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let mut name = Name::from_ascii("*._EX4m-pLE.CoM").unwrap();
    /// name.canonicalize();
    ///
    /// assert_eq!(
    ///     name,
    ///     Name::from_ascii("*._ex4m-ple.com").unwrap(),
    /// )
    /// ```
    pub fn canonicalize(&mut self) {
        self.labels
            .iter_mut()
            .for_each(|label| label.make_ascii_lowercase());
    }

    /// Returns true iff this `Name` is a parent zone of `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// let parent = Name::from_ascii("example.com").unwrap();
    /// let child = Name::from_ascii("a.example.com").unwrap();
    ///
    /// assert_eq!(child.zone_of(&child), true);
    /// assert_eq!(parent.zone_of(&parent), true);
    /// assert_eq!(parent.zone_of(&child), true);
    /// assert_eq!(child.zone_of(&parent), false);
    /// ```
    pub fn zone_of(&self, other: &Name) -> bool {
        if self.label_count() > other.label_count() {
            return false;
        }

        let label_pairs = self.labels.iter().rev().zip(other.labels.iter().rev());
        for (self_label, other_label) in label_pairs {
            if self_label != other_label {
                return false;
            }
        }

        true
    }

    /// Returns the label count of this `Name`.
    ///
    /// This is calculated the same way as the [`RRSIG::labels`](crate::rdata::RRSIG::labels) value,
    /// i.e. wildcards do not count (`"*.example.com"` has a label count of two) and the DNS root's
    /// name (`"."`) has a label count of zero.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// assert_eq!(Name::from_ascii("www.example.com").unwrap().label_count(), 3);
    /// assert_eq!(Name::from_ascii("*.example.com").unwrap().label_count(), 2);
    /// assert_eq!(Name::root().label_count(), 0);
    /// ```
    pub fn label_count(&self) -> u8 {
        if self.is_root() {
            0
        } else if self.is_wildcard() {
            (self.labels.len() - 1) as u8
        } else {
            self.labels.len() as u8
        }
    }

    /// Returns the length of the string returned if this `Name` is made into a [`String`].
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// assert_eq!(Name::root().string_len(), 1);
    /// assert_eq!(Name::from_ascii("example.com").unwrap().string_len(), 11);
    /// ```
    pub fn string_len(&self) -> usize {
        if self.is_root() {
            return 1;
        }

        let mut len = 0;
        for label in &self.labels {
            // + 1 for the dot at the end of the label which is not explicitly stored
            len += label.len() + 1;
        }
        // the last label has no dot at the end
        len - 1
    }

    /// Returns true iff this `Name` represents the DNS root (`"."`).
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// assert!(Name::root().is_root());
    ///
    /// assert_eq!(Name::from_ascii("example.com").unwrap().is_root(), false);
    /// ```
    pub fn is_root(&self) -> bool {
        self.labels.is_empty()
    }

    /// Returns true iff this `Name` is a wildcard, i.e. the first label is `"*"`.
    ///
    /// # Examples
    /// ```rust
    /// use toluol_proto::Name;
    ///
    /// assert_eq!(Name::from_ascii("*.example.com").unwrap().is_wildcard(), true);
    ///
    /// assert_eq!(Name::from_ascii("example.com").unwrap().is_wildcard(), false);
    /// ```
    pub fn is_wildcard(&self) -> bool {
        if let Some(label) = self.labels.get(0) {
            label == "*"
        } else {
            false
        }
    }

    /// Checks if the given string is a valid DNS name label.
    fn check_label(label: impl AsRef<str>) -> Result<(), ParseError> {
        let mut chars = label.as_ref().chars();
        // label is non-empty, so we can unwrap
        let mut c = chars.next().unwrap();
        // first label char must be a-z, A-Z, 0-9, or _
        if !c.is_ascii_alphanumeric() && (c != '_') {
            return Err(ParseError::NameInvalidChars);
        }
        // label chars in the middle must be a-z, A-Z, 0-9, _, or -
        for next_c in chars {
            if !c.is_ascii_alphanumeric() && (c != '_') && (c != '-') {
                return Err(ParseError::NameInvalidChars);
            }
            c = next_c;
        }
        // last label char must be a-z, A-Z, 0-9, or _
        if !c.is_ascii_alphanumeric() && (c != '_') {
            return Err(ParseError::NameInvalidChars);
        }

        Ok(())
    }
}

impl PartialEq for Name {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// This implements canonical ordering, as defined in
/// [RFC 4034, Section 6.1](https://www.rfc-editor.org/rfc/rfc4034#section-6.1).
///
/// # Examples
/// ```rust
/// use toluol_proto::Name;
///
/// let names_sorted: Vec<_> = [
///     "example",
///     "a.example",
///     "ylj-jljk.a.example",
///     "yljkjljk.a.example",
///     "Z.a.example",
///     "zABC.a.EXAMPLE",
///     "z.example",
///     "*.z.example",
///     "_.z.example",
///     "a.z.example",
/// ]
/// .into_iter()
/// .map(|n| Name::from_ascii(n).unwrap())
/// .collect();
///
/// let mut names = names_sorted.clone();
/// names.swap(0, 1);
/// names.swap(5, 1);
/// names.swap(8, 4);
/// names.swap(2, 9);
/// names.swap(6, 5);
/// names.swap(3, 0);
/// names.sort();
///
/// assert_eq!(names, names_sorted);
/// ```
impl Ord for Name {
    fn cmp(&self, other: &Self) -> Ordering {
        /*
        RFC 4034, Section 6.1:
            For the purposes of DNS security, owner names are ordered by treating individual labels
            as unsigned left-justified octet strings. The absence of a octet sorts before a zero
            value octet, and uppercase US-ASCII letters are treated as if they were lowercase
            US-ASCII letters.

            To compute the canonical ordering of a set of DNS names, start by sorting the names
            according to their most significant (rightmost) labels. For names in which the most
            significant label is identical, continue sorting according to their next most
            significant label, and so forth.

            For example, the following names are sorted in canonical DNS name order. The most
            significant label is "example". At this level, "example" sorts first, followed by names
            ending in "a.example", then by names ending "z.example". The names within each level are
            sorted in the same way.
                  example
                  a.example
                  yljkjljk.a.example
                  Z.a.example
                  zABC.a.EXAMPLE
                  z.example
                  \001.z.example
                  *.z.example
                  \200.z.example
        */

        // reverse the labels because we need to look at the most significant (i.e. rightmost)
        // labels first
        let mut self_lbls = self.labels.iter().rev();
        let mut other_lbls = other.labels.iter().rev();

        let (mut self_lbl, mut other_lbl) = (self_lbls.next(), other_lbls.next());
        loop {
            match (self_lbl, other_lbl) {
                (None, None) => return Ordering::Equal,
                (None, Some(_)) => return Ordering::Less,
                (Some(_), None) => return Ordering::Greater,
                (Some(self_lbl), Some(other_lbl)) => {
                    let self_lbl = self_lbl.to_ascii_lowercase();
                    let other_lbl = other_lbl.to_ascii_lowercase();

                    // this orders lexicographically, which is exactly what we want
                    match self_lbl.as_bytes().cmp(other_lbl.as_bytes()) {
                        Ordering::Less => return Ordering::Less,
                        Ordering::Greater => return Ordering::Greater,
                        Ordering::Equal => (),
                    }
                }
            }
            (self_lbl, other_lbl) = (self_lbls.next(), other_lbls.next());
        }
    }
}

impl Display for Name {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_root() {
            write!(f, ".")
        } else {
            let last_index = self.labels.len() - 1;
            for (i, label) in self.labels.iter().enumerate() {
                if i != last_index {
                    write!(f, "{}.", label)?;
                } else {
                    write!(f, "{}", label)?;
                }
            }
            Ok(())
        }
    }
}
