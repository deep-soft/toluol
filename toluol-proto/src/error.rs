//! Custom error type definitions.

use thiserror::Error;

use crate::Name;

/// High-level errors.
#[derive(Debug, Error)]
pub enum ToluolError {
    #[error("Tried to create a non-OPT record with OPT RDATA.")]
    OptRdataForNonOptRecord,

    #[error("Error during parsing.")]
    Parsing(#[from] ParseError),

    #[error("Error during encoding.")]
    Encoding(#[from] EncodeError),

    #[error("Could not validate DNSSEC signature.")]
    Dnssec(#[from] DnssecError),
}

/// Errors that may arise during parsing.
#[derive(Debug, Error)]
pub enum ParseError {
    #[error("Invalid opcode: valid are 0 to 2 and 4 to 6, got {0}.")]
    InvalidOpcode(u8),

    #[error("Invalid rcode: valid are 0 to 11 and 16 to 23, got {0}.")]
    InvalidRcode(u16),

    #[error("Invalid class: valid are 1, 3, 4, 254 or 255, got {0}.")]
    InvalidClass(u16),

    #[error("Invalid name in OPT record: must be root, is {0}.")]
    InvalidOptName(Name),

    #[error("Invalid name length: must be smaller than 255, is {0}.")]
    NameTooLong(usize),

    #[error("Invalid label length in name: must be smaller than 64, is {0}.")]
    LabelTooLong(usize),

    #[error("Invalid name: labels must contain only a-z, A-Z, 0-9, underscores, and hyphens, and must not start or end with a hyphen.")]
    NameInvalidChars,

    #[error("Invalid name: contains an empty label.")]
    EmptyLabel,

    #[error("Invalid label type: must be 192 (i.e. extended) or 0, is {0}.")]
    InvalidLabelType(u8),

    #[error("Received truncated message: if possible, resend query via TCP.")]
    TruncatedMessage,

    #[error("Encountered name compression where it is explicitly prohibited.")]
    CompressionProhibited,

    #[error("Non-ASCII string in message: {0}.")]
    NonAsciiString(String),

    #[error("Invalid DNSKEY protocol field: must be 3, is {0}.")]
    InvalidDnskeyProtocol(u8),

    #[error("Invalid LOC version: must be 0, is {0}.")]
    InvalidLocVersion(u8),

    #[error("Non-ASCII tag or value in CAA record: {0}.")]
    NonAsciiCaa(String),

    #[error("Invalid issue/issuewild name in CAA record: {0}.")]
    InvalidCaaIssueName(String),

    #[error("Invalid URL in CAA iodef record.")]
    InvalidCaaIodefUrl(#[from] url::ParseError),

    #[error("Invalid CAA parameter in value: {0}.")]
    InvalidCaaParameter(String),

    #[error("IO error.")]
    IoError(#[from] std::io::Error),
}

/// Errors that may arise during encoding.
#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("Domain name too long: allowed are up to 255 bytes, got {0}.")]
    DomainTooLong(usize),

    #[error("Label too long: allowed are up to 63 bytes, got {0}.")]
    LabelTooLong(usize),

    #[error("AA or RA flag set in a query.")]
    AaOrRaInQuery,

    #[error("Tried to encode non-ASCII string: {0}.")]
    NonAsciiString(String),

    #[error("IO error.")]
    IoError(#[from] std::io::Error),
}

/// Errors that may arise during DNSSEC validation.
///
/// These stem either from incorrect usage (e.g. passing an A record where an RRSIG record was
/// expected) or are actual validation errors (e.g. the signature has expired).
#[derive(Debug, Error)]
pub enum DnssecError {
    #[error("Invalid RRSIG label count: the record has {0} labels, but the RRSIG labels field has value {1}.")]
    InvalidRrsigLabelCount(u8, u8),

    #[error("Invalid record set: no records given.")]
    EmptyRrset,

    #[error("Invalid record set: not all records have the same owner name and record type.")]
    InvalidRrSet,

    #[error("Tried to use a record other than RRSIG for validation.")]
    NonRrsigRecordGiven,

    #[error("Tried to use a record other than DNSKEY for validation.")]
    NonDnskeyRecordGiven,

    #[error("The RRSIG does not cover the record set's type.")]
    RrsigDoesNotCoverType,

    #[error("The RRSIG record's owner is different from the record set's owner.")]
    RrsigHasDifferentOwner,

    #[error("The RRSIG record's class is different from the record set's class.")]
    RrsigHasDifferentClass,

    #[error("The RRSIG signature expiration lies before the signature inception.")]
    RrsigExpirationBeforeInception,

    #[error("The RRSIG signature is not valid yet.")]
    RrsigNotValidYet,

    #[error("The RRSIG signature has expired.")]
    RrsigExpired,

    #[error("The RRSIG signer's name is not in the record set's (parent) zone.")]
    RrsigSignerNotInParentZone,

    #[error("The RRSIG signer's name is different from the DNSKEY record's owner name.")]
    RrsigSignerDoesNotMatchDnskey,

    #[error("The RRSIG's key tag is different from the DNSKEY record's calculated key tag.")]
    RrsigKeyTagDoesNotMatchDnskey,

    #[error("The RRSIG's algorithm is different from the DNSKEY record's algorithm.")]
    RrsigAlgorithmDoesNotMatchDnskey,

    #[error("The DNSKEY record does not have the zone flag set.")]
    DnskeyNoZoneFlag,

    #[error("The DNSKEY record has been revoked.")]
    DnskeyRevoked,

    #[error("Unsupported DNSSEC algorithm.")]
    UnsupportedAlgorithm,

    #[error("Could not parse the DNSKEY public key data.")]
    ParseKey,

    #[error("Could not parse the RRSIG signature data.")]
    ParseSignature,

    #[error("The signature is invalid.")]
    InvalidSignature,

    #[error("Encoding during validation failed.")]
    EncodingFailed(#[from] EncodeError),
}
