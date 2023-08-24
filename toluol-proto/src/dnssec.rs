//! DNSSEC validation.

use std::cmp::min;

use chrono::Utc;
use sha2::{Digest, Sha256};

use crate::error::DnssecError;
use crate::rdata::{RdataTrait, DNSKEY, RRSIG};
use crate::{Class, NonOptRecord, RecordType};

/// A set of resource records with the same owner name and [`RecordType`]. Used to validate records.
#[derive(Clone, Debug)]
pub struct RrSet {
    records: Vec<NonOptRecord>,
    record_type: RecordType,
    class: Class,
}

impl RrSet {
    /// Create a new `RrSet`.
    ///
    /// `records` must non be empty, and all records must have the same record type, owner name, and
    /// class.
    pub fn new(records: Vec<NonOptRecord>) -> Result<Self, DnssecError> {
        if records.is_empty() {
            return Err(DnssecError::EmptyRrset);
        }

        let record_type = records[0].rtype;
        let owner = &records[0].owner;
        let class = records[0].class;

        if records
            .iter()
            .any(|rec| (rec.rtype != record_type) || (&rec.owner != owner) || (rec.class != class))
        {
            return Err(DnssecError::InvalidRrSet);
        }

        Ok(Self {
            records,
            record_type,
            class,
        })
    }

    /// Canonicalizes all records in the set and `rrsig_record`, validates the signature from
    /// `rrsig_record` using the key from `dnskey_record`, and updates the TTL of all records in the
    /// set and of `rrsig_record` according to the rules from RFC 4035, Section 5.3.3.
    ///
    /// If `ignore_time` is true, the signature inception and expiration times are ignored.
    ///
    /// If the signature is valid, `Ok(())` is returned. If it is invalid, an error is returned.
    ///
    /// To retrieve the validated and canonicalized records, use
    /// [`into_records()`](Self::into_records()).
    ///
    /// The canonicalization of `rrsig_record` is always done, but its TTL is only updated if the
    /// signature is valid.
    pub fn validate(
        &mut self,
        rrsig_record: &mut NonOptRecord,
        dnskey_record: &NonOptRecord,
        ignore_time: bool,
    ) -> Result<(), DnssecError> {
        let (rrsig, dnskey) =
            self.check_rrsig_and_dnskey(rrsig_record, dnskey_record, ignore_time)?;

        let rrset_received_ttl = self
            .records
            .iter()
            .map(|rec| rec.ttl)
            .min()
            .expect("Empty record set");

        rrsig.canonicalize();
        let canonicalize_res: Result<Vec<_>, _> = self
            .records
            .iter_mut()
            .map(|rec| rec.canonicalize(rrsig.labels, rrsig.original_ttl))
            .collect();
        canonicalize_res?;

        // because of lifetime issues, we cannot just do
        // `self.records.sort_unstable_by_key(|rec| &rec.encoded_rdata)`.
        // the solution is to create a temporary array containing the encoded rdata slices, sort
        // that and apply the same permutation to `self.records`.
        let temp_rdata: Vec<_> = self.records.iter().map(|rec| &rec.encoded_rdata).collect();
        let mut perm = permutation::sort(&temp_rdata);
        perm.apply_slice_in_place(&mut self.records);

        /*
        From RFC 4034, Section 6.3:
            RFC 2181 specifies that an RRset is not allowed to contain duplicate records (multiple
            RRs with the same owner name, class, type, and RDATA). Therefore, if an implementation
            detects duplicate RRs when putting the RRset in canonical form, it MUST treat this as a
            protocol error. If the implementation chooses to handle this protocol error in the
            spirit of the robustness principle (being liberal in what it accepts), it MUST remove
            all but one of the duplicate RR(s) for the purposes of calculating the canonical form of
            the RRset.
        */

        // for the same lifetime reasons as above, we can't use a reference to the encoded rdata as
        // the key. instead, we compute the hash of the encoded rdata. this also removes all
        // duplicates.
        self.records
            .dedup_by_key(|rec| Sha256::digest(&rec.encoded_rdata));

        let mut data_to_be_signed = Vec::with_capacity(1024);
        rrsig.encode_into_without_signature(&mut data_to_be_signed)?;

        for record in &self.records {
            record.encode_into(&mut data_to_be_signed)?;
        }

        dnskey.validate(&data_to_be_signed, &rrsig.signature)?;

        /*
        From RFC 4035, Section 5.3.3:
            If the resolver accepts the RRset as authentic, the validator MUST set the TTL of the
            RRSIG RR and each RR in the authenticated RRset to a value no greater than the minimum
            of:
            o  the RRset's TTL as received in the response;
            o  the RRSIG RR's TTL as received in the response;
            o  the value in the RRSIG RR's Original TTL field; and
            o  the difference of the RRSIG RR's Signature Expiration time and the current time.
        */
        let now = Utc::now().timestamp() as u32;
        let sig_valid_duration = rrsig.signature_expiration.wrapping_sub(now);

        let new_ttl = min(rrset_received_ttl, rrsig.original_ttl);
        let new_ttl = min(new_ttl, sig_valid_duration);
        let new_ttl = min(new_ttl, rrsig_record.ttl);

        rrsig_record.ttl = new_ttl;
        self.records.iter_mut().for_each(|rec| rec.ttl = new_ttl);

        Ok(())
    }

    /// Consumes the `Rrset` and returns the contained records.
    pub fn into_records(self) -> Vec<NonOptRecord> {
        self.records
    }

    /// Checks that the given RRSIG and DNSKEY record are valid and match the record set as well as
    /// each other.
    ///
    /// If `ignore_time` is true, the signature inception and expiration times are ignored.
    ///
    /// Returns the extracted RRSIG and DNSKEY RDATA.
    fn check_rrsig_and_dnskey<'r, 'd>(
        &self,
        rrsig_record: &'r mut NonOptRecord,
        dnskey_record: &'d NonOptRecord,
        ignore_time: bool,
    ) -> Result<(&'r mut RRSIG, &'d DNSKEY), DnssecError> {
        if rrsig_record.rtype != RecordType::RRSIG {
            return Err(DnssecError::NonRrsigRecordGiven);
        }
        let rrsig = match rrsig_record.rdata.as_mut_rrsig() {
            Some(rrsig) => rrsig,
            None => return Err(DnssecError::NonRrsigRecordGiven),
        };

        if dnskey_record.rtype != RecordType::DNSKEY {
            return Err(DnssecError::NonDnskeyRecordGiven);
        }
        let dnskey = match dnskey_record.rdata.as_dnskey() {
            Some(key) => key,
            None => return Err(DnssecError::NonDnskeyRecordGiven),
        };

        if rrsig.type_covered != self.record_type {
            return Err(DnssecError::RrsigDoesNotCoverType);
        }

        let owner = &self.records[0].owner;
        if &rrsig_record.owner != owner {
            return Err(DnssecError::RrsigHasDifferentOwner);
        }

        if rrsig_record.class != self.class {
            return Err(DnssecError::RrsigHasDifferentClass);
        }

        if serial_lt(rrsig.signature_expiration, rrsig.signature_inception) {
            return Err(DnssecError::RrsigExpirationBeforeInception);
        }

        if !ignore_time {
            let now = Utc::now().timestamp() as u32;
            if serial_lt(now, rrsig.signature_inception) {
                return Err(DnssecError::RrsigNotValidYet);
            }
            if serial_lt(rrsig.signature_expiration, now) {
                return Err(DnssecError::RrsigExpired);
            }
        }

        if !rrsig.signer_name.zone_of(owner) {
            return Err(DnssecError::RrsigSignerNotInParentZone);
        }
        if rrsig.signer_name != dnskey_record.owner {
            return Err(DnssecError::RrsigSignerDoesNotMatchDnskey);
        }

        if rrsig.key_tag != dnskey.key_tag() {
            return Err(DnssecError::RrsigKeyTagDoesNotMatchDnskey);
        }

        if rrsig.algorithm != dnskey.algorithm {
            return Err(DnssecError::RrsigAlgorithmDoesNotMatchDnskey);
        }

        if !dnskey.zone {
            return Err(DnssecError::DnskeyNoZoneFlag);
        }

        if dnskey.revoked {
            return Err(DnssecError::DnskeyRevoked);
        }

        Ok((rrsig, dnskey))
    }
}

/// Returns true iff the serial `s1` is less than the serial `s2`.
///
/// See RFC 1982, Section 3.2 for more on how to compare serials.
fn serial_lt(s1: u32, s2: u32) -> bool {
    let i1 = s1 as i64;
    let i2 = s2 as i64;
    ((i1 < i2) && ((i2 - i1) < (1 << 31))) || ((i1 > i2) && ((i1 - i2) > (1 << 31)))
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use chrono::{TimeZone, Utc};
    use data_encoding::BASE64;

    use crate::rdata::dnskey::{Algorithm, DNSKEY};
    use crate::rdata::{A, RRSIG};
    use crate::{Class, Name, NonOptRecord, RecordType};

    use super::RrSet;

    #[test]
    fn validate_ecdsap256_sha256() {
        // example from RFC 6605, Section 6.1
        let example_net = Name::from_ascii("example.net").unwrap();
        let www_example_net = Name::from_ascii("www.example.net").unwrap();

        let dnskey = DNSKEY {
            zone: true,
            secure_entry_point: true,
            revoked: false,
            algorithm: Algorithm::ECDSAP256SHA256,
            key: BASE64
                .decode(
                    b"GojIhhXUN/u4v54ZQqGSnyhWJwaubCvTmeexv7bR6edbkrSqQpF64cYbcB7wNcP+e+MAnLr+Wi9xMWyQLc8NAA==",
                )
                .unwrap(),
        };
        let dnskey_record = NonOptRecord::new(example_net, Class::IN, 3600, dnskey.into()).unwrap();

        let a_record = NonOptRecord::new(
            www_example_net.clone(),
            Class::IN,
            3600,
            A {
                address: Ipv4Addr::new(192, 0, 2, 1),
            }
            .into(),
        )
        .unwrap();
        let mut rr_set = RrSet::new(vec![a_record]).unwrap();

        let signature_expiration = Utc
            .datetime_from_str("20100909100439", "%Y%m%d%H%M%S")
            .unwrap()
            .timestamp() as u32;
        let signature_inception = Utc
            .datetime_from_str("20100812100439", "%Y%m%d%H%M%S")
            .unwrap()
            .timestamp() as u32;
        let rrsig = RRSIG {
            type_covered: RecordType::A,
            algorithm: Algorithm::ECDSAP256SHA256,
            labels: 3,
            original_ttl: 3600,
            signature_expiration,
            signature_inception,
            key_tag: 55648,
            signer_name: Name::from_ascii("example.net").unwrap(),
            signature: BASE64.decode(b"qx6wLYqmh+l9oCKTN6qIc+bw6ya+KJ8oMz0YP107epXAyGmt+3SNruPFKG7tZoLBLlUzGGus7ZwmwWep666VCw==").unwrap(),
        };
        let mut rrsig_record =
            NonOptRecord::new(www_example_net, Class::IN, 3600, rrsig.into()).unwrap();

        rr_set
            .validate(&mut rrsig_record, &dnskey_record, true)
            .unwrap();
    }
}
