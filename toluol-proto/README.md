# toluol-proto

[![crates.io](https://img.shields.io/crates/v/toluol-proto)](https://crates.io/crates/toluol-proto)
[![docs.rs](https://img.shields.io/docsrs/toluol-proto)](https://docs.rs/toluol-proto)

This crate contains the DNS protocol definitions and implementations needed for [`toluol`](https://crates.io/crates/toluol).

## Useful resources

- [RFC 1035 (original specification of the DNS protocol)](https://www.rfc-editor.org/rfc/rfc1035)
- [Explanation of the DNS specification](https://web.archive.org/web/20191124033230/http://www.zytrax.com/books/dns/ch15/)
- [Overview of the DNS record types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
- [Overview of some DNS parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)

### RDATA schema

If you ever need a compact representation of what the RDATA looks like for the most query types
(e.g. if you want to parse DNS messages yourself), here's a code excerpt from
`DnsType::rdata_schema()` in `src/lib.rs`.

```rust
DnsType::A => "ip4",
DnsType::NS | DnsType::CNAME | DnsType::DNAME | DnsType::PTR => "qname",
DnsType::SOA => "qname qname u32 u32 u32 u32 u32",
DnsType::HINFO => "string string",
DnsType::MX => "u16 qname",
DnsType::TXT => "text",
DnsType::RP => "qname qname",
DnsType::KEY | DnsType::DNSKEY => "u16 u8 u8 base64",
DnsType::AAAA => "ip6",
DnsType::LOC => "u8 u8 u8 u8 u32 u32 u32",
DnsType::SRV => "u16 u16 u16 qname",
DnsType::NAPTR => "u16 u16 string string string qname",
DnsType::CERT => "u16 u16 u8 base64",
DnsType::OPT => "options",
DnsType::DS => "u16 u8 u8 hex",
DnsType::SSHFP => "u8 u8 hex",
DnsType::RRSIG => "qtype u8 u8 u32 time time u16 qname base64",
DnsType::NSEC => "qname types",
DnsType::NSEC3 => "u8 u8 u16 salt hash types",
DnsType::NSEC3PARAM => "u8 u8 u16 salt",
DnsType::TLSA => "u8 u8 u8 hex",
DnsType::OPENPGPKEY => "base64",
DnsType::CAA => "u8 property",
```

## License

See `LICENSE.txt`.

---

Copyright (c) 2022 Max von Forell
