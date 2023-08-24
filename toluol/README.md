# toluol

[![crates.io](https://img.shields.io/crates/v/toluol)](https://crates.io/crates/toluol)
[![docs.rs](https://img.shields.io/docsrs/toluol)](https://docs.rs/toluol)

`toluol` is a command line tool for making DNS queries intended to replace `dig`. It can be used for
all sort of DNS queries, including:

- Regular DNS queries
- Queries for DNSSEC records with the `+do` flag
- DNS over TLS (DoT) with the `dot`/`+tls` flag
- DNS over HTTPS (DoH) with the `+doh`/`+https` flag
- DNS over HTTP (DoH but without TLS, great for locally debugging DoH) with the `+http` flag
- Reverse lookups with the `-x` option

Other useful features include:

- short, readable output by default &mdash; verbose output by choice
- IPv6 by default
- script friendly options:
  - JSON output (e.g. for use with [`jq(1)`](https://stedolan.github.io/jq), see
    [examples below](#examples))
  - unpadded output (e.g. for use with
    [`cut(1)`](https://www.man7.org/linux/man-pages/man1/cut.1.html), see
    [examples below](#examples))

This repository consists of a library crate for creating, encoding and parsing DNS messages and a
binary crate for making DNS queries from the command-line.

For example usage of most of the library capabilities have a look at the code of the binary
(`src/main.rs`).

## Installation

### Arch Linux (AUR)

`yay -S toluol`

### Via `cargo install`

`cargo install toluol`

Shoutout to [`cargo-update`](https://github.com/nabijaczleweli/cargo-update) &mdash; after
installing `toluol` as above, you can update it via `cargo install-update toluol`, if you have
`cargo-update` installed (or run `cargo install-update -a` to update all packages installed via
`cargo install`).

## Examples

AAAA query:

```sh
# the query type is not case-sensitive and order of the arguments does not matter, so `toluol example.com aaaa` would also work
# also, AAAA is the default query type, so in this case just `toluol example.com` would work as well
$ toluol AAAA example.com
example.com.  30283  AAAA  2606:2800:220:1:248:1893:25c8:1946

response from ordns.he.net:53 in 23 ms
```

DNS over TLS (DoT) query with sepcified nameserver:

```sh
# or `toluol @dns.google AAAA example.com +tls`
$ toluol @dns.google AAAA example.com +dot
example.com.  86400  AAAA  2606:2800:220:1:248:1893:25c8:1946

response from dns.google:853 in 35 ms
```

Query with DNSSEC records:

```sh
$ toluol AAAA example.com +do
example.com.  26860  AAAA   2606:2800:220:1:248:1893:25c8:1946
example.com.  26860  RRSIG  AAAA 8 2 86400 20220309052808 20220216115840 1618 example.com. JlODulmkXKTi5EvxUJDcVh2pDZY8CovFWykPS9HhjbicMQJyCsngkHeRWVzndGU9nTYKiBGRJY2cMPzV5S4Lxh3AojM42xsuT0kQh7dDWOgfuZEeaLbSsZgLA1Xy2WnrxHlHv965cOMDcylqXHi7WEgBhiFTBMP6w6R5vgKxp5w=

response from ordns.he.net:53 in 15 ms
```

Verbose output:

```sh
$ toluol AAAA example.com
Header:
        id: 57320, opcode: QUERY, rcode: NOERROR, flags: rd ra ad cd

OPT Pseudosection:
        EDNS: Version 0, flags: <none>; payload size: 512

Question Section:
        example.com.         AAAA

Answer Section:
        example.com.  28653  AAAA  2606:2800:220:1:248:1893:25c8:1946

Query metadata:
        Time:        15 ms
        Reply size:  68 bytes
        Server:      ordns.he.net:53
```

Reverse query:

```sh
$ toluol -x 2001:470:20::2
2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.7.4.0.1.0.0.2.ip6.arpa.  86400  PTR  ordns.he.net.

response from ordns.he.net:53 in 141 ms
```

Only print RDATA using [`cut(1)`](https://www.man7.org/linux/man-pages/man1/cut.1.html):

```sh
$ toluol MX gmail.com +no-padding +no-meta | cut -d' ' -f4-
10 alt1.gmail-smtp-in.l.google.com.
5 gmail-smtp-in.l.google.com.
40 alt4.gmail-smtp-in.l.google.com.
30 alt3.gmail-smtp-in.l.google.com.
20 alt2.gmail-smtp-in.l.google.com.
```

Only print RDATA as JSON array using [`jq(1)`](https://stedolan.github.io/jq):

```sh
$ toluol MX gmail.com +json | jq '[.[] | .rdata]'
[
  [
    "10",
    "alt1.gmail-smtp-in.l.google.com."
  ],
  [
    "5",
    "gmail-smtp-in.l.google.com."
  ],
  [
    "40",
    "alt4.gmail-smtp-in.l.google.com."
  ],
  [
    "30",
    "alt3.gmail-smtp-in.l.google.com."
  ],
  [
    "20",
    "alt2.gmail-smtp-in.l.google.com."
  ]
]
```

## Useful resources

- [RFC 1035 (original specification of the DNS protocol)](https://www.rfc-editor.org/rfc/rfc1035)
- [Explanation of the DNS specification](https://web.archive.org/web/20191124033230/http://www.zytrax.com/books/dns/ch15/)
- [Overview of the DNS record types](https://en.wikipedia.org/wiki/List_of_DNS_record_types)
- [Overview of some DNS parameters](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml)

## License

See `LICENSE.txt`.

---

Copyright (c) 2022 Max von Forell
