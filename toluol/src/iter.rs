//! Code for iterative DNS queries (+trace mode).

use crate::net::Nameserver;
use crate::util::{get_dnskeys, prepare_query, send_query};
use crate::QueryMetadata;
use anyhow::{Context, Result};
use lazy_static::lazy_static;
use rand::seq::IteratorRandom;
use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;
use toluol_proto::{EdnsConfig, Message, Name, NonOptRecord, OptRecord, Record, RecordType};

/// Contains the following information for an answer received from a nameserver:
/// - the zone that the nameserver is authoritative for
/// - nameserver information
/// - received answer
/// - number of received bytes
/// - duration of the query
pub type Answer = (Name, Nameserver, Message, u16, Duration);

/// Contains a list of all DNSKEY records, including their RRSIG records, for a list of zones.
pub type DnsKeys = Vec<Vec<NonOptRecord>>;

lazy_static! {
    /// IPv6 addresses of the root servers ({a,b,c,d,e,f,g,h,i,j,k,l,m}.root-servers.net).
    static ref ROOT_IPV6: Vec<Nameserver> = {
        let mut root_servers = Vec::with_capacity(13);
        let root_server_ips = [
            Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 0x2, 0x30),
            Ipv6Addr::new(0x2001, 0x500, 0x200, 0, 0, 0, 0, 0xb),
            Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc),
            Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd),
            Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe),
            Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf),
            Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d),
            Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53),
            Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53),
            Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 0x2, 0x30),
            Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 0x1),
            Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42),
            Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x351),
        ];
        for (i, prefix) in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'].iter().enumerate() {
            root_servers.push(Nameserver {
                ip: Some(IpAddr::V6(root_server_ips[i])),
                hostname: Some(format!("{}.root-servers.net.", prefix)),
                port: 53,
            });
        }
        root_servers
    };

    /// IPv4 addresses of the root servers ({a,b,c,d,e,f,g,h,i,j,k,l,m}.root-servers.net).
    static ref ROOT_IPV4: Vec<Nameserver> = {
        let mut root_servers = Vec::with_capacity(13);
        let root_server_ips = [
            Ipv4Addr::new(198, 41, 0, 4),
            Ipv4Addr::new(199, 9, 14, 201),
            Ipv4Addr::new(192, 33, 4, 12),
            Ipv4Addr::new(199, 7, 91, 13),
            Ipv4Addr::new(192, 203, 230, 10),
            Ipv4Addr::new(192, 5, 5, 241),
            Ipv4Addr::new(192, 112, 36, 4),
            Ipv4Addr::new(198, 97, 190, 53),
            Ipv4Addr::new(192, 36, 148, 17),
            Ipv4Addr::new(192, 58, 128, 30),
            Ipv4Addr::new(193, 0, 14, 129),
            Ipv4Addr::new(199, 7, 83, 42),
            Ipv4Addr::new(202, 12, 27, 33),
        ];
        for (i, prefix) in ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm'].iter().enumerate() {
            root_servers.push(Nameserver {
                ip: Some(IpAddr::V4(root_server_ips[i])),
                hostname: Some(format!("{}.root-servers.net.", prefix)),
                port: 53,
            });
        }
        root_servers
    };
}

/// Performs an iterative query for the information specified in `args`, starting at one of the
/// root servers. If `args.verify_dnssec` is true, also returns the DNSKEYs of all queried zones
/// (including the root zone) and their RRSIGs.
pub fn query(metadata: &QueryMetadata) -> Result<(Vec<Answer>, Option<DnsKeys>)> {
    // idea: first try an IPv6 nameserver, if that fails, try again with IPv4.

    let mut rng = rand::thread_rng();
    let nameserver = ROOT_IPV6
        .iter()
        .choose(&mut rng)
        .expect("No hardcoded IPv6 root servers");
    let res = resolve(metadata, nameserver.clone()).map(|res| (res.1, res.2));
    if res.is_ok() {
        return res;
    }

    let nameserver = ROOT_IPV4
        .iter()
        .choose(&mut rng)
        .expect("No hardcoded IPv4 root servers");
    resolve(metadata, nameserver.clone())
        .map(|res| (res.1, res.2))
        .context("Could not perform iterative query.")
}

/// Iteratively queries for the information specified in `args`, starting with `args.nameserver`
/// as the first nameserver. Returns a tuple of the query result (may be the empty string if the
/// requested record doesn't exist) and the same information that [`query()`] returns.
fn resolve(
    metadata: &QueryMetadata,
    mut nameserver: Nameserver,
) -> Result<(Record, Vec<Answer>, Option<DnsKeys>)> {
    let bufsize = 4096;
    let mut replies = Vec::new();
    let mut dnskeys = Vec::new();
    // store root nameserver for later
    let root_server = nameserver.clone();
    let use_ipv6 = matches!(root_server.ip, Some(IpAddr::V6(_)));
    let mut current_queried_zone = Name::root();

    // loop structure inspired by https://jvns.ca/blog/2022/02/01/a-dns-resolver-in-80-lines-of-go
    loop {
        if metadata.validate_dnssec {
            dnskeys.push(
                get_dnskeys(
                    current_queried_zone.clone(),
                    nameserver.clone(),
                    metadata.clone(),
                )
                .context(format!(
                    "Could not get DNSKEYs for the {} zone.",
                    current_queried_zone
                ))?,
            );
        }

        let query = prepare_query(metadata, bufsize)?;
        let (reply, bytes_recvd, elapsed) =
            send_query(metadata.connection_type, bufsize, &mut nameserver, &query)?;
        let reply = Message::parse(&mut Cursor::new(&reply)).context("Could not parse answer.")?;

        // push now because nameserver may be changed later
        replies.push((
            current_queried_zone.clone(),
            nameserver.clone(),
            reply.clone(),
            bytes_recvd,
            elapsed,
        ));

        // TODO what about CNAMEs/DNAMEs?

        if let Some(answer) = find_answer(metadata, &reply) {
            let dnskeys = if metadata.fetch_dnssec {
                Some(dnskeys)
            } else {
                None
            };
            // TODO remove clone
            break Ok((answer.clone(), replies, dnskeys));
        } else if let Some((zone, hostname, ip)) = find_glue(use_ipv6, &reply) {
            nameserver.ip = Some(ip);
            nameserver.hostname = Some(hostname.to_string());
            current_queried_zone = zone.clone();
        } else if let Some((ns_hostname, zone)) = select_ns(&reply) {
            let mut args2 = metadata.clone();

            // if root_server contains an IPv6 address and we've made it this far, we can assume
            // that IPv6 works. therefore first query for the nameserver's IPv6 address, and only
            // if there is no AAAA record, query for the IPv4 address
            args2.qtype = if use_ipv6 {
                RecordType::AAAA
            } else {
                RecordType::A
            };
            args2.name = ns_hostname.clone();
            nameserver.hostname = Some(ns_hostname.to_string());
            current_queried_zone = zone.clone();

            let mut res = resolve(&args2, root_server.clone());
            if res.is_err() && use_ipv6 {
                args2.qtype = RecordType::A;
                res = resolve(&args2, root_server.clone());
            }
            let ip = res.ok().and_then(|(rec, _, _)| {
                rec.as_nonopt().map(|nonopt| {
                    if use_ipv6 {
                        nonopt
                            .rdata()
                            .as_aaaa()
                            .expect("queried for AAAA, but didn't get AAAA")
                            .address
                            .into()
                    } else {
                        nonopt
                            .rdata()
                            .as_a()
                            .expect("queried for A, but didn't get A")
                            .address
                            .into()
                    }
                })
            });

            nameserver.ip = ip;
        } else {
            let dnskeys = if metadata.fetch_dnssec {
                Some(dnskeys)
            } else {
                None
            };
            // TODO what to return as record here?
            break Ok((
                Record::OPT(
                    OptRecord::new(
                        None,
                        EdnsConfig {
                            bufsize: 4096,
                            do_flag: false,
                            client_cookie: None,
                        },
                    )
                    .expect("couldn't create OPT record"),
                ),
                replies,
                dnskeys,
            ));
        }
    }
}

fn find_answer<'a>(metadata: &QueryMetadata, reply: &'a Message) -> Option<&'a Record> {
    reply.answers.iter().find(|rec| {
        let rec = rec.as_nonopt();
        if let Some(nonopt) = rec {
            (nonopt.owner == metadata.name) && (nonopt.rtype == metadata.qtype)
        } else {
            false
        }
    })
}

/// returns (zone name, nameserver hostname, nameserver ip)
fn find_glue(prefer_ipv6: bool, reply: &Message) -> Option<(&Name, &Name, IpAddr)> {
    // stores nameservers and which zones they are responsible for
    let nameservers: Vec<_> = filter_ns(reply)
        .into_iter()
        .map(|rec| {
            let name = &rec
                .rdata()
                .as_ns()
                .expect("NS record had non-NS RDATA")
                .name;
            (name, &rec.owner)
        })
        .collect();
    let find_glue_with_type = |typ: RecordType| {
        reply
            .additional_answers
            .iter()
            .find(|rec| {
                let rec = rec.as_nonopt();
                if let Some(nonopt) = rec {
                    (nonopt.rtype == typ) & nameservers.iter().any(|(ns, _)| *ns == &nonopt.owner)
                } else {
                    false
                }
            })
            .and_then(|rec| {
                rec.as_nonopt().map(|nonopt| {
                    let zone = nameservers
                        .iter()
                        .find(|(ns, _)| *ns == &nonopt.owner)
                        .unwrap()
                        .1;
                    let ip: IpAddr = match typ {
                        RecordType::A => nonopt
                            .rdata()
                            .as_a()
                            .expect("A record has non-A RDATA")
                            .address
                            .into(),
                        RecordType::AAAA => nonopt
                            .rdata()
                            .as_aaaa()
                            .expect("AAAA record has non-AAAA RDATA")
                            .address
                            .into(),
                        _ => {
                            unreachable!("tried to find glue record with type other than AAAA or A")
                        }
                    };
                    (zone, &nonopt.owner, ip)
                })
            })
    };
    if prefer_ipv6 {
        // look for an IPv6 glue record and return it immediately if we find one. if we don't find
        // one, look for an IPv4 glue record afterwards
        return find_glue_with_type(RecordType::AAAA)
            .or_else(|| find_glue_with_type(RecordType::A));
    }
    find_glue_with_type(RecordType::A)
}

/// randomly chooses one of the nameservers from the authoritative section and returns its hostname
/// and the zone name
fn select_ns(reply: &Message) -> Option<(&Name, &Name)> {
    filter_ns(reply)
        .into_iter()
        .choose(&mut rand::thread_rng())
        .map(|rec| {
            let name = &rec.rdata().as_ns().unwrap().name;
            (name, &rec.owner)
        })
}

/// returns all NS records from the authoritative section
fn filter_ns(reply: &Message) -> Vec<&NonOptRecord> {
    reply
        .authoritative_answers
        .iter()
        .filter_map(|rec| {
            rec.as_nonopt().and_then(|nonopt| {
                if nonopt.rtype == RecordType::NS {
                    Some(nonopt)
                } else {
                    None
                }
            })
        })
        .collect()
}
