//! Utility functions.

use anyhow::{Context, Result};
use toluol_proto::{
    EdnsConfig, HeaderFlags, Message, Name, NonOptRecord, Opcode, Record, RecordType,
};

use std::io::Cursor;
use std::time::Duration;

use crate::net::{send_query_tcp, send_query_udp, Nameserver};
use crate::{ConnectionType, QueryMetadata};

#[cfg(feature = "tls")]
use crate::net::send_query_tls;

#[cfg(feature = "http")]
use crate::net::send_query_http;

pub fn prepare_query(metadata: &QueryMetadata, bufsize: u16) -> Result<Vec<u8>> {
    // see https://tools.ietf.org/html/rfc6840#section-5.9 for why the cd flag is set
    let flags = HeaderFlags {
        aa: false,
        tc: false,
        rd: true,
        ra: false,
        ad: true,
        cd: true,
    };
    let msg = Message::new_query(
        metadata.name.clone(),
        metadata.qtype,
        Opcode::QUERY,
        flags,
        Some(EdnsConfig {
            do_flag: metadata.fetch_dnssec,
            bufsize,
            client_cookie: metadata.client_cookie,
        }),
    )
    .context("Could not create query.")?;
    msg.encode().context("Could not encode query.")
}

pub fn send_query(
    connection_type: ConnectionType,
    bufsize: u16,
    nameserver: &mut Nameserver,
    data: &[u8],
) -> Result<(Vec<u8>, u16, Duration)> {
    match connection_type {
        ConnectionType::Udp => send_query_udp(nameserver, bufsize, data),
        ConnectionType::Tcp => send_query_tcp(nameserver, bufsize, data),
        #[cfg(feature = "tls")]
        ConnectionType::Tls => send_query_tls(nameserver, data),
        #[cfg(feature = "http")]
        ConnectionType::HttpGet
        | ConnectionType::HttpPost
        | ConnectionType::HttpsGet
        | ConnectionType::HttpsPost => send_query_http(nameserver, connection_type, bufsize, data),
    }
}

pub fn get_dnskeys(
    zone: Name,
    mut nameserver: Nameserver,
    mut metadata: QueryMetadata,
) -> Result<Vec<NonOptRecord>> {
    let bufsize = 4096;
    metadata.qtype = RecordType::DNSKEY;
    metadata.name = zone;
    let query = prepare_query(&metadata, bufsize)?;
    let (reply, _, _) = send_query(metadata.connection_type, bufsize, &mut nameserver, &query)?;
    let reply = Message::parse(&mut Cursor::new(&reply)).context("Could not parse answer.")?;
    Ok(reply
        .answers
        .into_iter()
        .filter_map(|rec| {
            if let Record::NONOPT(
                nonopt @ NonOptRecord {
                    rtype: RecordType::DNSKEY | RecordType::RRSIG,
                    ..
                },
            ) = rec
            {
                Some(nonopt)
            } else {
                None
            }
        })
        .collect())
}
