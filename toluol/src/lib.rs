use toluol_proto::{Name, RecordType};

pub mod iter;
pub mod net;
pub mod util;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionType {
    Udp,
    Tcp,
    #[cfg(feature = "tls")]
    Tls,
    #[cfg(feature = "http")]
    HttpGet,
    #[cfg(feature = "http")]
    HttpPost,
    #[cfg(feature = "http")]
    HttpsGet,
    #[cfg(feature = "http")]
    HttpsPost,
}

#[derive(Clone, Debug)]
pub struct QueryMetadata {
    pub name: Name,
    pub qtype: RecordType,
    pub nameserver: String,
    pub port: u16,
    pub connection_type: ConnectionType,
    pub fetch_dnssec: bool,
    pub validate_dnssec: bool,
    pub client_cookie: Option<[u8; 8]>,
}
