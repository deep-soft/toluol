//! CLI argument definition and parsing.

use std::env;
use std::net::IpAddr;
use std::process;
use std::str::FromStr;

use owo_colors::OwoColorize;
use toluol::{ConnectionType, QueryMetadata};
use toluol_proto::{Name, RecordType};

#[derive(Clone, Debug)]
pub struct Args {
    pub nameserver: String,
    pub name: Name,
    pub qtype: RecordType,
    pub verbose: bool,
    #[cfg(feature = "json")]
    pub json: bool,
    pub print_meta: bool,
    pub pad_answers: bool,
    pub fetch_dnssec: bool,
    pub validate_dnssec: bool,
    pub iterative: bool,
    pub connection_type: ConnectionType,
    pub port: u16,
    pub cookie: bool,
}

enum ConsumeNext {
    Port,
}

const DEFAULT_NAMESERVER: &str = "ordns.he.net";
const DEFAULT_URL: &str = "example.com.";
const DEFAULT_QTYPE: RecordType = RecordType::AAAA;

impl Args {
    pub fn parse() -> Self {
        // skip executable name
        let args: Vec<String> = env::args().skip(1).collect();

        let mut nameserver = DEFAULT_NAMESERVER.into();
        let mut name = DEFAULT_URL.into();
        let mut qtype = DEFAULT_QTYPE;
        let mut verbose = false;
        #[cfg(feature = "json")]
        let mut json = false;
        let mut print_meta = true;
        let mut pad_answers = true;
        let mut fetch_dnssec = false;
        let mut validate_dnssec = false;
        let mut iterative = false;
        let mut connection_type = ConnectionType::Udp;
        let mut port = None;
        let mut cookie = false;

        // TODO infer that this a reverse query if the only CLI argument is an IPv4/IPv6 address?
        let mut reverse = false;
        let mut consume_next = None;

        for arg in args {
            if let Some(to_consume) = &consume_next {
                match to_consume {
                    ConsumeNext::Port => match arg.parse::<u16>() {
                        Ok(val) => port = Some(val),
                        Err(_) => err(format!("Invalid port: {}.", arg)),
                    },
                }
                consume_next = None;
            } else if let Some(ns) = arg.strip_prefix('@') {
                // nameserver
                nameserver = ns.to_string();
            } else if let Some(flag) = arg.strip_prefix('+') {
                // flags
                match flag {
                    "verbose" => {
                        verbose = true;
                    }
                    #[cfg(feature = "json")]
                    "json" => {
                        json = true;
                    }
                    "no-meta" => {
                        print_meta = false;
                    }
                    "no-padding" => {
                        pad_answers = false;
                    }
                    "do" => {
                        fetch_dnssec = true;
                    }
                    "validate" => {
                        fetch_dnssec = true;
                        validate_dnssec = true;
                    }
                    "trace" => {
                        iterative = true;
                    }
                    "cookie" => {
                        cookie = true;
                    }
                    "tcp" => {
                        connection_type = ConnectionType::Tcp;
                    }
                    #[cfg(feature = "tls")]
                    "dot" | "tls" => {
                        connection_type = ConnectionType::Tls;
                    }
                    #[cfg(feature = "http")]
                    "doh" | "https" | "https-post" => {
                        connection_type = ConnectionType::HttpsPost;
                    }
                    #[cfg(feature = "http")]
                    "https-get" => {
                        connection_type = ConnectionType::HttpsGet;
                    }
                    #[cfg(feature = "http")]
                    "http" | "http-post" => {
                        connection_type = ConnectionType::HttpPost;
                    }
                    #[cfg(feature = "http")]
                    "http-get" => {
                        connection_type = ConnectionType::HttpGet;
                    }
                    x => {
                        err(format!("Invalid flag: +{}.", x));
                    }
                }
            } else if let Some(option) = arg.strip_prefix('-') {
                // options
                match option {
                    "h" | "-help" => {
                        print_help();
                        process::exit(0);
                    }
                    "V" | "-version" => {
                        print_version();
                        process::exit(0);
                    }
                    "p" | "-port" => {
                        consume_next = Some(ConsumeNext::Port);
                    }
                    "x" => {
                        reverse = true;
                    }
                    x => {
                        err(format!("Invalid option: -{}.", x));
                    }
                }
            } else {
                match RecordType::from_str(&arg.to_uppercase()) {
                    Ok(t) => {
                        qtype = t;
                    }
                    Err(_) => {
                        // use URL as fallback
                        name = arg;
                    }
                }
            }
        }

        if verbose && !pad_answers {
            err("Cannot use both +verbose and +no-padding.");
        }

        if reverse {
            match IpAddr::from_str(name.as_str()) {
                Err(_) => {
                    err(format!(
                        "Expected IP address for reverse lookup, but got: {}.",
                        name
                    ));
                }
                Ok(IpAddr::V4(addr)) => {
                    let octets = addr.octets();
                    name = format!(
                        "{}.{}.{}.{}.in-addr.arpa",
                        octets[3], octets[2], octets[1], octets[0]
                    );
                }
                Ok(IpAddr::V6(addr)) => {
                    name = String::with_capacity(72);
                    for s in addr.segments().iter().rev() {
                        for c in format!("{:04x}", s).chars().rev() {
                            name.push(c);
                            name.push('.');
                        }
                    }
                    name.push_str("ip6.arpa");
                }
            }
            qtype = RecordType::PTR;
        }

        let name = match Name::from_ascii(name) {
            Ok(name) => name,
            Err(e) => err(e.to_string()),
        };

        #[cfg(not(any(feature = "tls", feature = "http")))]
        let ns_must_be_hostname = false;
        #[cfg(any(feature = "tls", feature = "http"))]
        let mut ns_must_be_hostname = false;
        #[cfg(feature = "tls")]
        {
            ns_must_be_hostname |= connection_type == ConnectionType::Tls;
        }
        #[cfg(feature = "http")]
        {
            ns_must_be_hostname |= [
                ConnectionType::HttpGet,
                ConnectionType::HttpPost,
                ConnectionType::HttpsGet,
                ConnectionType::HttpsPost,
            ]
            .contains(&connection_type);
        }

        if ns_must_be_hostname {
            if webpki::DnsNameRef::try_from_ascii_str(&nameserver).is_err() {
                err("The nameserver must be a valid hostname (not an IP address) for DoT/DoH.");
            }
            #[cfg(feature = "tls")]
            if (connection_type == ConnectionType::Tls) && port.is_none() {
                port = Some(853);
            }
            #[cfg(feature = "http")]
            if port.is_none() {
                if [ConnectionType::HttpGet, ConnectionType::HttpPost].contains(&connection_type) {
                    port = Some(80);
                } else if [ConnectionType::HttpsGet, ConnectionType::HttpsPost]
                    .contains(&connection_type)
                {
                    port = Some(443);
                }
            }
        }

        Self {
            nameserver,
            name,
            qtype,
            verbose,
            #[cfg(feature = "json")]
            json,
            print_meta,
            pad_answers,
            fetch_dnssec,
            validate_dnssec,
            iterative,
            connection_type,
            port: port.unwrap_or(53),
            cookie,
        }
    }
}

impl From<Args> for QueryMetadata {
    fn from(args: Args) -> Self {
        let client_cookie = if args.cookie {
            // TODO: this is not the correct way to generate a client cookie
            Some(rand::random())
        } else {
            None
        };
        Self {
            name: args.name,
            qtype: args.qtype,
            nameserver: args.nameserver,
            port: args.port,
            connection_type: args.connection_type,
            fetch_dnssec: args.fetch_dnssec,
            validate_dnssec: args.validate_dnssec,
            client_cookie,
        }
    }
}

macro_rules! var {
    ($var:expr) => {
        $var.if_supports_color(owo_colors::Stream::Stdout, |s| s.green())
    };
}

macro_rules! printopt {
    ($opt:expr, $desc:expr) => {
        println!(
            "\t    {:<19} ({})",
            $opt.if_supports_color(owo_colors::Stream::Stdout, |s| s.yellow()),
            $desc,
        )
    };
}

macro_rules! printflag {
    ($flag:expr, $desc:expr) => {
        println!(
            "\t    {:<12} ({})",
            $flag.if_supports_color(owo_colors::Stream::Stdout, |s| s.yellow()),
            $desc,
        )
    };
}

fn print_help() {
    let output = owo_colors::Stream::Stdout;
    print!("{}", "Usage:".if_supports_color(output, |s| s.purple()));
    println!(
        "\ttoluol [@{}] [{}] [{}] [{}] [{}]",
        var!("nameserver"),
        var!("domain"),
        var!("q-type"),
        var!("options"),
        var!("flags")
    );
    println!();

    println!("{}", "Where:".if_supports_color(output, |s| s.purple()));

    println!(
        "\t{} is the IP address or hostname of a DNS nameserver",
        var!("nameserver")
    );
    println!();

    println!("\t{} is the domain you want to query", var!("domain"));
    println!();

    println!(
        "\t{} is the record type you want (e.g. AAAA, A, TXT, MX, SOA, ...)",
        var!("q-type")
    );
    println!();

    println!("\t{} is one or more of the following:", var!("options"));
    printopt!("-h | --help", "print this help message");
    printopt!("-V | --version", "print the version of toluol");
    printopt!("-p | --port <port>", "use the given port number");
    printopt!("-x", "shortcut for reverse lookup");
    println!();
    println!("\t{} is one or more of the following:", var!("flags"));
    printflag!(
        "+verbose",
        "print all sections, i.e. header, OPT, and question"
    );
    #[cfg(feature = "json")]
    printflag!("+json", "format output as JSON; may be used with +verbose");
    printflag!(
        "+no-meta",
        "don't print query metadata, e.g. server and time"
    );
    printflag!(
        "+no-padding",
        "don't pad output; cannot be used with +verbose"
    );
    printflag!("+do", "fetch DNSSEC records");
    printflag!("+validate", "validate DNSSEC records; implies +do");
    printflag!("+trace", "query iteratively, starting from a root server");
    printflag!("+cookie", "send a random DNS client cookie to the server");
    printflag!("+tcp", "use TCP instead of UDP");
    #[cfg(feature = "tls")]
    {
        printflag!("+dot", "use DNS over TLS");
        printflag!("+tls", "use DNS over TLS");
    }
    #[cfg(feature = "http")]
    {
        printflag!("+doh", "use DNS over HTTPS, with POST");
        printflag!("+https", "use DNS over HTTPS, with POST");
        printflag!("+https-post", "use DNS over HTTPS, with POST");
        printflag!("+https-get", "use DNS over HTTPS, with GET");
        printflag!("+http", "use DNS over HTTP, with POST");
        printflag!("+http-post", "use DNS over HTTP, with POST");
        printflag!("+http-get", "use DNS over HTTP, with GET");
    }
    println!();

    println!("Note: the order of the arguments does not matter.");
    println!();

    println!(
        "If no arguments are specified, the default behaviour is\n`{}`.",
        format!(
            "toluol @{} {} {}",
            DEFAULT_NAMESERVER, DEFAULT_URL, DEFAULT_QTYPE
        )
        .if_supports_color(output, |s| s.green())
    );
    println!();

    println!(
        "Output is colourized by default. This can be tuned using the {}/\n{} environment variables.",
        var!("FORCE_COLOR"),
        var!("NO_COLOR")
    );
}

fn print_version() {
    println!("toluol v{}", env!("CARGO_PKG_VERSION"));
}

fn err(msg: impl AsRef<str>) -> ! {
    eprintln!("{}", msg.as_ref());
    process::exit(1)
}
