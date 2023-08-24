use std::cmp::max;
use std::io::Cursor;
use std::iter::zip;
use std::time::Duration;

use anyhow::{Context, Result};
use owo_colors::{OwoColorize, Style};
use toluol::net::Nameserver;
use toluol::util::{get_dnskeys, prepare_query, send_query};
use toluol::QueryMetadata;
use toluol_proto::{dnssec::RrSet, Message, NonOptRecord, RCode, Record, RecordType};

mod args;

use args::Args;

// TODO
// - better docs (examples!)
// - remove features (enable everything as this is not a lib crate anymore)
// - see if we can get nicer error messages
// - add tests for parsing (look at cargo fuzz)
// - more input validation when constructing lib data types
// - add new flag to only print the RDATA of the answer (re-use +short as that is free after implementing above point?)
// - better README
// - AXFR support
// - use resolv-conf (Linux) and ipconfig (Windows) crates to query the system's configured nameservers

fn main() -> Result<()> {
    let bufsize = 4096; // seems reasonable
    let args = Args::parse();
    let query_metadata: QueryMetadata = args.clone().into();
    let data = prepare_query(&query_metadata, bufsize)?;
    let mut nameserver = Nameserver::from_metadata(&query_metadata);

    if args.iterative {
        do_and_display_iterative_query(&args, &query_metadata)?;
        return Ok(());
    }

    let (answer, bytes_recvd, elapsed) =
        send_query(args.connection_type, bufsize, &mut nameserver, &data)?;

    let res = Message::parse(&mut Cursor::new(&answer)).context("Could not parse answer.")?;
    display_result(&res, &args, &nameserver, bytes_recvd, &elapsed);

    if args.validate_dnssec {
        let mut zone = args.name.clone();
        let dnskeys = loop {
            let dnskeys = get_dnskeys(zone.clone(), nameserver.clone(), query_metadata.clone())?;
            if !dnskeys.is_empty() {
                break dnskeys;
            }

            // try the parent zone's DNSKEYs
            // TODO figure out when to stop (e.g. we should not try to validate www.example.com with
            // the com DNSKEYs if example.com has no keys)
            if zone.is_root() {
                // this ensures consistent error message styling
                validate_result(res, &[], &args);
                return Ok(());
            }
            zone.pop_front_label();
        };
        validate_result(res, &dnskeys, &args);
    }

    Ok(())
}

fn do_and_display_iterative_query(args: &Args, metadata: &QueryMetadata) -> Result<()> {
    let headline_style = owo_colors::style().bold().blue();
    let (answers, dnskeys) = toluol::iter::query(metadata)?;
    let dnskeys = match dnskeys {
        None => vec![None; answers.len()],
        Some(dnskeys) => dnskeys.into_iter().map(Some).collect(),
    };
    for (i, (answer, dnskeys)) in zip(answers, dnskeys).enumerate() {
        let (zone, nameserver, answer, bytes_recvd, elapsed) = answer;
        if i > 0 {
            println!();
        }
        let zone = if zone.is_root() {
            "root".into()
        } else {
            zone.to_string()
        };
        println!(
            "{}",
            format!("response from {} nameservers:", zone)
                .if_supports_color(owo_colors::Stream::Stdout, |text| text
                    .style(headline_style))
        );
        display_result(&answer, args, &nameserver, bytes_recvd, &elapsed);

        // TODO for every answer except the last the DS record and its RRSIG are in the authoritative section
        if args.validate_dnssec && !answer.answers.is_empty() {
            let dnskeys = dnskeys.unwrap();
            validate_result(answer, &dnskeys, args);
        }
    }
    Ok(())
}

fn display_result(
    res: &Message,
    args: &Args,
    nameserver: &Nameserver,
    bytes_recvd: u16,
    elapsed: &Duration,
) {
    let output = owo_colors::Stream::Stdout;

    if args.verbose {
        #[cfg(feature = "json")]
        if args.json {
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
            return;
        }

        println!("{}", res.as_string(Some(output)));

        if args.print_meta {
            println!();
            println!(
                "{}",
                "Query metadata:".if_supports_color(output, |s| s.yellow())
            );
            println!("\tTime:        {} ms", elapsed.as_millis());
            println!("\tReply size:  {} bytes", bytes_recvd);
            println!("\tServer:      {}", nameserver);
        }
        return;
    }

    let all_answers: Vec<_> = res
        .answers
        .iter()
        .chain(res.authoritative_answers.iter())
        .chain(res.additional_answers.iter())
        // don't print OPT records
        .filter_map(|record| record.as_nonopt())
        .collect();

    #[cfg(feature = "json")]
    if args.json {
        println!("{}", serde_json::to_string_pretty(&all_answers).unwrap());
        return;
    }

    if all_answers.is_empty() {
        println!("<empty response>");
    } else if !args.pad_answers {
        for answer in &all_answers {
            println!("{}", answer.as_string(true, None, None, Some(output)));
        }
    } else {
        let (mut max_owner_len, mut max_type_len) = (0, 0);
        for answer in &all_answers {
            max_owner_len = max(max_owner_len, answer.owner.string_len());
            max_type_len = max(max_type_len, answer.rtype.to_string().len());
        }
        for answer in &all_answers {
            println!(
                "{}",
                answer.as_string(false, Some(max_owner_len), Some(max_type_len), Some(output))
            );
        }
    }

    if args.print_meta {
        let rcode = if let Some(opt) = res
            .additional_answers
            .iter()
            .filter_map(|rec| rec.as_opt())
            .next()
        {
            opt.rcode
        } else {
            res.header.rcode
        };
        let rcode = rcode.unwrap_or(RCode::NOERROR);
        let style = if rcode == RCode::NOERROR {
            Style::new().green()
        } else {
            Style::new().red()
        };

        println!();
        println!(
            "{} from {} in {} ms",
            rcode
                .to_string()
                .if_supports_color(output, |s| s.style(style)),
            nameserver,
            elapsed.as_millis()
        );
    }
}

fn validate_result(mut answer: Message, dnskeys: &[NonOptRecord], args: &Args) {
    let output = owo_colors::Stream::Stdout;
    let err_style = Style::new().bold().red();
    let ok_style = Style::new().bold().green();

    if dnskeys.is_empty() {
        let err = format!(
            "The {} record(s) could not be verified: no DNSKEY record found.",
            args.qtype
        );
        println!("{}", err.if_supports_color(output, |s| s.style(err_style)));
        return;
    }

    // Vec::drain_filter() is still unstable, so we roll our own thing
    let mut idx = 0;
    let mut rrsig_records = Vec::new();
    let mut rrset_records = Vec::new();
    while idx < answer.answers.len() {
        if let Record::NONOPT(nonopt) = &answer.answers[idx] {
            if nonopt.rtype == RecordType::RRSIG {
                rrsig_records.push(answer.answers.swap_remove(idx).into_nonopt());
                continue;
            } else if nonopt.rtype == args.qtype {
                rrset_records.push(answer.answers.swap_remove(idx).into_nonopt());
                continue;
            }
        }
        idx += 1;
    }

    let mut rrset = match RrSet::new(rrset_records) {
        Ok(rrset) => rrset,
        Err(e) => {
            let err = format!("The {} record(s) could not be verified: {}", args.qtype, e);
            println!("{}", err.if_supports_color(output, |s| s.style(err_style)));
            return;
        }
    };

    let rrsig = rrsig_records.into_iter().find(|rec| {
        rec.rdata()
            .as_rrsig()
            .expect("RRSIG record has non-RRSIG RDATA.")
            .type_covered
            == args.qtype
    });
    let mut rrsig = match rrsig {
        Some(rrsig) => rrsig,
        None => {
            let err = format!(
                "The {} record(s) could not be verified: no RRSIG record found.",
                args.qtype
            );
            println!("{}", err.if_supports_color(output, |s| s.style(err_style)));
            return;
        }
    };

    let dnskey_candidates: Vec<_> = dnskeys
        .iter()
        .filter(|rec| {
            // TODO what to do with the RRSIGs here?
            if rec.rtype != RecordType::DNSKEY {
                return false;
            }
            let rrsig_keytag = rrsig.rdata().as_rrsig().unwrap().key_tag;
            let rdata = rec
                .rdata()
                .as_dnskey()
                .expect("DNSKEY record has non-DNSKEY RDATA.");
            rdata.key_tag() == rrsig_keytag
        })
        .collect();

    let mut err = None;
    for dnskey in dnskey_candidates {
        match rrset.validate(&mut rrsig, dnskey, false) {
            Ok(()) => {
                let msg = format!(
                    "The {} record(s) have been validated using the RRSIG record.",
                    args.qtype
                );
                println!("{}", msg.if_supports_color(output, |s| s.style(ok_style)));
                return;
            }
            Err(e) => err = Some(e),
        }
    }

    // if we haven't returned early, that means validation did not succeed and we should have an
    // error
    let err = format!(
        "The {} record(s) could not be verified: {}",
        args.qtype,
        err.unwrap()
    );
    println!("{}", err.if_supports_color(output, |s| s.style(err_style)));
}
