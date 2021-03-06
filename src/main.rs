use std::convert::TryInto;
use std::env;
use std::fs;
use std::io;
use std::io::Read;
use std::io::Write;
use std::str::FromStr;

use cidr::Ipv4Cidr;
use failure::Error;
use failure::ResultExt;
use itertools::Itertools;
use septid::MasterKey;

mod buffer;
mod capture;
mod cluster_desc;
mod flows;
mod read;
mod spec;

fn main() -> Result<(), Error> {
    let args = clap::App::new(clap::crate_name!())
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            clap::SubCommand::with_name("capture")
                .arg(clap::Arg::with_name("daemon").long("daemon"))
                .arg(
                    clap::Arg::with_name("dest")
                        .long("dest")
                        .takes_value(true)
                        .required(true),
                )
                .arg(clap::Arg::with_name("raw").long("raw"))
                .arg(
                    clap::Arg::with_name("filter")
                        .long("filter")
                        .takes_value(true)
                        .required(true),
                ),
        )
        .subcommand(clap::SubCommand::with_name("make-pcap"))
        .subcommand(
            clap::SubCommand::with_name("flows")
                .arg(
                    clap::Arg::with_name("dump")
                        .long("dump")
                        .conflicts_with_all(&["guess-names", "naive-track"]),
                )
                .arg(clap::Arg::with_name("guess-names").long("guess-names"))
                .arg(clap::Arg::with_name("naive-track").long("naive-track"))
                .arg(
                    clap::Arg::with_name("file")
                        .short("f")
                        .multiple(true)
                        .takes_value(true)
                        .required(true),
                ),
        )
        .get_matches();

    match args.subcommand() {
        ("capture", Some(args)) => {
            let master_key =
                env::var("PCAP_MASTER_KEY").with_context(|_| "PCAP_MASTER_KEY must be set")?;
            let master_key: MasterKey =
                MasterKey::from_reader(io::Cursor::new(master_key.as_bytes()))?;

            let filter = args.value_of("filter").expect("required param");
            let dest = args.value_of("dest").expect("required param");
            let daemon = args.is_present("daemon");
            let raw = args.is_present("raw");

            capture::run_capture(
                master_key,
                filter,
                dest,
                daemon,
                if raw {
                    capture::pack_pcap_legacy_format
                } else {
                    capture::pack_mostly_data
                },
            )
        }
        ("make-pcap", _) => make_pcap(),
        ("flows", Some(args)) => {
            let spec = spec::load(fs::File::open("spec-lines.json")?)?;
            let desc = cluster_desc::ClusterDesc::from_reader(fs::File::open("cluster.toml")?)?;

            let paths: Vec<_> = args.values_of("file").expect("required arg").collect();
            let events = flows::all_files(&paths)?;

            if args.is_present("dump") {
                flows::dump_every(&spec, events)
            } else if args.is_present("guess-names") {
                let pods = Ipv4Cidr::from_str("10.32.0.0/16").expect("static input");
                println!("{:#?}", flows::guess_names(&pods, events)?);
                Ok(())
            } else if args.is_present("naive-track") {
                flows::naive_req_track(&spec, events)
            } else {
                flows::by_source(&spec, events)
            }
        }
        (_, _) => unreachable!("bad subcommand"),
    }
}

// well, this is getting nuts
fn make_pcap() -> Result<(), Error> {
    use std::convert::TryFrom;
    let stdin = io::stdin();
    let stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    // magic (le)
    stdout.write_all(&[0xd4, 0xc3, 0xb2, 0xa1])?;
    // version
    stdout.write_all(&[0x02, 0x00, 0x04, 0x00])?;
    // timezone
    stdout.write_all(&[0x00, 0x00, 0x00, 0x00])?;
    // sig figs (always zero)
    stdout.write_all(&[0x00, 0x00, 0x00, 0x00])?;
    // snap len (512?)
    stdout.write_all(&[0x00, 0x00, 0x02, 0x00])?;
    // network
    stdout.write_all(&[0x71, 0x00, 0x00, 0x00])?;

    let from = stdin;
    let mut from = zstd::Decoder::new(from)?;

    let mut buf = [0u8; 512];
    loop {
        from.read_exact(&mut buf)?;
        let actual_length = usize::try_from(u32::from_le_bytes(buf[8..12].try_into()?))?;
        stdout.write_all(&buf[..16 + actual_length])?;
    }
}
