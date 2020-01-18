use std::convert::TryInto;
use std::env;
use std::io;
use std::io::{Read, Write};

use digest::Digest;
use failure::Error;
use failure::ResultExt;

use crate::proto::Dec;
use crate::proto::Key;

mod capture;
mod flows;
mod proto;
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
        .subcommand(clap::SubCommand::with_name("decrypt"))
        .subcommand(clap::SubCommand::with_name("efficiency"))
        .subcommand(clap::SubCommand::with_name("make-pcap"))
        .subcommand(
            clap::SubCommand::with_name("flows").arg(
                clap::Arg::with_name("file")
                    .short("f")
                    .multiple(true)
                    .takes_value(true)
                    .required(true),
            ),
        )
        .get_matches();

    let master_key = env::var("PCAP_MASTER_KEY").with_context(|_| "PCAP_MASTER_KEY must be set")?;
    let master_key: Key = sha2::Sha512Trunc256::digest(master_key.as_bytes()).into();

    match args.subcommand() {
        ("capture", Some(args)) => {
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
        ("decrypt", _) => decrypt(master_key.into()),
        ("efficiency", _) => efficiency(master_key.into()),
        ("make-pcap", _) => make_pcap(master_key.into()),
        ("flows", Some(args)) => flows::flows(
            master_key.into(),
            spec::load(std::fs::File::open("spec.json")?).unwrap(),
            args.values_of("file").expect("required arg").collect(),
        ),
        (_, _) => unreachable!("bad subcommand"),
    }
}

fn decrypt(master_key: Key) -> Result<(), Error> {
    let stdin = io::stdin();
    let stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut dec = Dec::new(master_key, stdin)?;
    while let Some(frame) = dec.read_frame()? {
        stdout.write_all(&frame)?;
    }
    Ok(())
}

fn efficiency(master_key: Key) -> Result<(), Error> {
    use std::convert::TryFrom;
    let stdin = io::stdin();
    let stdin = stdin.lock();
    let mut dec = Dec::new(master_key, stdin)?;
    let mut total_bytes = 0;
    let mut frames = 0u64;
    while let Some(Some(frame)) = dec.read_frame().ok() {
        total_bytes += u64::try_from(frame.len())?;
        frames += 1;
    }
    println!("{} {}", frames, total_bytes);
    Ok(())
}

// well, this is getting nuts
fn make_pcap(master_key: Key) -> Result<(), Error> {
    use std::convert::TryFrom;
    let stdin = io::stdin();
    let stdin = stdin.lock();
    let stdout = io::stdout();
    let mut stdout = stdout.lock();
    let mut dec = Dec::new(master_key, stdin)?;
    // magic (le)
    stdout.write_all(&[0xd4, 0xc3, 0xb2, 0xa1])?;
    // version
    stdout.write_all(&[0x02, 0x00, 0x04, 0x00])?;
    // timezone
    stdout.write_all(&[0x00, 0x00, 0x00, 0x00])?;
    // sig figs (always zero)
    stdout.write_all(&[0x00, 0x00, 0x00, 0x00])?;
    // snap len (512?)
    stdout.write_all(&[0x02, 0x00, 0x00, 0x00])?;
    // network
    stdout.write_all(&[0x01, 0x00, 0x00, 0x00])?;

    let from = read::Reader::new(dec);
    let mut from = zstd::Decoder::new(from)?;

    let mut buf = [0u8; 512];
    loop {
        from.read_exact(&mut buf)?;
        let actual_length = usize::try_from(u32::from_le_bytes(buf[8..12].try_into()?))?;
        stdout.write_all(&buf[..16 + actual_length])?;
    }
    Ok(())
}
