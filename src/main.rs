use std::path::PathBuf;
use std::process;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(bin_name = "certinfo")]
#[clap(version, about)]
struct Cli {
    /// Target site. Accepts `example.com`, `example.com:8443` or
    /// `https://example.com/path`. The port defaults to 443.
    #[clap(long, short)]
    site: String,

    /// Directory the report is written to. Created if it does not exist.
    #[clap(long, short)]
    output: PathBuf,
}

fn main() {
    let cli = Cli::parse();

    let code = match certinfo::run::run(&cli.site, &cli.output) {
        Ok(path) => {
            println!("{}", path.display());
            0
        }
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    };

    process::exit(code);
}
