use std::path::PathBuf;
use std::process;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(bin_name = "certinfo")]
#[clap(version, about)]
struct Cli {
    /// Target site. Accepts `example.com`, `example.com:8443` or
    /// `https://example.com/path`. The port defaults to 443.
    #[clap(value_name = "SITE")]
    site: String,

    /// Directory the report is written to. Created if it does not exist.
    /// When omitted, the report is printed to stdout.
    #[clap(long, short)]
    output: Option<PathBuf>,
}

fn main() {
    let cli = Cli::parse();

    let code = match certinfo::run::run(&cli.site, cli.output.as_deref()) {
        Ok(Some(path)) => {
            println!("{}", path.display());
            0
        }
        // The report itself was already written to stdout; nothing to add.
        Ok(None) => 0,
        Err(e) => {
            eprintln!("{e:#}");
            1
        }
    };

    process::exit(code);
}
