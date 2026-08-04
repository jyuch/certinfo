use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use chrono::Local;

use crate::report;
use crate::target::Target;
use crate::tls;

/// Timeout applied to the TCP connect and to each subsequent read and write.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Fetch the certificate chain of `site` and emit the report.
///
/// With `output_dir` the report is written into that directory and the path of
/// the file is returned. Without it the report is printed to stdout and `None`
/// is returned.
pub fn run(site: &str, output_dir: Option<&Path>) -> anyhow::Result<Option<PathBuf>> {
    let target = Target::parse(site)?;

    // Before the handshake, so an unwritable output directory fails fast.
    if let Some(dir) = output_dir {
        fs::create_dir_all(dir)
            .with_context(|| format!("failed to create output directory {}", dir.display()))?;
    }

    let chain = tls::fetch_chain(&target, TIMEOUT)?;

    let at = Local::now();
    let text = report::render(&target, &chain, &at);

    match output_dir {
        Some(dir) => {
            let path = dir.join(report::report_file_name(&at));

            // `create_new` rather than `create`: two runs within the same second
            // would otherwise silently overwrite the earlier report.
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| format!("failed to create {}", path.display()))?;
            file.write_all(text.as_bytes())
                .with_context(|| format!("failed to write {}", path.display()))?;

            Ok(Some(path))
        }
        None => {
            // `write_all` rather than `print!`, which panics on a write error.
            let mut out = io::stdout().lock();
            out.write_all(text.as_bytes())
                .context("failed to write the report to stdout")?;
            // `main` ends in `process::exit`, which skips the flush std would
            // otherwise do when `main` returns.
            out.flush().context("failed to flush stdout")?;

            Ok(None)
        }
    }
}
