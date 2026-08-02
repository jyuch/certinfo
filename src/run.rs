use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use chrono::Local;

use crate::report;
use crate::target::Target;
use crate::tls;

/// Timeout applied to the TCP connect and to each subsequent read and write.
const TIMEOUT: Duration = Duration::from_secs(10);

/// Fetch the certificate chain of `site` and write the report into `output_dir`.
///
/// Returns the path of the file that was written.
pub fn run(site: &str, output_dir: &Path) -> anyhow::Result<PathBuf> {
    let target = Target::parse(site)?;

    fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {}", output_dir.display()))?;

    let chain = tls::fetch_chain(&target, TIMEOUT)?;

    let at = Local::now();
    let text = report::render(&target, &chain, &at);
    let path = output_dir.join(report::report_file_name(&at));

    // `create_new` rather than `create`: two runs within the same second would
    // otherwise silently overwrite the earlier report.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| format!("failed to create {}", path.display()))?;
    file.write_all(text.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;

    Ok(path)
}
