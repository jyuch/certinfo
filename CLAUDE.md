# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

certinfo is a command line tool written in Rust that inspects HTTPS server certificates. It performs a TLS handshake against a target site, captures the certificate chain the server presents, and writes a human readable report to `<output-dir>/yyyymmddhhmmss.txt`.

The defining design decision is that **trust chain validation is skipped on purpose**. The tool exists to diagnose broken certificates, so expired, self-signed and wrong-host chains must still produce a full report. Handshake signature verification is still performed, so the report always describes a chain the peer holds the private key for — only the path-to-a-trusted-root check is omitted.

## Build and Development Commands

```bash
# Build
cargo build
cargo build --release    # LTO + single codegen unit + strip

# Test
cargo test
cargo test test_name     # Run a single test by name

# Lint
cargo clippy --all-targets -- -D warnings
cargo fmt --check

# Run
cargo run -- --site https://www.rust-lang.org --output ./reports
```

The project uses Rust edition 2024. Windows MSVC builds use static CRT linking (configured in `.cargo/config.toml`), so the release binary depends only on OS DLLs.

## Architecture

### Data Flow

1. `Target::parse()` turns the `--site` argument into a host and port
2. `fs::create_dir_all()` ensures the output directory exists
3. `tls::fetch_chain()` resolves the host, connects, completes the TLS handshake with an accept-anything certificate verifier, and copies out the peer certificates plus the negotiated protocol and cipher suite
4. `report::render()` parses each DER certificate and formats the whole report as a `String`
5. `report::report_file_name()` derives the file name from the current local time
6. The report is written with `create_new`, so a same-second second run fails instead of overwriting

### Core Components

**`src/target.rs`** — Site argument parsing
- `Target { input, host, port }`; `input` is kept verbatim for the report header
- Accepts `example.com`, `example.com:8443` and `https://example.com/path`; strips path, query, fragment and userinfo; defaults the port to 443
- Rejects non-`https` schemes, port 0, and unbracketed IPv6 literals (ambiguous with `host:port`)
- `authority()` re-brackets IPv6 hosts for display and for `to_socket_addrs()`

**`src/tls.rs`** — TLS connection and chain extraction
- `fetch_chain()` returns `FetchedChain { certs, protocol, cipher_suite, peer_addr }`
- `AcceptAnyServerCert`: a `rustls::client::danger::ServerCertVerifier` whose `verify_server_cert()` always succeeds, but whose `verify_tls12_signature()` / `verify_tls13_signature()` delegate to the real `rustls::crypto` implementations. Do not weaken the signature methods — doing so would let a MITM substitute a chain the real server never sent.
- Synchronous `std::net::TcpStream`; `ClientConnection::complete_io()` drives the handshake, after which `peer_certificates()` is populated. No HTTP request is ever sent.
- Timeouts come from `TcpStream::connect_timeout` plus read/write timeouts

**`src/report.rs`** — Certificate formatting
- `render()` builds the whole report; `render_certificate()` emits one section per certificate
- `is_self_signed()` checks that the certificate verifies against **its own** public key, not just that subject equals issuer, because a DN can be forged
- `validity_status()` and `days()` take the current time as an `i64` parameter rather than reading the clock, which is what makes them testable
- Fixed 19-character label column keeps the output greppable and diffable

**`src/run.rs`** — Wires the above together and writes the file. Returns the written path.

**`src/main.rs`** — CLI (clap derive), maps `anyhow::Result` to an exit code via `eprintln!("{e:#}")` + `process::exit(1)`.

### Key Dependencies

- `rustls`: TLS client. Pinned to `default-features = false` + the `ring` provider rather than the default `aws-lc-rs`, because `aws-lc-sys` needs cmake and NASM at build time, which would break the "`cargo build --release` produces a self-contained exe with no external tooling" property. `x509-parser`'s `verify` feature also pulls `ring`, so there is exactly one crypto backend in the tree.
- `x509-parser` (with `verify`): DER parsing and signature verification
- `sha2`: SHA-256 fingerprints
- `chrono`: local-time file names and the report timestamp
- `clap` (derive): CLI
- `anyhow`: errors, with `with_context()` naming the concrete host or path at every fallible boundary

`rustls-pki-types` is intentionally **not** a direct dependency; use `rustls::pki_types::*`, which re-exports it.

### Project Structure

The crate is split into a library (`src/lib.rs` re-exports all modules) and a binary (`src/main.rs`). Tests live in `#[cfg(test)]` modules within each source file.

Test certificates are generated at test time with `rcgen` (a dev-dependency) rather than committed as fixtures, so no test can rot when a real certificate expires. `generate()` in `src/report.rs` takes explicit not-before/not-after offsets from the Unix epoch, which is how the expired-certificate case is covered deterministically.

## Important Notes

- `X509Certificate<'a>` borrows the DER buffer it was parsed from. Parse inside the render loop; never store a parsed certificate in a struct alongside its bytes.
- `x509_parser::prelude::*` brings a `time` module into scope that shadows the `time` crate. In test code use `::time::` with a leading `::`.
- Network-dependent code (`src/tls.rs`) has no unit tests on purpose — mocking a handshake would test the mock. Verify it by running against `badssl.com` subdomains: `expired`, `self-signed`, `wrong.host`, `ecc256`. Those hosts are occasionally slow and can time out; retry before assuming a regression.
- The report file name uses local time with one second of resolution. `create_new` turns a same-second collision into an error rather than a silent overwrite; do not "fix" this by adding a counter or random suffix, which would violate the `yyyymmddhhmmss.txt` format.
- The release profile enables aggressive optimization: LTO, single codegen unit, binary stripping
