use std::fmt::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Local};
use sha2::{Digest, Sha256};
use x509_parser::der_parser::oid::Oid;
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::target::Target;
use crate::tls::FetchedChain;

/// Width of the label column, so every value starts at the same offset.
const LABEL_WIDTH: usize = 19;
const RULE: &str =
    "================================================================================";

/// Name of the report file for the given instant, `yyyymmddhhmmss.txt`.
pub fn report_file_name(at: &DateTime<Local>) -> String {
    format!("{}.txt", at.format("%Y%m%d%H%M%S"))
}

/// Render the whole report.
pub fn render(target: &Target, chain: &FetchedChain, at: &DateTime<Local>) -> String {
    let parsed: Vec<Result<X509Certificate<'_>, String>> = chain
        .certs
        .iter()
        .map(|der| {
            X509Certificate::from_der(der.as_ref())
                .map(|(_, cert)| cert)
                .map_err(|e| e.to_string())
        })
        .collect();

    let mut out = String::new();
    render_header(&mut out, target, chain, at);
    for (index, cert) in parsed.iter().enumerate() {
        out.push('\n');
        match cert {
            Ok(cert) => render_certificate(
                &mut out,
                index,
                cert,
                chain.certs[index].as_ref(),
                parsed.get(index + 1).and_then(|next| next.as_ref().ok()),
                at.timestamp(),
            ),
            Err(e) => {
                out.push_str(RULE);
                let _ = writeln!(out, "\n[{index}] Unparsable certificate\n{RULE}");
                field(&mut out, "Parse error", e);
                field(
                    &mut out,
                    "SHA-256 fingerprint",
                    &fingerprint_sha256(chain.certs[index].as_ref()),
                );
            }
        }
    }
    out
}

fn render_header(out: &mut String, target: &Target, chain: &FetchedChain, at: &DateTime<Local>) {
    let _ = writeln!(out, "certinfo report\n{RULE}");
    field(out, "Target", &target.input);
    field(
        out,
        "Endpoint",
        &format!("{} -> {}", target.authority(), chain.peer_addr),
    );
    field(
        out,
        "Retrieved at",
        &at.format("%Y-%m-%d %H:%M:%S %:z").to_string(),
    );
    field(
        out,
        "TLS version",
        &chain.protocol.map_or_else(
            || "(unknown)".to_string(),
            // Debug renders `TLSv1_3`; the dotted form is what everyone writes.
            |v| format!("{v:?}").replace('_', "."),
        ),
    );
    field(
        out,
        "Cipher suite",
        &chain
            .cipher_suite
            .map_or_else(|| "(unknown)".to_string(), |c| format!("{:?}", c.suite())),
    );
    field(out, "Chain length", &chain.certs.len().to_string());
    out.push_str(
        "\nNote: the trust chain was not validated. This report describes the\n\
         certificates exactly as the server presented them.\n",
    );
}

fn render_certificate(
    out: &mut String,
    index: usize,
    cert: &X509Certificate<'_>,
    der: &[u8],
    issuer_cert: Option<&X509Certificate<'_>>,
    now: i64,
) {
    let self_signed = is_self_signed(cert);
    let role = if index == 0 {
        "End-entity certificate"
    } else if self_signed {
        "Root certificate"
    } else {
        "Intermediate certificate"
    };

    out.push_str(RULE);
    let _ = writeln!(out, "\n[{index}] {role}\n{RULE}");

    field(out, "Version", &(cert.version().0 + 1).to_string());
    field(out, "Serial number", &cert.raw_serial_as_string());
    field(out, "Subject", &cert.subject().to_string());
    field(out, "Issuer", &cert.issuer().to_string());
    field(out, "Not before", &cert.validity().not_before.to_string());
    field(out, "Not after", &cert.validity().not_after.to_string());
    field(out, "Status", &validity_status(cert.validity(), now));
    field(
        out,
        "Signature algorithm",
        &format_oid(&cert.signature_algorithm.algorithm),
    );
    field(out, "Public key", &public_key_summary(cert.public_key()));
    field(out, "SHA-256 fingerprint", &fingerprint_sha256(der));
    field(out, "Self-signed", if self_signed { "yes" } else { "no" });
    field(
        out,
        "Signed by next",
        &match issuer_cert {
            None => "(issuer not sent by the server)".to_string(),
            Some(issuer) => match cert.verify_signature(Some(issuer.public_key())) {
                Ok(()) => format!("yes, by [{}]", index + 1),
                Err(e) => format!("no, [{}] did not sign this certificate ({e})", index + 1),
            },
        },
    );
    field(
        out,
        "Basic constraints",
        &match cert.basic_constraints() {
            Ok(Some(ext)) => match ext.value.path_len_constraint {
                Some(len) => format!("CA={}, path length {len}", ext.value.ca),
                None => format!("CA={}", ext.value.ca),
            },
            Ok(None) => "(absent)".to_string(),
            Err(e) => format!("(unparsable: {e})"),
        },
    );
    field(
        out,
        "Key usage",
        &match cert.key_usage() {
            Ok(Some(ext)) => ext.value.to_string(),
            Ok(None) => "(absent)".to_string(),
            Err(e) => format!("(unparsable: {e})"),
        },
    );
    field(
        out,
        "Extended key usage",
        &match cert.extended_key_usage() {
            Ok(Some(ext)) => extended_key_usage_to_string(ext.value),
            Ok(None) => "(absent)".to_string(),
            Err(e) => format!("(unparsable: {e})"),
        },
    );

    match cert.subject_alternative_name() {
        Ok(Some(ext)) if !ext.value.general_names.is_empty() => {
            let _ = writeln!(out, "{:<LABEL_WIDTH$}:", "Subject alt names");
            for name in &ext.value.general_names {
                let _ = writeln!(out, "  {}", general_name_to_string(name));
            }
        }
        Ok(_) => field(out, "Subject alt names", "(absent)"),
        Err(e) => field(out, "Subject alt names", &format!("(unparsable: {e})")),
    }
}

fn field(out: &mut String, label: &str, value: &str) {
    let _ = writeln!(out, "{label:<LABEL_WIDTH$}: {value}");
}

/// A certificate is self-signed when its own public key verifies its signature.
/// The subject/issuer comparison alone is not enough, since either can be forged.
fn is_self_signed(cert: &X509Certificate<'_>) -> bool {
    cert.subject() == cert.issuer() && cert.verify_signature(None).is_ok()
}

fn validity_status(validity: &Validity, now: i64) -> String {
    let not_before = validity.not_before.timestamp();
    let not_after = validity.not_after.timestamp();

    if now < not_before {
        format!("not yet valid (starts in {} days)", days(not_before - now))
    } else if now > not_after {
        format!("EXPIRED ({} days ago)", days(now - not_after))
    } else {
        format!("valid ({} days remaining)", days(not_after - now))
    }
}

fn days(seconds: i64) -> i64 {
    seconds / 86_400
}

fn fingerprint_sha256(der: &[u8]) -> String {
    Sha256::digest(der)
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn format_oid(oid: &Oid<'_>) -> String {
    match oid2sn(oid, oid_registry()) {
        Ok(name) => format!("{name} ({oid})"),
        Err(_) => oid.to_string(),
    }
}

fn public_key_summary(spki: &SubjectPublicKeyInfo<'_>) -> String {
    let algorithm = format_oid(&spki.algorithm.algorithm);
    match spki.parsed() {
        Ok(PublicKey::Unknown(_)) => algorithm,
        Ok(key) => format!("{algorithm}, {} bits", key.key_size()),
        Err(e) => format!("{algorithm} (unparsable: {e})"),
    }
}

fn extended_key_usage_to_string(eku: &ExtendedKeyUsage<'_>) -> String {
    let mut usages = Vec::new();
    if eku.any {
        usages.push("Any".to_string());
    }
    if eku.server_auth {
        usages.push("TLS Web Server Authentication".to_string());
    }
    if eku.client_auth {
        usages.push("TLS Web Client Authentication".to_string());
    }
    if eku.code_signing {
        usages.push("Code Signing".to_string());
    }
    if eku.email_protection {
        usages.push("E-mail Protection".to_string());
    }
    if eku.time_stamping {
        usages.push("Time Stamping".to_string());
    }
    if eku.ocsp_signing {
        usages.push("OCSP Signing".to_string());
    }
    usages.extend(eku.other.iter().map(|oid| oid.to_string()));

    if usages.is_empty() {
        "(none)".to_string()
    } else {
        usages.join(", ")
    }
}

fn general_name_to_string(name: &GeneralName<'_>) -> String {
    match name {
        GeneralName::DNSName(s) => format!("DNS:{s}"),
        GeneralName::RFC822Name(s) => format!("email:{s}"),
        GeneralName::URI(s) => format!("URI:{s}"),
        GeneralName::DirectoryName(n) => format!("DirName:{n}"),
        GeneralName::RegisteredID(oid) => format!("RID:{oid}"),
        GeneralName::IPAddress(bytes) => match <[u8; 4]>::try_from(*bytes) {
            Ok(v4) => format!("IP:{}", Ipv4Addr::from(v4)),
            Err(_) => match <[u8; 16]>::try_from(*bytes) {
                Ok(v6) => format!("IP:{}", Ipv6Addr::from(v6)),
                Err(_) => format!("IP:<invalid, {} bytes>", bytes.len()),
            },
        },
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn file_name_is_yyyymmddhhmmss_txt() {
        let at = Local.with_ymd_and_hms(2026, 8, 2, 17, 41, 3).unwrap();
        assert_eq!(report_file_name(&at), "20260802174103.txt");
    }

    #[test]
    fn file_name_zero_pads_every_field() {
        let at = Local.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(report_file_name(&at), "20260102030405.txt");
        assert_eq!(report_file_name(&at).len(), "yyyymmddhhmmss.txt".len());
    }

    #[test]
    fn fingerprint_is_uppercase_colon_separated_sha256() {
        // SHA-256 of the empty input.
        let fingerprint = fingerprint_sha256(b"");
        assert_eq!(
            fingerprint,
            "E3:B0:C4:42:98:FC:1C:14:9A:FB:F4:C8:99:6F:B9:24:\
             27:AE:41:E4:64:9B:93:4C:A4:95:99:1B:78:52:B8:55"
                .replace(' ', "")
        );
        assert_eq!(fingerprint.split(':').count(), 32);
    }

    #[test]
    fn general_names_are_prefixed_by_kind() {
        assert_eq!(
            general_name_to_string(&GeneralName::DNSName("a.example")),
            "DNS:a.example"
        );
        assert_eq!(
            general_name_to_string(&GeneralName::IPAddress(&[127, 0, 0, 1])),
            "IP:127.0.0.1"
        );
        assert_eq!(
            general_name_to_string(&GeneralName::IPAddress(&[0u8; 16])),
            "IP:::"
        );
        assert_eq!(
            general_name_to_string(&GeneralName::IPAddress(&[1, 2, 3])),
            "IP:<invalid, 3 bytes>"
        );
    }

    #[test]
    fn extended_key_usage_lists_every_flag_set() {
        let eku = ExtendedKeyUsage {
            any: false,
            server_auth: true,
            client_auth: true,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocsp_signing: false,
            other: Vec::new(),
        };
        assert_eq!(
            extended_key_usage_to_string(&eku),
            "TLS Web Server Authentication, TLS Web Client Authentication"
        );

        let empty = ExtendedKeyUsage {
            any: false,
            server_auth: false,
            client_auth: false,
            code_signing: false,
            email_protection: false,
            time_stamping: false,
            ocsp_signing: false,
            other: Vec::new(),
        };
        assert_eq!(extended_key_usage_to_string(&empty), "(none)");
    }

    #[test]
    fn days_truncates_toward_zero() {
        assert_eq!(days(86_400), 1);
        assert_eq!(days(86_399), 0);
        assert_eq!(days(86_400 * 30 + 1), 30);
    }

    #[test]
    fn validity_status_covers_all_three_windows() {
        let validity = Validity {
            not_before: ASN1Time::from_timestamp(1_000_000).unwrap(),
            not_after: ASN1Time::from_timestamp(1_000_000 + 86_400 * 10).unwrap(),
        };
        assert!(
            validity_status(&validity, 999_999).starts_with("not yet valid (starts in 0 days)")
        );
        assert_eq!(
            validity_status(&validity, 1_000_000 + 86_400 * 3),
            "valid (7 days remaining)"
        );
        assert_eq!(
            validity_status(&validity, 1_000_000 + 86_400 * 12),
            "EXPIRED (2 days ago)"
        );
    }

    /// Build a self-signed certificate with the given validity window and SANs.
    fn generate(names: &[&str], not_before_days: i64, not_after_days: i64) -> Vec<u8> {
        use rcgen::{CertificateParams, KeyPair};

        let mut params =
            CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>())
                .unwrap();
        // `::time`, because the x509-parser prelude also brings in a `time` module.
        let epoch = ::time::OffsetDateTime::UNIX_EPOCH;
        params.not_before = epoch + ::time::Duration::days(not_before_days);
        params.not_after = epoch + ::time::Duration::days(not_after_days);

        let key_pair = KeyPair::generate().unwrap();
        params.self_signed(&key_pair).unwrap().der().to_vec()
    }

    #[test]
    fn detects_a_self_signed_certificate() {
        let der = generate(&["test.example"], 0, 36_500);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();

        assert!(is_self_signed(&cert));
        assert_eq!(cert.version().0 + 1, 3);
        assert!(cert.subject() == cert.issuer());
    }

    #[test]
    fn renders_subject_alt_names_one_per_line() {
        let der = generate(&["test.example", "*.test.example"], 0, 36_500);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();

        let mut out = String::new();
        render_certificate(&mut out, 0, &cert, &der, None, 86_400);

        assert!(out.contains("[0] End-entity certificate"));
        assert!(out.contains("  DNS:test.example\n"));
        assert!(out.contains("  DNS:*.test.example\n"));
        assert!(out.contains("Self-signed        : yes"));
        assert!(out.contains("Signed by next     : (issuer not sent by the server)"));
        assert!(out.contains("SHA-256 fingerprint: "));
        assert!(out.contains(&fingerprint_sha256(&der)));
    }

    #[test]
    fn renders_expired_certificates_as_expired() {
        // Valid for days 0..10 of the epoch, inspected on day 12.
        let der = generate(&["old.example"], 0, 10);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();

        let mut out = String::new();
        render_certificate(&mut out, 0, &cert, &der, None, 86_400 * 12);

        assert!(
            out.contains("Status             : EXPIRED (2 days ago)"),
            "{out}"
        );
    }

    #[test]
    fn reports_whether_the_next_certificate_signed_this_one() {
        let leaf_der = generate(&["leaf.example"], 0, 36_500);
        let other_der = generate(&["other.example"], 0, 36_500);
        let (_, leaf) = X509Certificate::from_der(&leaf_der).unwrap();
        let (_, other) = X509Certificate::from_der(&other_der).unwrap();

        let mut out = String::new();
        render_certificate(&mut out, 0, &leaf, &leaf_der, Some(&other), 86_400);

        assert!(
            out.contains("Signed by next     : no, [1] did not sign"),
            "{out}"
        );
    }
}
