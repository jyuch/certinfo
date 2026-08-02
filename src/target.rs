use std::fmt;

use anyhow::{Context, anyhow, bail};

/// Default port used when the site argument does not carry one.
const DEFAULT_PORT: u16 = 443;

/// A parsed connection target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// The argument as it was given on the command line, kept for the report header.
    pub input: String,
    /// Host name or IP literal, without brackets and without a port.
    pub host: String,
    pub port: u16,
}

impl Target {
    /// Parse a site argument.
    ///
    /// Accepts `example.com`, `example.com:8443`, `https://example.com/path`
    /// and bracketed IPv6 literals such as `[::1]:8443`. The port defaults to
    /// 443. Schemes other than `https` are rejected.
    pub fn parse(input: &str) -> anyhow::Result<Target> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            bail!("site must not be empty");
        }

        let rest = match trimmed.split_once("://") {
            None => trimmed,
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case("https") => rest,
            Some((scheme, _)) => {
                bail!("unsupported scheme `{scheme}://` in `{trimmed}`; only https is supported")
            }
        };

        // Drop path, query and fragment.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();

        // Drop userinfo.
        let authority = match authority.rsplit_once('@') {
            Some((_, host_port)) => host_port,
            None => authority,
        };

        let (host, port) = split_host_port(authority, trimmed)?;

        if host.is_empty() {
            bail!("could not determine host from `{trimmed}`");
        }
        if port == 0 {
            bail!("port must not be 0 in `{trimmed}`");
        }

        Ok(Target {
            input: trimmed.to_string(),
            host,
            port,
        })
    }

    /// `host:port`, with brackets around IPv6 literals.
    pub fn authority(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.authority())
    }
}

fn split_host_port(authority: &str, input: &str) -> anyhow::Result<(String, u16)> {
    if let Some(rest) = authority.strip_prefix('[') {
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| anyhow!("unterminated IPv6 literal in `{input}`"))?;
        let port = match tail {
            "" => DEFAULT_PORT,
            tail => {
                let port = tail
                    .strip_prefix(':')
                    .ok_or_else(|| anyhow!("expected `:port` after `]` in `{input}`"))?;
                parse_port(port, input)?
            }
        };
        return Ok((host.to_string(), port));
    }

    // An unbracketed IPv6 literal is ambiguous with `host:port`, so reject it
    // rather than silently mis-splitting it.
    if authority.matches(':').count() > 1 {
        bail!("ambiguous host `{input}`; wrap IPv6 literals in brackets, e.g. `[::1]:443`");
    }

    match authority.split_once(':') {
        Some((host, port)) => Ok((host.to_string(), parse_port(port, input)?)),
        None => Ok((authority.to_string(), DEFAULT_PORT)),
    }
}

fn parse_port(port: &str, input: &str) -> anyhow::Result<u16> {
    port.parse::<u16>()
        .with_context(|| format!("invalid port `{port}` in `{input}`"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_port(input: &str) -> (String, u16) {
        let target = Target::parse(input).unwrap();
        (target.host, target.port)
    }

    #[test]
    fn bare_host_defaults_to_443() {
        assert_eq!(host_port("example.com"), ("example.com".to_string(), 443));
    }

    #[test]
    fn explicit_port_is_used() {
        assert_eq!(
            host_port("example.com:8443"),
            ("example.com".to_string(), 8443)
        );
    }

    #[test]
    fn https_url_strips_scheme_path_query_and_fragment() {
        assert_eq!(
            host_port("https://example.com/a/b?q=1#frag"),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn https_url_keeps_explicit_port() {
        assert_eq!(
            host_port("https://example.com:8443/x"),
            ("example.com".to_string(), 8443)
        );
    }

    #[test]
    fn scheme_is_case_insensitive() {
        assert_eq!(
            host_port("HTTPS://example.com"),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn userinfo_is_dropped() {
        assert_eq!(
            host_port("https://user:pw@example.com/x"),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn surrounding_whitespace_is_trimmed() {
        assert_eq!(
            host_port("  example.com  "),
            ("example.com".to_string(), 443)
        );
    }

    #[test]
    fn bracketed_ipv6_literal() {
        assert_eq!(
            host_port("https://[2606:4700::1111]:8443/"),
            ("2606:4700::1111".to_string(), 8443)
        );
        assert_eq!(host_port("[::1]"), ("::1".to_string(), 443));
    }

    #[test]
    fn authority_brackets_ipv6() {
        assert_eq!(
            Target::parse("[::1]:9000").unwrap().authority(),
            "[::1]:9000"
        );
        assert_eq!(
            Target::parse("example.com").unwrap().authority(),
            "example.com:443"
        );
    }

    #[test]
    fn input_is_preserved_for_the_report() {
        let target = Target::parse("https://example.com/a").unwrap();
        assert_eq!(target.input, "https://example.com/a");
    }

    #[test]
    fn http_scheme_is_rejected() {
        assert!(Target::parse("http://example.com").is_err());
        assert!(Target::parse("ftp://example.com").is_err());
    }

    #[test]
    fn malformed_input_is_rejected() {
        assert!(Target::parse("   ").is_err());
        assert!(Target::parse("https://").is_err());
        assert!(Target::parse("example.com:notaport").is_err());
        assert!(Target::parse("example.com:99999").is_err());
        assert!(Target::parse("example.com:0").is_err());
        assert!(Target::parse("[::1").is_err());
        assert!(Target::parse("::1").is_err());
    }
}
