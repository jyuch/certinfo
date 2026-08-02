use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ProtocolVersion, SignatureScheme,
    SupportedCipherSuite,
};

/// The certificate chain a server presented, plus the handshake parameters.
pub struct FetchedChain {
    /// Leaf first, then whatever intermediates the server sent.
    pub certs: Vec<CertificateDer<'static>>,
    pub protocol: Option<ProtocolVersion>,
    pub cipher_suite: Option<SupportedCipherSuite>,
    pub peer_addr: SocketAddr,
}

/// Connect to `target` and return the certificate chain it presents.
///
/// Trust-chain validation is deliberately skipped so that expired, self-signed
/// or wrong-host certificates can still be inspected. The handshake signature
/// is still verified, which proves the peer holds the private key for the leaf
/// we are about to report on.
pub fn fetch_chain(
    target: &crate::target::Target,
    timeout: Duration,
) -> anyhow::Result<FetchedChain> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("failed to configure TLS protocol versions")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert {
            provider: provider.clone(),
        }))
        .with_no_client_auth();

    let server_name = ServerName::try_from(target.host.clone())
        .with_context(|| format!("invalid server name `{}`", target.host))?;

    let addr = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve `{}`", target.authority()))?
        .next()
        .ok_or_else(|| anyhow!("`{}` resolved to no addresses", target.authority()))?;

    let mut sock = TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("failed to connect to {addr}"))?;
    sock.set_read_timeout(Some(timeout))?;
    sock.set_write_timeout(Some(timeout))?;
    sock.set_nodelay(true)?;

    let mut conn = ClientConnection::new(Arc::new(config), server_name)
        .context("failed to start a TLS client connection")?;
    conn.complete_io(&mut sock)
        .with_context(|| format!("TLS handshake with {} failed", target.authority()))?;

    let certs: Vec<CertificateDer<'static>> = conn
        .peer_certificates()
        .ok_or_else(|| anyhow!("{} presented no certificates", target.authority()))?
        .iter()
        .map(|cert| cert.clone().into_owned())
        .collect();
    if certs.is_empty() {
        bail!(
            "{} presented an empty certificate chain",
            target.authority()
        );
    }

    let protocol = conn.protocol_version();
    let cipher_suite = conn.negotiated_cipher_suite();

    // Close politely; a failure here does not invalidate what we already read.
    conn.send_close_notify();
    let _ = conn.complete_io(&mut sock);

    Ok(FetchedChain {
        certs,
        protocol,
        cipher_suite,
        peer_addr: addr,
    })
}

/// A verifier that accepts every certificate chain.
///
/// Only trust-chain validation is skipped. Handshake signatures are still
/// checked against the crypto provider's algorithms, so a man in the middle
/// cannot make us report a chain the real server never presented.
#[derive(Debug)]
struct AcceptAnyServerCert {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
