certinfo
===

HTTPS server certificate reporter

## Overview

`certinfo` connects to an HTTPS site, takes the certificate chain the server presents during the TLS
handshake, and writes a human readable report to a text file named `yyyymmddhhmmss.txt`.

The trust chain is deliberately **not** validated. Expired, self-signed and wrong-host certificates
are reported just like valid ones, which is what makes the tool useful for diagnosing a broken site.
The handshake signature is still verified, so the report always describes a chain whose private key
the peer actually holds.

## Supported Platforms

Tested on Windows. Nothing in the implementation is platform specific, so it should work on Linux and
macOS as well. The Windows MSVC build links the CRT statically and depends only on OS DLLs, so the
resulting `certinfo.exe` is self contained.

## Usage

| Argument          | Description                                             |
|:------------------|:--------------------------------------------------------|
| `--site <SITE>`   | Target site. `-s` for short.                             |
| `--output <DIR>`  | Directory the report is written to. `-o` for short.      |

The site argument accepts three forms. The port defaults to 443 when it is omitted.

| Form                          | Resolves to           |
|:------------------------------|:----------------------|
| `example.com`                 | `example.com:443`     |
| `example.com:8443`            | `example.com:8443`    |
| `https://example.com/path`    | `example.com:443`     |

IPv6 literals must be bracketed, for example `[2606:4700::1111]:8443`. Schemes other than `https` are
rejected. The output directory is created if it does not exist.

``` powershell
.\certinfo.exe --site https://www.rust-lang.org --output .\reports
```

``` powershell
.\certinfo.exe -s expired.badssl.com -o .\reports
```

On success the path of the report is printed to stdout and the exit code is 0. On failure the reason
is printed to stderr and the exit code is 1.

## Output

``` text
certinfo report
================================================================================
Target             : https://www.rust-lang.org
Endpoint           : www.rust-lang.org:443 -> 185.199.109.153:443
Retrieved at       : 2026-08-02 18:00:38 +09:00
TLS version        : TLSv1.3
Cipher suite       : TLS13_AES_128_GCM_SHA256
Chain length       : 3

Note: the trust chain was not validated. This report describes the
certificates exactly as the server presented them.

================================================================================
[0] End-entity certificate
================================================================================
Version            : 3
Serial number      : 05:67:d3:62:1a:18:c5:30:c4:0d:fc:b4:42:f9:78:8a:3a:e0
Subject            : CN=rust-lang.org
Issuer             : C=US, O=Let's Encrypt, CN=YR2
Not before         : Jul 23 18:26:49 2026 +00:00
Not after          : Oct 21 18:26:48 2026 +00:00
Status             : valid (80 days remaining)
Signature algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11)
Public key         : rsaEncryption (1.2.840.113549.1.1.1), 2048 bits
SHA-256 fingerprint: 95:5F:3E:1F:27:6A:F0:15:DF:07:E0:65:60:EC:F2:45:5F:83:9D:41:CC:D8:08:50:DB:F5:C2:37:05:25:14:E8
Self-signed        : no
Signed by next     : yes, by [1]
Basic constraints  : CA=false
Key usage          : Digital Signature, Key Encipherment
Extended key usage : TLS Web Server Authentication
Subject alt names  :
  DNS:rust-lang.org
  DNS:www.rust-lang.org

... one section per certificate in the chain ...
```

`Status` reports the certificate's own validity window, so an expired site reads
`EXPIRED (4129 days ago)`. `Signed by next` states whether the following certificate in the chain
actually signed this one.

## Notes

The report file name has one second of resolution and uses local time. Two runs within the same
second would collide, so the second run fails with an "already exists" error rather than silently
overwriting the earlier report.
