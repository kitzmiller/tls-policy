
# TLS Policy

We have three supported configurations: **Secure**, **Deprecated**, and **Legacy**. Secure is the modern configuration which aims to support the majority of supported software and operating systems. Deprecated still meets the definition of PCI compliance by not allowing any vulnerable configurations but does still support deprecated configurations for older devices. Legacy must only be used when there is a business case requiring interoperability with older devices (e.g. Point-of-Sale registers). While many options are available for legacy configurations it is advised to only enable those cipher suites which are specifically required.

## Configuration examples

Rather than try to enumerate the cipher suites that we allow, [like Mozilla does](https://ssl-config.mozilla.org/), instead we specify what we do not allow, [like GnuTLS recommends](https://www.gnutls.org/manual/html_node/Priority-Strings.html#tab_003aprio_002dkeywords). In doing so we again place trust in the maintainers of our OS's but we gain the advantage of accepting new technologies right away. Whenever a cipher suite needs to be disabled there is usually a lot of support and attention given to the problem making that an easier time to perform updates. Also, the result is much more readable.

## Secure

### OpenSSL

    ALL:!aNULL:!PSK:!kRSA:!SRP:!DH:!kECDH:!eNULL:!ARIA:!CAMELLIA:!IDEA:!SEED:!RC4:!3DES:!EXP:!MD5:!SHA1:!SHA256:!SHA384:+AES128:+AES256

### Apache2

    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ALL:!aNULL:!PSK:!kRSA:!SRP:!DH:!kECDH:!eNULL:!ARIA:!CAMELLIA:!IDEA:!SEED:!RC4:!3DES:!EXP:!MD5:!SHA1:!SHA256:!SHA384:+AES128:+AES256

### GnuTLS

    NORMAL:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:-RSA:-DHE-RSA:-SHA1

### Nginx

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ALL:!aNULL:!PSK:!kRSA:!SRP:!DH:!kECDH:!eNULL:!ARIA:!CAMELLIA:!IDEA:!SEED:!RC4:!3DES:!EXP:!MD5:!SHA1:!SHA256:!SHA384:+AES128:+AES256;

## Deprecated

### OpenSSL

    ALL:!aNULL:!PSK:!kRSA:!DH:!kECDH:!eNULL:!IDEA:!RC4:!3DES:!EXP:!MD5:+AES128:+AES256

### Apache2

    SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
    SSLCipherSuite ALL:!aNULL:!PSK:!kRSA:!DH:!kECDH:!eNULL:!IDEA:!RC4:!3DES:!EXP:!MD5:+AES128:+AES256

### GnuTLS

    NORMAL:-VERS-TLS1.0:-VERS-TLS1.1:-VERS-DTLS1.0:-SHA1

### Nginx

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ALL:!aNULL:!PSK:!kRSA:!DH:!kECDH:!eNULL:!IDEA:!RC4:!3DES:!EXP:!MD5:+AES128:+AES256;

## Legacy

### OpenSSL

    ALL:!aNULL:!eNULL:!ARIA:!IDEA:!RC4:!3DES:!EXP:!MD5:+AES128:+AES256

### Apache2

    SSLProtocol all -SSLv3
    SSLCipherSuite ALL:!aNULL:!eNULL:!ARIA:!IDEA:!RC4:!3DES:!EXP:!MD5:+AES128:+AES256

### GnuTLS

    NORMAL

### Nginx

    ssl_protocols TLSv1.0 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers ALL:!aNULL:!eNULL:!ARIA:!IDEA:!RC4:!3DES:!EXP:!MD5:+AES128:+AES256;

## Protocols

| Protocol | Secure | Deprecated | Legacy | Notes |
| -- | :--: | :--: | :--: | -- |
| [SSLv2](https://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html) | ❌ | ❌ | ❌ | Disabled in [Chrome](https://security.googleblog.com/2018/10/modernizing-transport-security.html), [Firefox](https://support.mozilla.org/en-US/kb/secure-connection-failed-firefox-did-not-connect), [IE11 / Edge](https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11/), [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web). Prohibited by [RFC6176](https://www.rfc-editor.org/rfc/rfc6176). |
| [SSLv3](https://www.rfc-editor.org/rfc/rfc6101.html) | ❌ | ❌ | ❌ |  Disabled in [Chrome](https://security.googleblog.com/2018/10/modernizing-transport-security.html), [Firefox](https://support.mozilla.org/en-US/kb/secure-connection-failed-firefox-did-not-connect), [IE11 / Edge](https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11/), [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web). Prohibited by [RFC7568](https://www.rfc-editor.org/rfc/rfc7568.html). |
| [TLS 1.0](https://www.rfc-editor.org/rfc/rfc2246.html) | ❌ | ❌ | ✅ | Disabled in [Chrome](https://security.googleblog.com/2018/10/modernizing-transport-security.html), [Firefox](https://support.mozilla.org/en-US/kb/secure-connection-failed-firefox-did-not-connect), [IE11 / Edge](https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11/), [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web). Prohibited by [RFC8996](https://www.rfc-editor.org/rfc/rfc8996.html). |
| [TLS 1.1](https://www.rfc-editor.org/rfc/rfc4346.html) | ❌ | ❌ | ✅ | Disabled in [Chrome](https://security.googleblog.com/2018/10/modernizing-transport-security.html), [Firefox](https://support.mozilla.org/en-US/kb/secure-connection-failed-firefox-did-not-connect), [IE11 / Edge](https://blogs.windows.com/msedgedev/2018/10/15/modernizing-tls-edge-ie11/), [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web). Prohibited by [RFC8996](https://www.rfc-editor.org/rfc/rfc8996.html). |
| [TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246) | ✅ | ✅ | ✅ | |
| [TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) | ✅ | ✅ | ✅ | |

**Note:** See also: [Solving the TLS 1.0 Problem](https://docs.microsoft.com/en-us/security/engineering/solving-tls1-problem), [MSA3009008](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2015/3009008).

## Authentication

| Auth Mech | Secure | Deprecated | Legacy | Notes |
| -- | :--: | :--: | :--: | -- |
| NULL | ❌ | ❌ | ❌ | Atypical. Vulnerable to MitM attacks. |
| PSK | ❌ | ❌ | ✅ | Atypical. |
| DSS | ❌ | ❌ | ✅ | Atypical. |
| [SRP](https://www.rfc-editor.org/rfc/rfc2945.html) | ❌ | ✅ | ✅ | Atypical, CBC-mode HMACs only. |
| RSA | ✅ | ✅ | ✅ | Requires an RSA certificate (typical). Not to be confused with KxRSA. |
| [ECDSA](https://www.rfc-editor.org/rfc/rfc8422) | ✅ | ✅ | ✅ | Requires a DSA certificate. |

## Certificates

| Certificate | Secure | Deprecated | Legacy | Notes |
| -- | :--: | :--: | :--: | -- |
| RSA | ✅ | ✅ | ✅ | Must be at least 2048-bits. ([Chrome](https://archive.cabforum.org/pipermail/public/2013-September/002233.html), [Firefox](https://wiki.mozilla.org/CA:MD5and1024), [Safari](https://support.apple.com/en-us/HT210176))|
| DSS | ✅ | ✅ | ✅ | Must be at least 256-bits. ([Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web)) |

**Note:** Certificate lifetimes must not exceed [398 days](https://cabforum.org/2017/02/24/ballot-185-limiting-lifetime-certificates/).

**Note:** Certificates must not be signed with SHA1. [IETF](https://www.ietf.org/archive/id/draft-ietf-tls-md5-sha1-deprecate-09.html), [Chrome](https://security.googleblog.com/2014/09/gradually-sunsetting-sha-1.html), [Firefox](https://blog.mozilla.org/security/2015/10/20/continuing-to-phase-out-sha-1-certificates/), [Safari](https://support.apple.com/en-us/HT210176).

## Key Exchange

| Kx | Secure | Deprecated | Legacy | Notes |
| -- | :--: | :--: | :--: | -- |
| PSK | ❌ | ❌ | ✅ | Atypical. Also RSAPSK, DHEPSK, and ECDHEPSK. |
| [SRP](https://www.rfc-editor.org/rfc/rfc2945.html) | ❌ | ✅ | ✅ | Atypical, CBC-mode HMACs only. Disabled in [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web). |
| RSA | ❌ | ✅ | ✅ | Deprecated in [draft-ietf-tls-deprecate-obsolete-kex](https://www.ietf.org/id/draft-ietf-tls-deprecate-obsolete-kex-00.html), no PFS. Disabled in [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web). |
| DH | ❌ | ✅ | ✅ | Deprecated in [draft-ietf-tls-deprecate-obsolete-kex](https://www.ietf.org/id/draft-ietf-tls-deprecate-obsolete-kex-00.html), no PFS. Disabled in [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web). |
| DHE | ❌ | ✅ | ✅ | Parameter bit-length must be [at least 2048 bits](https://weakdh.org/). Some TLS implementations improperly implement DH parameter re-use which [weakens](https://raccoon-attack.com/) the cipher. Disabled in [Chrome](https://chromestatus.com/feature/5128908798164992), [Firefox](https://www.mozilla.org/en-US/firefox/78.0/releasenotes/), [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web). |
| [ECDH](https://www.rfc-editor.org/rfc/rfc8422) | ❌ | ✅ | ✅ | Discouraged in [draft-ietf-tls-deprecate-obsolete-kex](https://www.ietf.org/id/draft-ietf-tls-deprecate-obsolete-kex-00.html), no PFS. Disabled in [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web).|
| [ECDHE](https://www.rfc-editor.org/rfc/rfc8422) | ✅ | ✅ | ✅ | 

**Note:** For any server using a configuration not supporting [Perfect Forward Secrecy](https://en.wikipedia.org/wiki/Forward_secrecy) (PFS) it is critical that the same certificate (e.g. a wildcard certificate) not be used on any other system. See [DROWN](https://drownattack.com/) and [Heartbleed](https://heartbleed.com).

**Note:** [IISCrypto](https://www.nartac.com/Products/IISCrypto/) mentions "PKCS". Assuming that is [PKCS #3](https://www.teletrust.de/fileadmin/files/oid/oid_pkcs-3v1-4.pdf) then it should be disabled.
## Encryption

| Cipher | Secure | Deprecated | Legacy | Notes |
| -- | :--: | :--: | :--: | -- |
| NULL | ❌ | ❌ | ❌ | Atypical, cipher suites which do not actually encrypt data should obviously be avoided at all costs. |
| [EXP](https://en.wikipedia.org/wiki/Export_of_cryptography_from_the_United_States) | ❌ | ❌ | ❌ | Export ciphers DES, RC2, and RC4-40 use 40-bit keys which are 300 million billion billion times weaker than 128-bit keys. |
| [IDEA](https://en.wikipedia.org/wiki/International_Data_Encryption_Algorithm) | ❌ | ❌ | ❌ | Deprecated by [RFC5469](https://www.rfc-editor.org/rfc/rfc5469.html), Broken by [MitM attacks from 2011](https://link.springer.com/article/10.1007/s00145-013-9162-9), reduced to 126-bits by and a bicliques attack from 2012. |
| [RC4](https://en.wikipedia.org/wiki/RC4) | ❌ | ❌ | ❌ | Prohibited by [RFC 7465](https://www.rfc-editor.org/rfc/rfc7465.html). Disabled in [Chrome](https://bugs.chromium.org/p/chromium/issues/detail?id=375342#c87), [Safari](https://support.apple.com/guide/security/tls-security-sec100a75d12/web). |
| [3DES](https://www.rfc-editor.org/rfc/rfc1851.html) | ❌ | ❌ | ❌ | Broken by [Sweet32](https://sweet32.info/), [NIST Deprecation](https://csrc.nist.gov/News/2017/Update-to-Current-Use-and-Deprecation-of-TDEA). |
| [ARIA](https://www.rfc-editor.org/rfc/rfc5794.html) | ❌ | ✅ | ✅ | Atypical outside of South Korea. |
| [SEED](https://www.rfc-editor.org/rfc/rfc4162.html) | ❌ | ✅ | ✅ | Atypical outside of South Korea, CBC-mode HMACs only, no PFS. |
| [Camellia](https://www.rfc-editor.org/rfc/rfc5932.html) | ❌ | ✅ | ✅ | CBC-mode HMACs only. |
| [AES](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.197.pdf) | ✅ | ✅ | ✅ | AES-128 and AES-256 are permissible for all uses. AES-128 is preferred due to lower CPU overhead while retaining the required security. |
| [CHACHA20/POLY1305](https://www.rfc-editor.org/rfc/rfc7905) | ✅ | ✅ | ✅ | Faster than AES on devices without hardware support |


## HMACs

### HMAC modes

| HMAC mode | Secure | Deprecated | Legacy | Notes |
| -- | :--: | :--: | :--: | -- |
| CBC | ❌ | ✅ | ✅ | Practical application in TLS requires frequent padding to match the block size of the given cipher and this has lead to problems. [[1](https://en.wikipedia.org/wiki/Padding_oracle_attack)][[2](https://blog.cloudflare.com/padding-oracles-and-the-decline-of-cbc-mode-ciphersuites/)][[3](https://docs.microsoft.com/en-us/dotnet/standard/security/vulnerabilities-cbc-mode)][[4](https://blog.qualys.com/product-tech/2019/04/22/zombie-poodle-and-goldendoodle-vulnerabilities)]. Deprecated in [Chrome](https://groups.google.com/a/chromium.org/g/blink-dev/c/1eKb8bqT1Ds?pli=1), [Firefox](https://bugzilla.mozilla.org/show_bug.cgi?id=1316300). |
| [CCM_8](https://www.rfc-editor.org/rfc/rfc7251) | ❌ | ❌ | ❌ | Only provides a 64-bit HMACs. |
| [CCM](https://www.rfc-editor.org/rfc/rfc7251) | ❌ | ✅ | ✅ | Atypical, primarily for use in embedded systems. Introduced after GCM, low adoption. |
| [AEAD](https://www.rfc-editor.org/rfc/rfc5116) | ✅ | ✅ | ✅ | |

### HMAC algorithms

| HMAC | Secure | Deprecated | Legacy | Notes |
| -- | :--: | :--: | :--: | -- |
| [MD5](https://www.rfc-editor.org/rfc/rfc1321.html) | ❌ | ❌ | ❌ | Deprecated by [RFC6151](https://www.rfc-editor.org/rfc/rfc6151.html), prohibited by [draft-ietf-tls-md5-sha1-deprecate](https://www.ietf.org/archive/id/draft-ietf-tls-md5-sha1-deprecate-09.html). Disabled in [Chrome](https://www.chromium.org/Home/chromium-security/education/tls/#TOC-Cipher-Suites). |
| SHA1 | ❌ | ❌ | ✅ | Prohibited by [draft-ietf-tls-md5-sha1-deprecate](https://www.ietf.org/archive/id/draft-ietf-tls-md5-sha1-deprecate-09.html). Disabled in [Chrome](https://www.chromium.org/Home/chromium-security/education/tls/#TOC-Cipher-Suites), [Firefox](https://blog.mozilla.org/security/2017/02/23/the-end-of-sha-1-on-the-public-web/). |
| SHA256 SHA384 | ❌ | ✅ | ✅ | CBC-mode only. |
| [GCM](https://www.rfc-editor.org/rfc/rfc5288.html) | ✅ | ✅ | ✅ | |


## See also

- [PCI DSS - "Early TLS"](https://pcissc.secure.force.com/faq/articles/Frequently_Asked_Question/Does-PCI-DSS-define-which-versions-of-TLS-must-be-used)
- [PCI DSS - Use of SSL/Early TLS for POS POI Terminal Connections](https://www.pcisecuritystandards.org/documents/Use-of-SSL-Early-TLS-for-POS-POI-Connections.docx)
- [NIST - Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)
- [NSA - Eliminating Obsolete Transport Layer Security (TLS) Protocol Configurations](https://media.defense.gov/2021/Jan/05/2002560140/-1/-1/0/ELIMINATING_OBSOLETE_TLS_UOO197443-20.PDF)
