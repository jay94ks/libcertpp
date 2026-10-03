# API map — which header, which type

[한국어](api-map.ko.md)

A task-to-API index. Every name here was read out of the headers; when this
disagrees with a header, the header is right. `#include <certpp.hpp>` pulls in
all of it.

Namespaces: `certpp::` for `io`/`utils`/top-level types, `certpp::asn1::`,
`certpp::crypto::`, `certpp::x509::`, `certpp::dnssec::`.

## Certificates and PKI

| Task | Header | Type / entry point |
| --- | --- | --- |
| Parse a certificate | `x509/cert.hpp` | `CCert::importDer()`, `importPem()` |
| Read its fields | `x509/cert.hpp` | `subject()`, `issuer()`, `serialNumber()`, `notBefore()`, `notAfter()`, `keyAlgo()`, `signAlgo()`, `publicKey()` |
| Read an extension | `x509/cert.hpp`, `x509/ext.hpp`, `x509/exts/*.hpp` | `CCert::extensionOf(oid, out)`; ten concrete types under `exts/` |
| Read RSASSA-PSS parameters | `x509/cert.hpp` | `CCert::rsaPssParams()` |
| Verify one chain link | `x509/cert.hpp` | `CCert::verifyBy(issuer)` |
| Sign / verify arbitrary data with a certificate's key | `x509/cert.hpp` | `CCert::signData()`, `verifyData()` |
| Issue or self-sign a certificate | `x509/cert.hpp` | `CCertBuilder` |
| Parse or build a CRL | `x509/crl.hpp` | `CCrlReader`, `CCrlWriter`, `CCrlRevokationInfo` |
| Parse or build OCSP | `x509/ocsp.hpp` | `COcspRequest`, `COcspRequestBuilder`, `COcspResponse`, `COcspCertId`, `COcspEntry` |
| Hold a set of certificates and order them | `x509/chain.hpp` | `CCertCollection`, `SCertEntry`, `EChainResults` |
| Distinguished names | `name.hpp` | `CDistinguishedName`, `CName`, `ENameType` |

## Hashing, MACs, KDFs

| Task | Header | Entry point |
| --- | --- | --- |
| Hash something | `crypto/hasher.hpp` | `IHasher::create(EHASH_SHA256, out)`, then `reset()`/`push()`/`finish()` |
| Available hashes | `crypto/hashers/*.hpp` | MD4, MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512, SHAKE128/256, BLAKE2s, Streebog-256/512 |
| HMAC | `crypto/hmac.hpp` | `CHmac::compute(hasher, key, message, out)`, `CHmac::verify(...)` |
| HKDF | `crypto/hkdf.hpp` | `CHkdf::derive(hasher, salt, inputKey, info, out)`; also `extract()`/`expand()` |
| Poly1305 one-time MAC | `crypto/poly1305.hpp` | `CPoly1305::compute(key, message, out)` |
| BLAKE2s native keyed MAC | `crypto/blake2smac.hpp` | `CBlake2sMac` — *not* the same as HMAC-BLAKE2s |
| SipHash-2-4 | `crypto/siphash.hpp` | `CSipHash` |

## Symmetric and AEAD

| Task | Header | Entry point |
| --- | --- | --- |
| Block / stream cipher | `crypto/sym.hpp`, `crypto/syms/*.hpp` | `ISymmetric::builtIn(ESYM_AES)` etc.; AES, DES, TripleDES, ChaCha20 |
| CBC padding mode | `crypto/sym.hpp` | `ISymmetricContext::padding(ESYMPAD_PKCS7 \| ESYMPAD_NONE)` |
| ChaCha20-Poly1305 | `crypto/aeads/chacha20poly1305.hpp` | `CChaCha20Poly1305` |
| XChaCha20-Poly1305 (192-bit nonce) | `crypto/aeads/xchacha20poly1305.hpp` | `CXChaCha20Poly1305` |
| AES-GCM | `crypto/aeads/aesgcm.hpp` | `CAesGcm` |

## Asymmetric

| Task | Header | Entry point |
| --- | --- | --- |
| Any signature algorithm | `crypto/asym.hpp`, `crypto/keys.hpp` | `IAsymmetric::builtIn(EASYM_P256)`, then `createContext()` |
| Generate a key pair | `crypto/asym.hpp` | `IAsymmetric::generateKeyPair(bits, out)` |
| Import a public / private key | `crypto/asym.hpp` | `createPublicKey(span)`, `createPrivateKey(span)` |
| Sign / verify | `crypto/asym.hpp` | `IAsymmetricContext::sign()`, `verify()`, `signPss()`, `verifyPss()` |
| ECDH / X25519 key agreement | `crypto/asym.hpp` | `IAsymmetricContext::deriveSharedSecret(peer, out)` |
| Curve parameters | `crypto/eccurve.hpp`, `crypto/ec2curve.hpp` | `CEcCurve::knownCurves(ECURVE_P256, out)`; `CEc2Curve` for binary curves |
| ML-KEM (post-quantum KEM) | `crypto/kem.hpp`, `crypto/kems/mlkem.hpp` | `IKem::builtIn(EKEM_MLKEM768)`, then `encapsulate()`/`decapsulate()`; or raw-span `CMlKem` |
| ML-DSA (post-quantum signature) | `crypto/asyms/mldsa.hpp` | `CMlDsa`, via `IAsymmetric::builtIn(EASYM_MLDSA87)` |

Algorithm enumerators live in `crypto/keys.hpp` (`EAsymmetrics`, `EKems`),
`crypto/hasher.hpp` (`EHashers`) and `crypto/sym.hpp` (`ESymAlgos`).

## DNSSEC

| Task | Header | Entry point |
| --- | --- | --- |
| Canonical wire-format names | `dnssec/name.hpp` | `CDnsName::toWire()`, `fromWire()`, `countLabels()` |
| DNSKEY / DS / RRSIG RDATA | `dnssec/records.hpp` | `SDnskey`, `SDsRecord`, `SRrsig` |
| Key tag, DS digest | `dnssec/records.hpp` | `SDnskey::keyTag()`, `SDsRecord::fromDnskey()`, `matches()` |
| DNSKEY ↔ public key, RRSIG signature ↔ DER | `dnssec/keys.hpp` | `CDnssecKeys` |

## ASN.1 / DER

| Task | Header | Entry point |
| --- | --- | --- |
| Decode / encode TLVs | `asn1/decoder.hpp`, `asn1/encoder.hpp` | `CDecoder`, `CEncoder` |
| Sequential reading / writing | `asn1/reader.hpp`, `asn1/writer.hpp` | `CReader`, `CWriter` |
| Tags | `asn1/tag.hpp` | `CTag`, `ETagClass`, `EAsn1UniversalTag` |
| Big-integer and SEQUENCE helpers | `asn1/der.hpp` | `CDer::appendBigInteger()`, `appendSequence()`, `readOuterSequence()`, `readBigInteger()`, `maxSignatureSize()` |

## Utilities

| Task | Header | Type |
| --- | --- | --- |
| Arbitrary-precision integers | `utils/bignum.hpp` | `CBigNum` |
| Montgomery-domain modular arithmetic | `utils/montgomery.hpp` | `CMontgomery` |
| Binary-field elements | `utils/gf2m.hpp` | `CGf2m` |
| Constant-time compare / wipe | `utils/secure.hpp` | `CSecure::equals()`, `equalsMask()`, `select()`, `zero()` |
| Base64 | `utils/base64.hpp` | `CBase64::encode()`, `decode()` |
| Hex | `utils/hex.hpp` | `CHex` |
| Random bytes | `crypto/rng.hpp` | `CRng::fill(span)` |

## Buffers and spans

| Type | Header | Use it when |
| --- | --- | --- |
| `SByteSpan`, `SReadOnlyByteSpan` | `io/span.hpp` | Borrowing memory you already have. Owns nothing. |
| `TArray<T>` | `io/array.hpp` | A growable sequence; `add()`, `resize()`, `begin()`, `size()`. |
| `CBuffer` | `io/buffer.hpp` | A resizable working byte buffer. |
| `COctet` | `io/octet.hpp` | A fixed-size owning buffer for a finished result. |
| `IStream` | `io/stream.hpp` | Stream abstraction; `IStream::createMemory()` for an in-memory one. |
| `CString` | `string.hpp` | The library's string type (`TString<char>`). |
| `SDateTime`, `STimeSpan` | `time.hpp` | Certificate validity times. |
