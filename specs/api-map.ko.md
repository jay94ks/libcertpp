# API 맵 — 어떤 헤더, 어떤 타입

[English](api-map.md)

작업 기준 API 색인입니다. 여기 있는 모든 이름은 헤더에서 직접 읽어온 것이며,
이 문서와 헤더가 어긋난다면 헤더가 맞습니다. `#include <certpp.hpp>` 하나로
전부 끌어올 수 있습니다.

네임스페이스: `io`/`utils`/최상위 타입은 `certpp::`, 그 외에는
`certpp::asn1::`, `certpp::crypto::`, `certpp::x509::`, `certpp::dnssec::`.

## 인증서와 PKI

| 작업 | 헤더 | 타입 / 진입점 |
| --- | --- | --- |
| 인증서 파싱 | `x509/cert.hpp` | `CCert::importDer()`, `importPem()` |
| 인증서의 필드 읽기 | `x509/cert.hpp` | `subject()`, `issuer()`, `serialNumber()`, `notBefore()`, `notAfter()`, `keyAlgo()`, `signAlgo()`, `publicKey()` |
| 확장 읽기 | `x509/cert.hpp`, `x509/ext.hpp`, `x509/exts/*.hpp` | `CCert::extensionOf(oid, out)`; `exts/` 아래의 10종 구체 타입 |
| RSASSA-PSS 매개변수 읽기 | `x509/cert.hpp` | `CCert::rsaPssParams()` |
| 체인의 한 연결 검증 | `x509/cert.hpp` | `CCert::verifyBy(issuer)` |
| 인증서의 키로 임의의 데이터 서명/검증 | `x509/cert.hpp` | `CCert::signData()`, `verifyData()` |
| 인증서 발급 또는 자체 서명 | `x509/cert.hpp` | `CCertBuilder` |
| CRL 파싱 또는 빌드 | `x509/crl.hpp` | `CCrlReader`, `CCrlWriter`, `CCrlRevokationInfo` |
| OCSP 파싱 또는 빌드 | `x509/ocsp.hpp` | `COcspRequest`, `COcspRequestBuilder`, `COcspResponse`, `COcspCertId`, `COcspEntry` |
| 여러 인증서를 담아 두고 순서대로 정렬 | `x509/chain.hpp` | `CCertCollection`, `SCertEntry`, `EChainResults` |
| 식별 이름(DN) | `name.hpp` | `CDistinguishedName`, `CName`, `ENameType` |

## 해시, MAC, KDF

| 작업 | 헤더 | 진입점 |
| --- | --- | --- |
| 무언가를 해시하기 | `crypto/hasher.hpp` | `IHasher::create(EHASH_SHA256, out)`, 그다음 `reset()`/`push()`/`finish()` |
| 사용할 수 있는 해시 | `crypto/hashers/*.hpp` | MD4, MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512, SHAKE128/256, BLAKE2s, Streebog-256/512 |
| HMAC | `crypto/hmac.hpp` | `CHmac::compute(hasher, key, message, out)`, `CHmac::verify(...)` |
| HKDF | `crypto/hkdf.hpp` | `CHkdf::derive(hasher, salt, inputKey, info, out)`; `extract()`/`expand()`도 있습니다 |
| Poly1305 일회용 MAC | `crypto/poly1305.hpp` | `CPoly1305::compute(key, message, out)` |
| BLAKE2s 네이티브 키드 MAC | `crypto/blake2smac.hpp` | `CBlake2sMac` — HMAC-BLAKE2s와 같은 것이 *아닙니다* |
| SipHash-2-4 | `crypto/siphash.hpp` | `CSipHash` |

## 대칭키와 AEAD

| 작업 | 헤더 | 진입점 |
| --- | --- | --- |
| 블록/스트림 암호 | `crypto/sym.hpp`, `crypto/syms/*.hpp` | `ISymmetric::builtIn(ESYM_AES)` 등; AES, DES, TripleDES, ChaCha20 |
| CBC padding 모드 | `crypto/sym.hpp` | `ISymmetricContext::padding(ESYMPAD_PKCS7 \| ESYMPAD_NONE)` |
| ChaCha20-Poly1305 | `crypto/aeads/chacha20poly1305.hpp` | `CChaCha20Poly1305` |
| XChaCha20-Poly1305(192비트 nonce) | `crypto/aeads/xchacha20poly1305.hpp` | `CXChaCha20Poly1305` |
| AES-GCM | `crypto/aeads/aesgcm.hpp` | `CAesGcm` |

## 비대칭키

| 작업 | 헤더 | 진입점 |
| --- | --- | --- |
| 임의의 서명 알고리즘 | `crypto/asym.hpp`, `crypto/keys.hpp` | `IAsymmetric::builtIn(EASYM_P256)`, 그다음 `createContext()` |
| 키 쌍 생성 | `crypto/asym.hpp` | `IAsymmetric::generateKeyPair(bits, out)` |
| 공개키/개인키 가져오기 | `crypto/asym.hpp` | `createPublicKey(span)`, `createPrivateKey(span)` |
| 서명/검증 | `crypto/asym.hpp` | `IAsymmetricContext::sign()`, `verify()`, `signPss()`, `verifyPss()` |
| ECDH/X25519 키 교환 | `crypto/asym.hpp` | `IAsymmetricContext::deriveSharedSecret(peer, out)` |
| 곡선 매개변수 | `crypto/eccurve.hpp`, `crypto/ec2curve.hpp` | `CEcCurve::knownCurves(ECURVE_P256, out)`; 이진 곡선은 `CEc2Curve` |
| ML-KEM(양자내성 KEM) | `crypto/kem.hpp`, `crypto/kems/mlkem.hpp` | `IKem::builtIn(EKEM_MLKEM768)`, 그다음 `encapsulate()`/`decapsulate()`; 또는 span을 직접 받는 `CMlKem` |
| ML-DSA(양자내성 서명) | `crypto/asyms/mldsa.hpp` | `CMlDsa`, `IAsymmetric::builtIn(EASYM_MLDSA87)`을 통해 |

알고리즘 열거자(enumerator)는 `crypto/keys.hpp`(`EAsymmetrics`, `EKems`),
`crypto/hasher.hpp`(`EHashers`), `crypto/sym.hpp`(`ESymAlgos`)에 있습니다.

## DNSSEC

| 작업 | 헤더 | 진입점 |
| --- | --- | --- |
| 정규(canonical) 와이어 포맷 이름 | `dnssec/name.hpp` | `CDnsName::toWire()`, `fromWire()`, `countLabels()` |
| DNSKEY / DS / RRSIG RDATA | `dnssec/records.hpp` | `SDnskey`, `SDsRecord`, `SRrsig` |
| 키 태그(key tag), DS 다이제스트 | `dnssec/records.hpp` | `SDnskey::keyTag()`, `SDsRecord::fromDnskey()`, `matches()` |
| DNSKEY ↔ 공개키, RRSIG 서명 ↔ DER | `dnssec/keys.hpp` | `CDnssecKeys` |

## ASN.1 / DER

| 작업 | 헤더 | 진입점 |
| --- | --- | --- |
| TLV 디코딩/인코딩 | `asn1/decoder.hpp`, `asn1/encoder.hpp` | `CDecoder`, `CEncoder` |
| 순차 읽기/쓰기 | `asn1/reader.hpp`, `asn1/writer.hpp` | `CReader`, `CWriter` |
| 태그 | `asn1/tag.hpp` | `CTag`, `ETagClass`, `EAsn1UniversalTag` |
| 큰 정수 및 SEQUENCE 헬퍼 | `asn1/der.hpp` | `CDer::appendBigInteger()`, `appendSequence()`, `readOuterSequence()`, `readBigInteger()`, `maxSignatureSize()` |

## 유틸리티

| 작업 | 헤더 | 타입 |
| --- | --- | --- |
| 임의 정밀도 정수 | `utils/bignum.hpp` | `CBigNum` |
| Montgomery 영역 모듈러 연산 | `utils/montgomery.hpp` | `CMontgomery` |
| 이진체(binary-field) 원소 | `utils/gf2m.hpp` | `CGf2m` |
| constant-time 비교/지우기 | `utils/secure.hpp` | `CSecure::equals()`, `equalsMask()`, `select()`, `zero()` |
| Base64 | `utils/base64.hpp` | `CBase64::encode()`, `decode()` |
| 16진수 | `utils/hex.hpp` | `CHex` |
| JSON 값과 BSON 문서 파싱/생성 | `utils/json.hpp` | `CJson`, `CJsonPtr`, `parseJson()`, `parseBson()` |
| 무작위 바이트 | `crypto/rng.hpp` | `CRng::fill(span)` |

## 버퍼와 span

| 타입 | 헤더 | 쓰는 경우 |
| --- | --- | --- |
| `SByteSpan`, `SReadOnlyByteSpan` | `io/span.hpp` | 이미 가지고 있는 메모리를 빌려 쓸 때. 아무것도 소유하지 않습니다. |
| `TArray<T>` | `io/array.hpp` | 길이를 늘릴 수 있는 시퀀스; `add()`, `resize()`, `begin()`, `size()`. |
| `CBuffer` | `io/buffer.hpp` | 크기 조정이 가능한 작업용 바이트 버퍼. |
| `COctet` | `io/octet.hpp` | 완성된 결과물을 담는 고정 크기 소유 버퍼. |
| `IStream` | `io/stream.hpp` | 스트림 추상화; 메모리 기반이 필요하면 `IStream::createMemory()`. |
| `CString` | `string.hpp` | 이 라이브러리의 문자열 타입(`TString<char>`). |
| `SDateTime`, `STimeSpan` | `time.hpp` | 인증서 유효 기간 시각. |
