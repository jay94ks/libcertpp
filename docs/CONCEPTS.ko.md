# 아키텍처와 개념

[English](CONCEPTS.md)

## 개요

`libcertpp`는 C++17 라이브러리이며, 아직 초기 단계이지만 최초의 뼈대는
넘어섰습니다. `common` 기반, `version` 모듈, `utils`
모듈(DJB 해시 유틸리티, `CHex` 16진 디코딩, `CBase64` base64, 임의 정밀도
정수인 `CBigNum`, 이진체(binary-field, GF(2^m)) 원소인 `CGf2m`, JSON 파싱과
직렬화를 위한 `CJson`), `io`
계층(span, 증가 가능한 배열, 크기 조절 가능한 작업용 바이트
버퍼(`CBuffer`), 고정 크기 소유 버퍼(`COctet`), 그리고 스트림 추상),
`asn1` 모듈(태그 인코드/디코드, TLV 디코더/인코더, 순차 reader/writer 래퍼,
그리고 `CDer`의 임의 정밀도 `INTEGER`/`SEQUENCE` DER 보조 함수), `crypto`
모듈, `x509` 모듈, 그리고 `dnssec` 모듈이 있습니다.

`crypto`에는 다음이 있습니다. 밑바닥부터 구현한 MD4/MD5/SHA-1/SHA-224/
SHA-256/SHA-384/SHA-512/SHA3-256/SHA3-512/SHAKE128/SHAKE256/BLAKE2s/
Streebog-256/Streebog-512 구현을 갖춘 `IHasher` 인터페이스. CSPRNG
유틸리티(`CRng`). 아홉 개의 구체 구현을 갖춘 `IAsymmetric` 인터페이스
(RSA — PKCS#1 v1.5와 RSASSA-PSS 서명/검증, PKCS#1 v1.5 암호화/복호화.
DSA. `CEcdsa`, NIST P-192/P-224/P-256/P-384/P-521, secp256k1, 또는 14개
Brainpool 곡선(RFC 5639) 중 어느 것 위의 ECDSA와, 같은 곡선들 위의 ECDH 키
합의(RFC 5903 / SP 800-56A). `CEcdsa2`, 10개 NIST 이진/Koblitz 곡선
B-163/K-163 .. B-571/K-571 위의 ECDSA. `Ed25519`/`Ed448`, EdDSA
(RFC 8032). `X25519`, Diffie-Hellman 키 합의(RFC 7748). 그리고
`CGost3410`, 아홉 개 파라미터 집합 중 어느 것 위의 GOST R 34.10-2012
(RFC 7091). 그리고 `CMlDsa`, ML-DSA-44/65/87 서명(FIPS 204)). 병렬 `IKem`
인터페이스와 ML-KEM-512/768/1024(FIPS 203). 다섯 개의 구체 구현을 갖춘
`ISymmetric` 인터페이스(`AES`,
`ARIA`, `DES`, `TripleDES` — 모두 CBC, PKCS#7 padding 있음 또는 없음 — 그리고
`ChaCha20` 스트림 암호). 그리고 그 인터페이스 밖의 AEAD 셋,
`CChaCha20Poly1305`(RFC 8439 2.8), `CXChaCha20Poly1305`
(draft-irtf-cfrg-xchacha), `CAesGcm`(NIST SP 800-38D) — 모두 밑바닥부터이고
제3자 의존성은 없습니다.

`x509`는 DER로 인코딩된 `Certificate`(`CCert`/`CCertBuilder`)와 PKCS#10
`CertificationRequest`(`CCertRequest`/`CCertRequestBuilder`)를 파싱하고 빌드/자기
서명하며, `CertificateList`/CRL(`CCrlReader`/`CCrlWriter`), OCSP 요청/응답
(RFC 6960. `COcspRequest`/`COcspRequestBuilder`, `COcspResponse`/
`COcspResponseBuilder`)을 파싱하며(`CCert`의 경우 빌드/자기 서명도 합니다),
더해서 `x509/exts/` 아래에 열 개의 구체 `IExtension` 타입
(BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeName,
SubjectKeyIdentifier, AuthorityKeyIdentifier, CRLDistributionPoints,
AuthorityInformationAccess, CertificatePolicies, NameConstraints)이
있습니다. 링크 하나 단위의 서명 검증은 셋 모두에 있지만
(`CCert::verifyBy(issuer)`, `CCrlReader::verifyBy(issuer)`,
`COcspRequest`/`COcspResponse::verifySignature()`). `CCertCollection::buildChain()`은
발급자/주체 이름으로 인증서 순서를 잡고 `verifyLinks()`는 링크 서명을 검사하지만,
인증 경로 검증 엔진은 없습니다. 유효 기간, BasicConstraints, KeyUsage,
NameConstraints, 정책, 폐지, 신뢰 앵커 판단을 강제하지 않습니다.
[확장 지점과 범위](concepts/scope.ko.md#확장-지점과-범위)를 참고하십시오.

인증서와 그 키는 컨테이너로 담을 수 있습니다. `x509/chain.hpp`의
`CCertCollection`이 그것들을 짝지어 주는 PKCS#9 속성과 함께 보유하고
발급자 연결로 정렬하며(다시 말하지만 이는 검증이 아닙니다),
`IChainFormat`이 그 컬렉션을 파일로 읽고 씁니다. `x509/chain/pfx.hpp`가
PBES2와 `MacData` HMAC 위에 PKCS#12/PFX를 구현합니다.

공개 API 표면은 [`include/certpp/`](../include/certpp) 아래 헤더 기반이며,
엄브렐라 헤더 [`include/certpp.hpp`](../include/certpp.hpp)를 통해 다시
노출됩니다 — 사용할 수 있는 모든 공개 API 헤더가 거기 포함되어 있으므로, 소비자는
`#include <certpp.hpp>` 하나만으로 됩니다. 구현 파일은
[`src/`](../src) 아래에 있고 자신이 구현하는 헤더를 반영합니다(예:
`include/certpp/version.hpp` <-> `src/version.cpp`).

## 상세 개념 문서

- [저장소 구성](CONCEPTS.ko.md#세부-개념-문서)
- [모듈별 책임](CONCEPTS.ko.md#세부-개념-문서)
- [빌드 모델](concepts/development.ko.md#빌드-모델)
- [확장 지점과 범위](concepts/scope.ko.md#확장-지점과-범위)

## 세부 개념 문서

- [프로젝트 구조](concepts/structure.ko.md)
- [개발 모델](concepts/development.ko.md)
- [코어와 유틸리티](concepts/foundations.ko.md)
- [I/O와 ASN.1](concepts/data-encoding.ko.md)
- [해시와 대칭키 암호](concepts/symmetric.ko.md)
- [MAC, KDF, AEAD 및 난수](concepts/protocols.ko.md)
- [고전 비대칭키 암호](concepts/classical.ko.md)
- [비대칭키 인터페이스와 현대 곡선](concepts/asymmetric.ko.md)
- [포스트퀀텀 암호 내부 구조](concepts/post-quantum.ko.md)
- [인증서와 컨테이너](concepts/certificates.ko.md)
- [확장과 폐지](concepts/validation.ko.md)
- [범위, 통합 및 DNSSEC](concepts/scope.ko.md)
- [성능](concepts/performance.ko.md)
