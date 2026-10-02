# libcertpp

[English](README.md)

`libcertpp`는 X.509 인증서를 다루기 위한, 초기 단계의 C++17 라이브러리로
밑바닥부터 직접 구현되었습니다: 자체 ASN.1/DER 코덱, 자체 큰 수(big-number)
및 이진체(binary-field) 연산, 자체 해시/대칭키/비대칭키 암호화, 그리고 그
위에 쌓아올린 X.509 레이어까지 전부 포함합니다. 라이브러리 본체는 어떤
서드파티 암호화 의존성도 가지지 않습니다 (유일하게 가져다 쓰는 의존성인
[doctest](https://github.com/doctest/doctest)는 테스트 스위트에서만
사용됩니다).

## 구성 요소

- **`utils`** -- `CBigNum`(임의 정밀도 정수), `CGf2m`(이진체 GF(2^m) 원소),
  `CHex`, DJB 해시 유틸리티.
- **`io`** -- span 타입들, 가변 길이 배열(`TArray`), 크기 조정이 가능한
  작업용 바이트 버퍼(`CBuffer`), 완성된 결과물을 담는 고정 크기 소유
  버퍼(`COctet`), base64(`CBase64`), 스트림 추상화(`IStream`).
- **`asn1`** -- 태그 인코딩/디코딩, TLV 디코더/인코더, 순차 리더/라이터
  래퍼, 그리고 임의 정밀도 `INTEGER`/`SEQUENCE` DER 헬퍼인 `CDer`.
- **`crypto`**:
  - 해시: MD5, SHA-1, SHA-224/256/384/512, SHAKE128, SHAKE256 -- 모두
    밑바닥부터 구현.
  - CSPRNG(`CRng`) -- OS가 제공하는 난수 생성기를 직접 사용 (Windows에서는
    `BCryptGenRandom`, Linux에서는 `getrandom(2)`/`/dev/urandom`, 그 외
    POSIX 플랫폼에서는 `/dev/urandom`).
  - 비대칭키 알고리즘: RSA(PKCS#1 v1.5 및 RSASSA-PSS 서명/검증, PKCS#1
    v1.5 암호화/복호화), DSA, NIST P-192 ~ P-521·secp256k1·14종의
    Brainpool 곡선 위의 ECDSA, NIST 이진/Koblitz 곡선 10종 위의 ECDSA,
    Ed25519/Ed448(EdDSA, RFC 8032), X25519(Diffie-Hellman 키 교환,
    RFC 7748).
  - 대칭키 알고리즘: AES, DES, TripleDES(CBC/PKCS#7), ChaCha20 스트림
    암호.
  - 사용 가능한 경우 런타임에 자동 감지되는 하드웨어 가속(x86-64):
    큰 수 연산용 ADX/BMI2, 이진체 연산용 PCLMULQDQ, SHA-1/SHA-256용
    SHA-NI, AES용 AES-NI -- 각각 소프트웨어 폴백과, 소프트웨어 경로를
    강제하는 CMake 옵션을 함께 제공합니다.
  - 양자내성 암호화(PQC) 사전 작업: 설계 검토 문서와 (아직 구현되지 않은)
    `IKem`/`IKemContext` 인터페이스 초안 -- 자세한 내용은
    [`docs/pqc-review.md`](docs/pqc-review.md) 참고.
- **`x509`** -- DER 인코딩된 X.509 `Certificate`를 파싱하고 빌드/자체
  서명(`CCert`/`CCertBuilder`)하며, `CertificateList`/CRL을 파싱·빌드하고,
  OCSP 요청/응답(RFC 6960)을 파싱·빌드합니다. 10종의 구체적인 확장 타입
  (BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeName,
  SubjectKeyIdentifier, AuthorityKeyIdentifier, CRLDistributionPoints,
  AuthorityInformationAccess, CertificatePolicies, NameConstraints)도
  포함합니다.

전체 모듈 구성과 파일별 설명은 [`docs/architecture.md`](docs/architecture.md)
(영문)를 참고하세요.

## 빌드

CMake 3.15 이상과 C++17 컴파일러가 필요합니다.

```sh
cmake -S . -B build
cmake --build build --config Debug
```

기본적으로 공유 라이브러리를 빌드합니다. 정적 라이브러리를 빌드하려면
`-DCERTPP_BUILD_SHARED=OFF`를 전달하세요. 전체 CMake 옵션 목록(하드웨어
가속 토글, RNG 폴백, 설치 경로 등)은 [`docs/build.md`](docs/build.md)
(영문)를 참고하세요.

## 테스트

테스트는 [doctest](https://github.com/doctest/doctest)를 사용하며 CTest에
자동으로 등록됩니다:

```sh
ctest --test-dir build -C Debug --output-on-failure
```

## 예제

[`examples/`](examples/) 디렉터리에는 작은 CA 계층 구조 예제(루트 발급 →
중간 CA 발급 → 리프 인증서 발급 → 리프 키로 데이터 서명/검증)가 들어
있습니다 -- 자세한 내용은 [`examples/README.md`](examples/README.md)
(영문)를 참고하세요.

## 문서

- [`docs/architecture.md`](docs/architecture.md) -- 모듈별 책임과 전체
  구조 (영문).
- [`docs/coding-conventions.md`](docs/coding-conventions.md) -- 네이밍,
  헤더 가드, 포맷팅, 문서 주석 컨벤션 (영문).
- [`docs/build.md`](docs/build.md) -- 전체 CMake 빌드/설치 레퍼런스
  (영문).
- [`docs/changelog.md`](docs/changelog.md) -- 이 저장소의 git 히스토리보다
  앞선 작업까지 포함해, 무엇이 만들어지고 고쳐졌는지 시간순으로 기록한
  문서 (영문).
- [`docs/pqc-review.md`](docs/pqc-review.md) -- 양자내성 암호화 검토 및
  로드맵 (영문).

## 현재 상태

아직 초기 단계로 활발히 개발 중이며, 인터페이스가 변경될 수 있습니다.
제3자 보안 감사를 거치지 않았으므로 이 점을 감안하여 사용하시기 바랍니다.
