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
  - 해시: MD4, MD5, SHA-1, SHA-224/256/384/512, SHA3-256, SHA3-512,
    SHAKE128, SHAKE256, BLAKE2s(RFC 7693), 그리고 두 가지 다이제스트 길이
    모두를 지원하는 GOST R 34.11-2012("Streebog", RFC 6986) -- 모두
    밑바닥부터 구현.
  - MAC 및 키 유도: 위의 모든 해시 위에서 동작하는 HMAC(RFC 2104),
    HKDF(RFC 5869), Poly1305(RFC 8439), BLAKE2s의 네이티브 키드
    MAC(keyed MAC), 그리고 SipHash-2-4(RFC 9018의 DNS 서버 쿠키 PRF).
  - CSPRNG(`CRng`) -- OS가 제공하는 난수 생성기를 직접 사용 (Windows에서는
    `BCryptGenRandom`, Linux에서는 `getrandom(2)`/`/dev/urandom`, 그 외
    POSIX 플랫폼에서는 `/dev/urandom`).
  - 비대칭키 알고리즘: RSA(PKCS#1 v1.5 및 RSASSA-PSS 서명/검증, PKCS#1
    v1.5 암호화/복호화), DSA, NIST P-192 ~ P-521·secp256k1·14종의
    Brainpool 곡선 위의 ECDSA, NIST 이진/Koblitz 곡선 10종 위의 ECDSA,
    Ed25519/Ed448(EdDSA, RFC 8032), X25519(Diffie-Hellman 키 교환,
    RFC 7748), 소수체 곡선 위의 ECDH(RFC 5903), 그리고 9종의 명명된
    매개변수 집합을 지원하는 GOST R 34.10-2012(RFC 7091).
  - 대칭키 알고리즘: AES, DES, TripleDES(CBC, PKCS#7 패딩 또는 패딩 없음),
    ChaCha20 스트림 암호.
  - AEAD: ChaCha20-Poly1305(RFC 8439), XChaCha20-Poly1305
    (draft-irtf-cfrg-xchacha, 192비트 nonce), AES-GCM(NIST SP 800-38D).
    세 가지 모두 제자리(in-place) 동작을 지원하며(출력이 입력과 같은
    버퍼여도 됩니다), 컨텍스트를 재사용할 때 호출마다 메모리를 할당하지
    않고, 태그를 constant-time으로 비교하며 태그 검증 전에는 평문을 단 한
    바이트도 쓰지 않습니다.
  - 사용 가능한 경우의 하드웨어 가속(x86-64). 각각 소프트웨어 폴백과,
    소프트웨어 경로를 강제하는 CMake 옵션을 함께 제공합니다: 큰 수
    연산용 ADX/BMI2, 이진체 연산 및 GHASH용 PCLMULQDQ, SHA-1/SHA-256용
    SHA-NI, AES용 AES-NI, 그리고 4블록 SSE2 ChaCha20 키스트림. 마지막
    하나를 제외하면 모두 런타임 CPUID 검사로 선택되며, SSE2는 x86-64 ABI에
    포함되어 있으므로 검사가 필요하지 않습니다.
  - 양자내성 암호화(PQC): 세 가지 매개변수 집합 전체에 대한
    ML-KEM(FIPS 203). NIST ACVP 벡터로 검증했으며, 다른 알고리즘과
    동일하게 `IKem::builtIn(EKEM_MLKEM768)`으로 쓸 수도 있고, 스팬 기반
    `CMlKem`(K-PKE와 샘플러까지 노출)으로 직접 쓸 수도 있습니다. 이후
    계획은 [`docs/pqc-review.ko.md`](docs/pqc-review.ko.md) 참고.
- **`x509`** -- DER 인코딩된 X.509 `Certificate`를 파싱하고 빌드/자체
  서명(`CCert`/`CCertBuilder`)하며, `CertificateList`/CRL을 파싱·빌드하고,
  OCSP 요청/응답(RFC 6960)을 파싱·빌드합니다. 10종의 구체적인 확장 타입
  (BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectAlternativeName,
  SubjectKeyIdentifier, AuthorityKeyIdentifier, CRLDistributionPoints,
  AuthorityInformationAccess, CertificatePolicies, NameConstraints)도
  포함합니다.
  인증서 서명은 PKCS#1 v1.5와 RSASSA-PSS(RFC 4055) 모두 검증합니다. 해시,
  MGF1 해시, salt 길이를 DEFAULT로 가정하지 않고 `AlgorithmIdentifier`의
  parameters에서 읽어오며, 인코딩은 가능하지만 지원하지 않는 조합에 대해서는
  fail-closed로 동작합니다 -- 근사해 버리면 유효한 서명을 전부 거부하게 되고,
  호출자는 그것을 위조와 구별할 수 없기 때문입니다. 식별 이름(DN)은 EU 규제
  인증서가 담는 `organizationIdentifier`와 `domainComponent`를 포함해 14종의
  X.520 속성 타입을 지원합니다.
- **`dnssec`** -- DNSKEY/RRSIG/DS 변환(RFC 4034): 정규(canonical) 와이어
  포맷 도메인 이름, 각 레코드의 RDATA, Appendix B의 키 태그(key tag), DS
  다이제스트, 그리고 DNSSEC의 와이어 포맷과 이 라이브러리의 키·서명 사이의
  재인코딩(RSA는 RFC 3110/5702, ECDSA는 6605, EdDSA는 8080). DNSSEC은
  X.509의 인코딩을 하나도 재사용하지 않기 때문에, `x509`의 한 부분이 아니라
  독립된 모듈입니다.

전체 모듈 구성과 파일별 설명은
[`docs/architecture.ko.md`](docs/architecture.ko.md)를 참고하세요.

## 빌드

CMake 3.15 이상과 C++17 컴파일러가 필요합니다.

```sh
cmake -S . -B build
cmake --build build --config Debug
```

기본적으로 공유 라이브러리를 빌드합니다. 정적 라이브러리를 빌드하려면
`-DCERTPP_BUILD_SHARED=OFF`를 전달하세요. 전체 CMake 옵션 목록(하드웨어
가속 토글, RNG 폴백, 설치 경로 등)은
[`docs/build.ko.md`](docs/build.ko.md)를 참고하세요.

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

- [`docs/architecture.ko.md`](docs/architecture.ko.md) -- 모듈별 책임과
  전체 구조.
- [`docs/coding-conventions.ko.md`](docs/coding-conventions.ko.md) --
  네이밍, 헤더 가드, 포맷팅, 버퍼 처리, 문서 주석 컨벤션.
- [`docs/build.ko.md`](docs/build.ko.md) -- 전체 CMake 빌드/설치 레퍼런스.
- [`docs/changelog.ko.md`](docs/changelog.ko.md) -- 이 저장소의 git
  히스토리보다 앞선 작업까지 포함해, 무엇이 만들어지고 왜 그렇게 되었는지,
  그리고 어떤 버그를 발견해 고쳤는지 기록한 문서.
- [`docs/pqc-review.ko.md`](docs/pqc-review.ko.md) -- 양자내성 암호화 검토
  및 로드맵.
- [`docs/roadmap.ko.md`](docs/roadmap.ko.md) -- 요청받았으나 아직 구현하지
  않은 것들, 그리고 남아 있는 constant-time·성능 작업.

모든 문서는 영문 원본과 `<이름>.ko.md` 한국어 번역본이 함께 있습니다.
영문이 원본이며, 한국어 문서는 그 번역입니다.

## 현재 상태

아직 초기 단계로 활발히 개발 중이며, 인터페이스가 변경될 수 있습니다.
제3자 보안 감사를 거치지 않았으므로 이 점을 감안하여 사용하시기 바랍니다.
