# libcertpp

[English](README.md)

![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![CMake 3.15+](https://img.shields.io/badge/CMake-3.15%2B-064F8C)
![Windows | Linux](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-success)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

**X.509, ASN.1, 그리고 암호화를 C++17로 밑바닥부터 구현한 라이브러리.**

자체 DER 코덱, 자체 큰 수(big-number)·이진체(binary-field) 연산, 자체 해시,
대칭키 암호, AEAD, 서명 방식, 양자내성 알고리즘, 그리고 그 위에 쌓아올린
X.509 레이어까지 전부 포함합니다. 라이브러리 안에 서드파티 암호화 코드는 한
줄도 없습니다 — 유일하게 가져다 쓰는 의존성인
[doctest](https://github.com/doctest/doctest)는 테스트 스위트에서만 쓰이며
`certpp` 자체에는 링크되지 않습니다.

```cpp
#include <certpp.hpp>

using namespace certpp;
using namespace certpp::x509;

// 인증서를 파싱하고, 내용을 읽고, 누가 서명했는지 확인합니다.
CCert leaf;
if (leaf.importDer(leafDer) == ERET_OK) {
    CName cn;
    leaf.subject().tryGet(ENAME_CN, cn);

    // 링크 하나: 서명만 확인하며, 그 외에는 아무것도 확인하지 않습니다.
    const bool signedByIssuer = (leaf.verifyBy(issuer) == ERET_OK);
}
```

```cpp
using namespace certpp::crypto;

// 레코드를 제자리에서 인증 암호화합니다. `out`은 `in`과 같은 버퍼여도 됩니다.
CChaCha20Poly1305 aead;
aead.reset(key);

uint8_t tag[16];
aead.seal(nonce, aad,
          SReadOnlyByteSpan(record, length),
          SByteSpan(record, length),
          SByteSpan(tag, sizeof(tag)));
```

더 많은 예시는 [`specs/recipes.ko.md`](specs/recipes.ko.md)와, 빌드 과정에서
함께 컴파일되는 [`examples/`](examples/)(영문)에 있습니다.

## 구성 요소

**인증서** — DER/PEM `Certificate`의 파싱과 빌드(`CCert`, `CCertBuilder`), CRL,
OCSP 요청/응답(RFC 6960), 그리고 10종의 구체적인 확장 타입. 서명 검증은
PKCS#1 v1.5, RSASSA-PSS(RFC 4055 — DER 기본값을 가정하지 않고 실제 파라미터를
읽습니다), ECDSA, EdDSA, ML-DSA를 지원합니다. `organizationIdentifier`와
`domainComponent`를 포함한 14종의 X.520 이름 속성 타입을 인식합니다.

**해시** — MD4, MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512, SHAKE128/256,
BLAKE2s(RFC 7693), 두 가지 다이제스트 길이를 모두 지원하는
GOST R 34.11-2012 "Streebog"(RFC 6986).

**MAC 및 KDF** — 위의 모든 해시 위에서 동작하는 HMAC(RFC 2104),
HKDF(RFC 5869), Poly1305(RFC 8439), BLAKE2s의 네이티브 키드 MAC,
SipHash-2-4(RFC 9018).

**대칭키 및 AEAD** — AES, DES, TripleDES(CBC, PKCS#7 패딩 또는 패딩 없음),
ChaCha20. AEAD 3종: ChaCha20-Poly1305(RFC 8439),
XChaCha20-Poly1305(192비트 nonce), AES-GCM(SP 800-38D). 세 가지 모두 제자리에서
동작하고, 컨텍스트를 재사용할 때 레코드마다 메모리를 할당하지 않으며, 평문을 단
한 바이트도 쓰기 전에 태그를 constant-time으로 검증합니다.

**비대칭키** — RSA(PKCS#1 v1.5 및 RSASSA-PSS 서명/검증, v1.5 암호화/복호화),
DSA, NIST P-192~P-521·secp256k1·14종 Brainpool 곡선 위의 ECDSA, NIST
이진/Koblitz 곡선 10종 위의 ECDSA, Ed25519/Ed448(RFC 8032),
X25519(RFC 7748), 소수체 곡선 위의 ECDH(RFC 5903), 그리고 9종의 명명된
매개변수 집합을 지원하는 GOST R 34.10-2012.

**양자내성 암호화(PQC)** — ML-KEM(FIPS 203)과 ML-DSA(FIPS 204), 모든 매개변수
집합. NIST ACVP 벡터로 검증했습니다. 실제 제3자가 발급한 ML-DSA 인증서가 테스트
스위트에서 end-to-end로 검증됩니다.

**DNSSEC** — DNSKEY/RRSIG/DS 변환(RFC 4034): 정규(canonical) 와이어 포맷 이름,
RDATA, 키 태그, DS 다이제스트, 그리고 DNSSEC의 와이어 포맷과 이 라이브러리의
키·서명 사이의 재인코딩.

**하드웨어 가속** — 큰 수 연산용 ADX/BMI2, 이진체 연산 및 GHASH용 PCLMULQDQ,
SHA-NI, AES-NI, 그리고 4블록 SSE2 ChaCha20 키스트림. 각각 바이트 단위로 동일한
결과를 내도록 요구되는 소프트웨어 폴백과, 그것을 강제하는 CMake 스위치를 함께
제공하며, 명령어 집합이 기본(baseline)이 아닌 경우에는 런타임 CPUID 검사를
거칩니다.

전체 모듈 구성은 [`docs/architecture.ko.md`](docs/architecture.ko.md)에
파일 단위로 정리되어 있습니다.

## 빌드

```sh
cmake -S . -B build
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

기본적으로 공유 라이브러리를 빌드하며, 정적 라이브러리는
`-DCERTPP_BUILD_SHARED=OFF`로 빌드합니다. CMake 3.15 이상과 C++17 컴파일러가
필요하고, MSVC와 GCC로 빌드됩니다. 전체 옵션 목록은
[`docs/build.ko.md`](docs/build.ko.md)에 있습니다.

## CMake에서 사용하기

```sh
cmake --install build --prefix <prefix>
```

```cmake
find_package(certpp REQUIRED)
target_link_libraries(myapp PRIVATE certpp::certpp)
```

해당 prefix가 기본 탐색 경로에 없으면 `-DCMAKE_PREFIX_PATH=<prefix>`를
추가하세요. *정적* `certpp`는 반드시 일치하는 MSVC 런타임과 함께 사용해야
합니다.

## 문서

**라이브러리를 사용하는 쪽:**

- [`specs/`](specs/) — 에이전트와 처음 접하는 사람을 위한 참고 자료:
  [API 지도](specs/api-map.ko.md), [레시피](specs/recipes.ko.md), 그리고
  [함정](specs/pitfalls.ko.md) — 이 라이브러리를 잘못 호출했는데도 정상
  동작하는 것처럼 보이는 경우들을 모아 둔 문서입니다.
- [`examples/`](examples/)(영문) — 컴파일되는 CA 계층 구조 예제.

**라이브러리를 개발하는 쪽:**

- [`docs/architecture.ko.md`](docs/architecture.ko.md) — 모듈별 책임, 파일 단위 정리.
- [`docs/coding-conventions.ko.md`](docs/coding-conventions.ko.md) — 네이밍, 가드, 포맷팅, 버퍼 처리.
- [`docs/build.ko.md`](docs/build.ko.md) — 전체 CMake 빌드/설치 레퍼런스.
- [`docs/changelog.ko.md`](docs/changelog.ko.md) — 왜 이렇게 되어 있는지, 그리고 어떤 버그를 발견해 고쳤는지.
- [`docs/pqc-review.ko.md`](docs/pqc-review.ko.md) — 양자내성 암호화 검토 및 단계 구분.
- [`docs/roadmap.ko.md`](docs/roadmap.ko.md) — 요청받았으나 아직 만들지 않은 것들.

모든 문서는 영문 원본과 `<이름>.ko.md` 한국어 번역본이 함께 있습니다. 영문이
원본이며, 한국어 문서는 그 번역입니다.

## 테스트

모든 알고리즘은 자기 자신과만 비교하지 않고 **공개된 벡터**로 검증합니다 —
ML-KEM과 ML-DSA는 NIST ACVP, 그 외에는 해당 RFC가 제시한 테스트 벡터, 그리고
`tests/x509/certs/`에 들어 있는 실제 상용 발급 인증서들입니다. 새로 추가되는
단위는 여기에 **네거티브 컨트롤**을 더합니다: 불변식을 일부러 깨뜨려 테스트가
실제로 실패하는지 확인하는 것으로, 깨진 코드에서도 통과하는 테스트 스위트는
아무것도 측정하지 못하기 때문입니다. 공개 벡터로는 잡히지 않던 문제를 이 방법이
잡아낸 사례들은 [`docs/changelog.ko.md`](docs/changelog.ko.md)에 있습니다.

## 현재 상태

아직 초기 단계로 활발히 개발 중이며, 인터페이스가 변경될 수 있습니다.
**제3자 보안 감사를 거치지 않았습니다.** 일부는 설계상 constant-time이며 해당
문서 주석에 그렇게 명시되어 있고, 일부는 명시적으로 그렇지 않습니다 —
`CBigNum`과, 따라서 그 위에 올라간 소수체 곡선 ECDSA/ECDH가 그렇습니다.
정직한 목록은 [`specs/pitfalls.ko.md`](specs/pitfalls.ko.md)에 있습니다.
타이밍이 공격자의 입력이 되는 환경에서 쓰기 전에 이 점을 고려하시기 바랍니다.

[MIT 라이선스](LICENSE)로 배포합니다. 함께 포함된
[doctest](third-party/doctest/) 역시 MIT 라이선스이며 테스트 스위트에서만
쓰입니다. `certpp` 자체는 어떤 서드파티도 링크하지 않습니다.
