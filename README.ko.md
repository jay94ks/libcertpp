# libcertpp

[English](README.md)

![C++17](https://img.shields.io/badge/C%2B%2B-17-blue)
![CMake 3.15+](https://img.shields.io/badge/CMake-3.15%2B-064F8C)
![Windows | Linux](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey)
![Dependencies: none](https://img.shields.io/badge/dependencies-none-success)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15193/badge)](https://www.bestpractices.dev/projects/15193)

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
`domainComponent`를 포함한 14종의 X.520 이름 속성 타입을 인식합니다. PKCS#10
인증 요청(`CCertRequest`, `CCertRequestBuilder`, RFC 2986)을 양방향으로
지원하며, PKCS#9 `extensionRequest` 속성을 포함하고, 자기 서명을 호출할
메서드로 제공하기만 하는 것이 아니라 가져오는 시점에 검사합니다.

**체인과 컨테이너** — `CCertCollection`은 인증서 집합을 담고 누가 누구를
발행했는지에 따라 정렬하며(`buildChain()`), `verifyLinks()`가 각 링크의 서명을
검사합니다. 컬렉션 위의 컨테이너 형식 둘: 개인키를 위치가 아니라 암호학적으로
자기 인증서와 짝지어 주는 PEM, 그리고 아무것도 복호화되기 전에 MAC을 검증하는
PBES2/AES-256-CBC 위의 PKCS#12/PFX(RFC 7292)입니다. **path validation은
없습니다.** 유효 기간, `basicConstraints`, `keyUsage`, 이름 제약, 정책, 폐지는
검사되지 않으며, 루트가 신뢰할 수 있는 것인지를 결정하는 것은 여기에
없습니다. 이 라이브러리에서 나온 정렬된 체인은 검증기의 판정이 아니라
입력입니다.

**해시** — MD4, MD5, SHA-1, SHA-224/256/384/512, SHA3-256/512, SHAKE128/256,
BLAKE2s(RFC 7693), 두 가지 다이제스트 길이를 모두 지원하는
GOST R 34.11-2012 "Streebog"(RFC 6986).

**MAC 및 KDF** — 위의 모든 해시 위에서 동작하는 HMAC(RFC 2104),
HKDF(RFC 5869), password 기반 경우를 위한 PBKDF2(RFC 8018),
Poly1305(RFC 8439), BLAKE2s의 네이티브 키드 MAC, SipHash-2-4(RFC 9018).

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

**JSON 및 BSON** — JSON 값의 파싱·직렬화(`CJson`, `parseJson()`)와 중첩된
배열·객체 및 escape된 Unicode 문자열을 포함하는 BSON 문서의 인코딩·디코딩을
지원합니다. BSON 정수는 라이브러리의 `double` 숫자 타입으로 변환되며, JSON에
대응하는 값이 없는 BSON 타입은 거부합니다. `-DCERTPP_WITHOUT_JSON=ON`으로
설정하면 유틸리티를 빌드에서 제외할 수 있습니다.

**객체 식별자** — `COid`가 OID이고 `SRawOid`가 그 arc입니다. `COid`는 OID
사본이 아니라 캐시된 슬롯을 가리키는 포인터를 담습니다. 라이브러리가 정의하는
118개의 OID는 `COid`의 `static constexpr SKnownOid` 멤버로 한 번만 선언되어
있습니다(`COid::RSA`, `COid::CURVE_P256`, `COid::EXT_BASIC_CONSTRAINTS`,
`COid::PURPOSE_SERVER_AUTH`, `COid::PBES2`, `COid::DOMAIN_COMPONENT` 등). 라이브러리의
모든 OID 비교는 점-구분 텍스트가 아니라 arc 기준입니다. ASN.1 코덱은
`SRawOid`를 직접 읽고 쓰며, 문자열 기반 `readOidString()`/`encodeOidString()`
진입점은 OID 텍스트를 가진 호출자를 위해 남아 있고 그 위에 구현되어 있습니다.

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
- [`examples/`](examples/)(영문) — 컴파일되는 CA 계층 구조 예제, 더해서 모든
  공개 타입에 대한 컴파일되는 예제.
- [**위키**](../../wiki)(영문) — 공개 class, struct, enum당 레퍼런스 페이지
  하나이며, 헤더 자신의 doc 주석에서 생성되고 각각 자기가 나온 커밋이 찍혀
  있습니다. 통합 가이드, FAQ, 트러블슈팅도 있습니다.

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

## 성능

[`examples/05_benchmark.cpp`](examples/05_benchmark.cpp)로 측정했으므로,
주장이 아니라 재현 가능합니다. 그것을 빌드해 여러분 하드웨어에서 돌려
보십시오. 두 툴체인, 둘 다 Release이고, 4코어 i7-11370H(3.30 GHz 베이스,
이 부하에서 지속 약 3.92 GHz) 한 대에서
한 세션 안에 Windows의 MSVC 19.36(VS 2022 17.6)과 **WSL2 위** Ubuntu 24.04의
GCC 13.3으로 측정했습니다. 각 수치는 반복 20회 배치 3개 중 가장 빠른 것이며,
세 번 실행 중 최선이고, 둘은 동시에가 아니라 순차로 실행해 어느 쪽도 다른
쪽의 컴파일러를 측정하지 않게 했습니다. 실행 간 편차가 20~30%이므로 그보다
작은 것은 결과가 아닙니다. 굵게는 그 행에서 더 빠른 값입니다.

표는 이 라이브러리가 구현한 모든 알고리즘을 대상으로 합니다. 해시 14종,
블록 암호 구성 8종, KEM 매개변수 집합 3종, 서명 및 키 합의 방식 34종입니다.
하네스 출력의 어떤 행도 "(unavailable)"를 보고하지 않으며, 전부를 다루게 한
이유가 그것입니다.

GF(2^m) 곡선은 서명 아래에는 나타나고 키 합의 아래에는 없는 것인데, 그것이
이들이 구현하는 바입니다. ECDSA는 하고 ECDH는 하지 않습니다.

### OpenSSL과 비교

숫자는 혼자서는 아무 뜻이 없으므로, 같은 알고리즘을 같은 머신에서 OpenSSL 3.0.13과
비교해 측정했습니다.

**양쪽 모두 단독으로, 각자의 루프에서 측정했습니다.** 두 구현을 한 루프에서 번갈아
돌리는 것은 — 공정을 지키는 뻔한 방법처럼 보이지만 — 알고 보니 둘 다 망칩니다.
certpp의 SHA-256이 1523에서 765 MiB/s로 떨어지고 OpenSSL의 것도 거의 절반으로
떨어집니다. 번갈아 실행하면 캐시와 분기 예측기가 서로를 방해해서, 교차 수치는 암호
연산의 비교가 아니라 측정 방법의 비교가 됩니다. 그러므로 한쪽씩만 재고, 같은 워밍업,
같은 최선-5배치-300회 방식을 썼으며 결과는 나란히 *측정*해서 나란히 *인쇄*합니다.
OpenSSL은 이 라이브러리의 래퍼가 아니라 EVP를 직접 호출했는데, 이것은 `certpp`를
통해 오는 호출자가 더할 호출당 할당이 아니라 암호 연산 자체를 측정합니다.

워밍업도 세부사항이 아닙니다. OpenSSL은 생성자를 게으르게 해석해서 64 KiB SHA-256
첫 호출이 워밍업 후 38.9 µs 대비 963 µs가 들므로, 차갑게 비교하면 실속의 4분의
1로 보고됩니다.

[`examples/06_openssl_compare.cpp`](examples/06_openssl_compare.cpp)가 이를 재현하며,
OpenSSL이 설치된 곳에서만 OpenSSL을 링크합니다 — `certpp` 자체는 이것에 의존하지
않습니다.

| | certpp | OpenSSL | certpp는 |
|---|---|---|---|
| SHA-256, 64 KiB | 1523 MiB/s | 1580 MiB/s | **0.96배** |
| SHA-1, 64 KiB | 1743 MiB/s | 1855 MiB/s | 0.94배 |
| MD5, 64 KiB | 716 MiB/s | 807 MiB/s | 0.89배 |
| SHA3-256, 64 KiB | 308 MiB/s | 431 MiB/s | 0.72배 |
| SHAKE-256, 64 KiB | 310 MiB/s | 431 MiB/s | 0.72배 |
| SHA-512, 64 KiB | 352 MiB/s | 692 MiB/s | 0.51배 |
| AES-256-CBC, 64 KiB | 1262 MiB/s | 1345 MiB/s | **0.94배** |
| ARIA-256-CBC, 64 KiB | 28 MiB/s | 114 MiB/s | 0.25배 |
| Ed25519 서명 | 0.163 ms | 0.036 ms | 4.5배 느림 |

각 수치는 한 실행의 최선 다섯 개 중 하나이며, 단독으로 잰 쪽의 실행 간 편차는 1~3%
입니다 — 비율은 성립하지만 단일 실행의 절대값은 그 알고리즘의 속도가 아닙니다.

어떤 하나의 비율보다 결과의 형태가 더 많은 것을 말해 줍니다. **32비트 해시에서는
certpp가 OpenSSL의 4% 내입니다.** 15년간의 어셈블리를 쌓아온 코드에 대해 신생
라이브러리가 가질 법한 격차가 아닙니다. **64비트 워드에서는 절반쯤**이고 — SHA-512의
0.51배가 가장 분명한 행입니다. AES-256-CBC도 한때 0.53배였으나 지금은 0.94배입니다.
그 격차는 처음부터 암호가 아니라 블록 단위 인터페이스였고, 체인 값이 레지스터를
벗어나지 않게 되자 두 구현이 만났습니다. ARIA의 4분의 1은 진짜 부재가 어떤 것인지
보여 줍니다. AES-NI에 해당하는 명령이 없고, OpenSSL 것은 수작업 어셈블리이므로 이식
가능한 C++이 닿을 방법이 없습니다. Ed25519 서명은 4.5배 느린데, 이것은 상수 시간 필드
연산 때문입니다. `Fe25519`는 비용이 피연산자에 의존하지 않도록 의도적으로 고정 폭이고,
OpenSSL의 것은 그럴 필요가 없습니다.

32비트 결과는 설명할 가치가 있는데, roadmap가 예측한 것과 달랐기 때문입니다.
SHA-256과 SHA-1은 OpenSSL 수준에 이르는 반면 SHA-512는 그렇지 못한 데, 차이는 처음
둘은 양쪽 모두 같은 명령을 부르는 SHA-NI 위에서 도는 반면 SHA-512는 그렇지 못해 이
라이브러리의 스칼라 구현이 드러난다는 것입니다. 하드웨어 명령이 같은 곳에서는 그
주변의 소프트웨어가 병목이 아닙니다.

#### 서명

| | MSVC | GCC |
|---|---|---|
| RSA-2048 sign | **5.619 ms** | 5.250 ms |
| RSA-2048 verify | 0.143 ms | **0.150 ms** |
| DSA-2048 sign | 2.695 ms | **7.292 ms** |
| DSA-2048 verify | 6.581 ms | **18.069 ms** |
| Ed25519 sign | 0.198 ms | **0.201 ms** |
| Ed25519 verify | **0.873 ms** | 0.702 ms |
| Ed448 sign | **2.527 ms** | 2.499 ms |
| Ed448 verify | 10.661 ms | **10.758 ms** |
| ECDSA P-192 sign | **0.580 ms** | 0.520 ms |
| ECDSA P-192 verify | **1.448 ms** | 1.308 ms |
| ECDSA P-224 sign | **0.755 ms** | 0.670 ms |
| ECDSA P-224 verify | **1.945 ms** | 1.774 ms |
| ECDSA P-256 sign | **0.908 ms** | 0.862 ms |
| ECDSA P-256 verify | **2.428 ms** | 2.379 ms |
| ECDSA P-384 sign | **2.026 ms** | 2.016 ms |
| ECDSA P-384 verify | **5.694 ms** | 5.523 ms |
| ECDSA P-521 sign | **4.737 ms** | 4.379 ms |
| ECDSA P-521 verify | **13.545 ms** | 12.464 ms |
| ECDSA secp256k1 sign | **0.901 ms** | 0.843 ms |
| ECDSA secp256k1 verify | **2.435 ms** | 2.285 ms |
| Brainpool-160r1 sign | **0.462 ms** | 0.385 ms |
| Brainpool-160r1 verify | **1.078 ms** | 1.002 ms |
| Brainpool-192r1 sign | **0.569 ms** | 0.523 ms |
| Brainpool-192r1 verify | **1.407 ms** | 1.398 ms |
| Brainpool-224r1 sign | **0.705 ms** | 0.694 ms |
| Brainpool-224r1 verify | 1.888 ms | **1.980 ms** |
| Brainpool-256r1 sign | **0.919 ms** | 0.890 ms |
| Brainpool-256r1 verify | 2.412 ms | **2.415 ms** |
| Brainpool-320r1 sign | **1.412 ms** | 1.402 ms |
| Brainpool-320r1 verify | **3.741 ms** | 3.678 ms |
| Brainpool-384r1 sign | 2.004 ms | **2.186 ms** |
| Brainpool-384r1 verify | 5.369 ms | **5.908 ms** |
| Brainpool-512r1 sign | 4.007 ms | **4.314 ms** |
| Brainpool-512r1 verify | 11.341 ms | **11.553 ms** |
| Brainpool-160t1 sign | **0.412 ms** | 0.388 ms |
| Brainpool-160t1 verify | **1.074 ms** | 1.029 ms |
| Brainpool-192t1 sign | **0.546 ms** | 0.522 ms |
| Brainpool-192t1 verify | 1.361 ms | **1.381 ms** |
| Brainpool-224t1 sign | 0.708 ms | **0.712 ms** |
| Brainpool-224t1 verify | 1.851 ms | **1.918 ms** |
| Brainpool-256t1 sign | **0.903 ms** | 0.879 ms |
| Brainpool-256t1 verify | **2.414 ms** | 2.360 ms |
| Brainpool-320t1 sign | **1.400 ms** | 1.391 ms |
| Brainpool-320t1 verify | 3.815 ms | **3.887 ms** |
| Brainpool-384t1 sign | 2.086 ms | **2.147 ms** |
| Brainpool-384t1 verify | 5.484 ms | **5.902 ms** |
| Brainpool-512t1 sign | 4.086 ms | **4.166 ms** |
| Brainpool-512t1 verify | 11.223 ms | **11.557 ms** |
| ECDSA B-163 sign | 0.527 ms | **0.635 ms** |
| ECDSA B-163 verify | 1.760 ms | **2.282 ms** |
| ECDSA K-163 sign | 0.493 ms | **0.595 ms** |
| ECDSA K-163 verify | 1.681 ms | **2.214 ms** |
| ECDSA B-233 sign | 0.596 ms | **0.895 ms** |
| ECDSA B-233 verify | 1.983 ms | **3.296 ms** |
| ECDSA K-233 sign | 0.564 ms | **0.846 ms** |
| ECDSA K-233 verify | 1.971 ms | **3.023 ms** |
| ECDSA B-283 sign | 0.935 ms | **1.421 ms** |
| ECDSA B-283 verify | 3.112 ms | **5.049 ms** |
| ECDSA K-283 sign | 0.863 ms | **1.342 ms** |
| ECDSA K-283 verify | 2.910 ms | **4.731 ms** |
| ECDSA B-409 sign | 1.223 ms | **2.588 ms** |
| ECDSA B-409 verify | 4.057 ms | **9.392 ms** |
| ECDSA K-409 sign | 1.151 ms | **2.314 ms** |
| ECDSA K-409 verify | 3.834 ms | **8.651 ms** |
| ECDSA B-571 sign | 2.358 ms | **5.303 ms** |
| ECDSA B-571 verify | 7.586 ms | **19.857 ms** |
| ECDSA K-571 sign | 2.057 ms | **4.888 ms** |
| ECDSA K-571 verify | 7.161 ms | **18.295 ms** |
| GOST-256 Test sign | **0.822 ms** | 0.783 ms |
| GOST-256 Test verify | **2.372 ms** | 2.245 ms |
| GOST-256 A sign | 0.819 ms | **0.866 ms** |
| GOST-256 A verify | **2.495 ms** | 2.271 ms |
| GOST-256 B sign | **0.845 ms** | 0.816 ms |
| GOST-256 B verify | **2.391 ms** | 2.377 ms |
| GOST-256 C sign | **0.843 ms** | 0.794 ms |
| GOST-256 C verify | **2.325 ms** | 2.282 ms |
| GOST-256 D sign | 0.804 ms | **0.914 ms** |
| GOST-256 D verify | 2.370 ms | **2.381 ms** |
| GOST-512 Test sign | 3.820 ms | **3.949 ms** |
| GOST-512 Test verify | 11.152 ms | **11.435 ms** |
| GOST-512 A sign | **3.865 ms** | 3.829 ms |
| GOST-512 A verify | **12.447 ms** | 11.206 ms |
| GOST-512 B sign | **3.878 ms** | 3.817 ms |
| GOST-512 B verify | **11.184 ms** | 11.047 ms |
| GOST-512 C sign | **3.856 ms** | 3.806 ms |
| GOST-512 C verify | **11.117 ms** | 11.049 ms |
| ML-DSA-44 sign | 1.045 ms | **1.194 ms** |
| ML-DSA-44 verify | **0.346 ms** | 0.290 ms |
| ML-DSA-65 sign | 1.528 ms | **2.218 ms** |
| ML-DSA-65 verify | **0.565 ms** | 0.450 ms |
| ML-DSA-87 sign | **2.417 ms** | 2.232 ms |
| ML-DSA-87 verify | **0.903 ms** | 0.691 ms |

#### 키 합의와 KEM

| | MSVC | GCC |
|---|---|---|
| X25519 keygen | **0.328 ms** | 0.284 ms |
| X25519 derive | **0.165 ms** | 0.156 ms |
| ECDH P-192 keygen | **1.722 ms** | 1.675 ms |
| ECDH P-192 derive | 0.796 ms | **0.805 ms** |
| ECDH P-224 keygen | 2.296 ms | **2.323 ms** |
| ECDH P-224 derive | 1.063 ms | **1.070 ms** |
| ECDH P-256 keygen | **3.066 ms** | 3.022 ms |
| ECDH P-256 derive | **1.390 ms** | 1.361 ms |
| ECDH P-384 keygen | 6.937 ms | **7.019 ms** |
| ECDH P-384 derive | 3.343 ms | **3.407 ms** |
| ECDH P-521 keygen | **16.959 ms** | 16.325 ms |
| ECDH P-521 derive | **8.059 ms** | 7.784 ms |
| ECDH secp256k1 keygen | **2.913 ms** | 2.892 ms |
| ECDH secp256k1 derive | 1.357 ms | **1.396 ms** |
| ECDH bp160r1 keygen | 1.253 ms | **1.320 ms** |
| ECDH bp160r1 derive | **0.596 ms** | 0.581 ms |
| ECDH bp192r1 keygen | 1.691 ms | **1.771 ms** |
| ECDH bp192r1 derive | **0.809 ms** | 0.793 ms |
| ECDH bp224r1 keygen | 2.255 ms | **2.426 ms** |
| ECDH bp224r1 derive | 1.096 ms | **1.182 ms** |
| ECDH bp256r1 keygen | 2.943 ms | **3.040 ms** |
| ECDH bp256r1 derive | 1.387 ms | **1.410 ms** |
| ECDH bp320r1 keygen | **5.773 ms** | 4.708 ms |
| ECDH bp320r1 derive | **2.610 ms** | 2.221 ms |
| ECDH bp384r1 keygen | 6.842 ms | **7.326 ms** |
| ECDH bp384r1 derive | 3.342 ms | **3.429 ms** |
| ECDH bp512r1 keygen | 14.789 ms | **16.070 ms** |
| ECDH bp512r1 derive | 6.868 ms | **7.252 ms** |
| ECDH bp160t1 keygen | **1.419 ms** | 1.370 ms |
| ECDH bp160t1 derive | **0.750 ms** | 0.586 ms |
| ECDH bp192t1 keygen | **2.450 ms** | 1.759 ms |
| ECDH bp192t1 derive | **0.834 ms** | 0.812 ms |
| ECDH bp224t1 keygen | **2.520 ms** | 2.411 ms |
| ECDH bp224t1 derive | 1.055 ms | **1.136 ms** |
| ECDH bp256t1 keygen | 2.973 ms | **3.108 ms** |
| ECDH bp256t1 derive | 1.374 ms | **1.438 ms** |
| ECDH bp320t1 keygen | 4.642 ms | **4.726 ms** |
| ECDH bp320t1 derive | 2.147 ms | **2.203 ms** |
| ECDH bp384t1 keygen | 6.873 ms | **7.339 ms** |
| ECDH bp384t1 derive | 3.308 ms | **3.449 ms** |
| ECDH bp512t1 keygen | 14.437 ms | **15.295 ms** |
| ECDH bp512t1 derive | 6.696 ms | **7.113 ms** |
| ECDH B-163 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-163 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-233 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-233 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-283 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-283 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-409 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-409 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-571 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-571 | (agreement unsupported) | (agreement unsupported) |
| ML-KEM-512 keygen | **0.124 ms** | 0.094 ms |
| ML-KEM-512 encapsulate | **0.101 ms** | 0.079 ms |
| ML-KEM-512 decapsulate | **0.114 ms** | 0.096 ms |
| ML-KEM-768 keygen | **0.194 ms** | 0.145 ms |
| ML-KEM-768 encapsulate | **0.158 ms** | 0.124 ms |
| ML-KEM-768 decapsulate | **0.183 ms** | 0.138 ms |
| ML-KEM-1024 keygen | **0.290 ms** | 0.216 ms |
| ML-KEM-1024 encapsulate | **0.236 ms** | 0.176 ms |
| ML-KEM-1024 decapsulate | **0.275 ms** | 0.190 ms |

#### 해시, 64 KiB

| | MSVC | GCC |
|---|---|---|
| MD4 | **788.4 MiB/s** | 722.5 MiB/s |
| MD5 | 572.5 MiB/s | **716.2 MiB/s** |
| SHA-1 | **1782.1 MiB/s** | 1768.9 MiB/s |
| SHA-224 | **1552.2 MiB/s** | 1544.4 MiB/s |
| SHA-256 | **1556.5 MiB/s** | 1438.9 MiB/s |
| SHA-384 | 349.2 MiB/s | **361.3 MiB/s** |
| SHA-512 | 352.2 MiB/s | **359.0 MiB/s** |
| SHA3-256 | 107.7 MiB/s | **309.4 MiB/s** |
| SHA3-512 | 57.0 MiB/s | **163.6 MiB/s** |
| SHAKE-128 | 132.9 MiB/s | **381.3 MiB/s** |
| SHAKE-256 | 104.6 MiB/s | **309.7 MiB/s** |
| BLAKE2s | 410.6 MiB/s | **417.1 MiB/s** |
| Streebog-256 | 74.7 MiB/s | **107.3 MiB/s** |
| Streebog-512 | 71.5 MiB/s | **108.3 MiB/s** |

#### 블록 암호, CBC, 64 KiB

| | MSVC | GCC |
|---|---|---|
| AES-128-CBC | 1442.4 MiB/s | **1717.9 MiB/s** |
| AES-192-CBC | 1234.9 MiB/s | **1515.3 MiB/s** |
| AES-256-CBC | 1111.9 MiB/s | **1319.9 MiB/s** |
| DES-CBC | **9.1 MiB/s** | 5.1 MiB/s |
| 3DES-CBC | **3.0 MiB/s** | 1.7 MiB/s |
| ARIA-128-CBC | **58.1 MiB/s** | 38.3 MiB/s |
| ARIA-192-CBC | **51.8 MiB/s** | 33.1 MiB/s |
| ARIA-256-CBC | **45.3 MiB/s** | 28.4 MiB/s |

#### AEAD seal, 64 KiB

| | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305 | 751.0 MiB/s | **841.2 MiB/s** |
| XChaCha20-Poly1305 | 749.2 MiB/s | **841.5 MiB/s** |
| AES-256-GCM | 371.6 MiB/s | **465.3 MiB/s** |

#### AEAD seal, 64 B, 레코드당

| | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305 | **410 ns** | 338 ns |
| XChaCha20-Poly1305 | **545 ns** | 446 ns |
| AES-256-GCM | 220 ns | **234 ns** |

### P1과 P7이 닫지 못한 크로스-툴체인 격차 둘

기록되어 있던 격차는 RSA와 MD5 둘이었고, 둘 다 사라졌습니다. RSA-2048
서명은 `CMontgomery`를 그 아래로 연결하기 전에는 8.06 ms 대 19.1 ms였고
(지금은 5.62 대 5.25 ms), MD5의 23% 부족은 P7의 라운드 언롤링으로
닫혔습니다(지금은 GCC **719.7 MiB/s** 대 MSVC 571.7 — 이제 GCC가 앞섭니다).
모든 알고리즘을 다루면서 기록된 적 없는 격차가 둘 더 나왔습니다.

- **DSA-2048이 GCC에서 서명이 2.7배 느립니다.** 7.29 ms 대 2.70 ms이고,
  검증은 18.1 ms 대 6.6 ms입니다. 이것은 RSA의 격차보다 넓었고, 노이즈가
  아니라 코드 생성 결함으로 읽힐 만한 유일하게 남은 차이입니다. 백엔드는
  RSA가 쓰는 것과 같은 `CBigNum`이므로, 원인은 아마 `CMontgomery`가 거기서
  고친 것과 같은 형태일 것입니다. 다만 프로파일을 받아 본 적은 없으므로,
  그것은 가설일 뿐입니다.
- **모든 GF(2^m) 곡선이 GCC에서 1.2~2.1배 느립니다.** B-571 검증은 19.9 ms
  대 7.6 ms입니다. 곡선 열 개가 모두 같은 방향으로 움직이는데, 이것은 열 개의
  우연이 아니라 `CGf2m`의 공통 원인을 가리킵니다.

둘 다 이 README의 각주가 아니라
[`docs/roadmap.md`](docs/roadmap.ko.md)의 항목으로 들어갈 자리입니다. 측정이
사라지지 않도록 여기에 기록해 두지만, 어느 쪽도 조사한 적은 없습니다.

### 닫힌 AES-CBC 격차

AES-256-CBC는 남아 있던 격차 중 가장 넓었습니다 — OpenSSL 대비 0.53배로, 전용
하드웨어 명령을 가진 암호가 있을 자리가 아닌 곳이었습니다. 원인은 암호가
아니었습니다. `ISymmetricTransformer`의 블록 단위 인터페이스가
`CbcTransformer`에게 블록마다 `AesCore::encryptBlock()`을 한 번씩 부르게 했는데,
그 함수는 블록을 읽고 라운드를 돌리고 결과를 저장한 뒤 돌아옵니다. 그러면
트랜스포머가 암호문을 체인에 다시 복사하고, 다음 블록의 읽기가 그것을
가져갑니다. 블록당 읽기 두 번과 저장 두 번이 모두 레지스터를 벗어날 필요가
없는 체인에 쓰이고 있었습니다.

`AesCore::encryptCbcBulk()`는 체인 값을 `__m128i`에 들고 전체 수열을 돌려서,
이것이 블록당 읽기와 저장 각각 한 번으로 줄어듭니다. AES는 CPU에 AES-NI가 있는
곳에서만 이것을 제공하며, 암호 위의 어느 것도 대체하지 않습니다. 출력 공간 검사,
나머지 처리, PKCS#7 논리는 전부 제자리에 남아 있고, 이것이 두 경로가 같은 바이트를
만드는 이유입니다.

같은 빌드 디렉터리에서 연달아 잰 것, 세 실행의 중간값:

| | 이전 | 이후 | |
|---|---|---|---|
| AES-128-CBC, MSVC | 673.3 MiB/s | 1442.4 MiB/s | 2.14배 |
| AES-192-CBC, MSVC | 617.1 MiB/s | 1234.9 MiB/s | 2.00배 |
| AES-256-CBC, MSVC | 574.0 MiB/s | 1111.9 MiB/s | 1.94배 |
| AES-128-CBC, GCC | 847.2 MiB/s | 1717.9 MiB/s | 2.03배 |
| AES-192-CBC, GCC | 775.0 MiB/s | 1515.3 MiB/s | 1.95배 |
| AES-256-CBC, GCC | 717.2 MiB/s | 1319.9 MiB/s | 1.84배 |

AES-256-GCM은 그대로입니다(GCC 473 MiB/s, 이전 465와 노이즈 내). GHASH가 암호
대신 병목이고, AEAD는 CBC 경로로 들어가지 않기 때문입니다. 이식 가능한 빌드
(`CERTPP_DISABLE_HWACCEL_AES`)는 같은 스위트를 통과하고 벌크 경로를 전혀 쓰지
않습니다. 거기서는 `AesCore::hasAesNi()`가 false를 반환하므로 트랜스포머가 모든
것을 블록 단위 함수로 처리합니다.

### 느린 행들이 말하는 것

- **DES와 3DES가 AES보다 1000배 느립니다.** 이는 라이브러리가 아니라 암호
  자체가 느린 것입니다. 3DES는 블록당 DES 연산을 세 번 수행하고, DES는 어떤
  x86에서도 가속이 없습니다.
- **ARIA가 AES보다 약 45배 느립니다.** 이유는 정반대입니다. AES-NI는 하드웨어
  명령이고 ARIA에는 그것이 없어서, 이식 가능한 라운드가 구현 전부입니다. 새
  하드웨어 없이는 뺄 것이 없습니다.
- **소수체 곡선에서는 서명이 검증을 이깁니다.** P-256은 서명 0.91 ms, 검증
  2.43 ms입니다. 서명은 *고정* 베이스 점을 곱하고 미리 계산한 창 표를
  쓰는 반면, 검증은 호출자가 준 점을 곱하므로 그럴 수 없기 때문입니다.
- **RSA-2048은 설계가 비대칭입니다.** `e = 65537`이 검증을 곱셈 세 번으로
  만드는 반면, 서명은 완전한 CRT 지수화입니다.
- **AES-256-GCM은 AES-NI가 있음에도 ChaCha20-Poly1305 아래에 있습니다.**
  암호가 아니라 GHASH가 병목이고, AEAD는 `1/total = 1/cipher + 1/mac`으로
  합성되기 때문입니다.
- **64 B AEAD 행은 64 KiB 행과 뒤집힙니다.** AES-256-GCM은 레코드당 더
  빠르고(410 ns 대 220 ns) 대용량에서는 더 느립니다(751 대 371 MiB/s).
  AES-GCM은 블록 하나를 암호화하고 ChaCha20은 두 개를 암호화하는데, 작은
  레코드는 이 차이를 상각할 수 없기 때문입니다. 대용량 발신자와 레코드 단위
  호출자는 서로 다른 승자를 보고 있습니다.

나노초 단위 수치는 이 절에서 가장 시끄럽습니다. 두 AEAD 사이에서 30% 미만인
격차는 미정으로 보십시오.

### WSL2, 그리고 GCC 열이 *아닌* 것

GCC 수치는 **WSL2 위**에서 측정했습니다. 이 CPU의 bare metal 리눅스 설치가
아니라 VM 안의 실제 리눅스 커널이며, 이것은 위 조건의 절-clause가 아니라
독립적으로 남길 만한 기록입니다. 이 하네스는 단일 스레드 CPU-bound 암호
연산이므로 하이퍼바이저가 각 측정에서 차지하는 몫은 작아야 합니다. 다만
그것은 작아야 *할*이라는 논지이지 실제로 작다는 것을 보여 주지는 않으며,
이번 실행은 그 오버헤드를 어느 방향으로도 정량하지 않았습니다.

그러므로 이 열은 *이 툴체인이 이 조건에서*의 결과이지 리눅스 전반의 성능이
아닙니다. 이것이 가장 중요한 항목은 위의 DSA와 GF(2^m) 격차입니다. 컴파일러
결함으로 읽힐 만큼 큰 유일하게 남은 차이이며, 그러니 bare metal에서 다시
측정하기 전에 결함이라 부르지 말아야 하는 이유도 정확히 그것입니다.

두 열에 공통으로 적용되는 한계가 하나 더 있습니다. "Release"는 하나의 설정이
아닙니다. CMake의 기본값은 MSVC가 `/O2`, GCC가 `-O3`이므로 툴체인과 최적화
레벨이 함께 변합니다.

[`docs/roadmap.md`](docs/roadmap.ko.md)에 목표, 이미 끝난 것, 그리고 남은 각
공백이 실제로 무엇을 필요로 하는지가 있습니다.

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
