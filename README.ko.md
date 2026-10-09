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
작은 것은 결과가 아닙니다. 굵게는 그 열에서 가장 빠른 값입니다.

| 서명 | MSVC sign | MSVC verify | GCC sign | GCC verify |
|---|---|---|---|---|
| Ed25519 | **0.20 ms** | **0.87 ms** | **0.16 ms** | **0.71 ms** |
| ML-DSA-65 | 1.67 ms | 0.56 ms | 1.56 ms | 0.45 ms |
| ECDSA P-256 | 0.92 ms | 2.44 ms | 0.86 ms | 2.31 ms |
| ECDSA P-384 | 2.10 ms | 5.52 ms | 1.99 ms | 5.50 ms |
| ECDSA P-521 | 4.64 ms | 13.4 ms | 4.50 ms | 12.4 ms |
| Ed448 | 2.47 ms | 10.6 ms | 2.46 ms | 10.4 ms |
| RSA-2048 | **4.69 ms** | 0.140 ms | 5.48 ms | 0.156 ms |

| 키 합의 / KEM | MSVC 키 생성 | GCC 키 생성 | MSVC 연산 | GCC 연산 |
|---|---|---|---|---|
| X25519 | 0.33 ms | 0.280 ms | 0.164 ms derive | 0.140 ms derive |
| ML-KEM-768 | 0.193 ms | 0.142 ms | 0.169 / 0.185 ms encap/decap | 0.117 / 0.130 ms encap/decap |
| ECDH P-256 | 3.15 ms | 2.98 ms | 1.40 ms derive | 1.39 ms derive |

해시와 AEAD seal, 64 KiB:

| 해시 | MSVC | GCC |
|---|---|---|
| SHA-256 | **1534 MiB/s** | **1552 MiB/s** |
| MD5 | **593 MiB/s** | 455 MiB/s |
| BLAKE2s | 412 MiB/s | 401 MiB/s |
| SHA-512 | 353 MiB/s | 364 MiB/s |
| SHA3-256 | 108 MiB/s | 308 MiB/s |
| Streebog-256 | 75 MiB/s | 106 MiB/s |

| AEAD seal, 64 KiB | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305 | 578 MiB/s | **650 MiB/s** |
| XChaCha20-Poly1305 | 577 MiB/s | 648 MiB/s |
| AES-256-GCM | 370 MiB/s | 475 MiB/s |

위 64 KiB 행들은 AES-256-GCM을 마지막에 놓습니다. 64바이트에서는 셋 중 가장
빠르고, 그 역전은 두 툴체인 모두에서 재현됩니다.

| AEAD seal, 64 B | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305 | 410 ns | 332 ns |
| XChaCha20-Poly1305 | 545 ns | 449 ns |
| AES-256-GCM | **225 ns** | **179 ns** |

이 역전은 우연한 것이 아니라 구조적입니다. AES-GCM은 블록 하나를 암호화하는데
ChaCha20은 두 개를 암호화하고, 추가된 하나가 counter 0에서 Poly1305 one-time
key를 유도하는 블록입니다(RFC 8439 2.6). AES-GCM이 치르지 않는 비용이고,
작은 레코드에서는 페이로드로 상각할 수 없는 비용입니다. 양쪽 방향 모두
의미가 있습니다. 대용량을 보내는 쪽은 KiB 표를 보고, 한 번에 레코드 하나씩
seal하는 호출자는 AES-NI가 ChaCha의 더 단순한 setup보다 얻는 것이 적은 이
표를 보십시오.

이 나노초 수치는 이 절에서 가장 시끄러운 값입니다 — MSVC 실행 간 편차가 이
구간에서 24%, KiB 구간에서 2%입니다 — 여기도 나머지처럼 best-of-three이지만,
두 AEAD 사이에서 ~30% 미만인 격차는 미정으로 보십시오.

### WSL2, 그리고 GCC 열이 *아닌* 것

GCC 수치는 **WSL2 위**에서 측정했습니다. 이 CPU에 bare metal 리눅스를 설치한
환경이 아니라 VM 안의 실제 리눅스 커널이며, 이것은 위 조건의 절-clause가
아니라 독립적으로 남길 만한 기록입니다. 이 하네스는 단일 스레드 CPU-bound
암호 연산이므로 하이퍼바이저가 각 측정에서 차지하는 몫은 작아야 합니다.
다만 그것은 작아야 *할*이라는 논지이지 실제로 작다는 것을 보여 주지는
않으며, 이번 실행은 그 오버헤드를 어느 방향으로도 정량하지 않았습니다.

따라서 이 열은 *이 툴체인이 이 조건에서*의 결과이지 리눅스 전반의 성능이
아닙니다. 이 점이 가장 중요한 항목은 아래의 RSA 격차입니다. 여기서 측정
노이즈가 아니라 컴파일러 결함으로 읽힐 만큼 큰 차이는 이것 하나뿐인데,
그러니 bare metal에서 다시 측정하기 전에 결함이라 부르지 말아야 하는 이유도
정확히 그것입니다.

두 열에 공통으로 적용되는 한계가 더 있습니다. "Release"는 하나의 설정이
아닙니다. CMake의 기본값은 MSVC가 `/O2`, GCC가 `-O3`이므로 툴체인과 최적화
레벨이 함께 변합니다. 그리고 MSVC 열은 이 CPU에 대해 이전에 게시된 것을
대체하는데, 그쪽 자체의 설명이 부하가 걸린 상태에서 측정했다고 적혀 있었습니다.
다시 측정하니 모든 행이 같거나 더 빠르며 대부분은 10~20% 빠릅니다 — 가장 큰
변화는 ECDSA P-256 검증으로 3.53 ms에서 2.44 ms인데, 위에서 말한 편차를 아주
조금 넘어섭니다 — 그 어느 것도 설명할 코드 변경 없이 그러했습니다.

### 그 안의 다섯 가지는 설명할 만합니다

각각이 노이즈가 아니라 구현의 성질이기 때문입니다.

- **Ed25519는 최적화된 구현(50~100 µs에 검증합니다)보다 한 자릿수 벗어나
  있고**, 나머지 전부는 그보다 더 벗어나 있습니다. 그것은 전용 constant-time
  필드(`Fe25519`) 위에 있는 하나뿐인 곡선입니다. 소수체 곡선들은 여전히
  Montgomery 축약을 쓰는 범용 `CBigNum` 위에서 돌아갑니다.
- **소수체 곡선에서는 서명이 검증을 앞섭니다** — P-256은 0.92 ms에 서명하고
  2.44 ms에 검증합니다 — 서명은 *고정된* 기준점을 곱하며 미리 계산된 window
  표를 쓰는 반면, 검증은 호출자가 공급한 점을 곱하므로 그럴 수 없기 때문입니다.
- **RSA-2048은 설계상 한쪽으로 치우쳐 있습니다.** `e = 65537`이 검증을 곱셈
  세 번으로 만드는 반면, 서명은 schoolbook 큰 수 백엔드에서의 완전한 CRT
  지수화입니다.
- **AES-256-GCM은 AES-NI가 있어도 ChaCha20-Poly1305 아래에 앉습니다.** 암호가
  아니라 GHASH가 병목이고, AEAD가 `1/total = 1/cipher + 1/mac`로 합성되기
  때문입니다. 두 툴체인 모두에서 재현되지만, GCC 쪽에서 ChaCha20-Poly1305와
  벌리는 폭이 더 큽니다.
- **RSA는 두 툴체인이 이제 동의하는 유일한 행이며, 거기까지 오는 과정이
  기록할 만합니다.** RSA는 8.06 ms 대 19.1 ms — 2.37배 격차 — 였는데, 개인 키
  연산의 모듈러 곱셈 전부가 `CBigNum::modExp()`를 지나갔고
  `CBigNum::mod()`은 완전한 Knuth-D 긴 나눗셈이기 때문입니다. 이는 값 의존적
  작업(몫 자릿수마다 정규화와 시행 뺄셈)이므로 두 컴파일러가 다르게 번역합니다.
  `CMontgomery::modExp()`가 이미 있었고 나눗셈 없이 같은 일을 하는데, 곡선들은
  이미 그 위에 있었습니다. **유일하게 올라가지 않은 호출자가 RSA였습니다.**
  그곳으로 보내자 서명은 MSVC에서 42%, GCC에서 71% 줄었고, 부수적으로 격차도
  대부분 사라졌습니다 — 2.37배에서 1.17배입니다.
- **두 툴체인이 갈리는 곳은 MD5 하나이고, 방향도 반대입니다.** 593 MiB/s에 대해
  455 MiB/s입니다 — 가속이 관여하지 않는 스칼라 루틴 하나로, 크고 독립적인
  작업은 아닙니다. 그 외에는 GCC가 같거나 빠릅니다 — SHA3-256은 2.8배,
  Streebog은 42%, ML-KEM은 30%, AES-256-GCM은 28%입니다. 남은 항목의 근거는
  [`docs/roadmap.md`](docs/roadmap.ko.md)에 있습니다.

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
