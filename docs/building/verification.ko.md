# 테스트, 예제 및 정적 분석

[English](verification.md)

## 테스트

← [빌드와 검증](../BUILDING.ko.md)

모든 테스트 케이스는 [`tests/`](../../tests) 아래에 있으며, 소스 파일 하나당
CMake 실행 파일 하나가 대응하고, 각 파일이 검증하는 `include/certpp/`(및
`src/`) 경로를 그대로 따라갑니다 (예를 들어
[`tests/asn1/decoder.cpp`](../../tests/asn1/decoder.cpp)는 `asn1/decoder.hpp`를
테스트합니다). 특정 헤더 하나에 대응하지 않는 파일(여러 헤더에 걸친
통합/왕복 검사, 예컨대
[`tests/asn1/roundtrip.cpp`](../../tests/asn1/roundtrip.cpp))도 1:1 헤더 대응만
없을 뿐, 똑같이 해당 모듈 디렉터리 아래에 둡니다.

테스트는 [doctest](https://github.com/doctest/doctest)를 사용하며,
[`third-party/doctest/doctest.h`](../../third-party/doctest/doctest.h)에 단일
헤더로 벤더링되어 있습니다
([`third-party/CMakeLists.txt`](../../third-party/CMakeLists.txt)가 이를 CMake
`doctest` INTERFACE 타깃으로 노출하며, `CERTPP_BUILD_TESTS=ON`일 때만
`add_subdirectory`됩니다). 각 테스트 파일은 `#include
<doctest/doctest.h>` 앞에서 `DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN`을
`#define`하고, 평범한 `TEST_CASE(...)`/`CHECK(...)`/`REQUIRE(...)` 블록을
작성합니다. 모든 테스트 파일이 각자의 실행 파일로 컴파일되므로(아래 참고),
각 파일이 자기 `main`을 생성해도 ODR 충돌이 발생하지 않습니다.

빌드 및 실행:

```sh
cmake -S . -B build
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

`CMakeLists.txt`는 `src/**/*.cpp`와 똑같은 방식으로 `tests/**/*.cpp`를
glob하므로, 새 테스트 파일은 자동으로 포함됩니다 -- 어디에도 따로 나열할
필요가 없습니다. 테스트 빌드를 아예 건너뛰려면
`-DCERTPP_BUILD_TESTS=OFF`를 지정하세요.

CMake는 테스트 타깃에서 `NDEBUG`를 해제하고 모든 테스트 번역 단위에
[`tests/support/runtime.hpp`](../../tests/support/runtime.hpp)를 강제 include합니다. 따라서 Release에서도
표준 `assert`가 활성 상태로 유지되고, 실패한 식과 소스 위치를 `stderr`에 출력합니다.
Windows에서는 런타임 shim이 CRT 보고와 abort를 콘솔로 보내고 모달 오류 대화상자를
억제하므로, 무인 CTest 실패가 버튼 입력을 기다리지 않고 종료되어 로그를 남깁니다.

디스크상의 픽스처 데이터가 필요한 테스트(예:
[`tests/x509/realcerts.cpp`](../../tests/x509/realcerts.cpp)가 쓰는, 실제
인증서 파일들이 담긴 `certs/` 하위 디렉터리)는 모든 테스트 타깃이 자동으로
받는 `CERTPP_TEST_DIR` 컴파일 정의로 그 위치를 찾을 수 있습니다. 이 값은
해당 테스트 자신의 `.cpp` 파일이 있는 디렉터리의 절대 경로이며, 슬래시
방향이 정규화되어 있습니다 (Windows 역슬래시를 그대로 쓰면 문자열 리터럴이
깨집니다). 덕분에 테스트는 어떤 작업 디렉터리에서 실행되든 자신의 픽스처를
안정적으로 찾을 수 있습니다 -- `ctest`의 기본 작업 디렉터리는 `.exe`를
직접 실행할 때와 다르고, 그 둘 모두 호출자의 현재 디렉터리에 따라
달라집니다.

테스트는 보통 라이브러리에 링크하고 공개 헤더를 사용합니다. 비공개 구현을
직접 비교해야 하는 테스트는 명시적인 `src/` 파일 목록을 자기 실행 파일에
추가로 컴파일하고 `src/`를 인클루드 경로에 넣습니다. 현재 해당하는 것은:

- ML-KEM의 비공개 ring과 codec 단위를 컴파일하는 `tests/crypto/kems/` 테스트,
- 각자 필요한 비공개 ML-DSA 단위 부분집합을 컴파일하는 ring, rounding, codec,
  sampler, parameter, ACVP 테스트,
- GHASH, StreebogCore, SHA-512 바이트 로드 폴백, Fe25519, AesCore의 이식 가능/
  가속 경로 일치를 직접 검사하는 테스트입니다.

이 번역 단위들은 공개 API가 없으므로 `CERTPP_API`도 붙지 않습니다 -- 공유
오브젝트에서 익스포트되지 않으며, 링크로는 접근할 수 없습니다. 테스트에 두
번째 사본을 컴파일해 넣어도 안전한 것은 *바로* 이들이 익스포트되지 않기
때문이며, 그래서 라이브러리 자신의 것과 절대 충돌할 수 없습니다.

이 목록은 glob이 아니라 `CMakeLists.txt`의 `CERTPP_TEST_PRIVATE_SOURCES`에
직접 적어 둡니다. 익스포트된 구현은 테스트가 이미 `certpp`에서 그 심볼을
임포트하므로 이 목록에 넣지 않습니다. 다시 추가하면 중복 정의가 됩니다. 따라서
비공개 단위를 추가하는 것은 의도적인 CMake 변경이며, 그 밖은 공개 표면을 통해
테스트합니다.

## 설치 소비자, 퍼저, 검토 도구

일반 CTest 실행에는 `install_consumer`가 포함됩니다. 선택한 구성을 설치하고
`find_package(certpp)`를 쓰는 별도 프로젝트를 구성·빌드·실행하며, 공개 헤더와
링크된 라이브러리가 같은 버전을 보고하는지 검사합니다. 이 릴리스 검증만 실행하려면:

```sh
ctest --test-dir build -C Debug -R install_consumer --output-on-failure
```

파서 퍼저는 Clang을 사용해 별도 디렉터리에 빌드합니다:

```sh
cmake -S . -B build-fuzz -DCMAKE_CXX_COMPILER=clang++ \
  -DCERTPP_BUILD_FUZZERS=ON -DCERTPP_BUILD_TESTS=OFF \
  -DCERTPP_BUILD_EXAMPLES=OFF
cmake --build build-fuzz --config Debug
./build-fuzz/certpp_fuzz_asn1_der -runs=1000
```

나머지 타깃은 `certpp_fuzz_containers`, `certpp_fuzz_dnssec`,
`certpp_fuzz_json_bson`, `certpp_fuzz_x509_objects`입니다. libFuzzer에
AddressSanitizer와 UndefinedBehaviorSanitizer를 함께 사용합니다. 제한된 횟수의 깨끗한
실행은 smoke 검사이며, 장기 캠페인의 corpus는 소스 트리 밖에 보관합니다.

ML-DSA 타이밍 검토 도구도 선택적으로 빌드합니다:

```sh
cmake -S . -B build-audit -DCERTPP_BUILD_AUDIT_TOOLS=ON \
  -DCERTPP_BUILD_TESTS=OFF -DCERTPP_BUILD_EXAMPLES=OFF
cmake --build build-audit --config Release
./build-audit/certpp_mldsa_timing_audit
```

거부 결과별 타이밍 분포를 출력하여 검토자가 비교할 수 있게 합니다. 수동 검토를 위한
근거이며 constant-time 인증이나 안정적인 벤치마크 임계값은 아닙니다.

## Cppcheck 정적 분석

유지 보수하는 FLOSS 정적 분석 기준선은 2026-10-16에 WSL 2의 Ubuntu 24.04에서
Ubuntu 패키지 Cppcheck 2.13.0으로 갱신했습니다. 주 분석은 CMake의 GCC 컴파일
데이터베이스를 사용하므로 Cppcheck가 라이브러리 빌드와 같은 소스 파일, include
경로, 언어 표준 및 프로젝트 정의를 확인합니다. 설치 및 재현 명령은 다음과 같습니다.

```sh
sudo apt-get update
sudo apt-get install -y cppcheck
cmake -S . -B build-cppcheck \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCERTPP_BUILD_SHARED=OFF \
  -DCERTPP_BUILD_TESTS=OFF \
  -DCERTPP_BUILD_EXAMPLES=OFF
mkdir -p build-cppcheck/cppcheck-cache
cppcheck --project=build-cppcheck/compile_commands.json \
  --cppcheck-build-dir=build-cppcheck/cppcheck-cache \
  --enable=all --inconclusive --check-level=exhaustive \
  --inline-suppr --suppress=missingIncludeSystem \
  --suppress=unmatchedSuppression \
  --xml --xml-version=2 \
  2> build-cppcheck/cppcheck-library.xml
```

이 검사는 라이브러리 번역 단위 121개 전부와 그 번역 단위에서 도달하는 공개·비공개
헤더를 포함했습니다. 수정 후 진단 529건의 분류는 다음과 같습니다.

| 심각도 | 개수 | 검토 결과 |
| --- | ---: | --- |
| error | 0 | 남은 Cppcheck 오류가 없습니다. |
| warning | 15 | 모두 helper를 통한 초기화 또는 첫 읽기 전 보호 조건을 인식하지 못한 오탐으로 검토했습니다. |
| performance | 60 | 주로 생성자 초기화 목록 제안이며, 정확성 결함은 확인되지 않았습니다. |
| style | 453 | 대부분 공개 API를 미사용으로 판단한 결과, 의도적인 암시적 변환 및 광범위한 리팩터링 제안입니다. |
| information | 1 | checker 적용 보고: 이 구성에서 592개 중 172개가 활성화되었습니다. |

남은 경고 15건의 원인은 세 가지입니다. 10건은 변환 생성자가 명시적으로 초기화하는
`TString` 필드와 `memset`으로 초기화하는 `TStringConverter::_state`를 지적합니다.
4건은 `CBuffer`와 `COctet`의 복사 대입이 저장 필드를 갱신하지 않는다고 판단하지만,
두 연산자 모두 해당 필드를 갱신하거나 비우는 `store()`에 위임합니다. 마지막 경고는
`ChaCha20Transformer::_keystream`에 관한 것입니다. `_keystreamPos`가 블록 크기로
시작하므로 배열을 처음 읽으려 할 때 반드시 먼저 블록을 생성합니다.

검토 범위에서 발견한 조치 가능한 경고는 모두 수정했습니다.

- `SDateTime::now()`에서 UTC 조기 반환 뒤 도달할 수 없던 두 번째 `asUtc` 분기를
  제거했습니다.
- `ISymmetricKey`가 알고리즘을 `ESYM_UNKNOWN`으로 초기화하여, 향후 파생 키 타입이
  값을 설정하기 전에 미정 값을 노출할 수 없게 했습니다.
- 인증서 발급 예제 3개가 SHA-1 해시 객체 생성 결과를 역참조하기 전에 검사합니다.
  이에 따라 possible-null 경고 6건이 없어졌습니다.

컴파일 데이터베이스를 이용해 컴파일 대상 예제 16개를 추가 검사한 결과 오류는 없었고,
경고 10건은 모두 위에서 검토한 `TString` 오탐과 같았습니다. ML-DSA 타이밍 감사 도구와
독립 실행형 Fe25519 제곱 생성기에서는 error와 warning이 나오지 않았습니다. 생성된 위키
snippet은 따로 검사하지 않았으며, 그 원본인 유지 보수 대상 C++ 예제 소스는 예제 검사에
포함했습니다.

선택형 radix-51 소스도 x86-64 GCC의 `__int128` 기능 매크로를 명시하여 직접 검사했고
error와 warning이 없었습니다. Cppcheck 2.13.0은 컴파일 데이터베이스에서 GCC 내장
`__SIZEOF_INT128__`를 추론하지 않으므로, `CERTPP_ENABLE_FE25519_RADIX51=ON`인 전체
프로젝트를 별도 정의 없이 검사하면 헤더의 의도적인 미지원 대상 `#error`에 도달합니다.
이는 소스 결함이 아니라 분석기 모델의 한계입니다.

요청에 따라 WSL에서 실행했으므로 이 기준선은 Linux 전용입니다. MSVC 또는 Windows
CRT에서만 선택되는 분기는 포함하지 않습니다. 테스트 소스는 벤더링된 doctest 헤더를
각 테스트 번역 단위에서 전개하는 Cppcheck 2.13.0 정밀 검사가 현실적으로 너무 느려
제외했습니다. 이 파일들의 검증은 컴파일러 빌드와 CTest가 계속 담당합니다. 원시 XML과
Cppcheck 캐시는 무시되는 빌드 디렉터리에 두며 유지 보수 문서로 추적하지 않습니다.

## 예제

← [빌드와 검증](../BUILDING.ko.md)

[`examples/`](../../examples)에는 작고 실행 가능한 CA 계층 구조 예제가 들어
있습니다 (루트, 중간 CA, 리프를 차례로 발급한 뒤 리프의 키로 데이터를
서명하고 검증합니다). 기본적으로 빌드되며, 건너뛰려면
`-DCERTPP_BUILD_EXAMPLES=OFF`를 지정하세요.

```sh
cmake --build build --config Debug
./build/Debug/certpp_example_01_issue_ca_root
```

`CMakeLists.txt`는 `examples/*.cpp`를 glob하며(재귀적이지 않습니다 --
`common.hpp`는 예제가 아니라 공용 지원 코드입니다), 파일 하나당 실행 파일
하나를 `certpp_example_<stem>`이라는 이름으로 만듭니다. 테스트와 달리 이들은
의도적으로 CTest에 등록하지 **않습니다**: 각 예제가 다음 예제가 읽을
`.pem`을 기록하므로, 서로 독립적인 것이 아니라 순서가 있기 때문입니다. 모든
예제 타깃은 `examples/output/`(구성 시점에 생성되며 gitignore됩니다)을
가리키는 `CERTPP_EXAMPLE_OUTPUT_DIR` 컴파일 정의를 받으므로, 어떤 작업
디렉터리에서 실행하더라도 서로의 출력을 찾아낼 수 있습니다. 전부 새 키로
다시 생성하려면 그 디렉터리를 삭제하거나 1단계부터 다시 실행하세요. 각
예제가 무엇을 하는지는
[`examples/README.md`](../../examples/README.md)(영문)를 참고하세요.
