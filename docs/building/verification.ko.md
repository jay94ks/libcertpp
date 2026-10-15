# 테스트와 예제

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
