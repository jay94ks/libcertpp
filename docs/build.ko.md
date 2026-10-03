# 빌드

[English](build.md)

`libcertpp`는 CMake(3.15 이상)로 빌드하며, C++17 컴파일러가 필요합니다.

## 구성 및 빌드

공유 라이브러리 (기본값):

```sh
cmake -S . -B build
cmake --build build --config Debug
```

정적 라이브러리:

```sh
cmake -S . -B build -DCERTPP_BUILD_SHARED=OFF
cmake --build build --config Debug
```

단일 구성(single-config) 제너레이터(Makefiles, Ninja)에서는 `--config`
대신 빌드 타입을 지정하세요:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

## CMake 옵션

| 옵션                  | 기본값  | 효과                                                           |
|------------------------|---------|----------------------------------------------------------------|
| `CERTPP_BUILD_SHARED`  | `ON`    | `certpp`를 정적 라이브러리(`.lib`/`.a`)가 아니라 공유 라이브러리(`.dll`/`.so`)로 빌드합니다. |
| `CERTPP_BUILD_TESTS`   | `ON`    | `tests/` 아래의 테스트 실행 파일들을 빌드하고 CTest에 등록합니다. |
| `CERTPP_BUILD_EXAMPLES` | `ON`   | `examples/` 아래의 프로그램들을 `certpp_example_<name>` 실행 파일로 빌드합니다. 이들은 CTest에 등록되지 않습니다 (인증서를 `examples/output/`에 기록하며, 순서대로 직접 실행하도록 만들어져 있습니다). [`examples/README.md`](../examples/README.md)(영문)를 참고하세요. |
| `CERTPP_RNG_FALLBACK`  | `OFF`   | OS CSPRNG(Windows에서는 `BCryptGenRandom`, Linux에서는 `getrandom(2)`과 그것이 안 될 때의 `/dev/urandom`, 그 외 POSIX 플랫폼에서는 `/dev/urandom`)를 사용할 수 없는 경우 `crypto::CRng::fill()`이 `std::random_device`로 폴백하도록 허용합니다. 기본값인 `OFF`에서는 폴백이 컴파일 단계에서 제외되고, 그런 경우 `fill()`은 대신 `ERET_NOTSUP`을 반환합니다 -- `std::random_device`는 모든 표준 라이브러리에서 암호학적으로 안전하다고 보장되지 않으므로, OS 수준 CSPRNG가 정말로 존재하지 않는 환경을 위한 임시 방편으로만 켜십시오. |
| `CERTPP_DISABLE_HWACCEL_SIMD` | `OFF` | `CBigNum`의 ADX/BMI2, `CGf2m`과 `Ghash`의 PCLMULQDQ, `ChaCha20`의 4-블록 SSE2 키스트림을 비활성화하고(그리고 전이적으로, 앞의 두 가지 위에 쌓아올린 모든 비대칭키 알고리즘과 ChaCha20-Poly1305·XChaCha20-Poly1305·AES-GCM AEAD까지), 항상 소프트웨어 루프를 사용합니다. 켜든 끄든 x86-64 전용입니다 -- 다른 아키텍처에서는 아무런 영향이 없으며, 그런 아키텍처에는 애초에 소프트웨어 루프만 존재합니다. ADX/BMI2 및 PCLMULQDQ 경로와 달리 SSE2 경로는 런타임 CPU 검사가 필요하지 않습니다. SSE2는 x86-64 ABI의 일부이기 때문입니다. |
| `CERTPP_DISABLE_HWACCEL_SHA` | `OFF` | `SHA1`/`SHA256`의 SHA-NI 가속을 비활성화하고, 항상 소프트웨어 압축 루프를 사용합니다. 켜든 끄든 x86-64 전용입니다. `MD5`/`SHA384`/`SHA512`/`SHAKE128`/`SHAKE256`은 이 옵션과 무관하게 하드웨어 가속 경로가 아예 없으므로, 이 옵션은 그 알고리즘들에 아무런 영향이 없습니다. SHA-NI 자체가 SHA-1과 SHA-256만 다루기 때문입니다. Intel의 별도 SHA512 확장은 존재하지만, 믿고 쓸 수 있을 만큼 널리 퍼지지 않은 최신 확장이며 이 라이브러리는 사용하지 않습니다. |
| `CERTPP_DISABLE_HWACCEL_AES` | `OFF` | `AesCore`의 AES-NI 가속을 비활성화하여 -- 따라서 `AES` 블록 암호와 그 위에 쌓아올린 AES-GCM AEAD 양쪽 모두에 대해 -- 항상 소프트웨어 라운드 함수를 사용합니다. 켜든 끄든 x86-64 전용입니다. `DES`/`TripleDES`는 이 옵션과 무관하게 하드웨어 가속 경로가 아예 없으므로(주류 x86 확장 중 이들을 다루는 것이 없습니다), 이 옵션은 그 알고리즘들에는 아무런 영향이 없습니다. `ChaCha20`은 가속 경로가 있긴 하지만, AES 확장이 아니라 SSE2 기반이므로 `CERTPP_DISABLE_HWACCEL_SIMD`가 대신 이를 제어합니다. |

## 설치

```sh
cmake --install build --prefix <install-prefix>
```

`certpp` 라이브러리, 공개 헤더(`include/`), 그리고
`<prefix>/lib/cmake/certpp` 아래의 완전한 CMake 패키지 --
`certpp-targets.cmake`에 더해 `certpp-config.cmake`와
`certpp-config-version.cmake` -- 를 설치합니다. 이를 사용하는 프로젝트는
평범한 방식으로 가져다 쓸 수 있습니다:

```cmake
find_package(certpp REQUIRED)
target_link_libraries(myapp PRIVATE certpp::certpp)
```

해당 prefix가 이미 검색 경로에 없다면 `-DCMAKE_PREFIX_PATH=<prefix>`를
함께 지정하면 됩니다. 버전 파일은 `SameMajorVersion`이며, 공유 오브젝트의
`SOVERSION`과 일치합니다.

*정적* certpp는 반드시 일치하는 MSVC 런타임과 함께 사용해야 한다는 점에
유의하세요 -- Release 빌드를 설치한 뒤 Debug 쪽 소비자에 링크하면 링크
시점에 `_ITERATOR_DEBUG_LEVEL`/`RuntimeLibrary` 불일치 오류가 발생하는데,
이는 이 라이브러리에 국한된 것이 아니라 MSVC의 규칙입니다.

## `CERTPP_API`에 관한 참고 사항

`include/certpp/common.hpp`는 두 개의 전처리기 스위치를 기준으로 MSVC의
dllexport/dllimport용 `CERTPP_API`를 정의합니다:

- `__COMPILES_LIBCERTPP__` -- `certpp` 자체의 번역 단위(translation unit)를
  컴파일할 때만 정의됩니다 (`CMakeLists.txt`에서 `PRIVATE`로 설정).
  소비자 코드에서는 절대 이 매크로를 정의하지 마세요.
- `__SHARED_LIBCERTPP__` -- certpp를 공유 라이브러리로 빌드하거나 사용할 때
  정의됩니다. `CERTPP_BUILD_SHARED=ON`이면 `CMakeLists.txt`가 이를
  `PUBLIC` 컴파일 정의로 자동 전파하므로, `certpp::certpp`에 링크하는
  소비자는 아무것도 직접 하지 않아도 이를 그대로 받습니다.

## 테스트

모든 테스트 케이스는 [`tests/`](../tests/) 아래에 있으며, 소스 파일 하나당
CMake 실행 파일 하나가 대응하고, 각 파일이 검증하는 `include/certpp/`(및
`src/`) 경로를 그대로 따라갑니다 (예를 들어
[`tests/asn1/decoder.cpp`](../tests/asn1/decoder.cpp)는 `asn1/decoder.hpp`를
테스트합니다). 특정 헤더 하나에 대응하지 않는 파일(여러 헤더에 걸친
통합/왕복 검사, 예컨대
[`tests/asn1/roundtrip.cpp`](../tests/asn1/roundtrip.cpp))도 1:1 헤더 대응만
없을 뿐, 똑같이 해당 모듈 디렉터리 아래에 둡니다.

테스트는 [doctest](https://github.com/doctest/doctest)를 사용하며,
[`third-party/doctest/doctest.h`](../third-party/doctest/doctest.h)에 단일
헤더로 벤더링되어 있습니다
([`third-party/CMakeLists.txt`](../third-party/CMakeLists.txt)가 이를 CMake
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
[`tests/x509/realcerts.cpp`](../tests/x509/realcerts.cpp)가 쓰는, 실제
인증서 파일들이 담긴 `certs/` 하위 디렉터리)는 모든 테스트 타깃이 자동으로
받는 `CERTPP_TEST_DIR` 컴파일 정의로 그 위치를 찾을 수 있습니다. 이 값은
해당 테스트 자신의 `.cpp` 파일이 있는 디렉터리의 절대 경로이며, 슬래시
방향이 정규화되어 있습니다 (Windows 역슬래시를 그대로 쓰면 문자열 리터럴이
깨집니다). 덕분에 테스트는 어떤 작업 디렉터리에서 실행되든 자신의 픽스처를
안정적으로 찾을 수 있습니다 -- `ctest`의 기본 작업 디렉터리는 `.exe`를
직접 실행할 때와 다르고, 그 둘 모두 호출자의 현재 디렉터리에 따라
달라집니다.

"모든 테스트는 라이브러리에 링크해 공개 헤더를 통해서만 사용한다"는 원칙에
예외인 테스트가 몇 개 있습니다: 이들은 추가로, 나열된 `src/` 소스들을 자기
실행 파일에 함께 컴파일하고 `src/`를 인클루드 경로에 넣습니다. 현재 두 그룹이
여기에 해당합니다:

- `tests/crypto/kems/` 아래의 테스트는 `src/crypto/kems/mlkemring.cpp`와
  `mlkemcodec.cpp`를 함께 받습니다 -- ML-KEM의 격자 연산과 와이어 인코딩입니다.
- `tests/crypto/asyms/mldsaring.cpp`는 `src/crypto/asyms/mldsaring.cpp`를
  받는데, 이는 `crypto/asyms/` 전체가 아니라 그 테스트 하나에만 한정됩니다.
  거기에는 ML-DSA의 ring을 함께 컴파일할 이유가 없는 테스트가 스물 몇 개나
  더 있기 때문입니다.

이 번역 단위들은 공개 API가 없으므로 `CERTPP_API`도 붙지 않습니다 -- 공유
오브젝트에서 익스포트되지 않으며, 링크로는 접근할 수 없습니다. 테스트에 두
번째 사본을 컴파일해 넣어도 안전한 것은 *바로* 이들이 익스포트되지 않기
때문이며, 그래서 라이브러리 자신의 것과 절대 충돌할 수 없습니다.

이 목록들은 glob이 아니라 `CMakeLists.txt`에 직접 적어두며,
`src/crypto/kems/mlkem.cpp`/`mlkemsampler.cpp`는 의도적으로 제외되어
있습니다. 이들은 익스포트되는 `CMlKem`/`CMlKemSampler`/`MLKEM`을 구현하므로,
여기에 함께 컴파일하면 테스트가 이미 `certpp`에서 임포트하는 심볼을 중복
정의하게 됩니다. 따라서 새 비공개 번역 단위를 목록에 추가하는 것은 수동
작업인데, 그게 바로 의도한 바입니다. 그렇게 하지 않으면 링크 시점에 읽어내기
까다로운 형태로 실패하기 때문입니다. 그 밖의 라이브러리 전체는
`DesCore`, `KeccakCore`, `CbcTransformer`가 (`ISymmetric`/`IHasher`를 통해)
그러듯 공개 표면을 통해 테스트합니다.

## 예제

[`examples/`](../examples/)에는 작고 실행 가능한 CA 계층 구조 예제가 들어
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
[`examples/README.md`](../examples/README.md)(영문)를 참고하세요.

## AddressSanitizer 빌드

MSVC는 ASan을 직접 지원하며, 계측된 오브젝트가 평범한 오브젝트와 섞이지
않도록 별도의 빌드 디렉터리를 사용합니다:

```sh
cmake -S . -B build-asan -DCMAKE_CXX_FLAGS="/fsanitize=address /EHsc"
cmake --build build-asan --config Debug
ctest --test-dir build-asan -C Debug --output-on-failure
```

`build-asan/`은 (`build/` 및 모든 `build-*`/`build_*` 디렉터리와 마찬가지로)
gitignore됩니다. 다만 MSVC의 ASan에는 누수 탐지기가 포함되어 있지
**않으므로**, 이 방식으로는 out-of-bounds와 use-after-free는 잡아내지만
누수는 잡지 못합니다 -- `TString`의 소멸자에 있던 누수가 바로 그런 실행을
그대로 통과한 적이 있습니다
([`changelog.ko.md`](changelog.ko.md) 참고).
