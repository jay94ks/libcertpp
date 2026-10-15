# 구성과 설치

[English](configuration.md)

## CMake 옵션

| 옵션                  | 기본값  | 효과                                                           |
|------------------------|---------|----------------------------------------------------------------|
| `CERTPP_BUILD_SHARED`  | `ON`    | `certpp`를 정적 라이브러리(`.lib`/`.a`)가 아니라 공유 라이브러리(`.dll`/`.so`)로 빌드합니다. |
| `CERTPP_WITHOUT_JSON`  | `OFF`   | JSON 유틸리티 구현과 엄브렐라 헤더의 include를 제외하고, 설치 시 해당 헤더를 빼며, JSON 테스트 실행 파일을 건너뛰고, `CERTPP_WITHOUT_JSON` 정의를 소비자에게 전파합니다. |
| `CERTPP_BUILD_TESTS`   | `ON`    | `tests/` 아래의 테스트 실행 파일들을 빌드하고 CTest에 등록합니다. |
| `CERTPP_BUILD_EXAMPLES` | `ON`   | `examples/` 아래의 프로그램들을 `certpp_example_<name>` 실행 파일로 빌드합니다. 이들은 CTest에 등록되지 않습니다 (인증서를 `examples/output/`에 기록하며, 순서대로 직접 실행하도록 만들어져 있습니다). [`examples/README.md`](../../examples/README.md)(영문)를 참고하세요. |
| `CERTPP_RNG_FALLBACK`  | `OFF`   | OS CSPRNG(Windows에서는 `BCryptGenRandom`, Linux에서는 `getrandom(2)`과 그것이 안 될 때의 `/dev/urandom`, 그 외 POSIX 플랫폼에서는 `/dev/urandom`)를 사용할 수 없는 경우 `crypto::CRng::fill()`이 `std::random_device`로 폴백하도록 허용합니다. 기본값인 `OFF`에서는 폴백이 컴파일 단계에서 제외되고, 그런 경우 `fill()`은 대신 `ERET_NOTSUP`을 반환합니다 -- `std::random_device`는 모든 표준 라이브러리에서 암호학적으로 안전하다고 보장되지 않으므로, OS 수준 CSPRNG가 정말로 존재하지 않는 환경을 위한 임시 방편으로만 켜십시오. |
| `CERTPP_ENABLE_FE25519_RADIX51` | `OFF` | 기본 열 limb radix-2^25.5 대신 다섯 limb radix-2^51 `Fe25519` 배치를 선택합니다. 네이티브 64x64→128 곱셈이 필요하며, 지원 GCC 측정에서 종단간으로 더 빠르지 않아 기본으로 끕니다. |
| `CERTPP_DISABLE_HWACCEL_SIMD` | `OFF` | AES/SHA 확장 이외의 경로를 끕니다. `CBigNum`의 ADX/BMI2, `CGf2m`·`Ghash`의 PCLMULQDQ, `Ghash` 반사의 GFNI, SSE2/AVX2 ChaCha20, Keccak의 BMI1 ANDN, SHA-384/SHA-512의 BMI2 RORX, Poly1305의 AVX512-IFMA가 해당합니다. 이식 가능 구현은 계속 사용할 수 있습니다. |
| `CERTPP_DISABLE_HWACCEL_SHA` | `OFF` | SHA-1 및 SHA-224/SHA-256의 SHA-NI 압축 경로만 끕니다. SHA-384/SHA-512의 BMI2 RORX와 SHA-3/SHAKE의 BMI1 ANDN 경로는 `CERTPP_DISABLE_HWACCEL_SIMD`가 제어합니다. |
| `CERTPP_DISABLE_HWACCEL_AES` | `OFF` | `AesCore`의 AES-NI 가속을 비활성화하여 -- 따라서 `AES` 블록 암호와 그 위에 쌓아올린 AES-GCM AEAD 양쪽 모두에 대해 -- 항상 소프트웨어 라운드 함수를 사용합니다. 켜든 끄든 x86-64 전용입니다. `DES`/`TripleDES`는 이 옵션과 무관하게 하드웨어 가속 경로가 아예 없으므로(주류 x86 확장 중 이들을 다루는 것이 없습니다), 이 옵션은 그 알고리즘들에는 아무런 영향이 없습니다. `ChaCha20`은 대신 SSE2와 AVX2를 사용하며 `CERTPP_DISABLE_HWACCEL_SIMD`가 제어합니다. |

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
([프로젝트 변경 이력](../HISTORY.ko.md) 참고).
