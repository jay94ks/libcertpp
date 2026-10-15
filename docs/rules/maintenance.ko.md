# 버전 관리와 테스트

[English](maintenance.md)

## 버전 관리

← [프로젝트 규칙](../RULES.ko.md)

- `HEADER_VERSION`(`version.hpp`에 있음)은 ABI/API가 바뀔 때 올려야 하는 단
  하나의 숫자입니다. `LIBRARY_VERSION`(`version.cpp`에 있고
  `GetLibraryVersion()`이 반환함)은 `HEADER_VERSION`*으로서* 정의되므로 따로
  수정할 필요가 없습니다 — 요점은, 그 값이 바이너리가 컴파일될 때 사용된 헤더의
  버전으로 바이너리에 구워져 들어가는 반면, 사용자 쪽의 `HEADER_VERSION`은
  *그들이* 컴파일할 때 사용한 헤더의 값이라는 데 있습니다. 따라서 런타임에 이
  둘을 비교하는 것이 사용자가 헤더/바이너리 불일치를 감지하는 방법이며, 이는 둘
  중 하나만 손으로 작성된다는 바로 그 사실 덕분에 동작합니다.
- `CMakeLists.txt`의 `project(certpp VERSION ...)`(공유 라이브러리의
  `VERSION`/`SOVERSION`을 결정함)은 같은 숫자의 두 번째 독립 사본이며, 둘을
  맞춰 주는 장치는 아무것도 없습니다. `HEADER_VERSION`과 함께 올려 주십시오.

## 테스트

← [프로젝트 규칙](../RULES.ko.md)

- 모든 테스트 케이스는 테스트 대상 코드 옆이 아니라 `tests/` 아래에 둡니다.
  테스트 파일은 자신이 다루는 대상의 `include/certpp/`/`src/` 경로를
  반영합니다(`tests/asn1/decoder.cpp`는 `asn1/decoder.hpp`/`decoder.cpp`를
  테스트합니다). 여러 헤더에 걸친 통합/왕복 테스트도 1:1 헤더 대응은 없을 뿐
  여전히 해당 모듈 디렉터리 아래에 둡니다(`tests/asn1/roundtrip.cpp`).
  `CMakeLists.txt`는 `src/**/*.cpp`를 글로빙하는 것과 같은 방식으로
  `tests/**/*.cpp`를 글로빙하므로([BUILDING.ko.md](../BUILDING.ko.md) 참고), 새 테스트
  파일을 추가해도 CMake를 고칠 필요가 없습니다.
- 테스트는 [doctest](https://github.com/doctest/doctest)를 사용하며,
  `third-party/doctest/` 아래에 단일 헤더로 들어와 있습니다. 각 테스트 파일은
  `#include <doctest/doctest.h>` 앞에
  `DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN`을 `#define`하고(모든 테스트 파일이 각자
  실행 파일이므로 번역 단위 간에 충돌하는 일이 없습니다), `CHECK(cond)`(실패해도
  그 테스트 케이스의 나머지를 계속 검사함)나 `REQUIRE(cond)`(테스트 케이스를 즉시
  멈춤. 이후 검사가 유효하지 않은 상태를 읽게 될 전제 조건에 사용)을 사용하는
  `TEST_CASE("description") { ... }` 블록을 하나 이상 작성합니다. 이 패턴은
  `tests/asn1/decoder.cpp`를, 같은 본문을 여러 입력에 대해 입력별로 독립적인
  성공/실패 보고와 함께 돌려야 할 때의 `SUBCASE`/`CAPTURE` 사용은
  `tests/asn1/roundtrip.cpp`를 참고하십시오.
- 테스트 코드에는 공개 선언에 요구되는 완전한 Javadoc이 필요하지 않습니다(위
  "문서 주석" 참고) -- `TEST_CASE` 위에 그것의 자명하지 않은 점(어떤 회귀를
  고정하는지, 어떤 경우가 왜 보안과 관련되는지 등)을 적은 짧은 `/* ... */`면
  충분하며, 이름만으로 충분히 설명되는 `TEST_CASE`에는 주석이 전혀 필요하지
  않습니다.
