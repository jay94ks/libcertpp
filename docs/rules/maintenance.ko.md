# 버전 관리와 테스트

[English](maintenance.md)

## 버전, ABI 및 릴리스

← [프로젝트 규칙](../RULES.ko.md)

이 프로젝트는 Semantic Versioning을 따르며 현재 버전은 1.2.0입니다. patch 릴리스는
호환되는 수정, minor 릴리스는 소스와 ABI를 유지하는 공개 API 추가를 담을 수 있고,
공개 ABI나 소스 호환성을 깨는 변경에는 major 릴리스가 필요합니다. 설치된 CMake
패키지는 `SameMajorVersion`을 사용하고 라이브러리 `SOVERSION`은 major 버전입니다.
같은 major 버전 안에서는:

- 공개 함수 매개변수와 반환값의 타입, 순서, 소유권, 의미를 제거하거나 바꾸지 않습니다.
- 공개 enum 값은 기존 값을 재배열하거나 번호를 바꾸지 않고 뒤에 추가합니다.
- major 버전 증가 없이 공개 클래스 레이아웃이나 가상 함수 테이블을 바꾸지 않습니다.
- 설치 헤더, `CERTPP_API` export, 전이 링크 요구사항을 `certpp::certpp` 소비자가 계속
  사용할 수 있게 유지합니다.

`version.hpp`의 `HEADER_VERSION`은 런타임 헤더 버전입니다. 바이너리의
`LIBRARY_VERSION`은 이 값으로 컴파일되고 `GetLibraryVersion()`이 반환합니다.
`CMakeLists.txt`의 `project(certpp VERSION ...)`은 별도 사본이므로 둘은 항상 같아야
하며 릴리스에서 함께 갱신합니다.

### 릴리스 체크리스트

1. 위 호환성 규칙으로 공개 변경을 분류하고 SemVer 증가 폭을 정한 뒤 두 버전 선언을
   함께 갱신합니다.
2. 영문·한글 유지 보수 문서, 계획/이력, 파일 추가·이동·삭제 시 `docs/INDEX.md`를
   같은 변경에서 갱신합니다.
3. 기본 공유 및 정적 구성에서 전체 테스트를 실행하고, 암호 또는 플랫폼 코드를
   바꿨다면 하드웨어 가속을 끈 portable 구성도 실행합니다.
4. 릴리스 구성의 `install_consumer`를 실행하여 설치된 `find_package(certpp)` 프로젝트가
   빌드되고 실행되는지 확인합니다.
5. 파서/코덱 변경에는 제한된 퍼징 smoke 검사를, 타이밍 민감 변경에는 관련 검토
   도구를 실행합니다.
6. `git diff --check`, 저장소 상태, 공개 헤더 diff, 릴리스 노트를 검토합니다. 커밋,
   태그, 푸시는 사용자가 명시적으로 요청한 뒤에만 수행합니다.

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
