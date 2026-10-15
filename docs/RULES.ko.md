# 프로젝트 규칙

[English](RULES.md)

이 문서는 기존 헤더와 소스(`include/certpp/common.hpp`,
`include/certpp/version.hpp`, `include/certpp/asn1/tag.hpp`,
`include/certpp/asn1/decoder.hpp`, `include/certpp/io/span.hpp`,
`include/certpp/io/stream.hpp`, `src/version.cpp`, `src/common.cpp`,
`src/asn1/tag.cpp`, `src/asn1/decoder.cpp`, `src/io/stream.cpp`,
`src/io/memstream.hpp`, `src/io/memstream.cpp`)에 이미 자리잡은 컨벤션을
정리한 것입니다. 새 코드를 작성할 때는 새로운 스타일을 들이지 말고 이
컨벤션을 따르십시오.

## 파일 구성

- 모든 헤더는 `#pragma once`가 아니라 헤더 가드를 사용합니다:
  ```cpp
  #ifndef __INCLUDE_CERTPP_<PATH>_HPP__
  #define __INCLUDE_CERTPP_<PATH>_HPP__

  #endif
  ```
  가드 이름은 `include/` 기준 상대 경로를 대문자로 바꾸고, 영숫자가 아닌
  문자를 `_`로 치환한 뒤, 앞뒤를 이중 밑줄로 감싸서 만듭니다 (예:
  `include/certpp/version.hpp` -> `__INCLUDE_CERTPP_VERSION_HPP__`,
  `include/certpp/asn1/tag.hpp` -> `__INCLUDE_CERTPP_ASN1_TAG_HPP__`). 이는
  이 저장소에서 이미 쓰고 있는 `.vscode/my.code-snippets`의 "C/C++ Default
  Header Form" 스니펫(`kh` 접두사)과 일치합니다 — 새 헤더를 만들 때는 그
  스니펫을 사용하십시오.
- `.cpp` 파일은 자신과 대응하는 헤더를 가장 먼저, 상대 경로 `"..."` 형태가
  아니라 `certpp/...` 꺾쇠괄호 경로로 포함합니다 (예:
  `#include <certpp/version.hpp>`, `#include <certpp/asn1/tag.hpp>`).
- 모든 공개 코드는 `namespace certpp { ... }` 안에 둡니다.
- `include/certpp/` 아래의 템플릿이 아닌 모든 헤더에는 `src/` 아래에 대응하는
  `.cpp` 스텁 — 해당 헤더의 `#include`와 (내용이 비어 있을 수도 있는)
  네임스페이스 골격 — 이 하나씩 있으며, 아웃오브라인(out-of-line)으로 둘
  코드가 아직 없더라도 미리 만들어 둡니다 (`src/common.cpp`,
  `src/asn1/tag.cpp` 참고). 이렇게 하면 나중에 인라인이 아닌 코드를 추가할 때
  구조를 다시 바꾸지 않아도 되고, `CMakeLists.txt`가 `src/**/*.cpp`를 자동으로
  글로빙하므로 비용도 들지 않습니다. 전체가 템플릿인 헤더(예: `io/span.hpp`의
  `TSpan<T>`, `TReadOnlySpan<T>`)에는 `.cpp`를 **두지 않습니다**: 템플릿 정의는
  인스턴스화 지점에서 보여야 하므로 `.cpp`에 넣을 것이 없습니다.
- 중첩 네임스페이스를 사용하는 서브모듈(예: `asn1`)은 `include/certpp/`와
  `src/` 아래에 자신의 하위 디렉터리를 가집니다. 이때 C++17의
  `namespace certpp::asn1` 축약 표기가 아니라 두 번째 최상위 블록을 여는
  형태로 네임스페이스를 엽니다:
  ```cpp
  namespace certpp {
  namespace asn1 {

      // ...

  } // namespace asn1
  } // namespace certpp
  ```
  모든 단계의 닫는 괄호에는 끝나는 네임스페이스 이름을 적은 주석을 붙입니다.
  즉 `} // namespace asn1` 다음에 `} // namespace certpp`를 씁니다
  ([포맷팅](rules/style.ko.md#포맷팅) 참고).
- 모든 서브모듈이 중첩 네임스페이스를 필요로 하는 것은 아닙니다. 현재
  상태는: **`asn1`, `crypto`, `x509`, `dnssec`는 중첩하고**
  (`certpp::asn1`, `certpp::crypto`, `certpp::x509`, `certpp::dnssec`),
  **`io`와 대부분의 `utils` 타입은 중첩하지 않습니다** — 이들은 최상위
  헤더들처럼 자신의 타입을 `namespace certpp { ... }`에 바로 둡니다.
  `utils/json.hpp`의 JSON/BSON API는 기존 예외이며 `certpp::utils`에
  있습니다. 중첩 네임스페이스는 단순히
  "하위 디렉터리에 있다"는 이유가 아니라, 라이브러리의 나머지 부분과 구별되는
  자기만의 정체성과 네이밍 체계를 가진 모듈에만 허용됩니다(`asn1`의
  태그/열거형 이름은 ASN.1 고유의 것이고, `crypto`, `x509`, `dnssec`도
  마찬가지입니다). `io`와 대부분의 `utils` 타입이 바로 그 "단순히 하위
  디렉터리에 있을 뿐"인 경우이며, 라이브러리 전체가 수식 없이 가져다 쓰는
  범용 배관에 해당합니다. 새 예외를 만들지 말고 형제 헤더에 이미 정해진
  네임스페이스를 따르세요.
- 한 디렉터리가 같은 종류의 구체적 구현을 파일마다 하나씩 담고 있는 경우,
  타입 이름을 그대로 다 적는 대신 그 주제의 널리 알려진 약칭으로 각 파일 이름을
  지을 수 있습니다 — 예컨대 `CBasicConstraintsExtension`에 대해
  `x509/exts/bc.hpp`, `CSkiExtension`에 대해 `ski.hpp` — 단, 그 약칭이
  직접 만들어낸 것이 아니라 커뮤니티 표준으로 통하는 것일 때에만
  그렇습니다(인증서 검사 도구들과 RFC 본문이 이 확장들을 가리킬 때 쓰는 바로 그
  짧은 이름). 이는 기본 규칙이 아니라 예외입니다: 이미 자리잡은 약칭이 있고
  전체 이름을 쓰면 같은 디렉터리의 여러 파일에서 불필요하게 길어지는 경우가
  아니라면, 무엇을 정의하는지 그대로 적는 파일 이름을 택하십시오
  (`crypto/asyms/rsa.hpp` 참고).

### 내부 구현 헤더

- 공개 인터페이스를 구현하기 위해서만 존재하고 공개 API에는 자리가 없는 타입은
  `include/certpp/`가 아니라 `src/` 아래의 비공개 헤더+소스 한 쌍으로
  둡니다 — 예컨대 `src/io/memstream.hpp`/`.cpp`는
  `IStream::createMemory(...)`의 구체적 뒷받침인 `MemStream`을 정의하며,
  사용자는 이를 언제나 `IStream` 인터페이스를 통해서만 봅니다.
- 이 헤더의 헤더 가드는 `__INCLUDE_CERTPP_...`가 아니라
  `__SRC_<PATH>_HPP__`입니다(경로는 `src/` 기준 상대 경로) — 예:
  `src/io/memstream.hpp` -> `__SRC_IO_MEMSTREAM_HPP__`. 이렇게 하면 둘이
  혹시 충돌하는 일이 생겨도 공개 가드와 눈에 띄게 구별됩니다.
- `src/` 아래의 다른 파일들은 이 헤더를 `<certpp/...>` 꺾쇠괄호 형태가 아니라
  상대 경로의 이중 인용 부호 형태로 포함합니다(`#include "memstream.hpp"`) —
  꺾쇠괄호는 `include/` 아래의 헤더를 위해 남겨 둡니다.
- 다만 자신이 구현하는 공개 헤더는 여전히 `<certpp/...>` 형태로
  포함합니다(`src/io/memstream.hpp`는 `<certpp/io/stream.hpp>`를 포함합니다).
  그 부분은 *실제로* 공개 API이기 때문입니다.
- 공개 API 타입 접두사 규칙(`S`/`T`/`C`/`I`/`E`,
  [타입](rules/api.ko.md#타입) 참고)은 이 타입에는 적용되지 않습니다. 그 이유도 해당
  문서에서 설명합니다.

## 상세 문서

- [API 설계 규칙](rules/api.ko.md)
- [소스와 문서 스타일](rules/style.ko.md)
- [버전 관리와 테스트](rules/maintenance.ko.md)
