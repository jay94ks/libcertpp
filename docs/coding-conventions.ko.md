# 코딩 컨벤션

[English](coding-conventions.md)

이 문서는 기존 헤더와 소스(`include/certpp/common.hpp`,
`include/certpp/version.hpp`, `include/certpp/asn1/tag.hpp`,
`include/certpp/asn1/decoder.hpp`, `include/certpp/io/span.hpp`,
`include/certpp/io/stream.hpp`, `src/version.cpp`, `src/common.cpp`,
`src/asn1/tag.cpp`, `src/asn1/decoder.cpp`, `src/io/stream.cpp`,
`src/io/memstream.hpp`, `src/io/memstream.cpp`)에 이미 자리잡은 컨벤션을
정리한 것입니다. 새 코드를 작성할 때는 새로운 스타일을 들이지 말고 이
컨벤션을 따르십시오.

## 파일 구성

- 모든 헤더는 `#pragma once`가 아니라 인클루드 가드를 사용합니다:
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
- 서브모듈(예: `asn1`)은 `include/certpp/`와 `src/` 아래에 자신의 하위
  디렉터리를 가지며, 자신의 중첩 네임스페이스도 가집니다. 이때 C++17의
  `namespace certpp::asn1` 축약 표기가 아니라 두 번째 최상위 블록을 여는
  형태로 씁니다:
  ```cpp
  namespace certpp {
  namespace asn1 {

      // ...

  }
  }
  ```
  한 단계뿐인 `namespace certpp { ... }`와 달리, 중첩 네임스페이스는 뒤에
  `// namespace ...` 주석을 붙이지 않고 그냥 `}`로 닫습니다 (아래 "포맷팅"
  참고).
- 모든 서브모듈이 중첩 네임스페이스를 필요로 하는 것은 아닙니다. 현재
  상태는: **`asn1`, `crypto`, `x509`는 중첩하고**(`certpp::asn1`,
  `certpp::crypto`, `certpp::x509`), **`io`와 `utils`는 중첩하지
  않습니다** — 이들은 최상위 헤더들처럼 자신의 타입을
  `namespace certpp { ... }`에 바로 둡니다. 중첩 네임스페이스는 단순히
  "하위 디렉터리에 있다"는 이유가 아니라, 라이브러리의 나머지 부분과 구별되는
  자기만의 정체성과 네이밍 체계를 가진 모듈에만 허용됩니다(`asn1`의
  태그/열거형 이름은 ASN.1 고유의 것이고, `crypto`와 `x509`도 마찬가지입니다).
  `io`와 `utils`가 바로 그 "단순히 하위 디렉터리에 있을 뿐"인 경우이며,
  라이브러리 전체가 수식 없이 가져다 쓰는 범용 배관에 해당합니다.
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
- 이 헤더의 인클루드 가드는 `__INCLUDE_CERTPP_...`가 아니라
  `__SRC_<PATH>_HPP__`입니다(경로는 `src/` 기준 상대 경로) — 예:
  `src/io/memstream.hpp` -> `__SRC_IO_MEMSTREAM_HPP__`. 이렇게 하면 둘이
  혹시 충돌하는 일이 생겨도 공개 가드와 눈에 띄게 구별됩니다.
- `src/` 아래의 다른 파일들은 이 헤더를 `<certpp/...>` 꺾쇠괄호 형태가 아니라
  상대 경로의 이중 인용 부호 형태로 포함합니다(`#include "memstream.hpp"`) —
  꺾쇠괄호는 `include/` 아래의 헤더를 위해 남겨 둡니다.
- 다만 자신이 구현하는 공개 헤더는 여전히 `<certpp/...>` 형태로
  포함합니다(`src/io/memstream.hpp`는 `<certpp/io/stream.hpp>`를 포함합니다).
  그 부분은 *실제로* 공개 API이기 때문입니다.
- 공개 API 타입 접두사 규칙(`S`/`C`/`I`/`E`, 아래 "타입" 참고)은 이 타입에는
  적용되지 않습니다 — 이유는 "타입"을 참고하십시오.

## 타입

- 전역 네임스페이스를 건드리거나 `int`/`unsigned`를 그대로 쓰는 대신
  `common.hpp`의 별칭(`certpp::uint32_t`, `certpp::size_t`,
  `certpp::float32_t`, ...)을 사용하십시오.
- `common.hpp` 자체는 C 헤더(`<stddef.h>`, `<stdint.h>`)를 포함합니다. 바로 그
  C 타입들에 대한 별칭을 정의하는 것이 목적이기 때문입니다. 그 외의 모든
  곳에서는 표준 헤더의 C++ 형태를 포함하고(`<string.h>`가 아니라 `<cstring>`),
  맨 C 이름이 아니라 `std::` 네임스페이스를 통해
  호출하십시오(`io/span.hpp`의 `std::memcpy`, `std::memset`, `std::memcmp`).
- 순수 데이터/값 타입 집합체(aggregate)는 `struct`로 선언합니다. 템플릿이 아닌
  것에는 `S` 접두사를 붙이고(예: `SVersion`, `SDateTime`, `STimeSpan`),
  **템플릿**인 것에는 대신 `T` 접두사를 붙입니다(예: `io/span.hpp`의
  `TSpan<T>`, `TReadOnlySpan<T>`) — 이 접두사를 보면 그 타입을 이름만으로 쓸 수
  있는지, 아니면 타입 인자를 넘겨야 하는지 한눈에 알 수 있습니다. 그 외에는
  평범한 값 타입 집합체라는 이유만으로 템플릿에 `S`를 다시 쓰지 마십시오.
  공개 API의 일부인 구체적 인스턴스화에는 여전히 보통의 `S` 접두사 별칭을
  붙입니다(`using SByteSpan = TSpan<uint8_t>;`,
  `using SReadOnlyByteSpan = TReadOnlySpan<uint8_t>;`) — 구체적 별칭이 있는
  곳이라면 호출자는 `TSpan<uint8_t>`가 아니라 `SByteSpan`을 다룹니다.
- 가볍고 헤더 전용인 값 타입 struct는 모든 자명한 생성자/메서드를
  `constexpr ... noexcept`로 표시합니다(`TSpan`/`TReadOnlySpan` 참고):
  컴파일 시점에 평가될 수 있으므로 `constexpr`, 예외를 던질 수 없으므로
  `noexcept`입니다. `constexpr`이 아닌 코드를 호출하는 메서드, 예컨대 `TSpan`의
  `std::memcpy` 기반 메서드에만 (`constexpr` 없는) 평범한 `inline`을 남겨
  두십시오.
- 어떤 타입이 소유/변경 가능 변종과 읽기 전용 뷰를 모두 가질 때는, 읽기 전용
  쪽을 `<Prefix>ReadOnly<Name>`으로 이름 짓고(변경 가능 변종이 쓰는 `S`/`T`
  접두사를 그대로 사용) 변경 가능 변종으로부터의 암시적 변환 생성자를
  제공하십시오(`TReadOnlySpan(const TSpan<T>&)` 참고).
- 비공개 상태와 동작을 가지는 타입은 `class`로 선언하고 `C` 접두사를
  붙입니다(예: `asn1/tag.hpp`의 `CTag`): 필드는 비공개이고, 공개
  생성자/메서드를 통해서만 접근합니다.
- `S`/`T`/`C`/`I`/`E` 접두사는 특히 `include/certpp/` 아래의 **공개 API** 표면을
  표시합니다 — 사용자에게 지금 보고 있는 것이 어떤 종류의 타입인지 알리는
  신호입니다. 내부적으로 무언가를 구현하기 위해서만 존재하며 `src/` 아래에 있는
  타입("파일 구성" -> "내부 구현 헤더" 참고)은 신호를 보낼 공개 사용자가 없으므로,
  `C` 타입처럼 비공개 상태를 가지고 있더라도 접두사 없는 평범한
  `PascalCase`입니다(`src/io/memstream.hpp`에서 `IStream`을 구현하는
  `MemStream`).
- 순수 가상 추상 기반 클래스는 `class`로 선언하고 `I` 접두사를 붙입니다(예:
  `io/stream.hpp`의 `IStream`). `C` 타입과 달리 `I` 타입은 보통:
  - 그 옆에 `using <Name>Ptr = std::shared_ptr<I<Name>>;` 별칭을
    노출합니다(`IStreamPtr`). 사용자가 값이 아니라 스마트 포인터로 들고
    있기 때문입니다.
  - 생성 가능한 구현 타입을 노출하는 대신, 구체적 구현(흔히 비공개입니다.
    "파일 구성" -> "내부 구현 헤더" 참고)을 반환하는
    `static <Name>Ptr create...(...)` 팩토리 메서드를 가집니다.
  - 모든 구현이 지원하지는 않는 동작은 순수 가상이 아니라, `ERET_NOTIMPL`을
    반환하는 기본 본문을 가진 가상 메서드로 표시합니다(예:
    `IStream::trimExcess()`, `IStream::flush()`). `= 0`은 모든 구현이 반드시
    제공해야 하는 동작(`seek`, `read`, `write`, `close`)을 위해 남겨 둡니다.
  - 둘 다 의미가 있을 때는 `getX`/`setX`로 이름을 나누는 대신 getter와 setter가
    같은 이름을 overload합니다(`IStream::length() const`는 길이를 반환하고,
    `IStream::length(SizeType)`은 길이를 설정하려 시도하며 `ERetCode`를
    반환합니다. `position()`/`position(SizeType)`도 마찬가지입니다).
- 열거형은 (`enum class`가 아니라) 평범한 `enum`으로 선언하고 `E` 접두사를
  붙입니다(예: `ETagClass`, `EUniversalTags`). 값이 작고 안정적인 표현에서
  이득을 보는 열거형은 하위 타입을 명시합니다(`common.hpp`의
  `enum ERetCode : uint8_t { ... }`). 그렇지 않으면 기본값인 `int`에 맡깁니다.
  열거자(enumerator)에는 열거형 이름의 짧은 대문자 약칭을 접두사로 붙이며,
  해당 타입에 유효하지 않은/설정되지 않은 상태가 있는 경우 `..._INVALID`
  센티넬을 포함합니다:
  ```cpp
  enum ETagClass {
      EATAG_INVALID          = 0xFF,  // --> Invalid tag.
      EATAG_UNIVERSAL        = 0,
      EATAG_APPLICATION      = 1u << 6,
      // ...
  };
  ```
  이 약칭은 고정된 공식으로 유도하는 것이 아니라 그 열거형에 대해 분명하게
  읽히는 것이면 되며, 같은 헤더에 있는 두 열거형이 서로 다른 길이를 고를 수도
  있습니다(`asn1/tag.hpp`: `ETagClass` -> `EATAG_*`, `EUniversalTags` ->
  `EAUTAG_*`; `asn1/decoder.hpp`: `EEncodingRule` -> `EAENC_*`,
  `EDecoderStatus` -> `EDEC_*`). 새 약칭을 만들어내기 전에 같은 헤더의 형제
  열거형들을 확인하십시오. 값이 자명하지 않을 때는 각 열거자에 주변 항목들과
  열을 맞춘 `// --> Description.` 꼬리 주석을 달아 주십시오. 모든 열거자가
  같은 짧은 설명을 필요로 한다면, 줄마다 반복하는 대신 `enum` 위에 그것들을
  열거하는 블록 주석을 두는 것도 괜찮습니다(`EEncodingRule` 참고).
- 타입이나 자유 함수(free function)에 `CERTPP_API` 주석(`common.hpp` 참고)이
  필요한 것은, 멤버/정의가 `.cpp` 파일에 아웃오브라인(out-of-line)으로 있는
  경우뿐입니다 — 예컨대 `SVersion`(비교 연산자들이 `version.cpp`에
  정의되어 있습니다). 모든 메서드가 인라인이고 헤더에서 완전히 정의되는
  타입(예: `CTag`)에는 `CERTPP_API`가 필요하지 않습니다:
  export/import할 아웃오브라인 심볼이 없기 때문입니다.

## 버퍼 처리

- `TArray`/`CBuffer`/원시 배열의 byte 또는 원소 범위를 루프에서 한 원소씩
  채우거나 복사하지 마십시오. 원시 포인터를 얻어서(`toPtr()`/`begin()` 중 그
  타입이 노출하는 것) 채울 때는 `std::memset`, 복사할 때는
  `std::memcpy`/`std::memmove`를 사용하십시오 — 원소 단위 루프는 같은 의도를
  표현하는 하나의 일괄 호출보다 느리고, 올바름도 덜 분명하게 드러납니다. 같은
  이유로, 컨테이너에 원소 단위로 반복해 쓰기보다는 작은 고정 크기 배열을
  스택에 한 번 만들어 한 번의 일괄 호출로 써넣는 편을 택하십시오.
- 이 규칙의 두 절반은 분리할 수 있으며, 예외가 있는 것은 *일괄 호출* 쪽
  절반뿐입니다. 루프가 정말로 루프로 남아야 하는 경우(아래 목록)에도, 매 반복마다
  컨테이너의 `operator[]`를 거치는 대신 루프 밖으로 끌어올린 원시 포인터를
  통해 데이터에 접근합니다 — `CbcTransformer::processBuffered()`가 그 실제
  예입니다: 그 CBC XOR 결합과 constant-time 패딩 스캔은 여전히 명시적인 byte
  단위 루프지만, 그 모두가 맨 위에서 한 번 얻은 `uint8_t*`를 인덱싱합니다.
- 일괄 호출 쪽 절반은 다음에는 **적용되지 않습니다**:
  - constant-time/분기 없는 코드(`CSecure::equalsMask`/`select`,
    `CbcTransformer`의 PKCS#7 패딩 검사, EC/EdDSA 스칼라 곱셈
    래더) — 이를 데이터에 의존하는 길이의 `memcpy`나 조기 종료 비교로 접어
    넣으면 타이밍 side channel이 다시 생깁니다. 이런 코드는 명시적이고
    무조건적인 루프로 남겨 둡니다. 새로운 마스크 연산을 작성하기 전에
    `CSecure`(`utils/secure.hpp`)를 먼저 찾아보십시오: 두 버퍼 비교, 두 버퍼 중
    선택, 버퍼 지우기는 이미 거기에 있으며, 비밀에서 파생된 무언가에
    `std::memcmp`를 쓰는 것은 스타일 문제가 아니라 버그입니다 — 첫 불일치에서
    멈추므로 실행 시간이 일치한 접두사의 길이를 누설합니다.
  - 채우기나 복사가 아니라 원소 단위 결합인 경우 — CBC의
    `out[i] = in[i] ^ chain[i]`는 `memset`도 `memcpy`도 아니며, 이를 복사와
    제자리 XOR 패스로 쪼개면 같은 것을 표현하면서 블록을 두 번 읽게 됩니다.
  - 진짜 뒤집기(`out[i] = in[N-1-i]`)나 제자리 교환
    (`CBigNum::reverseBytesInPlace`) — `memcpy`/`memmove`는 순서를 보존하는
    복사만 할 수 있어서 둘 중 어느 것도 표현할 수 없습니다.
  - 조건부/필터링된 복사, 예컨대 `CRng::fillNonZero()`의 0 byte 거부
    루프 — 무조건적이지 않으므로 `memcpy`가 아닙니다.
  - 라운드별로 인덱싱되는 스케줄 데이터(AES/DES/3DES 라운드 키 배열)가 평평한
    byte 버퍼로 취급되는 것이 아니라 정말로 라운드로 인덱싱되는 경우. 그런
    배열을 인덱스 대 인덱스로 그대로 복사하는 것은 여전히 `memcpy` 대상이지만,
    그것을 *재배열*하는 것(DES/3DES 복호화 측 키 스케줄 역순)은 위 항목에 따라
    뒤집기입니다.
  - 이미 공개 헤더에 선언된 함수 시그니처가 요구하는
    `TArray<uint8_t>&`/`TArray<uint8_t>` 매개변수(예: `CEcCurve::encodePoint`,
    `CGf2m::toBigEndian`, `CHex::decode`) — 타입을 자유롭게 바꿀 수 있는 것은
    파일 지역/비공개 헬퍼 시그니처뿐이며, 공개 시그니처를 바꾸는 것은 별개의 더
    큰 결정입니다.
- `TArray`, `CBuffer`, `COctet`은 습관으로 골라 쓰는 서로 맞바꿀 수 있는
  컨테이너가 아닙니다 — 그 데이터가 어쩌다 달고 있는 RFC/명세 단계 이름이
  아니라, 실제 호출 지점에서 데이터가 맡는 역할에 따라 고르십시오:
  - `CBuffer`는 결과로 가는 중간에 있는 작업용 byte 버퍼를 위한 것입니다: 한 번
    (또는 적고 한정된 횟수만) 크기를 조정하고, 채우거나 `memcpy`로 써넣고,
    span으로 다시 읽습니다. 이렇게 쓰이는 `TArray<uint8_t>` — 즉 서로 구별되는
    원소들의 논리적 수열이 아니라 버퍼로 쓰이는 것 — 은 `CBuffer`로 타입을
    바꿔야 합니다.
  - `COctet`은 `encode`/`decode` 연산의 결정적 결과 *그 자체*이거나, 하나의
    단위로 저장/적재되는 고정 길이 데이터(키 blob, 다이제스트, 직렬화된 TLV의
    내용)를 위한 것입니다.
  - `TArray<T>`는 byte 버퍼가 아니라 논리적으로 구별되는 원소들의 실제
    수열(예: `TArray<SKeySizeSpec>`)일 때 `TArray<T>`로 남습니다.

## span 매개변수

- 출력 span은, 피호출자가 정말로 그것을 짧게 줄여야 하는 경우가 아니라면
  `const SByteSpan&`로 전달합니다. span의 `data`는 `uint8_t*`이므로 어느 쪽이든
  버퍼는 쓰기 가능한 상태로 남습니다. `const`는 span 자체를 재대입하는 것만
  막습니다.
- (const가 아닌) `SByteSpan&`는 `out = SByteSpan(out.data, written)` 대입으로
  실제로 더 짧은 길이를 되돌려 보고하는 피호출자를 위해 남겨 둡니다 —
  `IAsymmetricContext::sign()`과 `CBase64::finish()`가 그 예입니다. 어떤 함수가
  그 대입을 결코 수행하지 않는다면, 그 매개변수는 `const`여야 합니다.
- 이것은 겉모양 문제가 아닙니다. const가 아닌 lvalue 참조는 임시 객체에 바인딩할
  수 없으므로, `hasher->finish(SByteSpan(buf, len))`은 표준 C++에서 잘못된
  형식입니다 — MSVC는 확장으로 받아주지만 GCC와 Clang은 거부합니다.
  `IHasher::finish()`에 정확히 이 문제가 13개 호출 지점에 걸쳐 있었고, MSVC가
  아닌 모든 빌드를 깨뜨렸습니다. `docs/changelog.md`의 이식성 항목을
  참고하십시오.
- 같은 논리가 입력 span에도 적용됩니다: 유용하게 되돌려 쓸 수 있는 것이 없으므로
  const가 아닌 참조가 아니라 `const SReadOnlyByteSpan&`로 받으십시오.

## 네이밍

- 네임스페이스: 소문자(`certpp`, `certpp::asn1`).
- 타입: 접두사가 붙은 `PascalCase`(`include/certpp/` 아래의 공개 API에만
  해당) — 템플릿이 아닌 struct에는 `S`(`SVersion`), 템플릿 struct에는
  `T`(`TSpan<T>`), 클래스에는 `C`(`CTag`), 인터페이스에는 `I`(`IStream`),
  열거형에는 `E`(`ETagClass`). 위 "타입"을 참고하십시오. `src/` 아래의 내부
  구현 타입(예: `MemStream`)은 접두사 없는 `PascalCase`입니다.
- 열거자: `SCREAMING_SNAKE_CASE`이며, 열거형 이름에서 `E`를 뗀 약칭을 접두사로
  붙입니다(`EATAG_UNIVERSAL`, `EAUTAG_BOOLEAN`) — 위 "타입"을 참고하십시오.
- 자유 함수: `PascalCase`(`GetLibraryVersion`). 공개 API의 일부가 아니라 한
  헤더/번역 단위에 지역적인 `static` 헬퍼는 대신
  `camelCase`를 써도 됩니다(`asn1/decoder.hpp`의 `checkEncodingRule`) —
  `PascalCase` 규칙은 "이것은 호출 가능한 API다"를 알리는 것에 관한 것이고,
  파일 비공개 헬퍼에는 그 이야기가 해당되지 않습니다.
- 클래스 멤버 메서드: 단순한 접근자/술어도 포함해
  `camelCase`(`CTag`의 `isValid`, `isConstructed`, `tagClass`, `value`) — 이는
  자유 함수에 쓰는 `PascalCase`와 다릅니다.
- 비공개 멤버 필드: 앞에 밑줄을 붙인 `camelCase`(`CTag`의 `_flags`, `_value`).
  평범한 `S` struct의 공개 필드에는 접두사가 없습니다(`SVersion`의 `major`,
  `minor`, `patch`).
- 생성자 매개변수 / 지역 변수: `camelCase`이며, 자신이 초기화하는 필드와
  일관되게 줄여 쓰는 경우가 많습니다(`maj` -> `major`).
- 상수: `SCREAMING_SNAKE_CASE`(`HEADER_VERSION`, `LIBRARY_VERSION`). 클래스의
  `private: static constexpr` 비트마스크/플래그 상수도 포함합니다(`CTag`의
  `MASK_CLS`, `FLAG_INVALID`).
- 클래스가 상수로 노출하는 널리 알려진 OID(예: KeyPurposeId나 접근 방법
  OID)는 뒤에 `_OID`를 붙이는 것이 아니라 `OID_` 접두사를 써서
  `OID_<Name>`으로 이름 짓습니다(`OID_SERVER_AUTH`, `OID_OCSP_METHOD`,
  `OID_ANY_POLICY`). 이는 클래스 *자신*을 정의하는 OID(`IExtension::create()`가
  디스패치의 기준으로 삼는 것)에는 해당되지 않습니다: 그것은 단 하나뿐이고 혼동될
  다른 이름도 없으므로 그냥 `OID`로 이름
  짓습니다(`CBasicConstraintsExtension::OID`).
- 자연스러운 `SCREAMING_SNAKE_CASE` 이름이 C/C++ 표준 라이브러리 매크로와
  충돌하는 공개 상수는, 다른 이름으로 바꾸는 대신 뒤에 밑줄을 하나 붙여서
  여전히 "그 이름을 가진 ASN.1의 그것"으로 읽히게 합니다(`CTag::Shortcut`의
  `NULL_`은 `<cstddef>`의 `NULL`을 피하고, `TIME_UTC_`는 `timespec_get`이 쓰는
  `<ctime>`의 `TIME_UTC`를 피합니다). 이것은 이론적인 이야기가 아닙니다:
  `TIME_UTC`는 (`tests/`의 doctest 타이머처럼) `<ctime>`을 전이적으로 포함하게
  되는 헤더가 먼저 포함되기 전까지는 잘 컴파일되었고, 그 뒤로는 `TIME_UTC`가
  상수를 가리키는 대신 조용히 매크로의 `1`로 확장되어 선언을 깨뜨렸습니다. 이
  충돌은 포함 순서에 달려 있으므로 오랫동안 잘 컴파일되다가 전혀 무관한 변경
  때문에 깨질 수 있습니다 -- 표준 헤더에 있을 법한 이름의 상수라면 미리
  이름을 바꾸십시오.
- 매크로: 목적에 따라 `CERTPP_` 또는 `__...__` 접두사를 붙인
  `SCREAMING_SNAKE_CASE` — 공개 기능 매크로는 `CERTPP_`를 쓰고(`CERTPP_API`),
  사용자/빌드 스크립트가 정의하는 빌드 구성 스위치는 이중
  밑줄을 씁니다(`__SHARED_LIBCERTPP__`, `__COMPILES_LIBCERTPP__`).

## 포맷팅

- 4칸 들여쓰기, 탭 금지.
- 여는 중괄호는 선언과 같은 줄에 둡니다(`struct Foo {`, `class Foo {`,
  `if (...) {`). 예외는 본문이 비어 있거나 거의 비어 있고 초기화 리스트가 이미
  한 줄을 다 차지하는 생성자입니다 — 이 경우 본문의 여는 `{`를 별도의 줄에 둘
  수 있습니다(`CTag`의 비공개 위임 생성자 참고).
- struct나 class 안에서 멤버/메서드 사이에는 빈 줄 하나를 둡니다.
- `namespace certpp { ... } // namespace certpp` — 한 단계뿐인 네임스페이스는
  이름을 적은 꼬리 주석과 함께 닫습니다. 중첩 네임스페이스(서브모듈)는 각
  단계를 대신 그냥 `}`로 닫습니다(위 "파일 구성" 참고).
- 접근 지정자(`private:`/`public:`)는 각각 한 번만 쓰는 것이 아니라, 관련된
  멤버를 묶기 위해 반복합니다: 예컨대 `CTag`는 상수들을 하나의 `private:`
  아래에, 필드들을 또 다른 `private:` 아래에 묶고, 공개 생성자들을 `public:`
  아래에, 비공개 위임 생성자를 그것만의 `private:` 아래에 두고, 그 뒤에 나머지
  공개 생성자/메서드를 둡니다.
- 클래스 본문 안에서 인라인으로 정의되는, 표현식 하나로 끝나는 자명한 접근자
  메서드는, 클래스 내 정의가 암시적으로 인라인이더라도 `inline`을 명시적으로
  표시합니다(`inline bool isValid() const { ... }`).
- 클래스는 오직 다른 생성자들이 위임할 대상으로서 비공개의, 기본이 아닌
  생성자를 노출할 수 있으며(`CTag(uint8_t flags, uint32_t value)`), 이렇게
  공유 초기화/검증 로직을 한곳에 모읍니다.
- 소스/헤더 내용은 순수 ASCII입니다 — em-dash, 둥근 인용 부호, 그 밖의 ASCII가
  아닌 구두점을 쓰지 않습니다. 이 파일들은 BOM 없는 UTF-8로 저장되며, 영어가
  아닌 Windows 설치에서 MSVC의 기본(시스템 코드페이지) 소스 인코딩은 섞여 들어간
  ASCII가 아닌 바이트를 잘못 읽어 `C4819` 경고를 냅니다. em-dash를 쓰고 싶은
  자리에는 평범한 이중 하이픈(`--`)을 쓰십시오.
- 아무것도 없는 `// --` 줄은 선언 본문 안에서 논리적 하위 그룹을 나눕니다(예:
  `common.hpp`에서 `ERetCode`의 범용 코드와 더 구체적인 코드를 나누거나,
  `tag.hpp`에서 `CTag`의 태그 번호 상수와 연속 플래그 상수를 나누는
  경우) — 아래의 `// --> Description.` 형태와 달리, 뒤따르는 것을 설명하지 않고
  묶기만 합니다.
- 문장 바로 위에 놓인 `// -->` 주석은 그 특정 줄에 대해 자명하지 않은 *왜*를
  설명합니다(`MemStream::reserve`의
  `// --> Align the new capacity to the SIZE_ALIGN boundary.`나 `IStream`의
  `// --> Forward declaration of the IStream interface.` 참고) — 열거자 설명에
  쓰이는 것과 같은 표식(위 "타입" 참고)을 여기서는 인라인 문장 주석으로 다시
  쓰는 것입니다.

## 문서 주석

- 모든 공개 struct, 메서드, 자유 함수 바로 위에는 Javadoc 형식의 블록 주석이
  붙습니다:
  ```cpp
  /**
   * One-line summary of what this does.
   * @param name Description of the parameter.
   * @return Description of the return value.
   */
  ```
  자명한 선언에서는 `@param`/`@return`을 생략해도 되지만, 한 줄 요약은 남겨
  두십시오. 이는 자명하지 않은 `private:` 멤버에도 적용됩니다(예: `CTag`의
  비공개 위임 생성자) — `private`이라는 이유로 요약 주석이 면제되지는 않으며,
  아주 짧은 한 줄짜리 접근자만 면제됩니다(`CTag`의 `isValid`/`value`/... getter는
  `@return` 없이 한 줄 요약만 씁니다). 요약과 첫 `@param`/`@return` 태그 사이에
  빈 ` *` 줄을 두는 것은 비교적 최근 헤더(`span.hpp`)에서 흔하지만 필수는
  아닙니다 — 더 이른 헤더(`version.hpp`)는 요약을 태그로 바로 이어 갑니다.
- 요약 줄에 `@brief` 태그를 명시하는 것은 일탈이 아니라 받아들여지는 변형입니다.
  `x509/` 전체와 `utils/base64.hpp`(총 16개 헤더)가 이를 일관되게 쓰고, 더 오래된
  모듈들은 일관되게 쓰지 않습니다. 둘 다 괜찮지만, 한 헤더 안에서 두 방식을 섞지
  말고 *모듈 안에서* 일관성을 유지하십시오.
- `.cpp` 구현 파일 안에서는 전체 Javadoc 블록을 반복하는 대신, 선언의 요약을 다시
  적은 짧은 `/* ... */`를 각 정의 바로 위에 둡니다(`src/version.cpp` 참고).

## 버전 관리

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

- 모든 테스트 케이스는 테스트 대상 코드 옆이 아니라 `tests/` 아래에 둡니다.
  테스트 파일은 자신이 다루는 대상의 `include/certpp/`/`src/` 경로를
  반영합니다(`tests/asn1/decoder.cpp`는 `asn1/decoder.hpp`/`decoder.cpp`를
  테스트합니다). 여러 헤더에 걸친 통합/왕복 테스트도 1:1 헤더 대응은 없을 뿐
  여전히 해당 모듈 디렉터리 아래에 둡니다(`tests/asn1/roundtrip.cpp`).
  `CMakeLists.txt`는 `src/**/*.cpp`를 글로빙하는 것과 같은 방식으로
  `tests/**/*.cpp`를 글로빙하므로([build.ko.md](build.ko.md) 참고), 새 테스트
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
