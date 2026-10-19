# API 설계 규칙

[English](api.md)

## 타입

← [프로젝트 규칙](../RULES.ko.md)

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

← [프로젝트 규칙](../RULES.ko.md)

- `TArray`/`CBuffer`/원시 배열의 바이트 또는 원소 범위를 루프에서 한 원소씩
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
  예입니다: 그 CBC XOR 결합과 constant-time 패딩 스캔은 여전히 명시적인 바이트
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
  - 조건부/필터링된 복사, 예컨대 `IRng::fillNonZeroTo()`의 0 바이트 거부
    루프 — 무조건적이지 않으므로 `memcpy`가 아닙니다.
  - 라운드별로 인덱싱되는 스케줄 데이터(AES/DES/3DES 라운드 키 배열)가 평평한
    바이트 버퍼로 취급되는 것이 아니라 정말로 라운드로 인덱싱되는 경우. 그런
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
  - `CBuffer`는 결과로 가는 중간에 있는 작업용 바이트 버퍼를 위한 것입니다: 한 번
    (또는 적고 한정된 횟수만) 크기를 조정하고, 채우거나 `memcpy`로 써넣고,
    span으로 다시 읽습니다. 이렇게 쓰이는 `TArray<uint8_t>` — 즉 서로 구별되는
    원소들의 논리적 수열이 아니라 버퍼로 쓰이는 것 — 은 `CBuffer`로 타입을
    바꿔야 합니다.
  - `COctet`은 `encode`/`decode` 연산의 결정적 결과 *그 자체*이거나, 하나의
    단위로 저장/적재되는 고정 길이 데이터(키 blob, 다이제스트, 직렬화된 TLV의
    내용)를 위한 것입니다.
  - `TArray<T>`는 바이트 버퍼가 아니라 논리적으로 구별되는 원소들의 실제
    수열(예: `TArray<SKeySizeSpec>`)일 때 `TArray<T>`로 남습니다.

## span 매개변수

← [프로젝트 규칙](../RULES.ko.md)

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
  아닌 모든 빌드를 깨뜨렸습니다. `docs/HISTORY.md`의 이식성 항목을
  참고하십시오.
- 같은 논리가 입력 span에도 적용됩니다: 유용하게 되돌려 쓸 수 있는 것이 없으므로
  const가 아닌 참조가 아니라 `const SReadOnlyByteSpan&`로 받으십시오.

## 네이밍

← [프로젝트 규칙](../RULES.ko.md)

- 네임스페이스: 소문자(`certpp`, `certpp::asn1`).
- 타입: 접두사가 붙은 `PascalCase`(`include/certpp/` 아래의 공개 API에만
  해당) — 템플릿이 아닌 struct에는 `S`(`SVersion`), 템플릿 struct에는
  `T`(`TSpan<T>`), 클래스에는 `C`(`CTag`), 인터페이스에는 `I`(`IStream`),
  열거형에는 `E`(`ETagClass`). 위 "타입"을 참고하십시오. `src/` 아래의 내부
  구현 타입(예: `MemStream`)은 접두사 없는 `PascalCase`입니다.
- 열거자: `SCREAMING_SNAKE_CASE`이며, 열거형 이름의 짧은 대문자 약칭을 접두사로
  붙이되 선행 `E`는 유지합니다(`ETagClass` -> `EATAG_UNIVERSAL`,
  `EUniversalTags` -> `EAUTAG_BOOLEAN`). 이 약칭에 정해진 공식은 없으므로,
  같은 헤더의 형제 열거형들이 이미 쓰고 있는 약칭을 확인하십시오 — 위 "타입"을
  참고하십시오.
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
