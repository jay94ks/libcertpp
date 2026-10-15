# I/O와 ASN.1

[English](data-encoding.md)

## I/O 및 버퍼

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`io/span.hpp`**은 `TSpan<T>`(가변)와
  `TReadOnlySpan<T>`(읽기 전용. `TSpan<T>`에서 암묵적으로 생성 가능)를
  정의합니다 — 연속 메모리에 대한 소유하지 않는 뷰이고, 라이브러리 전체에서
  원시 포인터+길이 쌍 대신 씁니다.
  `SByteSpan`/`SReadOnlyByteSpan`은 `uint8_t` 인스턴스화의 별칭입니다(이것이
  따르는 `T` 대 `S` 접두사 규칙은
  [RULES.ko.md](../rules/api.ko.md#타입)를 보십시오). 전부
  템플릿이므로 `.cpp`가 없습니다.
- **`io/array.hpp`**은 `TArray<T>`를 정의합니다. 소유하며 증가 가능한
  배열로, 임의 원소 타입에 대한 `TSpan<T>`의 소유하는 대응물입니다
  (`TString<T>`은 문자 타입에 특화해 같은 역할을 합니다). `EArrayType`은
  직교하는 두 가지를 하나의 `uint8_t`에 담아 추적합니다. 상호 배타적인
  STATIC/DYNAMIC 하위 타입(`EARRAY_TYPE_MASK`. 배열이 자기 힙 할당을
  소유하는지, 아니면 — 정적 `wrap()`을 통해 — 절대 `delete[]`해서는 안 되는
  호출자 제공 버퍼를 단지 가리키고 있는지)과, 독립적인 `EARRAY_FIXED`
  플래그(현재 용량을 넘어 커져야 하는
  `reserve()`/`trimExcess()`/모든 `resize()`/`add()`/`insert()`를 거부)입니다.
  fixed가 아닌 STATIC 배열은 실제로 커져야 할 필요가 처음 생길 때 DYNAMIC으로
  변환됩니다 — 그 성장이 `reserve()`로 직접 요청되었든
  `resize()`/`add()`/`insert()`를 통해 간접적으로 요청되었든(모두 자리를
  만들기 위해 `reserve()`로 모이므로). 그 시점에 자기 버퍼를 할당하고
  wrap된 것을 가리키는 일을 멈추되, 애초에 소유한 적이 없으므로 해제하지는
  않습니다. `markFixed()`는 이미 설정된 하위 타입이 무엇이든 그것에
  `EARRAY_FIXED`를 OR하며, 아직 `EARRAY_NONE`인(갓 기본 생성되어 원소를 한
  번도 추가하지 않은) 배열에서는 아무 일도 하지 않습니다. 모든 변경 메서드
  (`add()`, `insert()`, `remove()`, `pop()`, `resize()`, `reserve()`,
  `trimExcess()`, `clear()`)는 `T`가 자명하게 생성/파괴 가능하다고 가정하지
  않고 placement `new`/명시적 `~T()` 호출로 원소 수명을 직접 관리하는데,
  `COctet`과 `TString<T>`가 자기 원소 타입에 대해 취하는 것과 같은 수동 수명
  접근입니다. `TSpan<T>`처럼 전부 템플릿이므로 `.cpp`가 없습니다.

  수명을 추적하는 원소 타입(소멸자가 나가면서 쓰는 낡은 매직 바이트 등을
  통해, 피연산자의 수명이 이미 끝난 생성자/`operator=` 호출을 표시해 주는
  타입)에 대해 `tests/io/array.cpp`를 쓰면서 실제 버그 세 개가 드러났습니다.
  `reserve()`는 `EARRAY_STATIC`을 `EARRAY_DYNAMIC`으로만 전환했고, 그것도
  `_data`가 이미 null이 아닐 때만 그랬습니다 — 그래서 평범하게 기본 생성된
  `TArray<T>()`(`EARRAY_NONE`)는 실제 원소를 `add()`한 뒤에도 영원히
  `EARRAY_NONE`을 보고하는 상태에 갇혔고, 이는 이 클래스를 쓰는 가장 흔한
  방식 하나에 대해 `empty()`/`operator bool()`(둘 다 크기와 무관하게
  `EARRAY_NONE`을 빈 것으로 취급합니다)을 영구히 틀리게 만들었습니다.
  `insert()`는 원본을 제자리로 이동 생성하고 파괴하는 방식으로 원소를
  밀어낸 뒤, 비워진 슬롯에 새 값을 placement 생성이 아니라 평범하게
  대입했습니다 — 그런데 그 슬롯의 객체 수명은 이미 끝나 있었고(밀어내기의
  일부로 소멸자가 돌았거나, 순수 추가의 경우에는 `resize()`가 방금 거기
  생성해 둔 살아 있는 기본 객체였으며, 수정은 재사용 전에 그것을 파괴해야
  합니다), 따라서 그 대입(또는 순수 추가의 경우 뒤따르는 밀어내기의
  placement `new`)이
  죽은 메모리 또는 아직 살아 있는 메모리에 대해 실행되었습니다. 그리고
  `markFixed()`는 `EARRAY_FIXED`를 OR하기 전에 `_type`을
  `~EARRAY_TYPE_MASK`로 mask했는데, 건드리지 말아야 했을 STATIC/DYNAMIC 하위
  타입 비트를 지워 버렸습니다(`EARRAY_FIXED`는 분리된 비트이므로 그런 mask가
  필요 없습니다. 그 코드가 분명히 복사해 온 `reserve()`/`trimExcess()`의
  정당한 "하위 타입을 교체한다" 패턴과 다릅니다). 관련 없는 네 번째 버그 —
  뒤집힌 `resize()` 단축 평가(`(_type & EARRAY_FIXED) || !reserve(size)`가
  아니라 `!(_type & EARRAY_FIXED) && !reserve(size)`)로, 커져야 하는 fixed
  배열에 대해 용량 검사를 완전히 건너뛰어 `add()`/`resize()`가 `_cap` 끝을
  넘어 placement `new`를 하게 만든 것 — 은 나머지 셋이 고쳐지고 테스트 모음이
  깨끗하게 돌 수 있게 된 뒤에 같은 테스트 모음이 잡았습니다.
- **`io/buffer.hpp` / `src/io/buffer.cpp`**는 `CBuffer`를 정의합니다.
  소유하며 크기 조절 가능한 원시 바이트 버퍼로, `resize()`, `store()`, 원시
  포인터를 위한 `toPtr()`, 그리고 넘겨주기 위한 `toSpan()`이 있습니다. 여기
  세 바이트 컨테이너 중 *작업용* 버퍼이고, 그 구분이 충분히 중요해서
  [`RULES.ko.md`](../RULES.ko.md)의 "버퍼 처리" 절이
  그것을 규정합니다. `CBuffer`는 결과를 조립하는 곳이고(한 번 resize하고,
  `memcpy`/`memset`으로 채우고, 다시 읽습니다), `COctet`은 완성된 고정 길이
  결과를 담아 두는 곳이며, `TArray<T>`는 바이트가 아니라 진짜로 구별되는
  원소들의 수열을 위한 것입니다. 라이브러리의 거의 모든
  `encode()`/`build()`가 `CBuffer`에 누적하고 마지막에 `COctet`으로
  변환합니다. 알아 둘 만한 날카로운 모서리 둘: `resize()`는 기존 내용을
  보존하지만 추가되는 바이트를 0으로 만들지는 **않습니다**
  (`TArray<uint8_t>`와 달리). 그리고 `bool`을 반환하므로 — 그것을 무시하고
  `toPtr()`로 쓰는 호출자는 할당 실패 시 범위를 벗어나 쓰는 것입니다.
- **`utils/base64.hpp` / `src/utils/base64.cpp`**는 `CBase64`를 정의합니다.
  base64 코덱의 양쪽 절반을 한 클래스에 담았습니다. 증분 변환
  (`push()`/`finish()`. 방향을 고정하는 `EBase64Mode` —
  `EB64M_ENCODE`, `LINE_LENGTH`에서 PEM 식으로 줄을 바꾸는
  `EB64M_ENCODE_BR`, `EB64M_DECODE` — 과 내부 `MAX_BUFFER` chunk 처리와
  함께), 그리고 버퍼 전체를 한 번에 처리하는 정적 일괄
  `encode()`/`decode()`입니다. 디코더는 `=` padding과 공백에 대해 의도적으로
  관대한데, 그것이 PEM 블록이 실제 세상에 나타나는 모습 그대로에 쓸 수 있게
  만들어 줍니다. `CCert::importPem()`/`exportPem()`이 주요 소비자입니다.
  `io/base64.hpp`는 이것이 **아니라는** 점에 유의하십시오. 아무것도 선언하지
  않고 `certpp.hpp`가 의도적으로 포함하지 않는 빈 자리표시 헤더입니다.
- **`utils/json.hpp` / `src/utils/json.cpp`**는 `CJson`을 정의합니다. null,
  boolean, number, string, array, object를 담는 JSON 값 트리입니다.
  `parseJson()`은 완전한 JSON 값 하나만 받고, `toString()`은 문자열과 객체
  키의 escape를 처리하며 유한한 `double`의 왕복 정밀도를 보존합니다. 깊이
  제한을 넘는 값과 유한하지 않은 숫자는 `null`로 출력됩니다.
  `toBson()`과 `parseBson()`은 중첩 객체/배열, boolean, string, null, double,
  BSON 정수(`double`로 변환)를 포함하는 BSON 문서를 처리하며, 지원하지 않는
  BSON 타입은 거부합니다. BSON scalar 루트는 인코딩할 수 없습니다.
  `CERTPP_WITHOUT_JSON`을 켜면 `certpp.hpp`의 선택적 include가 비활성화되고,
  설치 헤더에서 `json.hpp`가 빠지며 `tests/utils/json.cpp`도 건너뜁니다.
- **`io/octet.hpp` / `src/io/octet.cpp`**는 `COctet`을 정의합니다. 소유하는
  고정 크기 바이트 버퍼(`TString<T>`와 달리 크기 조절/증가 불가)입니다 —
  `store()`가 내용을 교체하고(복사해 소유권을 가집니다. null 포인터나 크기 0은
  거부되고 이전 내용을 건드리지 않으므로, 실패한 `store()`가 기존 인스턴스를
  망가뜨릴 수 없습니다), `clear()`가 해제하며,
  `toSpan()`/`toPtr()`이 읽기 전용 접근을 줍니다. 복사 생성/대입은 깊은
  복사입니다. 이동 *생성*은 소유권을 옮기고 원본을 비웁니다. 이동 *대입*은
  대신 swap하므로 원본이 대상이 가지고 있던 것을 갖게 됩니다 — 아래
  `io/array.hpp` 항목에서 설명하는 프로젝트 전반의 관례이며, 자기 자신으로의
  이동을 안전하게 유지하고 옛 버퍼를 원본 자신의 소멸자가 해제하도록
  남깁니다. `secureClear()`는 해제하기 전에 내용을 영으로 지웁니다. 비밀을
  담고 있는 `COctet`에 필요한데, 그 바이트가 읽기 전용
  `toPtr()`/`toSpan()`으로만 도달 가능하므로 `CSecure::zero()`를 밖에서
  겨눌 수 없기 때문입니다.
- **`io/stream.hpp` / `src/io/stream.cpp`**는 `IStream`을 정의합니다.
  읽기/쓰기/탐색 스트림 인터페이스
  (`capabilities()`/`EStreamCapability`로 능력을 질의하고,
  `trimExcess()`/`length(newLen)`/`flush()` 같은 선택적 연산은 순수 가상이
  아니라 기본적으로 `ERET_NOTIMPL`입니다)와, `IStream::createMemory(...)`
  팩토리 함수들입니다. `.cpp`는 팩토리만 구현합니다. 구체적인 메모리 내
  구현은 `MemStream`이며, `src/io/` 아래의 private 클래스
  (`memstream.hpp`/`.cpp`)로 `include/certpp/`를 통해 노출되지 않습니다
  (`MemStream::write()`가 성공한 모든 쓰기에서 바이트 수가 아니라 0을
  반환했습니다 — 실제 버그였는데, 그 반환값이 `IStream::write()`의 계약이
  호출자에게 짧거나 실패한 쓰기를 탐지하도록 허용하는 유일한 수단이기
  때문입니다. `CWriter`가 그것에 의존하기 시작했을 때 고쳤습니다). 왜 거기에
  있고 그 헤더 가드/include가 공개 헤더와 어떻게 다른지는
  [RULES.ko.md](../RULES.ko.md#내부-구현-헤더)를
  보십시오.

## ASN.1

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`asn1/tag.hpp` / `src/asn1/tag.cpp`**는 `CTag`를 정의합니다. ASN.1
  태그(클래스 + constructed 플래그 + 태그 번호)이며,
  `TReadOnlySpan<uint8_t>`/`TSpan<uint8_t>`와 상호 변환하는
  `decode()`/`encode()`, 그리고 표준 태그 클래스/universal 태그 번호를 위한
  `ETagClass`와 `EUniversalTags`가 있습니다.
- **`asn1/decoder.hpp` / `src/asn1/decoder.cpp`**는 `CDecoder`를 정의합니다.
  ASN.1 데이터를 디코드하는 정적 메서드들(`EEncodingRule`이 BER/CER/DER를
  선택하고, `EDecoderStatus`가 디코드가 왜 실패했는지 보고합니다)이며, 두
  계층으로 나뉩니다.
  - **TLV 프레이밍**(태그와 무관): `readEncodedValue()`가 완전한
    tag-length-value를 읽으며, 확정 길이 값과 BER/CER 비확정 길이 값 양쪽을
    다룹니다(후자는 end-of-contents 표시를 찾아 중첩된 값들을 스캔해
    해결하며, 악의적으로 깊은 비확정 길이 중첩이 스택을 소진시킬 수 없도록
    `MAX_NESTING_DEPTH` 가드로 경계가 지어집니다).
    `readNextElement()`는 그 위에 커서를 얹어 SEQUENCE/SET의 멤버를
    순회합니다. `tryReadEncodedValue()`는 같은 연산이면서 `bool`이 아니라
    `EDecoderStatus`를 반환하므로, 한 번에 한 chunk씩 바이트를 받는 호출자가
    "잘렸으니 더 보내라"(`EDEC_NEED_MORE`)와 "잘못됐으니 포기하라"를
    구별할 수 있습니다.
  - **내용 디코딩**(태그와 독립적이므로, 호출자의 태그가 평범한 universal
    태그였든 IMPLICIT/context-specific 태그였든 동작합니다):
    `decodeBoolean()`, `decodeInteger()`, `decodeEnumerated()`,
    `decodeNull()`, `decodeOctetString()`, `decodeBitString()` +
    `testNamedBit()`(NamedBitList. 예: X.509 KeyUsage), `decodeOid()` +
    `countOidArcs()`/`decodeOidString<TChar>()`(후자는 arc들을 점으로 구분된
    10진 텍스트로, 예컨대 "1.2.840.113549.1.1.1"로 `TString<TChar>`에
    포매팅합니다 — 순전히 ASCII 숫자와 `.`뿐이므로
    `decodeString<TChar>()`과 달리 두 `TChar` 모두에 대해 로케일과
    무관합니다), `decodeText()`/`decodeString<TChar>()`
    (UTF8String/PrintableString/IA5String/NumericString 문자 집합을
    검증합니다. 다른 문자열 태그는 통과시킵니다 —
    `decodeString<TChar>()`은 추가로 `TUtf8Encoding<TChar>`를 통해
    `TString<TChar>`로 전사합니다), 그리고
    `decodeUtcTime()`/`decodeGeneralizedTime()`(`SDateTime`으로),
    `decodeDistinguishedName()`(SEQUENCE의 내용 옥텟에서
    `CDistinguishedName`으로 — 기대하는 정확한 구조는 아래를 보십시오).
    이것들은 tag+length 헤더가 아니라 값의 내용 옥텟만 받습니다(바깥
    `readEncodedValue()` 호출의 `outArea`). `decodeOctetString()`과
    `decodeBitString()`은 각각 `SReadOnlyByteSpan&` 버전 옆에 `COctet&`
    오버로드를 가지며, 원본 버퍼를 가리키는 대신 내용을 소유하는 `COctet`에
    복사합니다.

  `decodeDistinguishedName()`은 X.501 Name/RDNSequence를 파싱합니다. 각 내용
  원소는 정확히 하나의 AttributeTypeAndValue(SEQUENCE { type OBJECT
  IDENTIFIER, value ANY })를 담은 SET(RelativeDistinguishedName)이어야
  합니다 — 다중 값 RDN은 곧바로 거부되는데, `CDistinguishedName`은
  `ENameType`당 `CName` 하나만 보유하므로 첫 값만 남기고 나머지를 조용히
  버리는 것이 잘못된 실패 방식이기 때문입니다. `type`은
  `CName::attributeTypeOf()`로 해석되어야 합니다 — 이름을 댈 수 없는 속성
  타입은 `Name` 전체를 실패시키며, 이것이 `organizationIdentifier` 하나가
  실제 EU 규제 인증서를 import 불가로 만들곤 했던 이유이고, 디코더가 건너뛰는
  법을 배우는 대신 `ENameType`이 자라야 했던 이유입니다(이름 없는 속성을
  버리면 서로 다른 두 DN이 같다고 비교되고, DN 동등성은
  `CCertCollection::buildChain()`이 발급자와 주체를 맞추는 기준입니다). `value`는 PrintableString, UTF8String
  또는 IA5String이어야 하며(`CEncoder::encodeDistinguishedName()`이 쓰는 세
  종류 — 아래 참고), `decodeString<wchar_t>()`로 디코드한 뒤 `CName`을
  생성하기 전에 `TString<wchar_t>::convertTo<char>()`로 좁은 형태로
  변환합니다(`CDistinguishedName::tryParse(CWideString)`의 같은 변환 경로를
  반영합니다). 바깥 문서의 규칙 집합과 무관하게 항상 DER의 규칙을
  적용하는데, X.501 Name은 BER/CER 문서 안에서도 실무에서 DER로 인코드되기
  때문입니다 — 그래서 `readEncodedValue()`와 달리 `EEncodingRule` 파라미터를
  받지 않습니다.

  `decoder.hpp`는 `EEncodingRule`/`checkEncodingRule`과 CER 세그먼트 한계
  검사(`CER_MAX_SEGMENT`/`exceedsCerSegmentLimit`)도 담고 있습니다. 디코더와
  `CEncoder` 둘 다 필요하기 때문입니다.
- **`asn1/encoder.hpp` / `src/asn1/encoder.cpp`**는 `CEncoder`를 정의합니다.
  쓰기 쪽 대응물이고, `CDecoder`의 두 계층을 반영합니다.
  - **TLV 프레이밍**: `writeEncodedValue()`가 확정 길이 형식으로
    tag-length-value를 씁니다(세 규칙 집합 모두에서 유효합니다. BER/CER의
    선택적 비확정 길이 형식은 절대 만들지 않습니다). 그리고
    `encodedValueSize()`가 목적지 버퍼 크기를 미리 잡아 줍니다.
    `writeSequenceOf()`/`writeSetOf()`는 이미 인코드된 자식들을 이어 붙여
    SEQUENCE/SET의 내용을 만듭니다. `writeSetOf()`는 추가로 먼저 CER/DER의
    정규 오름차순으로 재배열합니다(BER에서도 유효하므로 항상 적용합니다).
  - **내용 인코딩**: `encodeBoolean()`, `encodeInteger()`,
    `encodeEnumerated()`, `encodeNull()`, `encodeOctetString()`,
    `encodeBitString()` + `encodeNamedBitList()`(X.690 11.2.2에 따라
    뒤쪽의 0 비트를 다듬습니다), `encodeOid()` + `encodedOidSize()`,
    `encodeOidString<TChar>()` + `encodedOidStringSize<TChar>()`
    (`decodeOidString<TChar>()`의 역. private `parseOidArcs<TChar>()` 보조
    함수로 점 구분 10진 `TString<TChar>`를 파싱한 뒤 `encodeOid()`와 정확히
    같이 인코드합니다), `encodeText()`/`encodeString<TChar>()`
    (`decodeText()`/`decodeString<TChar>()`의 역. `TString<TChar>`를
    UTF-8로 전사한 뒤 `decodeText()`로 검증합니다) +
    `encodedStringSize<TChar>()`,
    `encodeUtcTime()`/`encodeGeneralizedTime()`(+
    `encodedGeneralizedTimeSize()`. 소수점 이하 초 부분이 있는지에 따라
    길이가 달라지기 때문입니다), 그리고 `encodeDistinguishedName()`(+
    `encodedDistinguishedNameSize()`. 아래 참고). `encodeOctetString()`과
    `encodeBitString()`도 각각 `const COctet&` 오버로드를 가지며,
    `COctet::toSpan()`을 통한 `SReadOnlyByteSpan` 버전의 얇은 래퍼입니다.
    이것들은 항상 DER 정규 값 인코딩(최소 길이 정수, `0xFF`/`0x00` 불리언,
    ...)을 내놓습니다 — 쓰는 쪽에게는 자유로운 선택이고 정규 형태는
    BER/CER에서도 유효하므로, 어느 것도 `EEncodingRule` 파라미터를 받지
    않습니다.

  `encodeDistinguishedName()`은 `decodeDistinguishedName()`의 역입니다.
  구성요소당 RDN(SET) 하나를, `CDistinguishedName`의 `ENameType`
  오름차순(`std::map` 자신의 순회 순서)으로, 각각 정확히 하나의
  AttributeTypeAndValue를 담아 씁니다 — `type`은 `CName::attributeOid()`에서,
  `value`는 구성요소의 *escape되지 않은* 텍스트
  (`CName::toString<wchar_t>(false)`)를 `encodeString<wchar_t>()`로 인코드한
  것(진짜, 로케일과 무관한 UTF-8)이며, 먼저 PrintableString으로 시도하고 그
  문자 집합 검사가 실패할 때에만 UTF8String으로 시도합니다. `ENAME_DC`가
  하나뿐인 예외입니다. RFC 4519 2.4가 `domainComponent`의 문법을 대안 없이
  IA5String으로 주므로, 그렇게 쓰고 대체로 넘어가지 않고 곧바로 실패합니다.
  private `buildAttributeTypeAndValue()`/`buildDistinguishedNameContent()`
  보조 함수들이 중첩된 TLV 바이트 전체를 스크래치 `TArray<uint8_t>`에
  아래에서 위로 만듭니다(OID TLV + 값 TLV -> AttributeTypeAndValue SEQUENCE
  TLV -> RDN SET TLV -> 이어 붙인 RDNSequence 내용).
  `encodedDistinguishedNameSize()`와 `encodeDistinguishedName()`은 둘 다 같은
  private 보조 함수를 호출하므로(무엇이 인코드되는지에 대해 서로 의견이
  갈릴 수 없습니다) 결과를 측정하는지 호출자의 목적지로 복사하는지만
  다릅니다. 구성요소가 없는 빈 `CDistinguishedName`은 내용 옥텟 0개(빈
  SEQUENCE)로 성공적으로 인코드됩니다 — `encodedStringSize()`와 마찬가지로,
  크기만 구하는 보조 함수의 `0` 반환은 "비었음"과 "인코드 불가" 사이에서
  모호합니다. 둘을 구별하려면 `encodeDistinguishedName()`을 직접 호출하고 그
  반환값을 확인하십시오. 디코더 쪽과 마찬가지로 항상 DER의 규칙을 적용하고
  `EEncodingRule` 파라미터를 받지 않습니다.
- **`asn1/reader.hpp` / `src/asn1/reader.cpp`**는 `CReader`를 정의합니다.
  `CDecoder`의 내용 수준 `decode*()` 메서드들을 스트림/커서 관리와 짝지어,
  호출자가 모든 필드마다 `readNextElement()` + `decode*()`를 손으로 쓰지
  않게 합니다. `IStream`에서 생성되며 그것을 지연 평가로 읽습니다.
  `growBuffer()`는 파싱 시도가 실제로 버퍼된 데이터를 다 썼을 때에만 소유하는
  `COctet`으로 chunk를 하나 더 당겨 오고, 스트림 전체를 미리 읽지 않으므로,
  생성 이후(그러나 필요해지기 전에) 스트림에 쓰인 데이터도 여전히
  보입니다. `CDecoder`는 여전히
  시도마다 연속된 span이 필요하고(BER/CER 비확정 길이 파싱은 앞을 스캔해야
  합니다) 따라서 성장 자체는 피할 수 없으며 그 시점만 조절됩니다. span에서
  직접 생성되면(예: 부모 원소의 이미 완전히 버퍼된 내용) 자라날 스트림이
  없으므로 단지 그 span을 가리킵니다. `growBuffer()`가 `COctet`을 재할당하므로
  (옛 할당을 해제합니다) 평범하게 저장한 `SReadOnlyByteSpan` 커서 스냅샷은
  호출 중간에 낡아질 수 있습니다 — 실패 시 커서를 되돌려야 하는 모든 메서드는
  private `withRollback()` 보조 함수를 거치는데, 그것은 재할당마다 올라가는
  `_generation` 카운터를 추적하고 매달릴 수 있는 저장된 포인터를 믿는 대신
  올바른 되돌림 대상을 재구성합니다(아무것도 자라지 않았다면 저장된 span,
  자랐다면 현재 버퍼 전체입니다. `growBuffer()`는 항상 저장된 span의 소비되지
  않은 바이트와 새로 읽은 바이트로 정확히 그것을 다시 만들기 때문입니다). 이
  소유하며 필요할 때 재할당되는 버퍼 때문에 `CReader`는 이동 전용입니다
  (복사하면 사본의 커서가 원본의 버퍼를 가리키게 됩니다). 모든 타입별
  `readBoolean()`/`readInteger()`/`readEnumerated()`/`readNull()`/
  `readOctetString()`/`readBitString()`(`SReadOnlyByteSpan`과 `COctet`
  오버로드)/`readOid()`/`readOidString<TChar>()`/`readText()`/
  `readString<TChar>()`/`readUtcTime()`/`readGeneralizedTime()`은 특정한
  평범한 UNIVERSAL, *primitive* 태그를 기대하며 다음 원소를 읽습니다
  (constructed 인코딩도 거부합니다. `CDecoder`의 내용 수준 디코더 중 어느
  것도 constructed/분절된 BER/CER 문자열을 재조립하지 않기 때문입니다) —
  불일치나 디코드 실패가 있으면 커서는 있던 자리에 정확히 남으므로, 호출자가
  다른 읽기를 시도하거나 OPTIONAL/DEFAULT 필드를 없는 것으로 취급할 수
  있습니다. `readDistinguishedName()`은 같은 태그-불일치-시-커서-유지 계약을
  따르지만 (`readSequence()`처럼) *constructed* SEQUENCE를 기대하고, 중첩된
  `CReader`를 반환하는 대신 `CDecoder::decodeDistinguishedName()`으로 완전히
  디코드합니다. `CDistinguishedName`은 그 자체로 완전한 값이고, 호출자가
  멤버 단위로 순회하는 것이 아니기 때문입니다.
  `readSequence()`/`readSet()`/`readConstructed()`는 constructed 값의 내용에
  대한 중첩 `CReader`를 반환하며, SEQUENCE/SET으로(또는
  `readConstructed()`의 경우 그 외의 임의 constructed 태그, 예컨대
  context-specific `[n]` EXPLICIT 래퍼로) 내려가기 위한 것입니다. 저수준
  `readNextElement()`가 이 모두의 바탕이고, 타입별 메서드들이 평범한
  universal 태그로 인식할 수 없는 IMPLICIT 태그 또는 CHOICE 내용을 위한
  비상구입니다.
- **`asn1/writer.hpp` / `src/asn1/writer.cpp`**는 `CWriter`를 정의합니다.
  쓰기 쪽 대응물이고, 각 타입별 `writeBoolean()`/`writeInteger()`/... 메서드가
  대응하는 `CEncoder::encode*()`로 내용을 스크래치 버퍼에 인코드한 뒤,
  `writeElement()`(내부적으로 `CEncoder::writeEncodedValue()`)로 완전한
  tag-length-value를 스트림에 쓰며, 스트림이 모든 바이트를 썼다고 보고하는지
  검증합니다. `writeSequence()`/`writeSet()`은 새로운 중첩 빌더 API를
  들이지 않고 `CEncoder::writeSequenceOf()`/`writeSetOf()`를 정확히
  반영합니다(이미 인코드된 자식들의 배열). 각 자식은 기존 `CEncoder` 전용
  테스트들이 이미 하는 것과 똑같이 `CEncoder`(또는 자기 메모리 스트림 위의
  중첩 `CWriter`)로 먼저 만드십시오. `writeDistinguishedName()`은 다른 타입별
  쓰기와 같은 스크래치-버퍼-다음-`writeElement()` 패턴을 따르며,
  `CEncoder::encodedDistinguishedNameSize()`로 버퍼 크기를 잡고
  `CEncoder::encodeDistinguishedName()`으로 채운 뒤 SEQUENCE 태그 아래로
  씁니다. `CReader`와 달리 `CWriter`는 `IStreamPtr` + `EEncodingRule`만
  보유하므로 자유롭게 복사 가능합니다.
