# 범위, 통합 및 DNSSEC

[English](scope.md)

## 확장 지점과 범위

← [개념](../CONCEPTS.ko.md)

`third-party/`는 이제 첫 의존성을 벤더링합니다. `doctest`(단일 헤더,
`third-party/doctest/` 아래)이고 `tests/`만 씁니다. 그
`third-party/CMakeLists.txt`가 벤더링된 각 의존성을 자기 CMake
타깃으로 노출합니다(오늘은 `doctest`뿐입니다). 루트 `CMakeLists.txt`는
`tests/` 밖의 무엇도 그것을 필요로 하지 않으므로
`CERTPP_BUILD_TESTS=ON`일 때만 `add_subdirectory(third-party)`합니다.
라이브러리 자신이 하는 모든 것은 밑바닥부터 구현되어 있고 의존성이 전혀
필요 없습니다. 해시들, 대칭 암호들, 비대칭 알고리즘들, 그리고 그 아래의 큰
수와 이진체 연산입니다.
따라서 아직 테스트 외 의존성이 없고 그것의 구체적인 후보도 없습니다. 미래의
어떤 작업이 진짜로 하나를 필요로 하게 되면, 같은 패턴을 따릅니다 — 자기
`third-party/<name>/` 디렉터리 아래에 벤더링하고
`third-party/CMakeLists.txt`에 짝이 되는 타깃을 추가하되,
`CERTPP_BUILD_TESTS` 뒤에 관문을 걸지 않고 `certpp` 자신에서 링크합니다.

구체 `IAsymmetric` 구현 — RSA, DSA, 소수·Brainpool·이진/Koblitz 곡선 위의
ECDSA, Ed25519, Ed448, X25519, GOST R 34.10-2012, ML-DSA — 은
`include/certpp/crypto/asyms/`와 `src/crypto/asyms/` 아래에 있으며, 구체
`IHasher` 구현들이 `hasher.hpp` 자신의 옆이 아니라 `crypto/hashers/` 아래에
있는 방식을 반영합니다. 단수인 `asym.hpp`/`hasher.hpp` 파일이 인터페이스를
정의하고, 복수인 `asyms/`/`hashers/` 디렉터리가 구체 알고리즘당 파일 하나를
담습니다. 새 `asyms/` 구현의 테스트는 오늘 `tests/crypto/hashers/`가 하는
것과 정확히 같이 `tests/crypto/asyms/` 아래의 같은 거울 경로를 따릅니다.
`IAsymmetric::builtIn()`(`src/crypto/asym.cpp`)이 각 `EAsymmetrics` 값을
자기 구체 클래스로 디스패치합니다. 새 알고리즘은 거기에 `case` 하나를
추가하고, 그 enumerator는 **`EASYM_MAX` 바로 앞으로 가며 절대 중간에 삽입되지
않습니다**. 이 enum은 ABI 경계를 넘으므로(이 라이브러리는 shared 객체로
출하되고 설치된 패키지로 소비됩니다), 번호를 다시 매기면 옛 헤더로 컴파일된
호출자가 조용히 다른 알고리즘을 선택하게 되고 그것을 진단할 것이 아무것도
없습니다. 그 다음 그 enum에 대한 모든 전수 switch를 확인하고, 알고리즘이
인증서에 나타난다면 `CCert`의 `KEY_ALGOS`/`SIG_ALGOS` 테이블과
`signsMessageDirectly()`도 확인하십시오. RSA의 키/서명 DER 인코딩, 그리고
미래의 모든 `asyms/` 구현의 그것은 `CEncoder`/`CDecoder`가 다루지 않는 임의
정밀도 `INTEGER`를 위해 `asn1::CDer`(`asn1/der.hpp`)를 거칩니다 — 그 자체의
doc 주석을 보십시오. 미래의 진짜로 라이브러리가 제공할 수 없는
의존성(아직 없습니다. RSA는 `CBigNum`만 필요했고 그것도 밑바닥부터
만들었습니다)은 대신 위의 벤더링하고-타깃을-노출하는 패턴을 따를 것입니다.

`x509/`는 파싱도 생성도 합니다. `CCert`/`CCertBuilder`가 `Certificate`를 읽고
만들며(그리고 서명하며), `CCrlReader`/`CCrlWriter`가 `CertificateList`를,
`COcspRequest`/`COcspResponse`와 그 빌더들이 OCSP 교환을,
`CCertRequest`/`CCertRequestBuilder`가 PKCS#10 `CertificationRequest`를
담당하고, 열 확장 전부가 parse/build 쌍을 가지며, DER뿐 아니라 PEM도
처리됩니다(`ECertFormat`, `importPem()`/`exportPem()`. 둘 다
`CPemChainFormat`에 위임합니다 — 아래 `x509/chain/pem.hpp` 참고). 새 확장
타입은 `x509/exts/`의 정착된 모양을 따르고(자기 `OID`를 가진 구체
`IExtension` 하위 클래스를 `ext.cpp`의 디스패치 테이블에 추가하고, 짝이 되는
`IExtensionBuilder`도 함께), GeneralName 모양이나 값 객체 목록 모양의 필드를
보유해야 한다면 그 모양들을 지역적으로 다시 정의하는 대신
`x509/generalname.hpp`/`access.hpp`/`policy.hpp`를 재사용합니다.

링크 하나 단위의 서명 검증은 자리를 잡았습니다. `CCert::verifyBy(issuer)`,
`CCrlReader::verifyBy(issuer)`, `CCertRequest::verify()`, 그리고 OCSP 자신의
`verifySignature()`가 각각 원래 서명된 바이트에 대해 "이 키가 이것에
서명했는가?"에 답합니다(손으로 하고 싶은 호출자를 위해
`CCert::tbsCertificate()`/`CCrlReader::tbsCertList()`/
`CCertRequest::certificationRequestInfo()`가 그 바이트를 노출합니다).
`CCertCollection::buildChain()`은 발급자/주체 이름으로 집합 순서를 잡고
`verifyLinks()`는 그 링크 검사를 적용합니다. 여전히 없는 것은 인증 경로 검증입니다.

- **인증 경로 검증** — 유효 기간, `BasicConstraints`/`KeyUsage`/
  `NameConstraints` 강제, 정책, 폐지, 신뢰 앵커 판단, 그리고 RFC 5280의
  "인식되지 않는 critical 확장을 거부하라" 규칙입니다. 이 라이브러리는
  관련 입력을 파싱하고 보존하며 그 정책들을 강제하지
  않습니다. 이 문서 맨 앞의 범위 설명을 보십시오. 같은 공백이 PKCS#10의 CA
  쪽에도 나타납니다. `CCertBuilder::subjectFrom()`은 검증된 요청의 subject와
  키를 건네주고, 그 subject 이름과 그 요청된 확장들이 인증*되어야 하는지*를
  결정하는 것은 이 라이브러리가 모델링하지 않는 정책입니다.

## 엄브렐라 헤더 및 테스트 통합

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`certpp.hpp`**은 소비자를 위한 단일 포함 지점입니다. `include/certpp/`
  아래에 새 공개 헤더를 추가하면 그 `#include`를 여기 추가하십시오.
  선택적 `utils/json.hpp` include는 `CERTPP_WITHOUT_JSON`으로 가드되며,
  JSON을 비활성화하면 CMake가 이 정의를 소비자에게도 전파합니다. 빈 호환성
  자리표시자인 `io/base64.hpp`는 포함하지 않으며(`CBase64`는
  `utils/base64.hpp`에 있습니다), `arch.hpp`는 소비자 API가 아니라 구현 기능
  관문 헤더입니다.
- **`tests/`**는 모든 테스트 케이스를 담고 있고, `CERTPP_BUILD_TESTS`(기본
  `ON`)로 소스 파일당 실행 파일 하나로 빌드되어 CTest에 등록됩니다. 파일
  배치/이름 관례는
  [RULES.ko.md](../rules/maintenance.ko.md#테스트)를, 빌드하고
  돌리는 방법은 [BUILDING.ko.md](../building/verification.ko.md#테스트)를 보십시오. 둘 다 이
  파일들이 쓰는 벤더링된 `doctest` 프레임워크를 다룹니다.

## DNSSEC

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

#### `dnssec`

`x509`의 일부가 아니라 별개 모듈인데, DNSSEC이 X.509의 인코딩을 하나도 공유하지
않기 때문입니다. 인증서가 공개키를 `SubjectPublicKeyInfo`로, ECDSA 서명을 DER
`SEQUENCE { r, s }`로 담는 자리에서, DNSSEC은 벌거벗은 키 재료와 벌거벗은
이어 붙임 `r | s`를 씁니다. 그래서 DNSKEY를 `IAsymmetric::createPublicKey()`에
건넬 수 없고 RRSIG 서명을 `verify()`에 건넬 수 없습니다. 중간에서 무언가가 다시
인코드해야 하며, 그것이 이 모듈의 목적 전부입니다.

- **`dnssec/name.hpp` / `src/dnssec/name.cpp`**는 `CDnsName`을 정의합니다.
  `toWire()`는 항상 ASCII 대문자를 소문자로 접고, API는 의도적으로 호출자에게
  그에 대한 선택권을 주지 않습니다. DS digest가 소유자 이름 다음 DNSKEY
  RDATA에 대해 취해지므로, 접히지 않은 채 digest에 도달하는 이름은 발행된 모든
  DS와 어긋나는 DS를 만들어 내고, 접기를 건너뛰는 옵션은 그것을 우연히 도달
  가능하게만 만들 것입니다. 압축 포인터(RFC 1035 4.1.4)는 해결되는 대신
  거부되는데, DNSSEC이 서명된 이름에서 그것을 금지하고 그것을 담고 있는
  이름은 메시지의 나머지 없이 정규화될 수 없기 때문입니다.
  `fromWirePrefix()`는 RRSIG RDATA를 위해 존재하며, 거기서는 서명자의 이름
  뒤에 아무 구분 없이 서명이 곧바로 따라옵니다.
- **`dnssec/records.hpp` / `src/dnssec/records.cpp`**는 `SDnskey`,
  `SDsRecord`, `SRrsig`를 정의합니다. 키 태그는 저장되는 대신 요청 시
  유도되는데, 그것이 식별자가 아니라 RDATA 전체에 대한 체크섬이기
  때문입니다. 필드로 보유하면 그것이 지칭하는 키와 어긋날 수 있게 됩니다.
  `SRrsig::toSignedPrefix()`는 서명 필드를 생략한 RDATA를 내놓으며, 그것이
  해시에 가장 먼저 먹여지는 것입니다(RFC 4034 3.1.8.1). 그 뒤에 오는 정규
  RRset을 조립하는 일은 호출자에게 맡겨져 있습니다. 이 라이브러리는 DNS
  RRset을 모델링하지 않기 때문입니다. 공개키는 여기서 DNS 인코딩으로
  남아 있고 `CDnssecKeys`만이 변환하는데, 그 둘이 독립적으로 실패할 수 있기
  때문입니다 — RDATA가 완벽히 제대로 생긴 채로도 이 라이브러리가 구현을 갖지
  않은 알고리즘의 키를 담고 있을 수 있고, 키 태그와 DS digest는 어느 쪽이든
  원시 RDATA에 대해 계산됩니다.
- **`dnssec/keys.hpp` / `src/dnssec/keys.cpp`**는 `CDnssecKeys`를 정의하고,
  그것이 재인코딩 계층입니다. RSA(RFC 3110)는 지수 길이, 지수, 그 다음
  모듈러스를 쓰는데, 이 라이브러리는 DER
  `SEQUENCE { INTEGER modulus, INTEGER exponent }`를 원합니다 — 두 피연산자가
  순서마저 반대로 나타난다는 점에 유의하십시오. ECDSA(RFC 6605)는 `x | y`를
  쓰는데, 그것은 `0x04` 접두사를 뺀 SEC1 비압축 점입니다. EdDSA(RFC 8080)는
  이미 올바른 형태이고, default가 아니라 명시적 case로 처리되므로 아무도
  구현하지 않은 알고리즘이 조용히 원시로 취급되는 대신 거부됩니다. 서명도
  같은 길을 가며, ECDSA 방향이 조심해야 하는 쪽입니다. DER `INTEGER`는 선행
  0 옥텟을 담지 않으므로, `r`과 `s`를 각각 곡선의 체 크기로 왼쪽을 채우지
  않고 다시 써 내보내면 `r`이 짧았던 만큼 `s`가 밀리고, RFC 6605 2는 고정
  폭을 요구합니다.

`fromPublicKey()`는 DNSSEC 알고리즘 번호를 추론하는 대신 받아야 하는데,
여러 번호가 하나의 키 타입을 공유하기 때문입니다. RSA/SHA-1, RSA/SHA-256,
RSA/SHA-512가 모두 같은 RSA 키를 담고 해시만 다릅니다. `hasherOf()`는
Ed25519와 Ed448에 대해 true를 반환하면서도 `EHASH_UNKNOWN`을 보고하는데,
그것들은 서명 스킴의 일부로 내부적으로 해싱하므로 호출자가 먼저 적용할 외부
해시가 없기 때문입니다.

이 모듈이 하지 *않는* 것은 RRset을 검증하는 일입니다. 레코드와 키를 변환하고,
키 태그와 DS digest를 계산하고, 호출자에게 서명되는 접두사를 건넵니다. 정규
RRset 구성과 검증 호출 자체는 그 밖입니다.
