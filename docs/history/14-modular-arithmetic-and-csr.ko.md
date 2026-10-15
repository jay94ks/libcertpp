# 모듈러 산술과 인증서 요청

[English](14-modular-arithmetic-and-csr.md)

## `CMontgomery`: 모든 모듈러 곱셈에서 긴 나눗셈을 빼내기

← [변경 이력](../HISTORY.ko.md)

`CBigNum::mulMod(other, modulus)`는 `mul(other)` 다음 `mod(modulus)`이고,
`mod()`는 Knuth의 알고리즘 D인 `divMod()`를 호출합니다. 그것은 그 메서드에는
올바른 모양입니다 — 그것은 아무것도 캐시할 곳이 없고, 짝수인 것을 포함해
0이 아닌 어떤 모듈러스에 대해서도 계속 동작해야 합니다 — 그러나 그것은 모든
곡선 연산의 모든 모듈러 곱셈이 완전한 큰 수 나눗셈을 수행했다는 뜻입니다.
`eccurve.cpp`, `ed448.cpp`, `ed25519.cpp`, `ecdsa.cpp`, `gost3410.cpp`의
`mulMod` 호출 지점 113개와 `mod` 호출 지점 51개에 걸쳐, 그것이 이 라이브러리
비대칭 알고리즘에서 단일 최대 비용이었습니다.

`include/certpp/utils/montgomery.hpp` + `src/utils/montgomery.cpp`가
`CMontgomery`를 추가합니다. 홀수 모듈러스 하나 더하기 한 번 미리 계산된
`n' = -m^-1 mod 2^32`와 `R^2 mod m`이며, `CBigNum`의 가공되지 않은 limb에
대한 CIOS Montgomery 곱셈을 지닙니다. API와 그것이 동작하는 두 영역은
[CONCEPTS.md](../CONCEPTS.ko.md)의 항목을 보십시오. 결정 셋이 여기
기록할 만합니다.

**Barrett이 아니라 Montgomery.** Barrett의 이점은 잉여 영역이 필요 없고
짝수 모듈러스에 대해 동작한다는 것이고, Montgomery의 것은 *여러 연산이
모듈러스 하나를 공유하는 한* 더 싼 내부 루프(Barrett의 ~2.5k²에 대비해
limb 곱셈 ~2k²이고, 그것이 함의하는 절단을 지닌 limb k+1개짜리 `mu`가
없습니다)입니다. 곡선 코드는 스칼라 곱셈당 고정된 소수 하나에 대해 연산
수백 개를 하는데, 그것이 정확히 그 경우이고, Barrett의 일반성은 여기서
아무것도 사 주지 않습니다. `CBigNum::mod()`가 이미 짝수 모듈러스 경우를
덮고 있고 남을 것이기 때문입니다.

**덧붙이는 것이고, 결코 대체가 아닙니다.** `CBigNum::mod()`와 `mulMod()`는
바이트 단위로 변경되지 않았습니다. Montgomery 축약은 홀수 모듈러스를
요구하므로 그것들을 조용히 다른 길로 보내는 것은 결코 선택지가 아니었습니다.
`CMontgomery`는 그것들 옆의 opt-in 빠른 경로이고, 짝수나 0인 모듈러스로
만들어진 것은 `isValid() == false`를 보고하며 그럴듯해 보이는 무언가를
계산하는 대신 모든 연산을 no-op으로 만듭니다.

**`add`/`sub`/`dbl`이 `mul`만큼 중요했습니다.** 들어갈 때의 기대는 이득이
곱셈에서 올 것이라는 것이었습니다. 거기서만 오지 않았습니다. 교체되던 코드는
필드 덧셈을 `.add(x)` 다음 `.mod(p)`로 표기했는데, 그것은 최대 `2p`인 합을
축약하기 위한 긴 나눗셈이고, 뺄셈은 `.modSub(y, p)`인데 그것은 *두*
피연산자를 먼저 축약합니다 — 둘 더입니다. 그것들은 컨텍스트에 대한 조건부
뺄셈 하나와 조건부 되더하기 하나이며, `doublePointJac()` 하나에만 그런 것이
일곱 개 있었습니다.

#### 무엇이 변환되었는가

- **`CEcCurve`의 Jacobian 점 산술**(`infinityJac`, `toJacobian`,
  `toAffineFromJac`, `doublePointJac`, `addJac`, 그리고 두 스칼라 곱셈 루프):
  더 나아가기 전에 측정하려고 먼저 호출자 하나입니다. 그것이 29개 소수 곡선
  전부를 — ECDSA, ECDH, GOST R 34.10-2012 똑같이 — 섬기기 때문입니다.
  컨텍스트는 곡선에 캐시되는 대신 `scalarMul()`/`scalarMulBase()` 호출마다
  만들어집니다. `p`/`a`/`b`가 공개 변경 가능 필드이고 캐시된 컨텍스트는 그중
  하나가 쓰일 때마다 무효화되어야 할 것이기 때문입니다. 그 두 나눗셈은 루프가
  그러지 않으면 할 수천 개에 비해 등록되지 않습니다.
- **`Edwards448`의 확장 투영 산술**(`toProjective`, `toAffine`,
  `identityPointProj`, `pointAddProj`), 더하기 `CMontgomery::modExp()`를
  통한 `fieldSqrt()`의 `x2^((p+1)/4)` — 각각 전에는 나눗셈이 뒤따랐던 모듈러
  곱셈 ~670개이고, 디코드된 점당 한 번, 즉 `verify()`당 한 번입니다.
- **의도적으로 변환되지 않음:** affine `add()`/`doublePoint()`/`isOnCurve()`.
  단일 군 연산은 그 하나뿐인 모듈러 역원에 지배되므로 컨텍스트가 분할 상환할
  것이 없고, 이것들은 검증 경로입니다 — 측정할 수 없는 이득을 위해 위험을
  감수할 곳이 아닙니다. `ed25519.cpp`는 그대로 두었는데, 그것이 동시에 전용
  `Fe25519` 필드로 옮겨 가고 있었고 그것이 그 한 곡선에 대한 더 나은
  고침이기 때문입니다.

`doublePointJac()`의 리터럴 8에 의한 곱셈(`8*C`)은 `dbl()` 호출 셋이
되었습니다. 8은 평범한 정수이고 피연산자는 Montgomery 형태이므로 그것으로
곱하는 것은 `toMont(8)`을 필요로 했을 것인데, 두 배화는 영역에 무관하며 —
어쨌든 더 쌉니다.

#### 측정된 효과

Release 빌드, (반복 30회 실행 5회의 최소) 호출 3회에 걸친 최소입니다. 이
기계는 다른 작업이 돌아가는 부하 걸린 4코어 i7-11370H이고, 단일 지표의 실행
간 편차가 30%에 이르렀으므로, 이것들은 최소값이고 ~20% 미만인 것은 노이즈로
읽어야 합니다.

| | 이전 | 이후 | |
|---|---|---|---|
| ECDSA P-256 sign | 6.81 ms | **2.04 ms** | 3.3x |
| ECDSA P-256 verify | 22.50 ms | **5.53 ms** | 4.1x |
| ECDSA P-384 sign | 13.34 ms | **4.27 ms** | 3.1x |
| ECDSA P-384 verify | 39.92 ms | **13.99 ms** | 2.9x |
| ECDSA P-521 verify | 72.36 ms | **28.94 ms** | 2.5x |
| Ed448 sign | 14.62 ms | **5.52 ms** | 2.6x |
| Ed448 verify | 70.73 ms | **23.83 ms** | 3.0x |

부수 효과로 테스트 모음 전체가 대략 50초에서 17.6초로 떨어졌습니다.

#### 검증

기존 테스트 케이스 118개가 **어떤 기대값도 편집되지 않은 채** 통과합니다 —
트리의 모든 RFC 8032, RFC 5903, FIPS 186-4, RFC 6986/7091, ACVP 벡터가 이
변경에 대한 검사이고, `tests/crypto/eccurve.cpp`의 군 법칙 케이스와
`kat_ecdsa.cpp`의 FIPS 벡터가 둘 다 깨진 변환을 잡아낼 수 있음이
증명되었습니다(아래 참조).

그러나 주된 증거는 `divmod.cpp`가 쓰인 방식으로 쓰인
`tests/utils/montgomery.cpp`입니다. 그것은 기대값에 대해서는 아무것도
단정하지 않고, 각 `CMontgomery` 연산이 자기가 빠른 경로인 그 `CBigNum`
연산과 일치한다는 것만 단정합니다. 라이브러리가 배포하는 모든 모듈러스(29개
`CEcCurve` 집합의 `p` *와* `n`, 더하기 edwards448의 `p`와 `L`), limb 1개에서
32개까지의 무작위 홀수 모듈러스, 단일 limb 모듈러스에 대한 전수
`[0, 2m+2]²` 커버리지(그것은 축약 패스의 내부 루프가 아예 돌지 않는
`s == 1` 경로를 연습합니다), 모듈러스당 `0`/`1`/`m-1`/`m`/`m+1`/`m²-1`/`m²+m`
피연산자 부류, 모듈러스 비트 폭의 두 배인 피연산자, 그리고 200단계 연쇄
수열에 걸쳐 단정 ~915,000개입니다 — 다른 모든 검사가 새로 축약된
피연산자에서 시작하며 누적되어서만 나타나는 오류를 숨길 것이기 때문입니다.

네거티브 컨트롤, 각각을 주입하고 다시 빌드하고 되돌렸습니다.

| 주입된 결함 | 잡아낸 것 |
|---|---|
| CIOS 곱셈에서 최종 조건부 뺄셈 제거 | `montgomery` 테스트 케이스 7개 중 6개에서 실패 2,499개 |
| 교란된 모듈러스에 대해 계산된 `n'`(sanity 검사도 비활성) | 7개 중 6개 케이스에서 실패 303,591개 |
| `modExp()`의 반환에서 `fromMont()` 떨어뜨림 | 실패 48개, `modExp` 케이스에서만 |
| `toAffineFromJac()`의 한 좌표에서 `fromMont()` 떨어뜨림 | `crypto_asyms_kat_ecdsa`(FIPS 186-4)와 `crypto_eccurve` 둘 다 실패 |

그중 첫 번째가 차분 테스트가 존재하는 이유인 것입니다. `[m, 2m)`의 축약되지
않은 결과는 `m` 모듈러로는 올바르므로, 그것은 조용히 전파되고 마침 거기
떨어지는 입력에 대해서만 느린 경로와 불일치합니다 — 그것들의 약 절반인데,
손으로 고른 기지 응답 테스트 모음은 그것을 전부 놓치기 쉽습니다.

이름 댈 만한 미묘함 하나인데, 첫 초안에서 틀렸기 때문입니다. CIOS 누산기는
`limbs(m)+2` 워드이고 그 최종 축약은 그중 낮은 `limbs(m)`에서 `m`을 빼면서
그 뺄셈이 밖으로 borrow했을 때 그리고 *그때만* 최상위 워드를 감소시켜야
합니다. `CBigNum::subtractLimbs()`는 자기 borrow를 보고하지 않으므로, 그
비교는 뺄셈 *전에* 참조되어야 하고 후가 아닙니다 — 첫 버전은 최상위 워드를
무조건 감소시켰습니다.

## `x509/csr`: PKCS#10 인증 요청 (RFC 2986)

← [변경 이력](../HISTORY.ko.md)

CSR 지원은 [`CLAUDE.md`](../../CLAUDE.md)와
[`docs/PLANS.md`](../PLANS.ko.md) 양쪽에서 의도적으로 범위 밖이라고
열거되어 있었습니다. 그것이 저장소 소유자의 결정으로 바뀌었고, 착륙한 것은
이것입니다. `x509/csr.hpp`의 `CCertRequest`/`CCertRequestBuilder`, 더하기
CA 쪽의 `CCertBuilder::subjectFrom()`입니다.

#### 결정 넷, 그리고 이유

- **`cert.hpp`에 추가가 아니라 자기 헤더 쌍.** `cert.hpp`는 이미 ~920줄이었고,
  CRL과 OCSP가 각각 자기 헤더를 받았습니다. 인증서 헤더 안의 세 번째
  프로토콜은 어울리지 않는 것이 되었을 것입니다.
- **`CCertRequest`/`CCertRequestBuilder`로 분리.** 트리에서 가장 가까운
  선례인 `COcspRequest`/`COcspRequestBuilder`를 따라 이름 지었습니다. 한
  당사자가 만들어 내고 다른 당사자가 소비하는 객체이며, 그것이 또한
  `CCrlReader`/`CCrlWriter`가 분리된 이유입니다. `CCsr`은 고려되었고
  떨어졌습니다 — 여기의 다른 모든 타입은 비공식 약어가 아니라 자기 ASN.1
  구조를 따라 이름 지어집니다.
- **키는 `crypto::SKeyPair` 하나로 들어오고, 다른 방법이 없습니다.** CSR의
  목적 전체는 자기가 나르는 공개키와 그 보유자가 가진 개인키가 한 쌍의
  절반들임을 증명하는 것이므로, 그것들을 독립적으로 설정하게 하는 API는
  호출자가 교환의 누구도 소유를 증명할 수 없는 키를 CA에게 인증해 달라고
  요청하는 요청을 만들어 내게 할 것입니다 — 그리고 그 서명은 여전히, 다만
  틀린 키에 대해 검증될 것입니다. `build()`는 또한 개인 절반에서 공개 절반을
  다시 유도해 비교하고(다르면 `ERET_KEY_ERROR`), 항상 서명하므로, 서명되지
  않았거나 잘못 서명된 요청으로 가는 경로도 없습니다.
- **`CCertBuilder::subjectFrom(request)`는 존재하고, "요청된 확장을 복사"하는
  대응물은 의도적으로 존재하지 않습니다.** 요청에서 발행하는 것이 CSR이
  존재하는 이유이므로, 그것을 빼면 모든 소비자가 같은 대입 둘을 손으로 쓰게
  남겼을 것입니다. 그러나 요청의 자기 서명은 키의 소유를 증명하고, 그
  subject 이름이나 요청된 `BasicConstraints`/`KeyUsage`/
  `SubjectAlternativeName`이 이 CA가 인증해야 할 것인지에 대해서는 아무것도
  말하지 않습니다. `copyExtensionsFrom()`은 라이브러리에서 단일 최대 위험
  메서드가 될 것입니다 — 그것이 CA가 요청자가 요청했다는 이유로 CA 인증서를
  발행하는 방식입니다 — 그래서 대신 요청된 확장을 허락하려는 CA는 그 확장
  하나를 읽고(`request.extension<CSanExtension>()`), 자기 정책에 대조해
  검사하고, 스스로 그것을 `extensions`에 밀어 넣습니다. 확장당 명시적 결정
  하나입니다.

#### 가져오기는 검증합니다. 단지 `verify()`를 제공하는 것이 아닙니다

`CCertRequest::importDer()`는 자기 서명을 검사하고 그것 없이는 `ERET_OK`를
보고하기를 거부합니다. 이 라이브러리가 검증할 수 없는 알고리즘으로 서명된
요청은 검사되지 않은 채 가져와지는 대신 거부됩니다(`ERET_NOTSUP`).
`verify()`도 공개이지만, 그것이 유일한 방어선은 아닙니다.

그것은 `CCert::importDer()`의 문서화된 관대함과 반대이고, 의도적입니다.
인증서의 필드는 발행자의 키에 닿을 수 없는 호출자에게도 의미 있게 남습니다 —
다른 당사자들이 그것들을 보증합니다. CSR의 필드는 그렇지 않습니다. 모든
필드가 그것을 만들어 낸 누군가의 인증되지 않은 주장이고, 자기 서명이 그
구조가 증언하는 유일한 것입니다. `ERET_OK`를 받은 호출자는 돌아가 다시 묻지
않으므로, "파싱되었지만 검증되지 않음"은 닿을 수 있어야 할 만한 상태가
아닙니다.

#### 리팩터

`CCertBuilder::build()`는 이미 `Name`, `AlgorithmIdentifier`,
`SubjectPublicKeyInfo`, `Extensions` 블록을 인코드하고, 서명 알고리즘을
해소하고, 서명했습니다. `CCert::importDer()`/`verifyBy()`는 이미 SPKI를
디코드하고, 그것에서 공개키를 만들고, 서명을 검사했습니다. CSR은 그 전부를
필요로 하므로, 복사되는 대신 그 두 몸체에서 `CCert` static으로 나왔습니다.
`encodeAlgorithmIdentifier()`, `encodeSubjectPublicKeyInfo()`,
`decodeSubjectPublicKeyInfo()`(그 다섯 결과를 나르는 private `SSpkiFields`와
함께), `makePublicKey()`, `encodeExtensions()`, `signTbs()`,
`verifySignedBlob()`이고, `parseExtensions()`는 멤버에서 출력 파라미터를
지닌 static으로 바뀌었습니다. `CCertBuilder::build()`가 그것들에 ~150줄을
잃었고 동일하게 동작합니다 — 기존 `CCertBuilder` 테스트 전부가 수정 없이
통과합니다.

그중 둘은 단순한 중복 제거를 넘어 하중을 받습니다. `signTbs()`와
`verifySignedBlob()`이 이제 해시-후-서명 대 메시지-서명(기존
`signsMessageDirectly()`를 통해)과 PKCS#1 v1.5 대 PSS를 결정하는 단일
장소입니다. 그 술어 자신의 doc 주석이 항목을 놓친 지점이 "컴파일에 실패하거나
시끄럽게 실패하지 않는다"고 이미 경고했고 — 그것은 가공되지 않은 TBS
바이트를 digest인 것처럼 해시-후-서명 verify에 건넵니다 — OCSP에 한때 정확히
그 버그가 있었습니다. CSR을 위해 그 결정의 다섯 번째 손으로 쓴 사본을 추가하는
것은 그것을 두 번째로 획득하는 분명한 방법이었습니다.

#### `attributes`는 선택이 아닙니다

RFC 2986 4.1절의 `attributes [0] IMPLICIT Attributes`에는 `OPTIONAL`이
없으므로, 나를 것이 없는 요청은 존재하지만 빈 SET(`A0 00`)을 쓰고 그 필드를
생략하는 요청은 잘못된 형태입니다. 이것은 PKCS#10에서 우연히 빼먹기 가장
쉽고 알아차리기 가장 어려운 단일 필드입니다. 그것을 선택으로 취급하는 파서와
그것을 생략하는 인코더는 서로 완벽하게 일치합니다. OpenSSL 자체가 그것 없는
요청을 받아들이는데, 그것이 여기서 양쪽 모두에서 검사가 명시적인 이유이고,
테스트 모음이 그 필드를 생략하면서 올바르게 서명된 픽스처를 나르며
`ERET_BADREQ`를 요구하는 이유입니다.

PKCS#9의 `extensionRequest`(1.2.840.113549.1.9.14)가 더 깊이 디코드되는
한 속성입니다. 그 단일 값이 `Extensions` SEQUENCE이고 `CCert::parseExtensions()`
에 건네지므로, 요청된 SubjectAlternativeName이 인증서 자신의 것이 그럴 것과
같은 `CSanExtension`으로 나타나고 `request.extension<T>()`가 정확히
`cert.extension<T>()`처럼 읽힙니다. 다른 모든 속성은 자기 타입 OID와
`values SET OF` 내용을 그대로 담은 `SCertRequestAttribute`로 돌아옵니다 —
양방향에서 같은 표현이므로, 파싱된 속성이 곧바로 빌더에 다시 먹여집니다.
빌더는 Attributes SET을 X.690 11.6절에 따라 순서 짓습니다(멤버 인코딩
오름차순, 더 짧은 접두사 먼저). 그것이 SEQUENCE OF가 아니라 SET OF이기
때문입니다.

#### 테스트: 자기 자신하고만 말하는 것은 아무것도

`tests/x509/csr.cpp`(케이스 20개, 단정 442개)입니다. 인수 픽스처는 전부 이
라이브러리 밖에서 만들어졌습니다. 하나의 실수를 공유하는 빌더와 파서는 서로
일치하기 때문입니다 — 위의 거의 모든 항목의 교훈입니다.

- `openssl req` 출력 넷(OpenSSL 3.4.0): 속성이 아예 없는 RSA/SHA-256, SAN +
  KeyUsage를 나르는 `extensionRequest`를 지닌 P-256, Ed25519(자기 해시 경로),
  그리고 RSASSA-PSS입니다.
- Python에서 RFC 2986의 ASN.1로 바이트 단위로 조립한 둘 — ASN.1 라이브러리
  없이 — 그리고 `openssl dgst -sign`으로 서명한 다음 `openssl req -verify`로
  확인했습니다. 하나는 속성 *둘*(challengePassword 더하기
  `extensionRequest`)을 나르므로, 그 둘짜리 SET과 그 SET의 DER 순서는 이
  라이브러리의 인코더가 결코 만들어 낸 적 없는 인코딩입니다. 다른 하나는
  의도적으로 `attributes [0]`가 빠져 있습니다.
- 이 라이브러리 자신의 출력에 대한 바이트 단위 기지 응답이고, 고정된 PKCS#1
  키에서 나온 것입니다(RSA PKCS#1 v1.5는 결정론적이므로 요청 전체가 고정된
  바이트 문자열 하나입니다). 그것을 Python에서 필드별로 손으로
  디코드했습니다 — version, 문자열 타입을 지닌 각 subject RDN,
  `openssl pkey -pubout`에 대조한 SPKI, 존재하고 비어 있고 정확히 `A0 00`이며
  CertificationRequestInfo 안에서 마지막이라고 확인된 `attributes`, 서명
  AlgorithmIdentifier의 OID와 그 NULL — 그리고 추출된 CRI 바이트에 대해
  `openssl dgst -verify`로 검사한 서명, 더하기 변경된 CRI에 대한 같은 서명이
  검증되지 *않을* 것을 요구했습니다.
- 반대 방향도 마찬가지입니다. 이 라이브러리가 RSA, RSASSA-PSS, DSA, P-256,
  P-384, Ed25519, Ed448에 대해 만드는 요청이 모두 `openssl req -verify`를
  통과하고, `openssl req -text`가 extensionRequest 속성에서 요청된 SAN을
  읽어 냅니다. (ML-DSA는 OpenSSL 3.4에 ML-DSA가 아예 없다는 이유만으로
  예외입니다. 그 요청의 DER는 `asn1parse` 아래에서 잘 걸립니다.)

네거티브 컨트롤 셋을 주입하고, 빌드하고, 돌렸습니다.

1. **넣을 것이 없을 때 `attributes [0]` 생략.** 잡혔습니다 — 가공되지 않은
   `A0 00`을 다시 읽어 내는 케이스를 포함해 케이스 4개가 실패했습니다.
2. **원래 바이트 대신 다시 인코드한 `CertificationRequestInfo`에 대조해
   검증.** 잡혔습니다 — 외부에서 만들어진 픽스처 다섯 개 전부가 가져오기에
   실패했습니다. 그것들의 DN이 이 라이브러리 자신의 인코더가 `PrintableString`
   을 선호하는 곳에서 `UTF8String`을 쓰기 때문입니다. 자기가 만든 모든 왕복
   케이스는 여전히 통과했는데, 그것이 바로 요점입니다. 이것은 왕복이 볼 수
   없는 버그이고, 그것은 모든 실세계 CSR을 거부했을 것입니다.
3. **검증 결과에 따라 행동하지 않고 가져오기.** 잡혔습니다 — 조작 케이스
   둘(뒤집힌 서명 비트, 그리고 서명된 subject CN 안의 뒤집힌 글자)이
   실패했습니다.
