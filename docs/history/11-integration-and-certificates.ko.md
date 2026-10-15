# 통합과 실제 인증서

[English](11-integration-and-certificates.md)

## 알고리즘 여덟 개를 한꺼번에 병합하기: 통합이 잡아낸 것

← [변경 이력](../HISTORY.ko.md)

요청된 알고리즘 여덟 개를 병렬로, 각각 자기 worktree에서 구현했는데, 그것은
각각이 다른 일곱 개를 담지 않은 트리에 대해 쓰였다는 뜻입니다. 그 비용의
대부분은 등록 지점에서의 병합 충돌입니다. 두 가지는 그 이상이었습니다.

#### `EHashers`가 ABI 경계를 넘어 번호가 다시 매겨졌습니다

`EHASH_MD4`가 `EHASH_MD5` 앞에 삽입된 상태로 도착했는데 — MD4와 MD5가 함께
속하므로 그쪽이 더 잘 읽힙니다 — 그로써 `EHASH_SHA256`을 4에서 5로, 그리고 그
뒤의 모든 enumerator를 옮겼습니다. 그것에 대해 제시된 근거는 이 저장소의
어떤 것도 `EHashers` 값을 캐스팅하거나 영속화하지 않는다는 것이었는데, 그것은
사실이고 바로 그 실수를 저장소 안에서 보이지 않게 만드는 것입니다. 그것은
공유 객체로 배포되고 설치된 패키지로 소비됩니다. 더 오래된 헤더에 대해
컴파일된 호출자는 계속 4를 넘기고 조용히 SHA-256 대신 SHA-224를 받습니다.

새 hasher는 이제 뒤에 덧붙여지며, 더 깔끔한 묶음이 쓸 수 없는 이유를 말하는
주석이 덧붙임 지점에 있습니다. `EHASH_BLAKE2S`와 두 Streebog enumerator는
병합될 때 같은 줄 아래로 옮겨졌습니다.

#### 낡은 정당화, 그리고 아무것도 테스트한 적 없던 검사

`CEcdsa`의 `deriveSharedSecret()`은 의도적으로 small-subgroup 테스트를
생략하고, 그 주석은 그것을 "`CEcCurve`가 배포하는 모든 소수 곡선은 cofactor가
1"이라고 정당화했습니다 — 쓰였을 때는 사실이었습니다. GOST 파라미터 집합에는
cofactor 4인 것 둘이 포함되므로, 두 브랜치가 만난 순간 그 문장이 거짓이
되었습니다.
어느 파일도 바뀌지 않은 상태로요. GOST 집합 자신의 메모, 즉 그 cofactor가
"이 라이브러리가 구현하지 않는 VKO 키 합의에만 중요하다"는 것도 같은 순간에,
같은 이유로 거짓이 되었습니다.

결론은 살아남습니다. `CEcCurve::decodePoint()`는 `n*Q == infinity`를 무조건
테스트하고, 모든 `EcPublicKey`는 그것을 통해서 아니면 `generateKeyPair()`에
의한 `d*G`로 만들어지므로, 작은 위수의 점이 키 합의에 닿을 수 없습니다.
진술된 이유만이 틀렸고, 이유만이 바뀌었습니다. (이에 대한 첫 시도는 그 경로가
도달 가능하다는 믿음에서 `deriveSharedSecret()`에도 검사를 추가했습니다.
아니었고, 중복된 스칼라 곱셈을 다시 제거했습니다.)

그 사건이 실제로 드러낸 것은 **부분군 검사가 테스트된 적이 한 번도
없었다**는 것입니다. cofactor 1 곡선에서는 그것이 실패할 수 없습니다 — 점의
위수는 1과 n뿐이고, 위수 1은 이미 거부되는 무한원점입니다 — 그래서 GOST
집합이 도착하기까지 라이브러리의 어떤 곡선도 그것을 연습할 수 없었습니다.
이제 구체적인 증인으로 만들어진, 그렇게 하는 케이스가 있습니다. `2P`는
정확히 `y == 0`일 때 무한원점이므로, 위수 2인 점은 `y = 0`으로 취한
`x^3 + a*x + b`의 근입니다. `ECURVE_GOST256A`에 대해 F_p 위에서
`gcd(x^p - x, x^3 + a*x + b)`를 계산하면 근이 정확히 하나인 삼차식이
나오므로, 그 곡선에는 위수 2인 점이 정확히 하나 있고, 테스트는 그것이 곡선
위에 있고, 필드 범위 안에 있고, 위수가 정확히 2이며, `decodePoint()`와
`createPublicKey()` 둘 다에 의해 거부된다고 단정합니다. 그 검사를 끄면 그
케이스가 실패하고 **나머지 열여섯 ECDH 케이스는 통과한 채 남는데**, 그것이
그 전에 커버리지가 얼마나 있었는지의 측정값입니다.

## 실제 인증서 하나, 무관한 공백 둘: RSASSA-PSS와 `organizationIdentifier`

← [변경 이력](../HISTORY.ko.md)

`tests/x509/certs/unimplemented/`는 실제로, 현재 유효한 상용 중간
인증서 — QuoVadis Root CA 1 G3가 발행한 "DigiCert QV G3 TS EUR RSA4096
RSASSA-PSS 2025 CA1" — 를 담고 있었고, `importDer()`가 그것에 대해
`ERET_BADREQ`를 반환했기 때문에 거기 보관되어 있었으며, 정확히 그것을 단정하는
테스트 케이스가 있었습니다. 디렉터리 이름과 테스트 자신의 제목이 둘 다 서명
알고리즘을 탓했습니다. 둘 다 실제로 어떤 공백이 가져오기를 실패시켰는지에
대해 틀렸고, 그 틀림은 기록할 만한 방식으로 틀렸습니다. 그 오귀속이 세 곳에
적히는 것을 살아남았기 때문입니다.

#### 실제로 가져오기를 실패시킨 공백

그 인증서의 subject는 ETSI EN 319 412 `organizationIdentifier`(2.5.4.97)를
나르는데, 그것은 EU 규제 및 적격 인증서에서 일상적이고 `CName`이 인식하던
X.520 타입 여섯 개 중 하나가 아니었습니다.
`CDecoder::decodeDistinguishedName()`은 `CName::attributeTypeOf()`가 이름을
댈 수 없는 `type`을 지닌 `AttributeTypeAndValue`를 거부하므로, 그 속성 하나가
subject `Name` 전체를 실패시켰습니다 — 그리고 `importDer()`가 서명 알고리즘이
읽히기도 전에 반환했습니다. RSASSA-PSS에는 닿은 적이 없었습니다.

고침은 어느 쪽으로도 갈 수 있었습니다. `ENameType`에 빠진 타입들을 가르치거나,
디코더가 인식하지 못하는 것을 건너뛰게 하거나입니다. 열린 끝을 지닌 시퀀스에
대해 파서가 해야 할 일은 건너뛰기라고 논할 만하고, 인식되지 않는 DN 속성을
이유로 인증서를 거부하는 것을 허용하는 RFC는 없습니다. 그래도 *여기서는*
틀린 선택이었습니다. `CDistinguishedName`이 이름 없는 속성을 보존할 여지가
없는 `std::map<ENameType, CName>`이기 때문입니다. 건너뛰면 그것을 버릴
것이고, 건너뛴 속성에서만 다른 두 DN이 그러면 같다고 비교될 것입니다. DN
동등성은 바로 체인 빌더가 발행자를 subject에 맞추는 기준이므로, 관대한
디코드는 파싱 실패를 틀린 인증서 매치로 바꿔 놓았을 것입니다. 대신 enum이
자랐고, 디코더는 진짜로 알려지지 않은 속성에 대해서는 여전히 닫힌 쪽으로
실패합니다.

`ENAME_OI` 더하기 `ENAME_SERIAL`, `ENAME_TITLE`, `ENAME_GN`,
`ENAME_SURNAME`, `ENAME_PSEUDONYM`, `ENAME_DNQ`, `ENAME_DC`가 `ENAME_MAX`
바로 앞에 **덧붙여졌는데**, `EHashers`가 덧붙여지는 것과 같은 ABI
이유에서입니다(위 "알고리즘 여덟 개를 한꺼번에 병합하기" 참조). 그 값들이
공유 라이브러리 경계를 넘기 때문입니다. 거기서 떨어져 나온 것 셋:

- `TYPE_OIDS`가 `[ENAME_MAX][4]`로 선언되어 있었는데,
  `domainComponent`(`0.9.2342.19200300.100.1.25`, arc 10개이고 2.5.4 arc
  밖의 유일한 인식 속성)가 거기에 들어가지 않습니다. 이제 타입당
  `SAttributeOid { count, arcs[MAX_OID_ARCS] }` 하나이고,
  `attributeOid()`/`attributeTypeOf()`와 `decodeDistinguishedName()`의 이전
  하드코딩된 `arcCount != 4` 검사가 거기에 따릅니다.
- `ENAME_MAX`가 표 셋의 크기를 정하고, 선언된 크기보다 초기화자가 적은 C++
  배열은 꼬리가 기본 생성된 채로 조용히 컴파일됩니다. `tests/name.cpp`의 왕복
  테스트는 여섯 타입을 손으로 열거했습니다. 이제 `ENAME_NONE + 1`에서
  `ENAME_MAX`까지 걸으며 그 전부에 대해
  `TYPE_KEYS`/`TYPE_LABELS`/`TYPE_OIDS` 각각에 항목을 요구합니다. 표 없이
  타입을 추가하는 것이 이제 0을 반환하는 대신 테스트를 실패시킵니다.
- `CName::typeOf()`가 `caseCmp(TYPE_KEYS[i], key, strlen(TYPE_KEYS[i]))`로
  비교했습니다 — *표의* 키가 긴 만큼의 문자 수만이고, 그것이 그것을 접두사
  매치로 만듭니다. 짧은 대문자 키 여섯 개로는 그것이 결코 중요하지
  않았습니다. `"organizationIdentifier"`가 존재하는 순간 그것이 `ENAME_O`로
  해소되었는데, `"O"`가 한 문자이고 매치하기 때문입니다. 이제 표 키 자신의
  NUL이 참여하도록 `strlen(key) + 1`을 비교하며, `caseCmp()`가 첫 불일치에서
  short-circuit하므로 어느 문자열의 끝도 지나쳐 읽히는 것이 없습니다.

`domainComponent`는 인코더와 디코더가 IA5String을 처리하는 것도 필요로
했습니다. RFC 4519 2.4절이 그것에 대안 없이 그 구문을 주므로, 그 OID를
인식하면서 그 유일한 합법 값 타입을 거부하는 것은 반쪽짜리 조치가 되었을
것입니다. 인코더는 `ENAME_DC`를 PrintableString/UTF8String 대체 없이
IA5String으로 쓰고, 디코더는 셋 다 받아들입니다.

#### RSASSA-PSS, 디렉터리 이름이 가리켰던 공백

`id-RSASSA-PSS`(1.2.840.113549.1.1.10, RFC 4055)가 이제 `SIG_ALGOS`에
있으므로, `signAlgo()`가 점으로 구분된 십진 OID 대신 `rsassaPss`를 보고합니다.
그 항목의 해시는 의도적으로 `EHASH_UNKNOWN`입니다. 표의 다른 모든 서명
알고리즘과 달리 이 OID는 어떤 digest의 이름도 대지 않습니다. digest, MGF1
해시, salt 길이가 모두 `AlgorithmIdentifier`의 `parameters`에 살고, 그것은
`importDer()`가 모든 알고리즘에 대해 버려 오던 것입니다.

`parseRsaPssParams()`(기존 `buildRsaPssParams()`의 역)가 그것들을 새
`SRsaPssParams`로 읽어 들이고, 그것은 `CCert::rsaPssParams(out)`로
노출되며, 그 다음 `_sigHashAlgo`가 `hashAlgorithm`에서 설정되므로
`createHasher()`와 `verifyBy()`가 다른 모든 곳에서 하는 대로 동작합니다. 네
필드 모두 `DEFAULT`가 있고 DER는 자기 기본값과 같은 필드가 없을 것을
*요구*하므로, 파싱은 정확히 그 기본값들을 지닌 `SRsaPssParams`의 생성자에서
시작하여, 생략된 필드를 "없음"이 아니라 자기 기본값으로 보고합니다. DER
아래에서 그 둘은 같은 진술이기 때문입니다. 픽스처 인증서는 넷 중 셋을
명시하고(SHA-256, MGF1-SHA-256, salt 32) `trailerField`를 생략합니다.

`verifyBy()`는 PSS 서명을 파싱된 해시와 salt 길이와 함께
`IAsymmetricContext::verifyPss()`로 보냅니다. 인코드 가능한 경우 둘은
근사되는 대신 `ERET_NOTSUP`으로 닫힌 쪽으로 실패합니다. `hashAlgorithm`과
다른 해시의 이름을 대는 `maskGenAlgorithm`인데 이 라이브러리의 `verifyPss()`가
그것을 표현할 수 없고(그것은 해시 알고리즘 하나를 받아 digest와 MGF1 둘 다에
씁니다 — RFC 8017이 권고하는 유일한 짝이고, 마주친 유일한 것입니다),
그리고 `trailerFieldBC`가 아닌 `trailerField`입니다. 어느 쪽이든 추측하면
모든 유효한 서명을 거부할 것이고, 호출자는 그것을 위조와 구별할 수 없습니다.
파싱에 실패하는 파라미터는 해소되지 않은 OID가 이미 그랬던 것과 같은 방식으로
취급됩니다. 최선 노력이고, `signAlgo()`는 여전히 해소되며, `_sigHashAlgo`는
`EHASH_UNKNOWN`으로 남고, `verifyBy()`는 `RSASSA-PSS-params`의 SHA-1
기본값으로 되돌아가는 대신 `ERET_NOTSUP`을 보고합니다.

#### 테스트가 증명할 수 있는 것과 할 수 없는 것

인증서는 `certs/implemented/`로 옮겨졌습니다. 그 테스트 케이스는 실제 파일의
내용을 단정합니다. `organizationIdentifier=NTRNL-30237459`를 포함한 subject
속성 넷, 발행자 속성 셋, 위의 PSS 파라미터, RSA-4096, 512바이트 서명, 그리고
그 확장들입니다.

그 부모는 QuoVadis Root CA 1 G3인데 이 저장소에 없으므로, **이 인증서의 실제
서명은 결코 검증되지 않습니다** — 틀린 키에 대조해 거부되기만 합니다. 그
거부는 그것이 반환하는 *어떤* 코드인지에 대해서는 여전히 단정할 만합니다.
EMSA-PSS-VERIFY에서 나온 `ERET_BADREQ`는 PSS 검증자가 파싱된 해시와 salt
길이로 진짜로 돌았다는 뜻인데, `ERET_NOTSUP`은 `verifyBy()`가 산술을 하기
전에 사양했다는 뜻일 것입니다. 검증 자체는 따로 연습됩니다. 실제 파일에서
파싱한 파라미터를 써서 생성된 RSA 키로 실제 인증서 자신의
`tbsCertificate()` digest에 서명하고, 그 다음 조작된 서명, 조작된 메시지,
salt 길이 20(DEFAULT, 즉 `[2]`를 무시하는 파서가 쓸 값), `saltLength - 1`,
`saltLength + 1`, 그리고 틀린 해시가 모두 실패하는 것을 확인하는
방식입니다.

`maskGenAlgorithm` 불일치 경로는 자연계의 어떤 것도 만들어 내지 않는 인증서를
필요로 했습니다. 테스트에서 실제 파일의 *외부* `signatureAlgorithm`
파라미터를 패치해 하나를 만드는데, `hashAlgorithm`이 여전히 `id-sha256`으로
읽히는 곳에서 MGF1의 해시 OID가 `id-sha384`로 읽히게 합니다 — 둘 다 내용
옥텟 9개이므로 그 편집은 길이를 보존하고 DER는 제대로 된 형태로 남으며,
`importDer()`는 TBSCertificate의 `AlgorithmIdentifier` 사본과 외부 것 사이에서
OID만 비교합니다. 그 인증서는 가져와지고, `rsaPssParams()`를 통해 불일치를
보고하며, `verifyBy()`에서 `ERET_NOTSUP`을 받습니다.

각 네거티브 컨트롤은 구현을 깨뜨리고 테스트가 실패하는 것을 보아 확인했습니다.
`saltLength`를 20으로 하드코딩하기, MGF1 해시를 `hashAlgorithm`의 값으로
하드코딩하기, 그리고 SHA-1 기본값이 적용되도록 `parameters` 파싱을 아예
건너뛰기입니다.

기존 테스트 둘은 깨지는 대신 의미가 바뀌었습니다.

- `tests/x509/cert.cpp`에서 `CCertBuilder`가 만드는 자기 서명 RSASSA-PSS
  인증서는 `signAlgo() == "1.2.840.113549.1.1.10"`을 단정하고 OID가 해소되지
  않았기 때문에 자기 서명을 `verifyPss()`를 통해 손으로 다시 검증해야
  했습니다. 이제 `rsassaPss`를 단정하고, `buildRsaPssParams()`가 쓴
  파라미터가 `importDer()`에서 변경 없이 나온다고 단정하며,
  `verifyBy(cert)`를 통해 검증합니다 — 작성자와 새 독자가 같은 인코딩에
  동의한다는 첫 종단 간 확인입니다.
- `tests/asn1/roundtrip.cpp`는 `decodeDistinguishedName()`이 **IA5String**으로
  다시 태그된 값을 거부한다고 단정했는데, 그것이 이제 받아들여져야 하는
  유일한 태그입니다. 대신 TeletexString, VisibleString, BMPString으로 다시
  태그하고(각각 여전히 거부됨), 그 다음 IA5String이 디코드된다고 단정하며,
  새 케이스가 `DC=example, CN=host` DN을 인코더를 통해 왕복시킵니다 — arc
  10개짜리 속성 OID를 양방향으로 연습하는 유일한 커버리지입니다.
