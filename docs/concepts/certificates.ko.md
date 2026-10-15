# 인증서와 컨테이너

[English](certificates.md)

## X.509 인증서

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`x509/cert.hpp` / `src/x509/cert.cpp`**는 `CCert`를 정의합니다. DER
  X.509 `Certificate`를 파싱해(`importDer(data)`) subject/issuer
  (`CDistinguishedName`), 유효 기간(`SDateTime`), 일련번호, 키/서명 알고리즘
  식별자, 원시 `SubjectPublicKeyInfo`, 그리고 모든 확장으로 만듭니다. 이
  클래스가 getter를 노출하는 필드만 유지됩니다 —
  `issuerUniqueID`/`subjectUniqueID`와 TBSCertificate에 박힌 서명 알고리즘
  사본은 읽고 지나가되 버립니다. 파싱은 하나의 일관된 최선 노력 계약을
  따릅니다. `importDer()`는 모든 필드를 먼저 지역 변수에 만들고 맨 마지막에만
  `*this`에 반영하므로(중간에 실패해도 객체를 반쯤 채워진 상태로 두는 일이
  없습니다), 그러나 인식하지 못하는 *알고리즘*(목록에 없는 키/서명/곡선
  OID)은 그 자체로 파싱 실패가 되는 일이 절대 없습니다 —
  `keyAlgo()`/`signAlgo()`가 OID 자신의 점 구분 10진 텍스트로 돌아가고,
  `publicKey()`/`createHasher()`는 단지 null을 반환합니다. 이 라이브러리가
  인증서의 암호 알고리즘에 대해 행동할 수 없을 때에도 나머지 데이터는
  여전히 의미가 있기 때문입니다. 세 private 정적 테이블
  `KEY_ALGOS`/`SIG_ALGOS`/`EC_CURVES`(각각 `{oid, name, which}`)가 그 해석을
  구동합니다. DSA 키의 쪼개진 `SubjectPublicKeyInfo` 표현
  (`Dss-Parms {p, q, g}` + 벌거벗은 `INTEGER y`)은
  `buildDsaPublicKeyBlob()`를 통해 `DSA::createPublicKey()`가 기대하는 독립
  `SEQUENCE {p, q, g, y}` blob으로 재조립되며, 이 추가 단계를 필요로 하는
  유일한 알고리즘입니다.

  `signatureAlgorithm`의 `parameters` 필드는 정확히 한 알고리즘,
  id-RSASSA-PSS(1.2.840.113549.1.1.10, RFC 4055)에 대해서만 읽힙니다 —
  OID 자신이 digest를 지칭하지 않으므로, 여기서 파라미터가 NULL 자리표시가
  아니라 검증자가 필요한 정보를 담는 유일한 서명 알고리즘입니다.
  `parseRsaPssParams()`(`buildRsaPssParams()`의 역)가 `RSASSA-PSS-params`를
  `SRsaPssParams`로 읽고 `rsaPssParams(out)`가 그것을 노출하며, 그 다음
  `_sigHashAlgo`가 그 `hashAlgorithm`에서 설정되므로 `createHasher()`와
  `verifyBy()`가 다른 모든 알고리즘에 대해서처럼 동작합니다. 네 필드 전부가
  `DEFAULT`이고 DER는 기본값과 같은 필드를 생략하므로, 파싱은 바로 그
  기본값들(SHA-1, MGF1-SHA-1, salt 20, `trailerFieldBC`)을 담고 있는
  `SRsaPssParams` 자신의 생성자에서 시작하며, 부재 필드는 "부재"가 아니라 그
  기본값으로 보고됩니다. DER 아래에서 그 둘은 같은 진술이기 때문입니다.
  파싱되지 *않는* 파라미터는 해석되지 않은 OID와 같은 최선 노력 계약을
  따릅니다. `signAlgo()`는 여전히 `rsassaPss`로 읽히지만 `_sigHashAlgo`는
  `EHASH_UNKNOWN`으로 남으므로, `verifyBy()`는 그 SHA-1 기본값으로
  돌아가는 대신 `ERET_NOTSUP`을 보고합니다 — 그렇게 돌아가는 것은 서명이
  무엇을 덮는지에 대한 추측이 될 것입니다.

  `publicKey()`/`privateKey()`는 진짜로 지연 평가됩니다.
  `_cachedPub`/`_cachedPvt`(`mutable`)는 `importDer()`가 지우기만 하고(다시
  만들지 않습니다) 각 접근자가 처음 호출될 때에만 실제로 생성됩니다 — 키를
  한 번도 요청하지 않는 호출자는 그것에 아무 비용도 치르지 않습니다.
  `privateKey(IPrivateKeyPtr&)`(setter)는 들어오는 키가 진짜로 이 인증서
  자신의 것인지, 그것의 유도된 공개키를 `publicKey()`와 비교해
  (`IKeyBase::compare()`) 받아들이기 전에 검증합니다. `createHasher()`는
  *서명* 알고리즘 자신의 digest를 해석합니다(`_sigHashAlgo`. `importDer()`
  중에 `signAlgo()`의 OID에서 설정됩니다) — `thumbprint()`와는 무관하며,
  그쪽은 인증서의 실제 서명 알고리즘과 무관하게 무조건 원시 인증서 전체의
  SHA-1 digest입니다. 대부분의 도구에서 인증서 "지문"의 통상적 의미와
  일치합니다.

  확장들은 `std::vector<IExtensionPtr>`(`_extensions`)로 보유되며,
  `IExtension::create()`를 통해 private `parseExtensions()`가 한 번
  채웁니다. 그것은 각 확장의 `critical()` 플래그도 기록하고, RFC 5280이
  금지하는 중복 쌍을 쌓는 대신 반복된 OID를 건너뜁니다 — 첫 등장만
  유지합니다. 그러지 않으면 `extensionOf()`의 첫 일치 조회와 `_extensions`를
  직접 순회하는 호출자가 서로 다른 답을 낼 수 있습니다. 조회는
  `extensionOf(oid, out)`(선형 탐색 — 실제 인증서의 확장 수는 항상 작으므로
  map이 필요 없습니다)으로 하거나, 더 흔하게는 공개
  `template<typename TExtension> extension<TExtension>()` 보조 함수로
  하는데, 그것은 `TExtension::OID`를 조회하고 결과를
  `dynamic_pointer_cast`합니다 — 예컨대
  `cert.extension<CBasicConstraintsExtension>()`입니다. `keyUsages()`,
  `subjectKeyIdentifier()`, `authorityKeyIdentifier()`는 모두 각각
  `exts/ku.hpp`/`ski.hpp`/`aki.hpp` 위의 `extension<T>()`를 부르는 얇은
  호출자이고, 거의 모든 소비자가 필요로 하는 세 확장이므로 (모든 호출자가
  `extension<CKeyUsagesExtension>()` 등을 직접 적어야 하게 하는 대신) 자기
  이름을 가진 메서드로 유지합니다.

  `verifyBy(issuer)`는 "이 발급자가 이 인증서에 서명했는가?"에 답합니다 —
  자기 서명된 것에는 `*this`를 넘기십시오. `tbsCertificate()`(파싱된 필드를
  다시 인코드한 것이 아니라 `rawData()`에 나타나는 원래 TBS TLV. 서명이
  발급자의 바이트를 덮으므로, 다시 인코드하면 그것이 담고 있는 어떤 특이점도
  조용히 "고쳐" 버릴 것입니다)를 해싱하고 발급자의 공개키로 `signature()`에
  대조해 확인합니다. 해싱을 할지 말지는 `_sigHashAlgo == EHASH_UNKNOWN`이
  아니라 *발급자 키* 자신의 알고리즘에서 결정됩니다. 그 값이 모호하기
  때문입니다 — `resolveSigAlgo()`는 등록되지 않은 OID에 대해 그것을 건드리지
  않고 두는데, 이는 EdDSA의 정당한 "별도 해시 없음"과 구별되지 않으며,
  그것을 EdDSA로 읽으면 원시 TBS 바이트를 digest인 것처럼 ECDSA/DSA 검증에
  건네게 됩니다.

  그 결정이 `CCert::signsMessageDirectly(which)`이고, 각 지점에서 반복되는
  술어가 아니라 함수 하나입니다 — Ed25519, Ed448, 그리고 세 ML-DSA
  파라미터 집합이 메시지 자체를 서명합니다. 네 곳이 그것에 대해 의견이
  일치해야 하고(`CCert::verifyBy()`, `CCrlReader::verifyBy()`, 그리고 두 OCSP
  `verifySignature()`), 항목 하나를 놓친 지점은 컴파일에 실패하지도, 큰 소리로
  실패하지도 않습니다. 원시 TBS 바이트를 hash-then-sign 검증에 건네거나,
  digest를 ML-DSA에 건네 메시지 대신 그 32바이트 문자열을 서명합니다. 둘 다
  여기서 실제 버그였고, 어느 쪽도 자기 서명 왕복에는 보이지 않습니다.

  자기 해싱 알고리즘에 대해서는 서명 BIT STRING의 내용이 통째로 전달됩니다.
  ML-DSA의 서명은 ECDSA의 `SEQUENCE { r, s }`와 달리 EdDSA의 `R || S`와 정확히
  같이 내부 ASN.1이 없는 불투명한 blob 하나(`c-tilde || z || h`)입니다 —
  ECDSA 쪽은 `verifyBy()`가 아니라 EC 구현이 스스로 풀어냅니다.

  `verifyBy()`는 *링크 하나*에 대한 검사입니다. 이름 연결도, 유효 기간도,
  제약 강제도 없습니다. RSASSA-PSS로 서명된 인증서는 PKCS#1 v1.5의
  `verify()`가 아니라, 자신의 `RSASSA-PSS-params`가 명시하는 해시와 salt
  길이로 `IAsymmetricContext::verifyPss()`를 거쳐 갑니다. 인코드할 수는
  있지만 지원되지 않는 두 경우는 근사되지 않고 `ERET_NOTSUP`으로 닫히며
  실패합니다. `maskGenAlgorithm`이 `hashAlgorithm`과 다른 해시를 지칭하는
  경우(이 라이브러리의 `verifyPss()`는 해시 알고리즘 하나를 받아 둘 다에
  쓰는데, 그것이 RFC 8017이 권장하는 유일한 짝입니다)와, `trailerField`가
  `trailerFieldBC`가 아닌 경우입니다. 틀린 MGF1 해시로 검증하면 모든 유효한
  서명을 거부할 것이고, 호출자는 그것을 위조와 구별할 수 없습니다.

  `importDer()`는 없을 때 악용 가능했던 몇 가지 DER 규칙을 강제하며, 각각
  `tests/x509/malformed.cpp`가 덮습니다. `Certificate` SEQUENCE가 입력
  전체여야 합니다(뒤에 붙은 것은 `_rawData`에 그대로 유지되므로, 그것을
  받아들이면 인증서 하나에 무한히 많은 `thumbprint()` 값이 생기고
  `exportDer()`가 DER가 아닌 바이트를 다시 내놓게 됩니다). `extensions [3]`
  래퍼가 constructed여야 하고 파싱되어야 합니다. 잘못된 것을 "확장 없음"으로
  취급하면 제약이 걸린 인증서가 제약 없는 인증서로 바뀌면서도 import는
  성공했기 때문입니다. `TBSCertificate.signature`가
  `Certificate.signatureAlgorithm`과 같은 알고리즘을 지칭해야 합니다
  (RFC 5280 4.1.1.2 — 내부 사본은 서명되고 외부는 아닌데, 검증을 구동하는
  것은 외부입니다). 그리고 `signatureValue`의 BIT STRING이 사용하지 않는
  비트를 0으로 선언해야 합니다. `SubjectPublicKeyInfo` 쪽이 이미 그래야 했던
  것처럼요.

  실제 상용 인증서를 `tests/x509/certs/implemented/`에 `.der` 파일로
  체크인합니다. 테스트는 `CMakeLists.txt`가 모든 테스트 타깃에 지정하는
  `CERTPP_TEST_DIR` 컴파일 정의와 `readCertFile()`을 통해 이 파일들을 읽습니다.
  `identrust-mldsa-root.der`은 실재하는 "IdenTrust Pilot Root TLS ML-DSA
  CA 1"(OID 2.16.840.1.101.3.4.3.19이고 이는 **id-ml-dsa-87**입니다. arc가
  ML-DSA-44/65/87에 대해 .17/.18/.19로 흐르고, 인증서 자신의 2592바이트 키와
  4627바이트 서명이 어느 것인지 확인해 줍니다)이며, 자기 서명되어 있으므로
  그것에 대한 `cert.verifyBy(cert)`는 제3자 포스트 양자 인증서를 종단 간으로
  검증합니다. 동반 테스트는 TBS, 서명, 공개키의 비트를 각각 하나씩 뒤집어
  각 검증이 실패해야 한다고 요구합니다.

## 인증서 체인 및 컨테이너

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`x509/chain.hpp` / `src/x509/chain.cpp`**는 `SCertEntry`(인증서, 선택적
  개인키, 그리고 PKCS#12 bag이 담는 PKCS#9 `friendlyName`/`localKeyId`),
  `CCertCollection`(인증서 집합을 누가 누구에게 발급했는지로 정렬하는 조회들과
  `buildChain()` — 경로 검증이 *아닙니다*. 범위 설명 참고), 그리고 컨테이너
  포맷이 구현하는 인터페이스 `IChainFormat`을 정의합니다.
  `IChainFormat::builtIn()`이 어떤 포맷이 존재하는지 알아야 하는 유일한
  곳이므로, 포맷을 추가하는 것은 거기서의 변경이고 다른 어디에서도
  아닙니다. `detect()`는 첫 바이트로 PEM과 PFX를 가립니다.
- **`x509/chain/pem.hpp` / `src/x509/chain/pem.cpp`**는
  `CPemChainFormat`을, 그리고 그와 함께 이 라이브러리의 PEM 처리 **전부**를
  정의합니다. 다중 블록 스캔, 캡슐화 경계, 레이블, base64 프레이밍, 그리고
  "이 파일은 개인키도 담고 있다"는 컨테이너의 관심사이므로, 원래 형태가
  DER인 `CCert`가 아니라 여기 있습니다.
  `CCert::importPem()`/`exportPem()`/`detectCertFormat()`은 얇은 위임이고,
  파일 하나에 인증서 하나가 흔한 경우이므로 유지합니다. `load()`는
  추가(append)하며 파일 전체가 파싱되기 전까지 아무것도 반영하지 않으므로,
  중간에 깨지는 컨테이너는 컬렉션을 있던 그대로 둡니다. 키 블록은 위치가
  아니라 `CCert::privateKey()` 자신의 공개키 비교로 인증서와 짝지어지므로,
  파일 안의 뒤바뀐 키나 남의 키가 잘못 짝지어질 수 없습니다. 이 라이브러리가
  구현하지 않는 알고리즘을 쓰는 인증서는 버려지지 않고 적재되고(파싱됩니다.
  그 키만 쓸 수 없습니다), 구조적으로 깨진 블록은 컨테이너 전체를
  `ERET_BADREQ`로 만들며, 비밀번호로 암호화된 키 블록 —
  `ENCRYPTED PRIVATE KEY`, 또는 RFC 1421의 `Proc-Type: 4,ENCRYPTED` — 은
  `ERET_NOTSUP`입니다. PEM에는 그것을 열 비밀번호가 없기 때문입니다.
  **PEM에는 기밀성이 전혀 없습니다**. `needsPassword()`는 false이고,
  `password` 인자는 곧바로 무시되며, 써 내보낸 개인키는 평문으로 디스크에
  갑니다 — 그래서 그것을 쓰는 것이 선택적(opt-in)이고
  (`CPemChainFormat(true)`. `CCert::exportPem(out, true)`가 만드는 것입니다)
  `builtIn()`은 인증서 전용 형태를 반환합니다. PKCS#9 속성은 openssl 자신의
  `Bag Attributes` 모양으로 경계 밖에 타고 가며, RFC 7468 5.2가 명시적으로
  허용하고 다른 어떤 reader든 건너뜁니다.
- **`x509/chain/pfx.hpp` / `src/x509/chain/pfx.cpp`**는 `CPfxFormat`,
  `IChainFormat`으로서의 PKCS#12/PFX(RFC 7292)를 정의합니다. 그것이 쓰는
  구조는 AuthenticatedSafe가 인증서 bag들을 `pkcs7-encryptedData`로, 키
  bag들을 각각 `pkcs8ShroudedKeyBag` 하나를 담은 `pkcs7-data`로 보유하고,
  AuthenticatedSafe 전체에 대한 `MacData` HMAC을 가진 v3 PFX입니다. 기록할
  만한 결정들:

  - **암호화는 PBES2만**입니다(PBKDF2-HMAC-SHA256 + AES-256-CBC. 암호화되는
    부분마다 새 salt와 IV). 레거시 PKCS#12 PBES1 암호
    (RC2-40-CBC, `pbeWithSHAAnd3-KeyTripleDES-CBC`)는 쓰지도 읽지도
    않습니다. 그런 컨테이너는 `ERET_NOTSUP`으로 돌아오는데, 깨진 암호로
    복호하거나 잘못된 것으로 보고하는 대신 "나는 이것을 읽을 수 없다"고
    말하는 것입니다. 이것은 OpenSSL 3이 기본으로 쓰는 것이기도 하므로,
    레거시 암호를 거부하는 데 실무상 비용이 없습니다.
  - **MAC은 HMAC-SHA-256**입니다. RFC 7292의 예제와 2021년쯤까지의 모든
    도구는 SHA-1을 썼습니다. SHA-1 MAC은 읽을 때 여전히 *검증*되는데,
    그것을 거부하는 것은 현존하는 대부분의 컨테이너를 거부하는 것을
    뜻하기 때문입니다.
  - **`MacData`의 키는 PBKDF2가 아니라 RFC 7292 부록 B 자신의 KDF에서
    purpose 바이트 3으로 나오며**, 이는 선택이 아닙니다. RFC 7292 4절이
    그 유도를 명시하므로, 실재하는 어떤 컨테이너를 읽든 그것이 필요합니다.
    그 사용은 정확히 그 키 하나에 국한되며 — 어떤 PBES1 키나 IV도 그것으로
    유도되는 일이 없습니다 — `crypto/`의 무엇이 아니라 `pfx.cpp`의 파일 지역
    보조 함수입니다. `CPbkdf2`와 달리 다른 무엇도 손을 뻗어서는 안 되는
    레거시 PKCS#12 전용 구성이기 때문입니다. PBKDF2가 MAC 키를 유도하게
    해 주는 RFC 9579의 PBMAC1은 구현되어 있지 않습니다.
  - **비밀번호가 같은 파일 안에서 서로 다른 두 방식으로 인코드되며**, 이것이
    다른 어떤 도구도 읽을 수 없는 컨테이너의 가장 유력한 단일 원인입니다.
    PBES2는 PKCS#5이고 비밀번호 바이트를 주어진 대로 받습니다. 부록 B의
    KDF는 PKCS#12 자신의 것이고 그것을 NUL로 끝나는 빅엔디언 UTF-16
    BMPString으로 받습니다. `CPfxFormat`은 그 변환을 하기 위해 `password`
    span을 UTF-8로 읽으며, OpenSSL 3과 일치합니다(그쪽은 UTF-8을
    변환하는데, 더 오래된 `OPENSSL_asc2uni`는 각 바이트를 Latin-1 식으로
    0 확장했습니다). ASCII 비밀번호에 대해서는 둘이 일치하므로, 비-ASCII
    비밀번호로 다른 곳에서 쓰인 컨테이너만이 실제로 그것을 못 박습니다 —
    `fixtures/openssl-utf8-password.p12`가 그것을 위해, 그리고 그것만을 위해
    있습니다.
  - **안쪽의 무엇이든 복호되거나 파싱되기 전에 MAC이 검증됩니다.** 그것이
    통과하기 전까지 AuthenticatedSafe는 공격자가 통제하는 바이트입니다.
    먼저 복호하면 이 클래스가 padding oracle이 될 것이고, 먼저 파싱하면
    아무도 보증하지 않은 입력에 ASN.1 reader를 노출시킬 것입니다.
    `MacData`가 아예 없는 컨테이너도 같은 방식으로 거부되는데, RFC 7292가
    그것을 OPTIONAL로 둔 것은 ASN.1에 대한 진술이고 인증되지 않은 blob을
    믿으라는 허락이 아니기 때문입니다. 비교는 `CSecure::equals()`를 거치고,
    틀린 비밀번호, 실패한 MAC, 없는 MAC이 모두 `ERET_KEY_ERROR`를
    반환합니다 — 의도적으로 구별되지 않습니다. "틀린 비밀번호"를 "손상된
    파일"과 구분하는 구현은 공격자에게 어느 쪽을 계속 시도해야 하는지
    알려 준 것이기 때문입니다.
  - **`MAX_MAC_ITERATIONS`가 하나뿐인 인증되지 않은 계산에 상한을 둡니다.**
    MAC을 확인할 수 있기 전에 MAC 키가 유도되어야 하므로, `MacData`의 반복
    횟수는 이 포맷에서 쓴 쪽이 아니라 파일을 제공한 쪽이 고르는 유일한
    횟수이고 — 20억 번을 주장하는 200바이트 컨테이너는 그것을 여는 쪽에게
    몇 분의 CPU입니다. 상한은 10,000,000이고 RFC 7292의 1024, OpenSSL의
    2048, 또는 이 라이브러리 자신의 600,000보다 한참 위이므로 상호운용성
    비용이 없습니다. 피해를 경계 짓는 것이고 강도에 대한 판단이 아니며,
    읽히는 컨테이너의 횟수에는 의도적으로 *하한*이 없습니다.
  - **`DEFAULT_ITERATIONS`는 600,000**이고, PBKDF2-HMAC-SHA256에 대한
    OWASP의 2023년 수치이며, 여기 release 빌드에서 유도당 대략 0.3초로
    측정되었습니다. 정당화가 필요한 숫자는 이것이 아니라 대안들입니다.
    RFC 7292의 예제는 1024라고 하고 OpenSSL은 아직 2048을 기본으로 씁니다.
    컨테이너는 한 번 쓰이고 수년간 공격받으므로, 비용은 쓰는 쪽에
    속합니다. *읽기*에 대한 하한이 아닙니다 — 컨테이너는 그것이 담고 있는
    횟수가 무엇이든 그대로 읽힙니다.
  - **`save()`는 빈 비밀번호를 거부합니다**(`ERET_BADREQ`).
    `IChainFormat::needsPassword()`에 따른 것입니다. 개인키는 있지만
    `localKeyId`가 없는 항목에는 하나를 부여합니다 — 인증서의 SHA-1
    지문이고, OpenSSL이 쓰는 것입니다 — 그 속성이 들어오는 길에 키 bag을
    자기 인증서 bag과 짝지어 주는 유일한 것이기 때문입니다.
  - 키는 `CCert::exportPkcs8PrivateKey()` / `importPkcs8PrivateKey()`를
    통해 PKCS#8로 오갑니다. 그것들은 두 번 쓰이는 대신 `CCert`의 기존 PEM 쪽
    PKCS#8 처리에서 빼낸 것입니다. 각 알고리즘이 `privateKey` OCTET STRING
    안에 무엇을 넣는지는 `cert.hpp` 자신의 doc 주석을 보시고, PKCS#8 DSA
    키는 `y`를 담고 있지 않으므로 그것을 읽는 데 `g^x mod p` 비용이 든다는
    점에 유의하십시오.
