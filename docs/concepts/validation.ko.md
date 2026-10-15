# 확장과 폐지

[English](validation.md)

## X.509 확장

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`x509/ext.hpp` / `src/x509/ext.cpp`**는 `IExtension`을 정의합니다.
  디코드된 모든 X.509 확장의 구체적인(`I` 접두사에도 불구하고 순수 가상이
  아닙니다 — 이 라이브러리가 더 모델링하지 않는 OID에 대해 그 자체로 완전히
  쓸 수 있습니다) 기반입니다. `oid()`(점 구분 10진 텍스트) +
  `value()`(원시, 아직 DER로 인코드된 `extnValue` 옥텟) +
  `critical()`(`Extension.critical`, RFC 5280 4.2. 기본값 `false`이고,
  부재 필드에 대한 DER 자신의 기본값과 일치합니다), 그리고
  `IExtensionPtr`과 정적 `IExtension::create(oid, value)` 팩토리입니다.
  `create()`는 OID로 `x509/exts/` 아래의 맞는 구체 클래스에
  디스패치하고(아래 참고), 이 라이브러리가 온전히 모델링하지 않는 OID에
  대해서는 private `UnknownExtension`(`ext.cpp`에 정의되어 있고 공개 API의
  일부가 아닙니다)으로 돌아갑니다 — 그래서
  `CCert::extensionOf()`/`extension<T>()`(아래 `cert.hpp` 참고)는 존재하는
  확장에 대해 그 구체 타입이 인식되는지와 무관하게 항상 *무언가*를 반환하고
  null을 반환하는 일이 없습니다. `critical()`에는 공개 setter가
  있습니다(oid/value만 받는 각 구체 하위 클래스의 생성자에 모두 엮어 넣지
  않았습니다). 그래서 `CCert::parseExtensions()`가 파싱된 인증서의
  `Extension.critical` 필드에서 읽은 값을
  `create()`가 반환한 뒤 별도 단계로 기록할 수 있고, `IExtensionBuilder`가
  자기가 만든 확장을 `CCertBuilder::extensions`에 추가하기 전에 critical로
  설정할 수 있습니다(`CCertBuilder::build()`는 false일 때 `critical`
  BOOLEAN을 DER 정규적으로 생략하고 true일 때만 씁니다). 이 라이브러리는
  `critical()`을 파싱하고 보존합니다. RFC 5280의 "인식되지 않는 critical
  확장을 가진 인증서를 거부하라" 규칙을 어디에서도 스스로 강제하지는
  않습니다 — `CCert`에는 체인 검증 엔진이 아예 없으므로(이 문서 자신의 범위
  설명 참고), 그 정책 결정은 `CCert`의 파싱된 확장을 소비하며 그 위에 검증기를
  만드는 코드에 맡겨져 있습니다.
- **`x509/generalname.hpp` / `src/x509/generalname.cpp`**는 `CGeneralName`을
  정의합니다. `GeneralName` 하나(RFC 5280 4.2.1.6)이고 9지 CHOICE
  (`EGeneralNameType`. context-specific 태그 0–8)이며 서로 다른 네 확장이
  씁니다(`SubjectAltName`, `AuthorityKeyIdentifier`의
  `authorityCertIssuer`, `CRLDistributionPoints`의 `fullName`,
  `AuthorityInformationAccess`의 `accessLocation`, 그리고
  `NameConstraints`의 `GeneralSubtree.base`) — 각각에 9지 CHOICE 디코더를
  중복하는 대신 여기 한 번만 빼냈습니다. 상용 인증서에서 현실적으로 보이는
  대안만 타입별 접근자를 얻습니다
  (`rfc822Name`/`dNSName`/`uniformResourceIdentifier`/`registeredID`에
  대해서는 `text()`, `directoryName` 대안에 대해서는 `directoryName()`).
  `otherName`/`x400Address`/`ediPartyName`은 그 드문 모양들을 온전히
  모델링하는 대신 원시, 아직 DER로 인코드된 내용(`raw()`)만 유지합니다.
  `decode()`의 `directoryName` 경우는 내부 `RDNSequence`에 도달하기 전에
  TLV 계층을 하나 더 벗깁니다. `directoryName [4]`가 EXPLICIT이어야
  하기 때문입니다(`Name` 자체가 CHOICE이고, ASN.1은 그것에 암묵적 태그를
  붙이는 것을 금지합니다) — 여기의 IMPLICIT인 다른 모든 대안과 다릅니다.
  `decodeList()`는 `GeneralNames` `SEQUENCE OF GeneralName` 전체를
  디코드하며, 개별 원소의 `decode()`가 파싱할 수 없는 것은 중단하지 않고
  건너뜁니다. 이 모듈의 정착된 최선 노력 철학과 일치합니다(아래 `cert.hpp`
  참고). `CGeneralSubtree`(`NameConstraints`의 `GeneralSubtree`: `base`
  `GeneralName`과 선택적 `minimum`/`maximum` 거리 경계)는 바로 이 파일
  `CGeneralName` 바로 아래에 있습니다. 그것 외에는 자기 정체성이 없는
  `GeneralName` 모양의 값이기 때문입니다.
- **`x509/access.hpp` / `src/x509/access.cpp`**는
  `CAccessDescription`(`AuthorityInformationAccess`의 `AccessDescription`:
  접근 방법 OID + `CGeneralName` 위치)과, 그 아래에 `ECrlReasons` +
  `CDistributionPoint`(`CRLDistributionPoints`의 `DistributionPoint`:
  `fullName`/`nameRelativeToCrlIssuer` CHOICE, 선택적 `reasons` 비트 플래그,
  선택적 `crlIssuer`)를 정의합니다. `ECrlReasons`의 비트 위치는
  `ReasonFlags` BIT STRING 자신의 RFC 5280 4.2.1.13 명명 비트 번호와 직접
  대응합니다(비트 1 = `keyCompromise` .. 비트 8 = `aACompromise`).
  `exts/ku.hpp`의 `EKeyUsages`(아래 참고)와 다릅니다 — 여기에는 보존해야 할
  기존의, 테스트된 비트 배치가 없으므로, `EKeyUsages`의 역사적 반전을
  무관한 새 코드에 전파하는 대신 자연스러운 RFC 번호를 그대로 씁니다.
  `CDistributionPoint::decode()`의 `distributionPoint [0]` 경우는
  `CGeneralName`의 `directoryName` 경우와 같은 EXPLICIT-CHOICE 이유로 TLV
  계층을 하나 더 벗깁니다(`DistributionPointName`이 CHOICE입니다). 두 클래스
  모두 각각이 뒷받침하는 단일 확장 클래스 옆에 있지 않고 이 파일 하나로
  묶여 있는데, 미래의 호출자가
  `CCdpExtension`/`CAiaExtension`과 독립적으로 그것들을 생성/비교하고 싶을
  수 있기 때문입니다.
- **`x509/policy.hpp`**은 `CPolicyInformation`(`CertificatePolicies`의
  `PolicyInformation`: 정책 OID + `policyQualifiersRaw()`)을 정의합니다.
  `policyQualifiers` `SEQUENCE OF PolicyQualifierInfo`는
  `PolicyQualifierInfo` 자신의 `CPSuri`/`UserNotice` CHOICE를 온전히
  모델링하는 대신 의도적으로 원시, 아직 DER로 인코드된 내용으로 유지합니다 —
  호출자는 압도적으로 `policyIdentifier()` 자체만 필요하므로(예:
  `OID_ANY_POLICY` 같은 특정 CA/Browser 포럼 정책 OID를 확인하기 위해),
  추가 파싱 복잡도가 아직 값을 하지 않습니다. 전부 인라인이므로 짝이 되는
  `.cpp`가 없습니다.
- **`x509/exts/`**는 이 라이브러리가 모델링하는 RFC 5280 확장당 구체
  `IExtension` 하위 클래스 하나를 담고 있으며, 이름은 온전히 적는 대신 통용
  약칭으로 붙였습니다(`bc.hpp` = `CBasicConstraintsExtension`,
  `ku.hpp` = `CKeyUsagesExtension`(+ `EKeyUsages`), `eku.hpp` =
  `CEkuExtension`, `san.hpp` = `CSanExtension`, `ski.hpp` =
  `CSkiExtension`, `aki.hpp` = `CAkiExtension`, `cdp.hpp` =
  `CCdpExtension`, `aia.hpp` = `CAiaExtension`, `cp.hpp` =
  `CPoliciesExtension`, `nc.hpp` = `CNameConstraintsExtension`).
  전부 같은 모양을 따릅니다. 자기 확장 OID를 지칭하는
  `public static constexpr const char* OID`(`ext.cpp`의 디스패치 테이블이
  대조합니다), 원시 `extnValue` 옥텟을 받아 최선 노력으로 파싱하는 생성자
  하나(잘못된 필드는 확장 전체를 실패시키는 대신 안전한 기본값으로 남습니다.
  아래 `CCert::importDer()` 자신의 철학을 반영합니다), 그리고 디코드된 결과에
  대한 읽기 전용 접근자들입니다. 각각 인코딩 방향을 위해
  `IExtension::encodeValue(CBuffer&)`와 순수 가상
  `IExtensionBuilder::build()`(`x509/ext.hpp`) 위의 짝이 되는
  `C<Name>ExtensionBuilder`도 가집니다 — 열 개 parse/build 쌍 전부가
  존재하므로 확장을 왕복할 수 있고, `CCertBuilder::extensions`가 그 빌더들을
  받습니다. `EKeyUsages`(`ku.hpp`)가 "자연스러운 RFC 비트 순서"의 하나뿐인
  예외입니다. 그 비트 위치는 `KeyUsage` BIT STRING 자신의 명명 비트 번호에서
  역사적으로 반전되어 있으며, 위의 `ECrlReasons`의 RFC 직접 관례에 맞추도록
  "바로잡는" 대신 `CCert`가 원래 정의한 그대로(그리고 기존 테스트가 이미
  단정하는 그대로) 정확히 보존됩니다. 이미 테스트된 공개 enum의 값을 바꾸는
  것은 고치는 변경이 아니라 깨뜨리는 변경이기 때문입니다. `eku.hpp`는
  추가로 널리 알려진 `KeyPurposeId` OID 상수들
  (`OID_SERVER_AUTH`, `OID_CLIENT_AUTH`, ...)과 `has(oid)` 편의 조회를
  정의합니다. `cdp.hpp`/`aia.hpp`/`cp.hpp`/`nc.hpp`는 각각 얇은
  확장 수준 래퍼(OID + 디코드된 항목들의 `TArray`)이고, 위의 그 파일들
  항목에 따라 `x509/access.hpp`/`x509/policy.hpp`/`x509/generalname.hpp`가
  실제로 정의하는 값 타입들을 둘러쌉니다.

## CRL, OCSP 및 인증 요청

← [모듈](../CONCEPTS.ko.md#세부-개념-문서)

- **`x509/crl.hpp` / `src/x509/crl.cpp`**는 CRL(RFC 5280 5) 쪽을 정의하며,
  읽기/쓰기 클래스 하나가 아니라 세 타입으로 나뉩니다.
  `CCrlRevokationInfo`는 `revokedCertificates` 항목 하나입니다
  (`serialNumber()`, `timestamp()`, `reason()`, 더해서 인증서에 대해 그것을
  시험하는 `isFor(cert)`와 자기 TLV를 위한 `encode()`/`decode()`).
  `CCrlReader`는 `CertificateList`를 파싱하고(`decode()`, 그 다음
  `version()`/`issuer()`/`thisUpdate()`/`nextUpdate()`/`revokations()`)
  호출자가 실제로 가진 두 질문에 답합니다 — 일치하는 항목을 위한
  `find(cert, out)`과 폐기됨/안 됨 판정만을 위한 `check(cert)`입니다.
  그리고 `CCrlWriter`가 하나를 만듭니다
  (`add(cert, when, reason)`/`remove(cert)`, 그 다음 발급자의 키로 서명하는
  `build(issuer, out)`). reader/writer 분리는 `CCert`의 단일
  import/export 클래스가 아니라 `asn1` 자신의 `CReader`/`CWriter`를
  반영하는데, CRL이 자연스럽게 서로 다른 당사자에 의해 생산되고 소비되기
  때문입니다.
  `ECrlReasons`(`x509/access.hpp`)는 CRLDistributionPoints 확장과
  공유됩니다. RFC 5280 5.3.1의 `CRLReason` 와이어 값과 그 플래그 비트
  사이의 ENUMERATED-플래그 매핑은 의도적으로 1:1이 아니므로
  (`ReasonFlags` 비트 7/8 대 ENUMERATED 9/10, 그리고 ENUMERATED 8
  `removeFromCRL`은 플래그가 아예 없습니다), 호출 지점마다 직접 적는 대신
  자기만의 private `CrlReasonCodec`(`src/x509/crlreason.hpp`)에 있습니다.
  `verifyBy(issuer)`/`tbsCertList()`/`signature()`는 `CCert` 자신의 셋을
  정확히 반영하며, 발급자 키의 알고리즘에서 해시 여부를 결정하는 것까지
  같습니다 — 그 이유는 해당 항목을 보십시오.
  범위 설명 둘: `check()`는 인증서가 그 목록에 나타나는지만 보고합니다 —
  자기 서명은 전혀 검증하지 않으며(`verifyBy()`를 따로 호출하십시오), 그 CRL이
  인증서 자신의 발급자가 발행한 것인지도 확인하지 않으므로, 일련번호가 충돌하는
  무관한 CA의 CRL도 여전히 판정을 내놓을 것입니다 — 그리고 `CCrlWriter`는
  `crlExtensions`를 내놓지 않으므로, RFC 5280 5.1.2가 기대하는
  `CRLNumber`/`AuthorityKeyIdentifier`가 그것이 만든 CRL에는 없습니다.
- **`x509/ocsp.hpp` / `src/x509/ocsp.cpp`**는 OCSP(RFC 6960) 요청/응답 쌍을
  정의합니다. `x509/`에서 서명 *검증*이 존재하는 유일한 곳입니다.
  `COcspCertId`는 호출자가 고른 `hashAlgo()`(기본 SHA-1. 배포된 responder들이
  기대하는 것입니다) 아래에서 발급자 이름 해시, 발급자 키 해시, 일련번호로
  인증서를 식별하는 `CertID`입니다. `COcspEntry`는 `SingleResponse`
  하나입니다(`certId()`, `status()`, `reason()`,
  `thisUpdate()`/`nextUpdate()`/`revocationTime()`).
  `COcspRequest`/`COcspRequestBuilder`와
  `COcspResponse`/`COcspResponseBuilder`는 그 다음 CRL 타입들과 같은
  파싱 쪽/빌드 쪽 분리를 따릅니다. 빌더는 인증서를
  받고(`add(cert, issuer, hashAlgo)`), nonce를 생성하고(`generateNonce()`),
  DER를 `build()`합니다. 파싱 쪽은 `decode()`, 디코드된 항목들, 그리고 —
  `CCert`/`CCrlReader`와 달리 — 진짜 `verifySignature(responderCert)`를
  노출합니다. `EOcspStatus`가 최상위 `responseStatus`를 담고, 문법상
  `EOCSP_OK`만이 그 이상의 무엇을 담으므로, `COcspResponse::status()`를 먼저
  확인해야 다른 어떤 접근자든 의미를 가집니다. `find()`/`check()`는
  `CCrlReader`의 것을 반영합니다. 양쪽이 모두 필요한 공유 와이어 보조
  함수들(nonce와 basic-response OID, 단일 확장 목록 인코딩,
  `GeneralizedTime` 포매팅)은 private
  `OcspCodec`(`src/x509/ocspcodec.hpp`)에 있습니다.
- **`x509/csr.hpp` / `src/x509/csr.cpp`**는 PKCS#10(RFC 2986) 인증 요청 쌍
  `CCertRequest`/`CCertRequestBuilder`를 정의하며,
  `COcspRequest`/`COcspRequestBuilder`를 따라 이름 지었습니다 — 가장 가까운
  선례인데, CSR도 마찬가지로 한 당사자가 생산하고 다른 당사자가 소비하는
  객체 하나이기 때문입니다. 파싱 쪽은 `CCert`의 표면을 반영합니다
  (같은 `ECertFormat`을 쓰는 `importDer()`/`importPem()`/`importFrom()`,
  `exportDer()`/`exportPem()`/`exportAs()`, `subject()`,
  `keyAlgo()`/`signAlgo()`, `rawPublicKey()`/`publicKey()`, `signature()`,
  `rsaPssParams()`, `extensionOf()`/`extension<T>()`), 더해서
  `certificationRequestInfo()` — `CCert::tbsCertificate()`와 같은
  원래-바이트이지-다시-인코드한-것이-아니라는 의미에서 정확히 서명된
  바이트입니다.

  PKCS#10에 특정하고 알아 둘 만한 것이 셋 있습니다.

  1. **import가 자기 서명을 검증하고, 그것 없이는 실패합니다.** CSR의 모든
     필드는 그것을 만든 쪽의 인증되지 않은 주장입니다. 자기 서명이 요청이
     증명하는 유일한 것(`subjectPKInfo`의 개인 절반을 보유하고 있음)이므로,
     `importDer()`는 그것이 확인되기 전에는 `ERET_OK`를 보고하기를 거부하고,
     이 라이브러리가 검증할 수 없는 알고리즘으로 서명된 요청은 확인 없이
     import되는 대신 거부됩니다. 그것은 `CCert::importDer()`의 의도적인
     관대함과 반대이고, 이유가 있습니다. 인증서의 필드는 발급자의 키에
     도달할 수 없는 호출자에게도 여전히 의미가 있지만, 요청의 필드는 그렇지
     않습니다. 손으로 다시 확인하기 위해 `verify()`도 공개되어 있습니다.
  2. **`attributes [0] IMPLICIT Attributes`는 OPTIONAL이 아닙니다.** 담을 것이
     없는 요청도 존재하지만 빈 SET(`A0 00`)을 쓰며, 그 필드를 생략한 요청은
     거부됩니다 — OpenSSL 자신은 그런 요청을 받아들이므로, 이 검사는
     명시적이어야 합니다. `SCertRequestAttribute`는 속성 하나의 타입 OID와
     그 `values SET OF` 내용을 그대로 보유하고, 양방향에서 같은 의미를
     가지므로 파싱된 속성이 빌더로 바로 되돌아갑니다. PKCS#9의
     `extensionRequest`(`CCertRequest::OID_EXTENSION_REQUEST`)가 더 디코드되는
     하나뿐인 속성입니다. 그 `Extensions` 값이
     `CCert::parseExtensions()`를 거치므로, 요청된 SubjectAlternativeName이
     인증서 자신의 것과 같은 `CSanExtension`으로 드러납니다.
  3. **키는 `SKeyPair` 전체로 제공되고 그 외에는 없습니다.**
     `CCertRequestBuilder`에는 서명하는 개인키와 별도로 공개키를 지정할
     방법이 없고, `build()`가 공개 절반을 다시 유도해 비교합니다 — 그래서
     서명되지 않은 요청으로 가는 길도, 요청자가 증명할 수 없는 키를 요구하는
     요청으로 가는 길도 없습니다. `build()`는 자기 출력을
     `CCertRequest::importDer()`에 건네므로, 방금 만들어 낸 서명이 쓰인 그
     바이트에 대해 다시 검증됩니다.

  CA 쪽 절반은 **`CCertBuilder::subjectFrom(request)`**이며, 요청의 subject
  이름과 공개키를 인증서 빌더로 복사하고 의도적으로 그 외에는 아무것도 하지
  않습니다. 요청의 요청된 확장을 복사하는 메서드는 없는데, 그것이 바로 CA가
  요청자가 요구했다는 이유로 CA 인증서를, 또는 요청자가 통제하지 않는 도메인에
  대한 인증서를 발급하게 되는 방식이기 때문입니다. 하나를 허용하고 싶은 CA는
  그 특정 확장을 읽고(`request.extension<CSanExtension>()`) 자기 정책에
  대조해 확인한 뒤 스스로 `extensions`에 밀어 넣습니다.

  DER 작업의 거의 전부가 중복되지 않고 `CCert`와 공유됩니다.
  `encodeName()`, `encodeAlgorithmIdentifier()`,
  `encodeSubjectPublicKeyInfo()`/`decodeSubjectPublicKeyInfo()`,
  `makePublicKey()`, `encodeExtensions()`, `parseExtensions()`,
  `resolveSigAlgoForSigning()`/`resolveSigAlgo()`/`parseRsaPssParams()`,
  `signTbs()`, `verifySignedBlob()`이 모두 friend를 통해 도달하는 `CCert`의
  static이고, 그중 여럿은 바로 이것을 위해 `CCertBuilder::build()`의 본문에서
  빼낸 것입니다. `signTbs()`/`verifySignedBlob()`가 가장 중요합니다.
  hash-then-sign과 메시지-서명 중 어느 것인지(`signsMessageDirectly()`를
  통해), 그리고 PKCS#1 v1.5와 PSS 중 어느 것인지를 결정하는 단 하나의
  장소이므로, CSR의 자기 서명이 인증서의 것과 미묘하게 다른 규칙으로
  확인될 수 없습니다.
