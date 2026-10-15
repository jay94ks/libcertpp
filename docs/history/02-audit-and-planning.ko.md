# 감사, 문서화 및 계획

[English](02-audit-and-planning.md)

## 프로젝트 전반 감사: 메모리 안전성, DER 엄격성, 서명 검증

← [변경 이력](../HISTORY.ko.md)

다섯 부분으로 나눈 읽기 전용 감사(utils/io/asn1, hashers/RNG/대칭,
비대칭/곡선, x509/examples, 그리고 문서를 코드에 대조)가 아래의 수정들을
만들어 냈습니다. 두 조각이 독립적으로 같은 결함 둘 — digest 절단 버그와
최소가 아닌 INTEGER 수락 — 을 보고했는데, 그것이 둘 다를 여기 자세히
설명하는 이유의 일부입니다.

#### 메모리 안전성

- `TString`의 소멸자가 `clear()`만 호출했고, 그것은 계약상 용량을 보존하므로
  `_data`를 전혀 해제하지 않았습니다. 한 번이라도 할당한 모든
  `CString`/`CWideString`이 자기 버퍼를 누출했고, 모든 인증서 파싱에서도
  그랬습니다. 이제 `~TArray()`가 이미 하던 것처럼 `clear()`를 `trimExcess()`와
  짝지웁니다. 그 소멸자 자신의 doc 주석은 그동안 줄곧 "할당된 메모리를
  해제한다"고 주장하고 있었습니다. MSVC의 ASan에는 누수 탐지기가 없는데,
  그것이 앞서의 ASan 실행이 발견 사항 0건을 보고한 이유입니다.
- `MemStream::seek()`이 `ESEEK_END`만 clamp했으므로,
  `ESEEK_SET`/전진 `ESEEK_CUR`이 `_pos`를 끝 너머에 세울 수 있었습니다. 그
  다음 `read()`/`write()`가 가용 공간을 `_span.size - _pos` / `_cap - _pos`로
  계산했는데 — 거기서부터 거대한 값으로 내려 넘치는 부호 없는 뺄셈이고,
  `write()`의 `reserve()`를 건너뛰며 두 `memcpy` 모두를 범위 밖으로
  데려갑니다. 세 곳 모두에서 고쳤습니다. `seek()`이 clamp하고, 두 접근자가
  빼는 대신 비교합니다.
- `MemStream::length()`가 보이는 길이를 늘리면서 `reserve()`가 초기화한 적
  없는 바이트를 공개했습니다 — 다음 `read()`가 읽을 수 있는 원시
  `new uint8_t[]`의 내용입니다. 이제 0으로 채웁니다.
- `TString`의 대입 연산자 셋이 `SelfType`을 **값으로** 반환했으므로, 모든
  대입이 버려질 문자열을 복사 생성했고(그리고 소멸자 수정 전에는 그것을
  누출했습니다), 이동 대입은 올바르게 swap한 뒤에도 그랬습니다. `TArray`는
  줄곧 올바른 시그니처를 갖고 있었습니다.

#### 신뢰할 수 없는 경계에서의 DER 엄격성

- `CDer::readBigInteger()`가 최소가 아닌 INTEGER를 받아들였습니다. 선행
  `0x00` 하나를 벗기고 나머지는 `fromBigEndian`이 흡수하게 두었으므로
  `02 02 00 05`와 `02 03 00 00 05` 둘 다 5로 디코드되었습니다. 따라서 이
  라이브러리가 파싱하는 모든 DER 서명과 키에 추가적인 유효한 인코딩이
  있었습니다 — 서명 가변성(malleability)입니다.
  `CDecoder::decodeInteger()`는 줄곧 X.690 8.3.2의 규칙을 올바르게 구현하고
  있었습니다. 이 경로만 그것을 받지 못한 것입니다.
- `CDer::readOuterSequence()`가 `bytesRead`를 계산하고 버렸으므로 SEQUENCE
  뒤에 붙은 바이트가 받아들여졌습니다. 유효한 서명에 쓰레기를 덧붙여도
  여전히 검증되었습니다.
- 두 엄격화 모두 `tests/x509/realcerts.cpp`의 실재하는 상용 발급 인증서들에
  대해 검증했고, 그것들은 여전히 파싱됩니다 — 즉 더 엄격해진 규칙이 실재하는
  무엇도 거부하지 않으면서 가변적인 인코딩을 거부합니다.

#### 서명 검증

- `COcspRequest`/`COcspResponse::verifySignature()`가
  `_sigHashAlgo == EHASH_UNKNOWN`을 "EdDSA이므로 원시 바이트를 검증"으로
  취급했습니다. 그러나 `CCert::resolveSigAlgo()`는 `void`이고 `SIG_ALGOS`
  밖의 어떤 OID(id-RSASSA-PSS, SHA-3 계열, 잘못된 무엇이든)에 대해서도 그
  값을 건드리지 않고 두므로, "인식되지 않음"이 EdDSA의 정당한 "별도 해시
  없음"과 구별되지 않게 되었습니다. 따라서 알 수 없는 알고리즘이 해싱되지
  않은 `tbsRequest`/`tbsResponseData`를 ECDSA/DSA 검증에 건넸고, 그쪽은
  그것을 부분군 위수의 비트 길이로 절단합니다 — 그래서 서명이 메시지의 충돌
  저항적 해시 대신 평문의 접두사를 덮었습니다. 두 지점 모두 이제 검증하는 키
  자신의 `EAsymmetrics`에서 결정하고, 그 외에는 `ERET_NOTSUP`으로 닫히며
  실패합니다. `CCert`는 여기서 항상 닫히며 실패했습니다. OCSP만 그것을
  뒤집었습니다.
- FIPS 186-4 6.4절은 digest의 가장 왼쪽 `min(N, outlen)` **비트**를
  요구하는데, `CBigNum::fromBigEndianTruncated()`는 `ceil(N/8)`
  **바이트**를 유지하고 시프트를 전혀 하지 않아 자기 doc 주석과
  모순되었습니다. 부분군 위수가 바이트 정렬되지 않은 여덟 개 이진 곡선에
  대해, ECDSA는 따라서 이 라이브러리에 대해서는 검증되고 다른 어떤 것에
  대해서도 검증되지 않는 서명을 만들어 냈습니다 — 곡선/해시 조합 16개이고,
  예컨대 K-163과 SHA-256은 FIPS가 93비트를 원하는 자리에서 88비트를
  시프트합니다. 서명과 검증이 서로 일치했으므로 테스트 모음은 줄곧
  통과했습니다. 곡선별 테스트는 자기 출력만 검증하며, 그것이 바로 그 맹점입니다.
  DSA와 20개 소수 곡선 전부는 영향이 없습니다. 그쪽의 `N`은 바이트 정렬되어
  있고, P-521은 충분히 긴 digest가 없으므로 절단하는 일이 없습니다.
- RSA `decryptBlock()`이 `c >= n`을 받아들였는데, RFC 8017 5.1.2가 그것을
  금지하며 타이밍 식별자이기도 합니다 — 그런 ciphertext에 대해서는 CRT
  재암호화 검사가 결코 일치할 수 없으므로, 그런 것들 전부가 조용히 느린
  전체 모듈러스 대체 경로를 탔습니다. `encryptBlock()`의 `keyBytes >= 11`
  가드도 없었는데, 그것이 없으면 `keyBytes < 2`가 되게 할 만큼 작은, 들여온
  키가 선두 바이트 읽기를 버퍼 밖으로 데려갔습니다.
- DSA의 `createPrivateKey()`가 version 필드만 검증했으므로, 0인 모듈러스나
  범위를 벗어난 `x`가 `sign()`에 도달해 0으로 나눴습니다.
  `createPublicKey()`는 `p`/`q`/`g`는 거부했지만 `y`는 거부하지 않았습니다.
  둘 다 이제 import 경계에서 값싼 구조 검사를 적용하되, 전체 검증은 여전히
  `checkPrivateKey()`에 남겨 둡니다.

#### 그 외 정확성

- `SHAKE128`/`SHAKE256::finish()`가 살아 있는 스펀지 상태에서 짜냈으므로,
  rate 블록 하나보다 긴 출력에 대해 두 번째 호출이 같은 바이트를 다시 주는
  대신 출력 스트림의 *연속*을 반환했습니다. 이제 MD5/SHA-1/SHA-2가 임시
  객체를 마무리하는 방식에 맞춰 사본에서 짜냅니다. rate 이하의 출력은 permute를
  하지 않는데, 그것이 출하된 길이들(32/64, 그리고 Ed448의 114)이 그것을
  드러낸 적이 없는 이유입니다.
- MSVC의 `hasSha()`(두 번)와 `hasAdxBmi2()`가 leaf 0의 최댓값을 먼저
  확인하지 않고 CPUID leaf 7을 읽었습니다. CPUID는 범위를 벗어난 leaf에
  0이 아니라 *지원되는 가장 높은* leaf의 데이터로 답하므로, 최댓값이 7보다
  낮은 CPU에서는 이것들이 있지도 않은 SHA-NI나 BMI2/ADX 지원을 보고하고
  그 다음 유효하지 않은 명령을 실행할 수 있었습니다. GCC/Clang 경로는 항상
  안전했습니다 — `__get_cpuid_count()`가 내부적으로 그 확인을 합니다.
  `hasAesNi()`/`hasPclmul()`은
  leaf 1을 쓰고 영향을 받은 적이 없습니다.
- `src/utils/djb.cpp`가 `<certpp/utils/Djb.hpp>`를 포함하고 있었습니다. 파일은
  `djb.hpp`이므로, 빌드는 대소문자를 구분하지 않는 파일 시스템에서만 동작했던
  것입니다. 전체를 쓸어 그것이 트리에서 유일한 그런 include임을 확인했습니다.
- `CDistributionPoint::encode()`가 `nameRelativeToCRLIssuer`를 primitive
  `81`로 다시 내놓았습니다. 그것은 SET인
  `[1] IMPLICIT RelativeDistinguishedName`이고 IMPLICIT 태그는 constructed
  비트를 보존하므로(X.690 8.14) 와이어 형태는 `A1`입니다 — 그리고
  `decode()`가 둘 다 받아들이므로, 유효한 입력이 유효하지 않은 출력으로 다시
  만들어지고 있었습니다. 그 `decode()`도 BIT STRING을 검증하기 전에
  `_hasReasons`를 설정해 DER가 담은 적 없는 reason을 보고했습니다. 이제 앞에서
  한 번 디코드하는데, 그것이 중복된 재검증 여덟 번도 없애 줍니다.
- `DsaPrivateKey`의 고정 기저 window 테이블이 `const` 메서드에서 채워지는
  `mutable` 멤버였습니다 — 두 스레드가 같은 키 객체로 서명하는 순간
  데이터 경쟁입니다. 대신 생성자에서 만듭니다(모듈러 곱셈 15회이고, 그 키를
  만들어 낸 DER 파싱보다 적습니다).

## 문서화 패스

← [변경 이력](../HISTORY.ko.md)

문서의 모든 주장을 코드에 대조해 감사하고 어긋난 것을 고쳤는데, 라이브러리의
가장 새로운 경계에 집중되어 있었습니다.

- **`CONCEPTS.md`의 확장 클래스 이름 일곱 개가 존재하지 않았습니다**(16회
  등장) — `CSubjectAlternativeNameExtension`과 그 동류들인데, 코드에는 짧은
  `CSanExtension`/`CSkiExtension`/`CAkiExtension`/`CCdpExtension`/
  `CAiaExtension`/`CPoliciesExtension`/`CEkuExtension`이 있습니다.
- **"인코딩 쪽은 아직 없다"**는 거짓이었습니다. 열 확장 전부가 한동안
  `C<Name>ExtensionBuilder`와 `IExtension::encodeValue()`를 갖고 있었습니다.
- **"이것이 자라날 곳"**이 여전히 `x509/`를 파싱 전용으로 설명했는데, 그 문서
  자신의 개요가 이미 그것과 모순되고 있었습니다. 진짜로 없는 것을 중심으로
  다시 썼습니다. 인증서/CRL 서명 검증(`CCert`는 서명을 파싱하고 그것도 TBS
  범위도 노출하지 않습니다 — `tests/x509/cert.cpp`가 그것들에 닿기 위해 DER를
  손으로 다시 걸어야 합니다), 체인 구축과 경로 검증, 그리고 CSR 지원입니다.
  미래 의존성이 "인증서 생성이 구현되면 비대칭 암호"가 될 것이라고 주장하던
  낡은 제3자 단락도 함께 없앴습니다.
- `CCert::import()`를 전반적으로
  `importDer()`/`importPem()`/`importFrom()`으로 고쳤습니다. `EREG_AGAIN`
  (4회 등장. 어디에도 존재하지 않는 이름)을 `ERET_AGAIN`으로 고쳤습니다.
  `Sha2_32Transform()`/`Sha2_64Transform()`을
  `Sha2_32Core::transform()`/`Sha2_64Core::transform()`으로 고쳤습니다 — 이
  파일이 이미 끝났다고 주장했던 이름 변경입니다.
- `COctet`의 이동 대입이 원본을 비우는 것으로 설명되어 있었습니다. 프로젝트
  관례에 따라 swap하며, 같은 문서가 다른 곳에서는 올바르게 그렇게 말하고
  있었습니다. 하드웨어 가속이 `CERTPP_DISABLE_HWACCEL_AES`가 빠진 채
  "독립적인 빌드 옵션 둘"로 설명되어 있었습니다. SHAKE128이 "가속 경로 없음"
  목록에서 빠져 있었습니다.
- `BUILDING.md`가 빠져 있던 `CERTPP_BUILD_EXAMPLES` 행, Examples
  절(`CERTPP_EXAMPLE_OUTPUT_DIR`과 예제들이 왜 의도적으로 CTest 케이스가
  아닌지를 포함), 그리고 `build-asan/`이 암시하지만 아무것도 문서화하지 않던
  AddressSanitizer 레시피를 얻었습니다.
- `RULES.md`의 버퍼 처리 규칙이 이제 두 절반을 구분합니다.
  일괄 호출 절반에는 예외가 있고, 원시 포인터 절반은 루프로 남아야 하는
  코드에도 적용됩니다. `CbcTransformer`가 그 작업 예제입니다.
- README 둘 다 `CBuffer`를 "고정 크기 소유 바이트 버퍼"라고 불렀는데 — 그것은
  크기 조절 가능한 작업용 버퍼이고 `COctet`이 고정 크기 쪽입니다 —
  `COctet`/`CBase64`를 완전히 빠뜨렸습니다. `HISTORY.md`와 README 둘의
  "아직 git 역사 없음" 전제가 이제 거짓이 아니라 그-당시-참으로 되어 있습니다.
- `CLAUDE.md`가 `x509`를 "파싱한다(아직 생성하지 않는다)"고 주장했고, 대칭
  암호도 CRL/OCSP도 나열하지 않았고, 다섯 문서 중 셋만 링크했습니다.

## 포스트 양자: 검토 정리, 구현 계획 추가

← [변경 이력](../HISTORY.ko.md)

`docs/PQC.md`는 PQ 코드가 하나도 없던 때 작성되어 자기 첫 단계에서부터
낡아 있었습니다. 트리에 맞춰 조정하고 확장했습니다.

- 상태 표를 추가했습니다. SHAKE128과 공유 `KeccakCore`는 **완료**이고(검토는
  그것들을 앞으로 할 일로 설명했습니다), `IKem`/`IKemContext`와 KEM 키 계열은
  **선언만** 되어 있습니다.
- 인터페이스 절을 고쳤습니다. 구현된 `encapsulate()`는 공개키 파라미터를 받지
  않고(`sign()`/`verify()`처럼 바인딩된 키에 작용합니다), KEM 키는
  `IPublicKey`의 재사용이 아니라 자기 계열
  (`EKems`/`IKemKeyBase`/`IKemPublicKey`/`IKemPrivateKey`/`SKemKeyPair`)입니다.
- 위의 SHAKE 멱등성 버그를 고치는 동안 발견한 제약을 기록했습니다. 두 XOF
  모두 인스턴스당 고정 출력 길이 하나를 노출하므로, FIPS 203/204의 상한
  없는 거부 샘플링 스트림에는 아직 존재하지 않는 증분 스퀴즈가 필요합니다.
  이제 2단계이고, 선행 조건입니다.
- ML-KEM 우선 순서를 다시 검토했습니다. 원래 세 이유 중 둘이 약해졌습니다 —
  KEM 인터페이스가 이제 존재하고, TLS 하이브리드 논거는 이 라이브러리가
  아니라 업계에 대한 것인데 이 라이브러리에는 TLS 스택이 없어 KEM의 트리 내
  소비자도 없습니다. 그에 맞서,
  `tests/x509/certs/unimplemented/identrust-mldsa-root.der`은 실재하고
  현재 유효한 ML-DSA 루트이며 `CCert`가 알고리즘만 빼고 이미 완전히
  파싱합니다. 2–3단계가 어느 쪽이든 공유되므로, 권고는 "ML-KEM을 먼저
  두되 4단계에서 순서를 진짜로 열린 것으로 취급할 것"으로 남겨 두었습니다.
- 7단계 구현 계획을 추가했고, 수락 테스트를 구체적으로 진술했습니다. 그
  IdenTrust 픽스처가 `certs/unimplemented/`에서 `certs/implemented/`로
  옮겨 가는 것입니다.
- `src/crypto/kem.cpp`를 추가해 `IKem::builtIn()`이 정의를 갖게 되었습니다 —
  어디에도 구현 없이 선언되어 있었고, 그것이 호출을 null 반환이 아니라 링크
  오류로 만들었으며, `kem.hpp`를 컨벤션이 요구하는 짝이 되는 `.cpp`가 없는
  하나뿐인 비템플릿 공개 헤더로 남겨 두었습니다.
