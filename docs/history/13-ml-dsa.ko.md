# ML-DSA와 최초의 PQ 인증서

[English](13-ml-dsa.md)

## 포스트 양자: ML-DSA 자체(FIPS 204), 그리고 검증된 첫 실제 PQ 인증서

← [변경 이력](../HISTORY.ko.md)

이것 밑의 층들은 이미 들어와 있었고 이미 검증되어 있었습니다 — 환,
라운딩/hint 기계, 비트 패킹, 거부 샘플러 셋, 파라미터 표입니다. 여기에
착륙한 것은 그것들 위의 모든 것입니다. FIPS 204 7.2절의 키 및 서명 인코더,
KeyGen/Sign/Verify, `IAsymmetric` 래퍼, 그리고 실제 포스트 양자 인증서를
검증되게 만드는 X.509 배선입니다.

- `MlDsaScheme`(`src/crypto/asyms/mldsascheme.hpp`/`.cpp`):
  `pkEncode`/`pkDecode`, `skEncode`/`skDecode`, `sigEncode`/`sigDecode`,
  `w1Encode`, 그리고 `keyGenInternal`/`signInternal`/`verifyInternal` 더하기
  `sign`/`verify`입니다. ξ와 `rnd`를 파라미터로 받으며, 그것이 그것을 벡터로
  구동할 수 있게 하는 요소입니다.
- `CMlDsa`(`include/certpp/crypto/asyms/mldsa.hpp` +
  `src/crypto/asyms/mldsa.cpp`): `IAsymmetric`으로서의 ML-DSA이고, 파라미터
  집합당 인스턴스 하나입니다. `EAsymmetrics`가
  `EASYM_MLDSA44`/`EASYM_MLDSA65`/`EASYM_MLDSA87`를 `EASYM_MAX` 앞에
  덧붙여 얻었습니다 — 그 enum이 ABI 경계를 넘으므로, 중간에 삽입하면 이미
  컴파일된 호출자가 조용히 다른 알고리즘을 고르게 남길 것입니다.
- X.509: `CCert`의 `KEY_ALGOS`와 `SIG_ALGOS`에 있는 RFC 9881의
  `.17`/`.18`/`.19`, `CCertBuilder`가 하나를 발행할 수 있도록 ML-DSA에 대해
  가르쳐진 `resolveSigAlgoForSigning()`, 그리고 네 검증 경로에 복사되어 있던
  `EASYM_ED25519 || EASYM_ED448` 술어를 대체하는
  `CCert::signsMessageDirectly()`입니다.

#### 검증이 먼저 왔고, Python으로

C++ 아래의 모든 것이 그중 어떤 것이 쓰이기 전에 확립되었습니다. 발행된
알고리즘에서 전사하고 기존 구현에서 빌린 것은 아무것도 없는 독립 FIPS 204
참조가 NIST의 ACVP 벡터를 완전히 재현했습니다 — **keyGen 75/75, 24개 그룹
전부에 걸쳐 바이트 단위로 정확한 sigGen 360/360, sigVer 판정 180/180**입니다.
24개 sigGen 그룹은 표준이 인정하는 모든 조합을 덮습니다. 결정론적과 hedged,
내부와 외부 인터페이스, 순수와 미리 해시된 것, 그리고 `externalMu`
변종입니다. 그 다음 C++가 첫 실행에서 같은 벡터와 일치했는데, 그것이 그
순서로 하는 요점입니다.

Python 참조가 잡아낸 버그 둘이고, 둘 다 왕복에는 보이지 않았을 것입니다.

- `rejBoundedPoly`가 반환하기 전에 자기 계수를 mod q로 축약했으므로, s1의
  −1이 q−1이 되었고, 그러면 `BitPack(η − coefficient)`이 말도 안 되는 필드를
  인코드했습니다. `pk`는 여전히 keyGen 케이스 75개 전부에서 일치했고 — NTT는
  자기가 건네받은 것이 어느 대표원인지 신경 쓰지 않습니다 — `sk`만
  달랐습니다. 키를 생성하고 그것을 쓰는 테스트는 통과했을 것입니다.
- `sampleInBall`과 `expandMask`도 같은 축약을 지녔고 거기서는 무해했지만,
  고침은 같습니다. 이 셋은 **부호 있는** 계수를 만들어 내며, C++ 층은 처음부터
  그것을 올바르게 하고 있었습니다.

#### 이 계획이 결코 이름 대지 않았던 것: 메시지 관례 둘

FIPS 204에는 `M'`를 그대로 서명하는 내부 인터페이스(알고리즘 7–8)와 먼저
`IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx`를 앞에 붙이는
외부 인터페이스(알고리즘 2–3)가 있습니다. RFC 9881의 `id-ml-dsa-*` OID는 빈
컨텍스트를 지닌 **외부** 인터페이스를 뜻합니다 — 그래서 X.509 서명은 TBS
바이트 단독이 아니라 `0x00 || 0x00 || tbsCertificate`를 덮습니다.

이것을 틀리는 것은 자기 일관적인 버그의 이상적인 모양입니다. 완벽하게
왕복하고, ACVP sigGen 그룹의 절반(`signatureInterface: "internal"`인 열두
개)과 일치하며, 모든 진짜 인증서를 거부합니다. 두 형태 모두 `MlDsaScheme`에
있고, `CMlDsa`는 외부 것만 노출하며,
`tests/crypto/asyms/kat_mldsa.cpp`가 그 둘이 불일치한다는 것과 각각이 상대의
서명을 거부한다는 것을 직접 단정합니다.

`sign()`/`verify()`는 μ를 스스로 계산해 그것을 내부 형태에 그
`externalMu`로 건네며, 접두사와 메시지를 한 버퍼로 연결하지 않습니다. μ가
`H(tr ‖ M')`이고 `H`가 자기 부분들을 순서대로 흡수하므로 결과는 비트 단위로
동일하지만, 메시지가 결코 복사되지 않습니다 — 그리고 `tr`이 개인키의 고정
오프셋에 앉아 있으므로 그것을 읽는 데는 비용이 들지 않습니다.

#### `2.16.840.1.101.3.4.3.19`는 ML-DSA-87입니다

그 arc는 ML-DSA-44/65/87에 대해 `.17`/`.18`/`.19`로 가며, 그 셋이 연속이라는
것이 off-by-one을 가설적인 것이 아니라 현실적인 오류로 만듭니다. 인증서가
레지스트리를 참조하지 않고 그것을 정리해 줍니다. 그 `SubjectPublicKeyInfo`
BIT STRING이 2592바이트를 담고 그 `signatureValue`가 4627을 담는데, 그 짝은
ML-DSA-87 하나에만 속합니다(ML-DSA-65의 것은 1952와 3309입니다).

모든 파라미터 집합이 다른 키 길이*와* 서명 길이를 지니므로, 혼동은 틀린
답이 아니라 깔끔한 거부입니다 — `createPublicKey()`가 그 바이트를 곧바로
거부합니다. 정확히 그 이유로 테스트가 ML-DSA-65 키를 ML-DSA-87에
제시합니다.

#### 인수 테스트

`tests/x509/certs/unimplemented/identrust-mldsa-root.der`가
`certs/implemented/`로 옮겨 갔고, 그 테스트 케이스가 이제
`cert.verifyBy(cert) == ERET_OK`를 단정합니다. 그것은 다른 누군가의 구현이
이 라이브러리가 고르지 않은 바이트에 대해 만들어 낸 진짜 ML-DSA-87 서명이며,
`CCert`, `CMlDsa`, `MlDsaScheme`을 통해 종단 간으로 검증됩니다.

그것은 ML-DSA 구현이 일관되게 틀림으로써는 통과할 수 없는 테스트 모음의
유일한 검사입니다. 동반 케이스가 TBSCertificate에서 한 비트, 서명에서 한
비트, 공개키에서 한 비트를 뒤집고 각각이 실패할 것을 요구합니다 — 그러지
않으면 위의 성공이 무조건 `ERET_OK`를 반환하는 `verify()`로도 만족될
것입니다.

인코딩 세부 둘은 가정되는 대신 인증서에서 읽어 냈습니다. `parameters`가 그
AlgorithmIdentifier 셋 전부에서 없고, BIT STRING 둘 다
내부 `OCTET STRING` 래퍼 없이 가공되지 않은 FIPS 204 바이트를 나릅니다.
그래서 `CCert`는 DSA의 쪼개진 `Dss-Parms`와 달리 ML-DSA에 대해 재형성 단계가
필요 없습니다.

#### `signsMessageDirectly()`, 그리고 그것이 함수 하나인 이유

`CCert::verifyBy()`, `CCrlReader::verifyBy()`, 그리고 OCSP
`verifySignature()` 둘이 각각 `keyAlgo == EASYM_ED25519 ||
keyAlgo == EASYM_ED448`을 테스트해 먼저 해시할지를 결정했습니다. 알고리즘 셋이
더해진 것은 그 술어의 사본 넷을 그것이 떠내려갈지가 아니라 언제 떠내려갈지의
문제로 만들었습니다 — 그리고 항목을 놓친 지점은 최악의 방향으로 조용히
실패합니다. 가공되지 않은 TBS 바이트를 해시-후-서명 verify에 건네거나(위수의
비트 길이로 절단되므로 서명이 평문의 접두사를 덮습니다), digest를 ML-DSA에
건네고 메시지 대신 그 32바이트 문자열에 서명합니다. 첫 번째는 이 라이브러리의
OCSP 경로에 있던 실제 버그였습니다. 어느 것도 자기 서명 왕복에는 보이지
않습니다.

그것은 의도적으로 `_sigHashAlgo == EHASH_UNKNOWN`의 테스트가 *아닙니다*.
그것은 `resolveSigAlgo()`가 등록되지 않은 OID에 대해 남겨 두는 것이기도
합니다. 서명 쪽의 `sigIsEddsa` 지역 변수가 같은 이유로
`sigIsSelfHashing`으로 이름이 바뀌었습니다. 거기서는 `EHASH_UNKNOWN` 테스트가
모호하지 않습니다. `resolveSigAlgoForSigning()`이 자기가 모르는 알고리즘에
대해 `EHASH_UNKNOWN`이 아니라 false를 반환하기 때문입니다.

#### 메시지에 서명하는 것을 위한 digest 모양 인터페이스

`IAsymmetricContext::sign(digest, out)`에는 제시할 두 번째 관례가 없고,
ML-DSA에는 외부에서 공급되는 digest가 없습니다. 그것은 메시지에서 μ를
유도하고 그 다음 격자 commitment에 서명합니다. 미리 계산된 SHA-256 값을
넘기면 **그 32바이트 문자열에 대한** 유효한 ML-DSA 서명이 나옵니다 — 다른
어떤 구현도 생성하거나 검사하지 않을 것입니다. 검증자가 자기가 받은
메시지에서 μ를 다시 유도하기 때문입니다.

해결은 Ed25519/Ed448이 이미 확립했고 `CDnssecKeys::hasherOf()`가 반대쪽에서
진술하는 것입니다. 파라미터가 메시지를 나르고, `sizeOfDigest()`가 그렇다고
말하기 위해 0으로 남습니다. 0은 "계산할 digest가 없다, 메시지를 넘겨라"를
뜻하며, 그것은 IdenTrust 루트 자신의 컨텍스트에 대해 단정됩니다. 파라미터는
자기 인터페이스 이름을 유지합니다 — 구현별로 이름을 바꾸는 것은 override
관계를 명료하게 하는 대신 흐릴 것입니다.

#### 서명은 hedged이며, 그것이 KAT가 가공되지 않은 층을 거치는 이유입니다

`CMlDsa`는 서명마다 새 32바이트 `rnd`를 뽑으므로(FIPS 204의 권고
기본값), 한 메시지에 대한 두 서명이 다르고 어느 것도 고정된 답과 비교될 수
없습니다. 결정론적 서명 — `rnd`가 전부 0 — 은 테스트용 장치가 아니라 표준
자신의 변종이고, 모든 ACVP `deterministic: true` 그룹이 쓰는 것입니다. 그것은
`MlDsaScheme`을 통해 도달 가능하고 의도적으로 `CMlDsa`를 통해서는 아니므로,
호출자가 그것을 우연히 고를 수 없습니다.

#### 영 소거, 그리고 그것이 덮지 않는 것

FIPS 204 3.6.3절은 민감한 중간값이 더 필요하지 않게 되는 즉시 파괴될 것을
요구합니다. 서명의 거부 루프에는 `continue` 경로 넷과 이른 반환 열두 개가
있으므로, 바닥에 쓰인 지우기는 그 전부에 의해 건너뛰어질 것입니다 —
`CMlKem::decapsulate()`의 단일 탈출이 피하도록 만들어졌던 것과 같은 실패
양식입니다. 이쪽은 대신 RAII scrubber를 씁니다. ρ, K, tr, μ, ρ'',
s1/s2/t0과 그 NTT 형태들, masking 벡터 y, 인코드되기 전의 z, 그리고 `c*s`
곱이 모두 스코프가 어떻게 떠나지든 스코프 탈출 시 지워집니다. A-hat은
그대로 둡니다 — 그것은 ρ의 함수이고, ρ는 공개키에 실려 다닙니다.

그것은 표준이 역시 언급하는 검증 중간값으로는 **확장되지 않습니다**. 검증이
건드리는 모든 것이 공개이므로 거기에는 보호할 것이 없고, 그렇게 말하는 것이
그렇지 않은 것처럼 암시하는 지우기보다 더 유용합니다.

#### 네거티브 컨트롤

의도적인 파손 다섯이고, 각각을 다시 빌드하고 돌려 무언가가 실패하는 것을
확인한 다음 되돌렸습니다. 이것이 테스트 모음의 값이 기대는 측정입니다. 이
버그들 전부가 자기 자신과는 완벽하게 동작하는 구현을 남기기 때문입니다.

- **Decompose의 `(q-1)` 예외를 `rp == q-1`로 다시 쓰기**(그것인 폭 γ₂의 띠
  대신, 그것이 읽히는 단일 점으로). `mldsarounding`, KAT 테스트 모음 둘,
  **그리고 IdenTrust 인증서**에 잡혔습니다 — 실패 넷입니다.
- **`ExpandA`의 행/열 시드 바이트 교환.** `mldsasampler`, KAT 테스트 모음
  둘, 그리고 인증서에 잡혔습니다. `tests/crypto/asyms/mldsa.cpp` —
  `IAsymmetric` 왕복 테스트 모음 — 은 **통과했는데**, 그것이 나머지 셋에
  대한 논거 전부입니다. 전치된 행렬은 다르지만 유효한 방식이고, 키를
  생성하고 그것으로 서명하고 자기 자신에 대조해 검증하는 것은 그것을 볼 수
  없습니다.
- **`skDecode`의 s1/s2 범위 검사 삭제.** `kat_mldsa`에 잡혔는데, 그것은 첫
  s1 계수가 −5로 디코드되는 키를 먹이고 `checkPrivateKey()`,
  `signInternal()`, *그리고* `sign()`이 모두 그것을 거부할 것을 요구합니다.
  `IAsymmetric` 테스트 모음도 여전히 같은 키를 거부했지만 두 번째 경로로
  거부했습니다 — `publicKey()`가 공개 절반을 다시 유도하고, 그 tr이 그 다음
  불일치합니다 — 그래서 범위 검사는 그 테스트가 측정하는 것이 아닙니다.
- **`verifyInternal()`의 최종 commitment 비교를 `return true`로 교체.**
  모든 것에 잡혔습니다. KAT 테스트 모음 둘, `IAsymmetric` 테스트 모음, 그리고
  인증서의 조작 케이스입니다.

- 다섯 번째는 계획이 요구한 것이 아니라 이 작업 중에 추가된 검사에 대한
  것입니다. **`publicKeyOf()`의 다시 유도된 t0 비교 제거.** t0은 어떤 디코드
  검사도 닿을 수 없는 개인키의 한 부분입니다 — 그 필드가 13비트 범위에 대해
  정확히 13비트 폭이므로 모든 바이트 문자열이 합법적인 t0으로 디코드되고,
  `tr = H(pk)`는 그것을 덮지 않습니다.
  그것을 잡아낼 수 있는 유일한 것인 `tests/crypto/asyms/mldsa.cpp`의 t0 조작
  케이스에 잡혔습니다.

원래 컨트롤 넷 중 셋은 새로 생성된 키에 대한 서명-후-검증 왕복에는 보이지
않습니다. 그것이 이 테스트 모음이 하기 위해 존재하는 측정입니다.

새 파일 셋에 걸쳐 테스트 케이스 19개, 단정 510개입니다(`kat_mldsa.cpp` 7/137,
`kat_mldsaver.cpp` 4/137, `mldsa.cpp` 8/236). 더해서 `tests/x509/cert.cpp`의
ML-DSA 빌더 케이스와 `tests/x509/realcerts.cpp`의 인증서 케이스 둘입니다.
테스트 모음은 121개이고 전부 통과합니다.

#### 의도적으로 여기 없는 것

순수 변종만입니다. HashML-DSA는 Python 참조에서 검증되었지만(ACVP의
`preHash` 그룹 열두 개가 모두 일치) C++에는 없습니다. RFC 9881 8.3절이 그
OID들이 X.509 인증서에 나타나서는 안 된다(MUST NOT)고 말하고, 트리의 다른
어떤 것도 그것들을 필요로 하지 않습니다. `MlDsaScheme`도 ML-KEM의 공개
`CMlKem`과 달리 `src/`에 private으로 남습니다 — 모든 진입점이
`MlDsaParams`로 파라미터화되어 있고, 그 시그니처들을 내보내는 것은 이미
테스트된 그 private 헤더를 공개 API로 옮기거나 중복시키는 것을 뜻할
것입니다. 호출자가 필요로 하지 않는 표면을 위해서요.
