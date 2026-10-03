# 포스트 양자 암호: 검토와 구현 계획

[English](pqc-review.md)

이 문서는 포스트 양자(post-quantum, PQ) 코드가 하나도 없던 시점에 작성된 사전
설계 검토 — "무엇이 필요하고, 무엇을 먼저 해야 하는가" — 로 시작했습니다. 제안
내용 중 일부는 그 뒤에 실제로 구현되었으므로, 아래 검토 절들은 트리에 실제로
들어 있는 것을 설명하도록 수정했고, 구체적인 [구현 계획](#구현-계획)을 문서 끝에
덧붙였습니다.

## 현재 상태

| 항목 | 상태 |
|---|---|
| `SHAKE128` (`crypto/hashers/shake128.hpp`) | **완료** — `EHASH_SHAKE128`, 엄브렐라 헤더, KAT 테스트 |
| 공유 `KeccakCore` (`src/crypto/hashers/keccakcore.hpp`) | **완료** — permutation + 스펀지 흡수, SHAKE128/SHAKE256이 공유 |
| `IKem`/`IKemContext` (`crypto/kem.hpp`) + KEM 키 계열 (`crypto/keys.hpp`) | **완료** — 알고리즘보다 먼저 설계되었고, 지금은 그 뒤에 ML-KEM이 있습니다. `EKems`에 세 멤버가 있고 `IKem::builtIn()`이 이들을 디스패치합니다. `certpp.hpp`에 포함 |
| 증분 SHAKE 스퀴징 (`SHAKE128`/`SHAKE256::squeeze()`) | **완료** — chunk 크기에 무관한 스트리밍 출력. 모든 chunk 크기와 rate 경계에 걸쳐 `hashlib`과 대조 검증 |
| ML-KEM 환 연산 (`src/crypto/kems/mlkemring.hpp`) | **완료** — R_q(q=3329) 위의 NTT/역 NTT/기본 경우 곱셈. 트위들(twiddle) 테이블은 ZETA에서 유도해 항목 단위로 단정하고, NTT 영역 곱셈은 schoolbook negacyclic 곱셈과 대조 |
| ML-KEM 샘플러 + ByteEncode/ByteDecode/Compress | **완료** — `src/crypto/kems/mlkemcodec.hpp`. 샘플러는 이제 `CMlKemSampler`로 공개되어 있습니다 (`crypto/kems/mlkem.hpp`). 독립 모델과 배열 전체 체크섬으로 고정 |
| SHA3-256 / SHA3-512 (ML-KEM의 H와 G) | **완료** — 이 계획이 놓쳤던 선행 조건. 라이브러리에 SHAKE는 있었지만 고정 출력 SHA-3가 없었습니다 |
| ML-KEM 알고리즘 (`crypto/kems/mlkem.hpp`: `CMlKem`, `SMlKemParams`, `SMlKemPoly`) | **완료** — 원시 span 위의 K-PKE와 FO 변환. 암묵적 거부(implicit rejection)와 키 검사 음성 케이스를 포함해 세 파라미터 집합 전부를 ACVP로 검증 |
| `IKem`으로서의 ML-KEM (`crypto/kems/mlkem.hpp`, `EKEM_MLKEM512/768/1024`) | **완료** — `MLKEM` 하나가 세 집합 전부를 담당합니다. 키는 FIPS 203 자체 인코딩으로 직렬화되고, `CRng`를 끌어다 쓰는 계층은 여기뿐입니다 |
| ML-DSA 파라미터 집합 (`src/crypto/asyms/mldsaparams.hpp`) | **완료** — FIPS 204 표 1. 모든 키/서명 길이를 유도하고 표 2에 대해 `static_assert` |
| ML-DSA 샘플러 (`src/crypto/asyms/mldsasampler.hpp`) | **완료** — SampleInBall/RejNTTPoly/RejBoundedPoly와 ExpandA/ExpandS/ExpandMask. ExpandA의 전치된 시드 순서를 포함해 dilithium-py와 교차 확인한 기지 응답(known-answer)으로 고정 |
| ML-DSA 비트 패킹 + hint 인코딩 (`src/crypto/asyms/mldsacodec.hpp`) | **완료** — SimpleBitPack/BitPack과 그 역, 세 가지 거부 조건을 모두 갖춘 HintBitPack/HintBitUnpack. 디코딩이 보장할 수 없는 범위는 문서화하고 `inRange()`를 제공 |
| ML-DSA 라운딩/hint (`src/crypto/asyms/mldsarounding.hpp`) | **완료** — Power2Round/Decompose/HighBits/LowBits/MakeHint/UseHint. 역변환 항등식을 버킷 경계에서, 그리고 Decompose의 `(q-1)` 구간 전체에 걸쳐 확인했습니다. 그 구간은 읽히는 모습과 달리 단일 점이 아니라 폭 gamma2의 띠입니다 |
| ML-DSA 환 연산 (q=8380417) | **완료** — `src/crypto/asyms/mldsaring.hpp`. 완전한 8단 NTT (zeta의 위수가 ML-KEM의 256이 아니라 512이므로 변환이 끝까지 진행되고 NTT 영역 곱셈은 pointwise입니다). FIPS 204 부록 B에 인쇄된 표와 schoolbook negacyclic 곱셈에 대해 확인 |
| ML-DSA 알고리즘 (`src/crypto/asyms/mldsascheme.hpp`: `MlDsaScheme`) | **완료** — FIPS 204 7.2의 키/서명 인코더와, 내부(알고리즘 6–8)·외부(알고리즘 2–3) 양쪽 형태의 KeyGen/Sign/Verify를 원시 span 위에 구현. 세 파라미터 집합, 24개 sigGen 그룹 전부, 네 가지 sigVer 거부 사유 전부를 ACVP로 검증 |
| `IAsymmetric`으로서의 ML-DSA (`crypto/asyms/mldsa.hpp`, `EASYM_MLDSA44/65/87`) | **완료** — `CMlDsa` 하나가 세 집합 전부를 담당합니다. 키는 FIPS 204 자체 인코딩으로 직렬화되고, 서명은 hedged이며, `CRng`를 끌어다 쓰는 계층은 여기뿐입니다 |
| PQ용 X.509 OID/알고리즘 배선 | **ML-DSA에 대해 완료** — `CCert`의 `KEY_ALGOS`/`SIG_ALGOS`에 RFC 9881의 `.17`/`.18`/`.19`, 네 검증 지점이 공유하는 `signsMessageDirectly()`, 그리고 ML-DSA로 서명한 인증서를 발급할 수 있는 `CCertBuilder`. IdenTrust ML-DSA-87 파일럿 루트가 이제 자기 서명을 검증합니다. ML-KEM 자체의 SubjectPublicKeyInfo 래핑(RFC 9935)은 아직 배선되지 않았습니다 |

즉 1–5단계는 완료이고, 6단계는 ML-DSA에 대해 완료입니다. ML-KEM은 동작하며, 세
파라미터 집합 전부에서 NIST 벡터와 일치하고, 원시 span 형태인 `CMlKem`(이것이
테스트 벡터에서 바로 검증할 수 있게 해 준 형태)으로도, 라이브러리의 다른 모든
알고리즘처럼 `IKem::builtIn(EKEM_MLKEM768)`으로도 도달할 수 있습니다. ML-DSA는 한
계층 아래에서 같은 모양입니다. 그 환 연산은 Keccak 프리미티브와 NTT의 일반적인
형태 외에는 ML-KEM의 것과 아무것도 공유하지 않으며(`MlDsaRing`은 파라미터화가
아니라 별개의 단위입니다), 그 위에 라운딩과 hint 기계, `HintBitUnpack`의 세 가지
거부 조건을 포함한 비트 패킹, 세 개의 거부 샘플러, Expand* 절차, 파라미터 표가
있고, 이제 `MlDsaScheme`(7.2 인코더와 KeyGen/Sign/Verify)이 있으며 `CMlDsa`가
이를 `IAsymmetric`으로 노출합니다.

이것을 단지 자기 일관적인(self-consistent) 것이 아니라 실재하게 만드는 것은
다음입니다. `tests/x509/realcerts.cpp`의 IdenTrust ML-DSA-87 파일럿 루트, 즉 다른
사람의 구현이 서명한 인증서가 이제 `cert.verifyBy(cert)`를 통과합니다. PQ 쪽에
남은 것은 ML-KEM의 X.509/CMS 래핑(RFC 9935)과, 7단계의 나머지 알고리즘 재평가입니다.

## 이것이 libcertpp에 특별히 중요한 이유

`libcertpp`는 X.509/ASN.1 라이브러리입니다. 그 `crypto` 모듈은 `x509::CCert`의
파싱/빌드와 서명 검증을 동작하게 하려고 존재하며, 지금 가지고 있는 모든
`IAsymmetric` 알고리즘(RSA, DSA, `CEcdsa`/`CEcdsa2`, `Ed25519`/`Ed448`,
`X25519`)은 실제 인증서나 CMS/PKCS#7 구조가 키나 서명을 담을 수 있는 바로 그
집합입니다. IETF LAMPS 워킹 그룹은 이제 X.509 프로파일을 **발행**했습니다 —
RFC 9881 (ML-DSA, 2025-10), RFC 9909 (SLH-DSA, 2025-12), RFC 9935 (ML-KEM,
2026-03) — 따라서 OID와 SubjectPublicKeyInfo/서명 인코딩은 움직이는 중이 아니라
정해졌습니다. 복합(composite) ML-DSA+ECDSA
(`draft-ietf-lamps-pq-composite-sigs`)는 IESG 승인을 받고 RFC 편집자 큐에 있습니다.
폐기 쪽에서는 **NIST IR 8547**(최초 공개 초안, 2024-11-12)이 112비트 보안의
고전 알고리즘(RSA-2048, P-256 등)을 2030년 이후 폐기 예정으로, 2035년 이후
금지로 제안하고 있고 SP 800-131A Rev 3(ipd, 2024-10-21)이 그 동반 문서입니다 —
둘 다 아직 초안이므로 그 날짜는 법이 아니라 방향으로 받아들이십시오. 인증서
라이브러리는 결국 그것에 의존하게 될 대부분의 소프트웨어보다 더 긴 관련성
지평을 가지므로, PQ 지원은 투기적인 것이 아닙니다 — `x509::CCert`가 건네받는
모든 인증서를 파싱하고 검증하기 위해 결국 필요해집니다.

## 표준화된 알고리즘 (상태 재확인 2026-10-02)

NIST는 2024년 8월에 세 개의 PQ 표준을 확정했고, 그 외에 이미 선정된 네 번째와
여전히 진행 중인 추가 후보들이 있습니다.

| 표준 | 알고리즘 (이전 이름) | 범주 | 난해성 가정 |
|---|---|---|---|
| FIPS 203 | ML-KEM (Kyber) | 키 캡슐화 (KEM) | Module-LWE (격자) |
| FIPS 204 | ML-DSA (Dilithium) | 전자 서명 | Module-LWE / Module-SIS (격자) |
| FIPS 205 | SLH-DSA (SPHINCS+) | 전자 서명 | 해시 함수 안전성만 |
| FIPS 206 (개발 중. 2026-10-02 기준 **공개 초안 없음**) | FN-DSA (Falcon) | 전자 서명 | NTRU 격자 (최단 벡터) |

NIST는 또한 격자 가정이 미래에 깨졌을 때 표준화된 PQ KEM이 하나도 남지 않는 일이
없도록, 구조적으로 독립적인 ML-KEM 대비 예비로 2025-03-11에 **HQC**(Hamming
Quasi-Cyclic, 부호 기반 KEM)를 선정했습니다. **FIPS 207**로 계획되어 있으나
초안은 발행되지 않았습니다. (NIST가 2027년경 확정을 목표로 한다는 보도가 있었지만
이는 간접 정보이며, 그렇게 명시한 날짜 있는 NIST 페이지는 없습니다.) 목표가 아니라
다시 살펴볼 후보로 취급하십시오.

FIPS 203/204/205는 모두 2024-08-13에 확정되었고 신뢰해도 안전합니다. FN-DSA와
HQC가 움직이는 두 부분이며, 둘 다 1–6단계의 중요 경로에는 없습니다.
**2026-10-02 재확인:** FIPS 206은 FIPS 204로부터 25개월이 지난 지금도 공개 초안이
없고, HQC는 여전히 초안 전 단계입니다. 둘 다 계획을 바꾸지 않습니다 — 오히려
FN-DSA의 공백은 이 문서를 처음 쓸 때보다 그것을 미루는 근거를 더 좋게 만듭니다.
`IKem` 작업에도 이제 관련되는 것: **SP 800-227 "Recommendations for
Key-Encapsulation Mechanisms"가 2025-09-18에 최종 확정**되었고, KEM을 어떻게
노출하고 사용해야 하는지에 대한 규범적 지침입니다.

**libcertpp 권고 범위: ML-KEM과 ML-DSA만.** 원래의 우선순위는 아래 이유로
ML-KEM이 먼저였습니다. 그 순서는 이후 재검토되었습니다 —
"[ML-KEM 우선 순서 재평가](#ml-kem-우선-순서-재평가)"를 보십시오. 그쪽이 현재
입장입니다.

- **ML-KEM 먼저.** KEM이 서명 스킴보다 먼저 필요합니다. TLS 1.3의 PQ/하이브리드
  키 교환(`X25519MLKEM768`, 이미 주요 브라우저와 OpenSSL 3.x에 출하 중)이 오늘날
  가장 널리 배포된 단일 PQ 사용 사례이고, 이 글을 쓸 당시 `libcertpp`에는 KEM
  모양의 인터페이스가 전혀 없었기 때문입니다(아래 "인터페이스 수준의 적합성"
  참고 — 그 뒤에 하나가 선언되었습니다). 더 단순한 프리미티브(RNG에 의존하는
  도메인 파라미터 없음, hash-then-sign 구성 없음, 단일 encapsulate/decapsulate
  왕복)를 상대로 새 인터페이스 모양을 먼저 만드는 것이 ML-DSA를 상대로 만드는
  것보다 위험이 낮습니다.
- **ML-DSA 두 번째.** PQ 서명 인증서를 파싱/생성하기 위해 `x509::CCert`/
  `CCertBuilder`가 실제로 필요한 서명 알고리즘입니다. ML-KEM이 필요한 것과 같은
  모듈 격자 기계(NTT, `R_q = Z_q[X]/(X^256+1)`, 중심 이항 샘플링)를 재사용하므로,
  연이어 구현하면 둘이 저수준 연산 대부분을 공유합니다 — 아래 "공유 기반" 참고.
- **SLH-DSA와 FN-DSA: 의도적으로 연기, 거부가 아님.** SLH-DSA가 ML-DSA보다 나은
  점은 더 보수적인 난해성 가정(격자 문제 대신 순수 해시 안전성) 하나뿐이고, 그
  대가로 서명이 대략 30–50배 커지고(7856–49856 바이트 대 ML-DSA의
  2420/3309/4627 바이트) 서명이 훨씬 느립니다(서명마다 머클 트리의 머클 트리
  순회 전체). ML-DSA가 존재한 뒤의 합리적인 알고리즘 민첩성 대비책이지, 첫
  목표는 아닙니다. FN-DSA(Falcon)는 셋 중 가장 작은 PQ 서명을 주지만, 그 서명
  알고리즘은 constant-time을 유지하고 서명 분포 누출을 통한 키 복구를 피하기
  위해 특정한 라운딩/정밀도 보장을 갖춘 부동소수점 연산으로 격자 위의 이산
  가우시안 분포에서 샘플링해야 합니다 — 발행되었지만 여전히 제대로 하기가
  쉽지 않은 구성(아래 "진짜로 어려운 것" 참고)이고, ML-KEM/ML-DSA가 견고해진
  뒤에 다시 볼 만한 것이지 그 전은 아닙니다.

## 인터페이스 수준의 적합성

`IAsymmetric`(`include/certpp/crypto/asym.hpp`)은 두 연산을 중심으로 모양이
잡혀 있습니다. `sign()`/`verify()`(hash-then-sign, `IAsymmetricContext`로 바인딩)와
`createEncrypter()`/`createDecrypter()`(RSA의 단일 블록 PKCS#1 암복호를 모델로 한
`IAsymmetricTransformer` 세션). 각 PQ 알고리즘을 그 모양에 대조해 보면:

- **ML-DSA는 `sign()`/`verify()`에 그대로 맞습니다.** 메시지 digest 위의
  Fiat-Shamir-with-aborts 서명 스킴으로, `ECdsa`/`Ed25519`의 기존
  `sign()`/`verify()`와 같은 모양입니다 — 새 인터페이스는 필요 없고, 새
  `IAsymmetric` 구현(`crypto/asyms/` 아래의 `MLDSA`, 기존 일곱 개 옆)만 있으면
  됩니다.
- **ML-KEM은 기존 두 모양 어디에도 맞지 않습니다.** KEM의 공개 연산
  (`Encaps(pk) -> (ciphertext, sharedSecret)`)은 ciphertext *와* 호출자가
  지정하지 않은 새로운 공유 비밀을 함께 만들어 냅니다 — `createEncrypter()`가
  잡힌 모양인 "내가 고른 이 평문을 암호화해라"가 아니며,
  `Decaps(sk, ciphertext) -> sharedSecret`은 복호된 메시지가 아니라 비밀을
  돌려줍니다. ML-KEM을 `createEncrypter()`/`createDecrypter()`로 밀어 넣는 것
  (예컨대 공유 비밀을 "평문"으로 취급하는 것)은 새는, 혼란스러운 추상이 될
  것입니다. 따라서 **새 형제 인터페이스**를 얻었고, 이제 존재합니다.
  `crypto/kem.hpp`의 `IKem`/`IKemContext`로, `IAsymmetric`/
  `IAsymmetricContext`의 모양(키 크기 명세, `generateKeyPair()`,
  `checkPrivateKey()`, `createPublicKey()`/`createPrivateKey()`,
  `createContext()`)을 반영하면서 sign/verify/encrypt/decrypt 자리에
  `encapsulate()`/`decapsulate()`를 둡니다.

  구현된 인터페이스의 두 가지 세부는 이 검토의 원래 스케치와 다르며, 둘 다
  의도적입니다.

  - `encapsulate(SByteSpan& ciphertext, SByteSpan& sharedSecret)`는 공개키
    파라미터를 **받지 않습니다**. 컨텍스트가 바인딩한 키에 대해 작동하는데,
    이는 `IAsymmetricContext::sign()`/`verify()`가 이미 따르는 "인자가 아니라
    바인딩된 키에 대해 작동한다"는 같은 관례입니다 — 호출자는 두 키를 받는
    `keyPair(peerPublicKey, nullptr)` 오버로드로 상대의 공개키를 바인딩합니다.
    `decapsulate(const SReadOnlyByteSpan& ciphertext, SByteSpan& sharedSecret)`
    도 마찬가지로 바인딩된 개인키에 대해 작동합니다.
  - KEM 키는 `IPublicKey`/`IPrivateKey`의 재사용이 아니라 **자체 키 계열**입니다
    (`crypto/keys.hpp`의 `EKems`, `IKemKeyBase`, `IKemPublicKey`,
    `IKemPrivateKey`, `SKemKeyPair`). KEM 키는 비대칭이긴 하지만 서명 키도
    Diffie-Hellman 키도 아니며, 이는 `ESymmetrics`가 대칭 키에 이미 적용하고
    있는 것과 같은 논리입니다.

  어느 쪽이든 이는 경계가 분명한 추가적 변경이었습니다 — 기존 인터페이스의
  모양은 하나도 바뀌지 않았고, 이 라이브러리의 유일한 기존 순수 KEX 알고리즘인
  `X25519`는 `IKem`에 맞춰 개조하지 않고 그대로 두었습니다. 대칭성을 위해 잘
  동작하는 Diffie-Hellman 인터페이스를 KEM의 encapsulate/decapsulate 모양에
  맞추도록 강제하는 것은 그 변경 비용만큼의 값이 없습니다.

## 공유 기반: ML-KEM과 ML-DSA가 필요한 것, 그리고 이미 있는 것

두 알고리즘 모두 같은 다항식 환 `R_q = Z_q[X]/(X^256+1)` 위에서 동작하고
(ML-KEM: `q = 3329`, ML-DSA: `q = 8380417`), 둘 다 다음이 필요합니다.

1. **도메인 분리된 확장을 위한 SHAKE 기반 XOF/해시 계층**(행렬 생성, 샘플링,
   ML-DSA의 Fiat-Shamir 챌린지) — **그리고 ML-KEM에는 고정 출력 SHA-3.**
   이 항목은 원래 SHAKE128이 있으면 해시 계층은 끝났다고 주장했는데, 그것은
   틀렸습니다. FIPS 203은 `H = SHA3-256`과 `G = SHA3-512`를 쓰고, 라이브러리에는
   고정 출력 SHA-3가 전혀 없었습니다. 둘 다 추가되었고
   (`EHASH_SHA3_256`/`EHASH_SHA3_512`), XOF들과는 `KeccakCore`를, 서로는 새
   private `Sha3Core`를 공유합니다 — SHA-3는 SHAKE와 같은 스펀지이고, rate와
   SHAKE가 `0x1F`를 쓰는 자리의 `0x06` 도메인 바이트만 다릅니다. ML-DSA에는
   SHA-3가 필요 없습니다. FIPS 204는 SHAKE만 씁니다. **완료.** FIPS 203/204는
   행렬/벡터 확장에 SHAKE128을, 그 외 모든 것(G, H, 서명 XOF)에 SHAKE256을
   쓰는데, 이제 둘 다 존재합니다. `SHAKE256`은 이미 있었고,
   `SHAKE128`(`crypto/hashers/shake128.hpp`, `EHASH_SHAKE128`)이 이를 위해
   추가되었습니다. Keccak-f[1600] permutation과 스펀지 흡수는 rate에 무관하므로
   둘에 동일한데, `SHAKE256`에서 끌어올려 공유
   `KeccakCore`(`src/crypto/hashers/keccakcore.hpp`)로 만들었습니다. 이 코드베이스가
   `DesCore`/`Sha2_32Core`/`Sha2_64Core`에 이미 쓰고 있는 "공유 private 헤더+cpp"
   패턴과 같습니다. PQ 작업에만 해당하는 주의점 하나: 두 XOF 모두 인스턴스당
   고정 출력 길이 하나만 노출합니다(`IHasher::byteWidth()`, 생성 시 결정).
   따라서 *임의 길이* 스트림을 스퀴징하는 것 — 이것이 바로 FIPS 203/204가 행렬
   확장에 SHAKE128을 쓰는 방식입니다 — 에는 충분히 긴 인스턴스를 미리 잡거나
   두 클래스에 증분 스퀴즈 진입점을 추가하는 것이 필요합니다. 계획의 2단계를
   보십시오.
2. **q에 대한 모듈러 다항식 연산**: 덧셈/뺄셈(자명함), 그리고 실용적이기 위해
   **수론적 변환(Number-Theoretic Transform, NTT)**이 필요한 곱셈(소박한
   schoolbook 다항식 곱셈은 모든 실제 구현에서 비교/테스트용으로만 쓰입니다).
   이것은 **완전히 새로운 것**입니다 — `CBigNum`/`CGf2m`에 해당하는 것이 없습니다.
   `CBigNum`은 정수 위의 임의 정밀도(RSA/DSA 모양, 폭 무제한)이고, `CGf2m`은
   GF(2^m)(이진 곡선 모양, XOR 기반)입니다. 어느 것도 고정 폭의, 작은
   모듈러스(`< 2^23`), NTT에 친화적인 환 원소가 아닙니다. 정방향/역방향 NTT,
   pointwise 곱셈, 그리고 mod-q 연산을 위한 Montgomery/Barrett 축약을 갖춘
   `CPolyRing` 모양의 새 타입(범용 수 타입이라기보다 진짜로 PQ 특화이므로
   `utils/` 아래나 알고리즘 옆일 가능성이 높습니다)이 두 알고리즘이 올라앉는
   핵심 신규 프리미티브입니다.
3. **XOF 출력 스트림에서의 중심 이항 / 거부 샘플링**. LWE 기반 안전성 증명이
   필요한 작은 계수의 "노이즈" 다항식으로 균일 난수/의사난수 바이트를 바꾸는
   것입니다 — 새롭지만, (1)과 (2)가 있으면 직관적입니다.
4. **키 생성과 (ML-KEM) 캡슐화 난수를 위한 CSPRNG**. `CRng`가 지금 그대로
   정확히 이를 담당합니다. 새 작업 없음.
5. **인코딩/패킹**: 다항식 계수를 와이어 포맷의 비트 패킹 표현으로 압축/해제하는
   것(FIPS 203 알고리즘 5/6, "ByteEncode"/"ByteDecode") — 새롭지만 기계적이고,
   암호학적인 무엇보다 이 라이브러리의 기존 DER TLV 인코드/디코드 규율
   (`asn1/der.hpp`)에 정신적으로 더 가깝습니다.

대략 정리하면 항목 1과 4는 완료이고, 2/3/5가 실제 신규 작업입니다 — 거의
전적으로 두 알고리즘이 공유하는 NTT 기반 환 연산에 집중되어 있습니다.

## 진짜로 어려운 것 (위험이 실제로 있는 곳)

이 라이브러리의 기존 비대칭 알고리즘들과 달리, **격자 기반 PQ 스킴은 이 프로젝트에
정착한 "타이밍 하드닝보다 정확성" 입장을 용인하지 않습니다**(`CEcCurve`의 자체
doc 주석에 적혀 있고, RSA의 PKCS#1 v1.5 Bleichenbacher 계열 타이밍 구조를 고치지
않고 둔 이유이기도 합니다 — `docs/changelog.ko.md`의 보안 감사 항목 참고). 그
입장이 RSA/ECDSA/EdDSA에 통하는 이유는 그 알고리즘들의 *설계*(잘 고른 기준점,
투영 좌표, Montgomery ladder)가 형식적인 constant-time 보장 없이도 공격자가
악용할 수 있는 *구조적* 분기 대부분을 이미 제거하기 때문입니다. ML-KEM/ML-DSA에는
그런 여유가 없습니다.

- **거부 샘플링은 본질적으로 데이터 의존적입니다.** ML-DSA의 서명 알고리즘은 후보
  서명을 생성하고 어떤 계수가 허용 범위를 벗어나면 *거부하고 재시도*합니다 —
  소박한 구현의 재시도 횟수(따라서 그 타이밍)는 개인키에 대한 정보를 누출하며,
  이것이 초기 Dilithium/Kyber 구현에 대한 몇몇 실용적 키 복구 공격이 작동한 방식
  바로 그것입니다. 참조/"하드닝된" 구현들은 이를 특정한 constant-time 비교·샘플링
  패턴으로 처리하며(Kyber의 복호 실패 검사에는 명시적인 constant-time 재암호화
  비교로), 이는 근사하면 안 되고 정확히 따라야 합니다.

  **구현이 도달한 지점을 그대로 말하면:** `MlDsaScheme::signInternal()`의 재시도
  루프는 constant-time이 *아니며*, Fiat-Shamir-with-aborts의 어떤 구현도 그럴 수
  없습니다 — 재시도의 기준이 되는 네 가지 경계는 비밀 벡터와 메시지의 함수입니다.
  대신 한 것은 FIPS 204 부록 C가 실제로 요구하는 것입니다. 루프에 상한이 없으므로
  동작이 달라질 수 있는 소진 경로가 없고, 비밀 중간값은 각 `continue`를 포함한
  모든 탈출 지점에서 영으로 지워집니다. 한 반복 안의 연산은 비밀로 인덱싱되는
  테이블 조회가 없는 직선 코드입니다. 발행된 Dilithium 공격들을 특정해 이 코드를
  타이밍 부채널(side-channel) 감사한 적은 **없으며**, 그것이 이 코드에 대한
  명백한 다음 작업입니다.
- **ML-KEM 디캡슐화는 Fujisaki-Okamoto(FO) 변환의 암묵적 거부를 요구하며**,
  이것은 제대로 하기가 미묘합니다. 잘못되거나 무효한 ciphertext가 유효한 것과
  (타이밍으로든 출력으로든) *관측 가능하게 다른* 디캡슐화 실패를 일으켜서는 안
  됩니다 — FO 변환의 요점 전체가 "실패" 공유 비밀을 키 의존적 PRF에서 유도해
  공격자가 "ciphertext 거부됨"과 "ciphertext 수락됨"을 구별할 수 없게 하는
  것이고, 이것이 바탕 PKE에 대한 선택 ciphertext 공격을 KEM에 대해 실행 불가능하게
  만드는 요소입니다. 이는 단순한 성능 문제가 아니라 정확성 *그리고* 안전성
  요구사항을 동시에 만족해야 하는 사안입니다.
- **NTT 구현 버그는 넣기 쉽고 놓치기 쉽습니다.** 버터플라이 단계의 off-by-one이나
  잘못된 트위들 인자 테이블은 종종 격리된 상태에서는 제대로 왕복하는(정방향 NTT
  후 역 NTT가 입력을 복원하는) *어떤* 자기 일관적 결과를 여전히 만들어 내면서도,
  표준의 정확한 중간 표현과는 조용히 호환되지 않습니다 — 이것이 중요한 이유는
  FIPS 203/204가 상호운용성을 위해 NTT의 정확한 알고리즘(종단 동작만이 아니라)을
  명세의 일부로 고정하기 때문입니다. 자기 일관성이 아니라 공식 ACVP/NIST 기지
  응답 테스트 벡터에 대한 바이트 단위 검증이 필요하며, 이는 이 프로젝트 자신이
  정착시킨 교훈(P-521 위수 전사 오류, SHAKE256 회전 테이블 전치,
  `CBigNum::mul()`의 ADX 캐리 전파 버그 — 각각 "타당해 보였고" KAT 벡터가 잡기
  전까지 자기 일관성 검사를 통과했습니다)과 같습니다.

  [`changelog.ko.md`](changelog.ko.md)에 기록된 감사는 같은 교훈의 더 날카로운
  버전을 추가했고, PQ 작업이 초대하는 바로 그 실패 양상이므로 여기서 분명히 말해
  둘 만합니다. ECDSA의 FIPS 186-4 digest 절단이 *비트* 단위가 아니라 *바이트*
  단위였고, 그래서 부분군 위수가 바이트 정렬되지 않은 여덟 개 이진 곡선에서 이
  라이브러리는 자기 자신에 대해서는 완벽히 검증되고 다른 어떤 것에 대해서도
  검증되지 않는 서명을 만들어 냈습니다. 존재하는 동안 모든 테스트를 통과했는데,
  곡선별 테스트가 자기 출력을 서명하고 다시 검증하기만 했기 때문입니다. 트위들
  테이블이 잘못된 NTT는 정확히 그 모양으로 실패합니다. **와이어 포맷이 명세된
  무엇에 대해서도 자기 일관적인 왕복은 정확성의 증거가 아닙니다.** 외부 ACVP
  벡터는 이 작업에 대한 선택적 마무리가 아니라, 이 부류의 버그를 검출할 수 있는
  유일한 수단입니다.
- **부채널 표면이 이 라이브러리가 지금까지 다뤄 온 것보다 넓습니다.** 비밀
  데이터로 인덱싱되는 테이블 조회(거부 샘플링과 인코딩에서 흔합니다)는
  *알고리즘*이 그 외에는 constant-time이어도 캐시 타이밍 위험입니다 — 이는 이
  라이브러리의 기존 constant-time 작업(`CbcTransformer`의 padding 검사,
  `CEcCurve`/`CEc2Curve`/`Ed25519`/`Ed448`의 분기 없는 스칼라 곱)이 마주할 필요가
  없었던 것입니다. 그것들은 모두 데이터 의존적 테이블 인덱싱이 없는 직선
  연산이기 때문입니다.

이 중 어느 것도 진행하지 말아야 할 이유는 아닙니다 — ML-KEM/ML-DSA를 처음부터
ACVP KAT 모음을 상대로 신중하게 구현해야 하는(고전 알고리즘들에 non-constant-time
입장이 기정사실화된 방식처럼 "동작하는" 구현에 나중에 끼워 맞추는 것이 아니라)
이유이고, 일반적인 정확성 테스트와는 별개의 패스로 데이터 의존적 분기와 테이블
인덱스를 특정해 검토해야 하는 이유입니다.

## 의존성 입장

이 라이브러리의 다른 모든 알고리즘(RSA/DSA/ECDSA/EdDSA/X25519/AES/DES/ChaCha20,
모두 밑바닥부터, 제3자 암호 의존성 없음)과 일관되게: **ML-KEM/ML-DSA를 밑바닥부터
구현**하고, `CRng`/`SHAKE256`과 위에서 설명한 새 공유 Keccak/NTT 프리미티브를
재사용합니다. NIST 참조 구현과 잘 감사된 오픈소스 포팅(예: `pq-crystals` 참조
코드)은 알고리즘 *그리고* 그 문서화된 constant-time 패턴을 참고하기에 적절하고,
ACVP KAT 벡터는 적절한 정확성 오라클입니다 — 그러나 어떤 코드도 벤더링해서는 안
되며, 이는 `third-party/`의 현재 범위(doctest만, 테스트 전용)와 일치합니다.

## ML-KEM 우선 순서 재평가

이 검토는 원래 ML-KEM을 ML-DSA보다 앞에 두었습니다. 거기서 든 세 이유 중 둘은
이후 약해졌으므로, 그 순서는 물려받기보다 다시 진술할 만합니다.

- *"`libcertpp`에는 아직 KEM 모양의 인터페이스가 전혀 없고, 더 단순한 프리미티브를
  상대로 만드는 것이 위험이 낮다."* 대체로 소진되었습니다. `IKem`/`IKemContext`는
  그 뒤에 설계되고 선언되었습니다. 남은 것은 그것을 상대로 구현하는 일인데, 이는
  그 논거가 다루던 인터페이스 설계 위험이 더는 아닙니다.
- *"TLS 1.3 하이브리드 키 교환이 가장 널리 배포된 PQ 사용 사례다."* 업계에
  대해서는 참이지만 **이** 라이브러리에 대한 논거는 아닙니다. `libcertpp`는 TLS
  스택이 없는 X.509/ASN.1 라이브러리이므로, 내부에서 KEM을 소비하는 것이 없습니다.
  ML-KEM은 트리 내 호출자 없이 출하될 것이고, ML-DSA는 `CCert`/`CCertBuilder`를
  직접 풀어 줍니다.
- *"ML-KEM이 더 단순한 프리미티브다."* 여전히 참이고 여전히 실제 논거입니다 —
  ML-DSA는 같은 환 연산 위에 aborts 있는 거부 샘플링, hint 인코딩, 재시도 루프를
  더합니다. (이 항목은 원래 그 루프를 "constant-time"이라고 불렀습니다. 그럴 수
  없습니다. 5단계를 보십시오. FIPS 204가 실제로 요구하는 것과 함께 정정이
  기록되어 있습니다.)

ML-DSA가 고칠 구체적인, 트리 안의 것도 있었고 그것은 이후 고쳐졌습니다.
`identrust-mldsa-root.der`는 실재하고 현재 유효한 자기 서명 ML-DSA 파일럿
루트("IdenTrust Pilot Root TLS ML-DSA CA 1", 서명/키 OID는 NIST CSOR ML-DSA
arc의 `2.16.840.1.101.3.4.3.19`로 ML-DSA-87)이고,
`tests/x509/realcerts.cpp`는 `CCert`가 그것의 전부 — subject, issuer, 유효기간,
BasicConstraints, KeyUsage, ExtendedKeyUsage, SKI, AKI — 를 파싱하고 알고리즘은
아무것으로도 해석하지 못한다고 단정하곤 했습니다. 지금은
`certs/implemented/`에 있고, 테스트 케이스는 대신
`cert.verifyBy(cert) == ERET_OK`를 단정합니다.

**당시의 권고: 공유 기반을 위해 ML-KEM을 먼저 두되, 순서는 진짜로 열린 것으로
취급할 것.** 실제로 그렇게 되었고, 순서는 그다지 중요하지 않은 것으로 드러났습니다
— `q = 8380417`과 1의 512제곱근 때문에 ML-DSA의 환은 ML-KEM 것의 파라미터화가
아니라 별개의 단위가 되므로, ML-DSA는 Keccak 프리미티브만 ML-KEM과 공유합니다.
ML-KEM이 앞당겨 치른 것은 규율이었습니다. 모든 길이를 유도하고 `static_assert`한
파라미터 집합 구조체, `CMakeLists.txt`의 private 단위를 테스트에 직접 컴파일해
넣는 구성, 그리고 C++를 쓰기 전에 ACVP 집합 전체를 Python으로 재현하는 습관. 셋
모두 그대로 재사용되었습니다.

## 테스트 벡터, 미리 찾아 검증해 두기

4–6단계는 NIST의 ACVP 벡터에 의존하므로, 알고리즘 작업을 시작하기 전에 찾아
확인했습니다 — Knuth-D와 ECDSA 절단 작업을 안전하게 만든 것과 같은 순서입니다.
두 집합 모두 `usnistgov/ACVP-Server`의 `gen-val/json-files/<DIR>/<FILE>`에
있으며, 다음처럼 가져옵니다.

```
https://raw.githubusercontent.com/usnistgov/ACVP-Server/<rev>/gen-val/json-files/<DIR>/<FILE>
```

`master`를 추적하지 말고 `<rev>`를 고정하십시오.
`975de31eb83d87039ec88934fdc47d8c312b892d`가 2026-08-12 기준 `master` HEAD이고,
아래 수치들은 그것에 대해 측정되었습니다.

| 알고리즘 | `<DIR>` | 커버리지 |
|---|---|---|
| ML-KEM | `ML-KEM-keyGen-FIPS203` | 75 케이스 (파라미터 집합당 25) |
| ML-KEM | `ML-KEM-encapDecap-FIPS203` | 캡슐화 75, 디캡슐화 30, 그리고 키 유효성 그룹 |
| ML-DSA | `ML-DSA-keyGen-FIPS204` | 75 케이스 (파라미터 집합당 25) |
| ML-DSA | `ML-DSA-sigGen-FIPS204` | 24 그룹 x 15 = 360 케이스 |
| ML-DSA | `ML-DSA-sigVer-FIPS204` | 12 그룹 x 15 = 180 케이스, 그중 144개가 음성 |

`internalProjection.json`을 쓰십시오. 입력 *과* 기대 출력을 한 레코드에 담은
유일한 파일입니다(`prompt.json`에는 입력, `expectedResults.json`에는 출력이
있고 `tcId`로 결합합니다). 모든 바이트 필드는 대문자 16진수이고 `0x`는 없습니다.
파라미터 집합은 개별 테스트가 아니라 *그룹*에 있습니다.

파일이 단지 존재한다는 것 이상으로, 검증이 확인한 것:

- **선언된 모든 필드 길이가 표준 자체의 파라미터 표와 일치합니다** — FIPS 203 표 3과
  FIPS 204 표 2 — ML-KEM 180개와 ML-DSA 615개 레코드 전부에 걸쳐서이고, FIPS 204
  크기들은 추가로 표 1의 파라미터에서 인코딩 공식을 통해 재유도했습니다. 어디에도
  불일치가 없었습니다.
- **ML-KEM의 암묵적 거부 오라클은 이름만 바꾼 정상 경로가 아니라 실재합니다.**
  `reason: "modified ciphertext"`인 디캡슐화 케이스 45개 전부가
  `k == SHAKE256(z || c, 32)`(FIPS 203의 `J(z || c)`)를 만족하고, 유효한 케이스는
  하나도 만족하지 않습니다 — 깔끔한 분리이며, 오류가 아니라 키에서 유도된
  의사난수 비밀을 반환해야 하는 Fujisaki-Okamoto 경로를 테스트하는 데 꼭 필요한
  것입니다.
- **ML-DSA 벡터는 독립 구현에 대해 다시 돌렸습니다** (PyPI `dilithium-py`,
  오라클로만 사용 — 벤더링 없음): keyGen 75/75, sigGen 360/360이 바이트 단위로
  일치하고 sigVer 180/180의 판정이 일치했습니다. 즉 자기 일관적일 뿐 아니라 두
  번째 구현이 쓸 수 있음이 확인되었습니다.
- **ML-DSA의 음성 커버리지는 디코드 경로**이며, 변형된 메시지·변형된
  commitment·변형된 hint·변형된 `z`에 36개씩 고르게 나뉩니다 — 아래의 가변성
  (malleability) 함정들이 바로 그곳에 있습니다.
- **hedged ML-DSA 서명도 바이트 단위로 재현 가능합니다.** prompt가 `rnd`를
  제공하기 때문입니다. 이 계획의 이전 버전은 결정론적 변형만 벡터와 비교할 수
  있다고 가정했는데, 실제로는 24개 sigGen 그룹 전부를 비교할 수 있습니다.

## 구현 계획

각 단계는 녹색 `ctest` 실행으로 끝나고 독립적으로 커밋 가능합니다. 아래의 "KAT"은
해당 알고리즘에 대한 NIST ACVP 벡터를 뜻하며,
`tests/crypto/hashers/shake128.cpp`의 NIST 벡터가 이미 그랬던 것과 같은 방식으로
가져와 옮겨 적고 — "진짜로 어려운 것"에서 다시 말한 교훈에 따라 — 두 번째 독립
구현과 교차 확인합니다.

### 1단계 — KEM 인터페이스 마감 (소규모) — **완료**

- `src/crypto/kem.cpp`가 이제 `IKem::builtIn(EKems)`를 정의하며,
  `src/crypto/asym.cpp`의 `IAsymmetric::builtIn()` 디스패치를 반영합니다.
  4단계가 첫 파라미터 집합을 추가하기 전까지는 모든 입력에 `nullptr`를
  반환하는데, 이는 정직한 동작이며 그것이 대체한 "정의 없음"과 달리 링크
  시점에 실패하지 않고 링크됩니다.
- `crypto/kem.hpp`는 여전히 의도적으로 `include/certpp.hpp`에서 **빠져**
  있습니다. 유일한 팩토리가 아무것도 반환할 수 없는 헤더를 포함하는 것은 존재하지
  않는 API를 광고하는 일입니다. `EKems`에 첫 멤버가 생기는 같은 변경에서, 4단계와
  함께 들어갑니다. [`architecture.ko.md`](architecture.ko.md)가 이를 의도적인
  것으로 기록합니다.

### 2단계 — 증분 SHAKE 스퀴징 (소규모, 선행 조건) — **완료**

FIPS 203의 `SampleNTT`는 상한 없는 SHAKE128 스트림에서 거부 샘플링을 하고
FIPS 204도 챌린지/마스크 확장에서 같은 일을 하는데, `SHAKE128`/`SHAKE256`은
오프셋 0부터의 고정 길이 `finish()` 하나만 노출했습니다 — 스트리밍할 방법이
없었습니다.

이제 둘 다 `squeeze(const SByteSpan&)`를 가집니다. 첫 호출에서 `finish()`가 하는
것과 정확히 같이 흡수를 마무리한 뒤, 스펀지를 전진시키고 현재 rate 블록 안의
커서를 추적하면서 출력 스트림의 연속 chunk를 반환합니다. 출력 길이가
`byteWidth()`와 무관하다는 것이 요점 전체입니다. 두 진입점이 모두 필요한 padding
단계는 중복하지 않고 공유 `finalizeAbsorption()`으로 분리했습니다.

`finish()`는 *사본*에서 스퀴징을 계속하므로 반복 가능한 상태로 남고 커서를 건드리지
않습니다. 둘은 번갈아 쓰는 것이 아니라 대안으로 문서화되어 있습니다. 테스트할
만한 성질은 chunk 무관성이고, `tests/crypto/hashers/shake_squeeze.cpp`가 1바이트
부터 시작하는 모든 chunk 크기에 대해, 각 rate 경계(SHAKE128은 168, SHAKE256은
136)에 정확히 걸치는·바로 앞인·바로 뒤인 분할을 포함해 그것을 단정합니다 — 그
경계가 스펀지가 permute하는 지점이므로, 커서 off-by-one은 다른 어디에서도
드러나지 않습니다. 기대 스트림은 Python `hashlib`에서 나오며, rate 블록 세 개
더하기 7바이트 길이입니다.

### 3단계 — 공유 환 연산 (실제 작업) — **ML-KEM에 대해 완료**

아직 공개 헤더가 없는 private 단위들의 집합입니다 — 어떤 알고리즘이 노출해야 할
때까지 여기 있는 것은 API에 들어가지 않으며, 컨벤션에 따라 `src/` 아래의 구현
클래스는 타입 접두사를 받지 않습니다.

- `R_q = Z_q[X]/(X^256+1)` 위의 `MlKemRing`/`MlDsaRing` 또는 하나의 파라미터화된
  `PolyRing`: 계수 덧셈/뺄셈, Montgomery와 Barrett 축약, 정방향/역방향 NTT,
  pointwise 곱셈. ML-KEM은 `q = 3329`, ML-DSA는 `q = 8380417`을 씁니다. 템플릿
  하나냐 구체 타입 둘이냐는 둘 다 작성된 뒤에 결정하고 그 전에는 하지 않습니다 —
  이 프로젝트의 기본 선호는 투기적 추상보다 명확한 두 사본입니다.
- zeta/트위들 테이블은 손으로 옮겨 적지 않고 실행 시점에 1의 거듭제곱근에서
  유도하며, 항목 단위로 단정합니다.

  이 계획의 이전 버전에 대한 정정: **FIPS 203에는 작업 예제도 중간값도 전혀
  없습니다.** 부록은 A(미리 계산된 NTT zeta 테이블), B(SampleNTT 루프 경계),
  C(CRYSTALS-KYBER와의 차이)뿐이고, NIST는 ML-KEM용 예제 값 페이지도 발행하지
  않습니다. FIPS 204도 같습니다 — 종단 간 중간값은 없지만, 부록 B가 전체
  `zetas[0..255]` 표를 줍니다. 따라서 가능한 오라클은 이렇습니다. 테이블을 1의
  거듭제곱근의 정의적 거듭제곱에 대해 단정하고, 정방향과 역방향 변환이 왕복하는지
  확인하고, NTT 영역 곱셈을 schoolbook negacyclic 곱셈에 대해 확인하고, 그 다음
  종단 간 ACVP 벡터에 의존하는 것. 그 벡터들은 NTT 관례를 간접적으로 고정하므로
  — 트위들 순서가 전치되면 `ek`와 `c`가 바이트 단위로 달라집니다 — 버그는 여전히
  잡힙니다. 다만 버터플라이 하나로 국소화되지는 않을 것입니다.
- 2단계 XOF 스트림 위의 중심 이항 샘플링과 거부 샘플러. 둘 다 이제
  `MlKemSampler`(`src/crypto/kems/mlkemsampler.cpp`)로 존재합니다. `sampleNtt()`가
  `SHAKE128::squeeze()`의 첫 실제 소비자이고, 2단계를 구체적으로 정당화합니다.
  시드에 따라 453–498바이트의 스트림을 소비하는데, rate 블록 세 개쯤이고 길이를
  미리 알 수 없습니다.
- `ByteEncode`/`ByteDecode` 비트 패킹(FIPS 203 알고리즘 5/6)과
  `Compress`/`Decompress`(알고리즘 3/4). 이제
  `MlKemCodec`(`src/crypto/kems/mlkemcodec.hpp`)입니다. 압축 라운딩은 ML-KEM이
  쓰는 모든 폭에서 [0, q) 안의 *모든* 계수에 대해 정확한 유리수 정의와 대조했고,
  이것이 추측하지 않는 편이 나은 세부 하나를 정리했습니다. q는 홀수이므로 흔히
  쓰는 `(x*2^d + q/2)/q`는 `q/2`를 절단하고 half-up 반올림 규칙을 운에 맡깁니다.
  그 형태와 증명 가능하게 올바른 `(2*x*2^d + q)/(2*q)`는 모든 곳에서 실제로
  일치하지만 — 그중 하나만이 구성적으로 옳고, 구현된 것은 그쪽입니다.
  `isCanonical12()`는 `ByteDecode_12`의 의도적 비단사성을 자체 조회로 노출합니다.
  ML-KEM의 캡슐화 키 유효성 검사가 정확히 "이것이 q 이상인 12비트 세그먼트 없이
  디코드되는가"이기 때문입니다.

무엇을 그 위에 올리기 전의 검증 관문: 정방향-역방향 NTT 왕복, NTT 영역 곱셈을
schoolbook negacyclic 참조에 대조, 환의 정의적 항등식(`X^256 == -1`) 직접 단정,
그리고 모든 트위들을 구현이 만드는 방식과 독립적으로 1의 거듭제곱근에서 재유도.
**ML-KEM의 환에 대해 완료** — `tests/crypto/kems/mlkemring.cpp`를 보십시오. 그리고
격자 연산에는 공개 API가 없어 export되지 않으므로, `CMakeLists.txt`가 그 private
단위들을 해당 테스트에 바로 컴파일해 넣는다는 점에 유의하십시오.

### 4단계 — ML-KEM (`IKem`의 첫 구현) — **완료**

- `include/certpp/crypto/kems/mlkem.hpp` + `src/crypto/kems/mlkem.cpp`가
  `CMlKem`을 담습니다. K-PKE(알고리즘 13–15)와 그 위의 FO 변환(알고리즘 16–18)이고,
  **암묵적 거부**가 있습니다 — 잘못된 ciphertext는 키에서 유도된 의사난수 비밀인
  `J(z || c)`를 내고, `decapsulate()`에는 나쁜 ciphertext에 대한 실패 모드가 아예
  없습니다. 더해서 `SMlKemParams`(세 파라미터 집합, 모든 크기를 표에 실린 다섯
  수치에서 유도)와 `CMlKemSampler`/`SMlKemPoly`가 있는데, 원시 span 형태가 그 자체로
  유용하므로 — 상호운용성 테스트를 위해, 이미 자기 버퍼를 소유한 호출자를 위해,
  그리고 KEM이 아니라 K-PKE를 원하는 사람을 위해 — `src/`에서 끌어올렸습니다.
- 관문 달성: `tests/crypto/kems/kat_mlkem.cpp`가 세 파라미터 집합 전부에 대해
  ACVP keyGen/캡슐화/디캡슐화 벡터를 구동하며, `modified ciphertext` 레코드
  (암묵적 거부는 오류 경로가 아니라 정의된 출력이므로 ACVP가 기대 공유 비밀을
  발행합니다)와 `encapsulationKeyCheck`/`decapsulationKeyCheck` 음성 레코드를
  포함합니다. 별도의 왕복 케이스가 ciphertext 한 비트를 뒤집고, 디캡슐화가 여전히
  성공하며 *다른* 비밀을 반환하고, 두 번 물어도 *같은* 그 다른 비밀을 반환한다고
  단정합니다.
- `SMlKemParams::isValid()`는 모든 `CMlKem` 진입점이 가장 먼저 호출합니다.
  파라미터 구조체를 공개하면 호출자가 표준이 정의한 적 없는 집합을 건넬 수 있다는
  뜻이고, 구현은 `MAX_K`/`maxCiphertextBytes()`에서 고정 용량 버퍼 크기를 잡으므로
  — FIPS 203의 세 집합이 아닌 어떤 것도 그것으로부터 크기 하나를 유도하기 전에
  거부되어야 합니다. 테스트 케이스가 여덟 진입점 전부가 그런 집합을 거부하는지
  확인하며, 길이 검사가 거부 이유가 될 수 없도록 모든 span을 *그 엉터리 집합에
  맞게* 정확히 잡습니다.
- `include/certpp/crypto/kems/mlkem.hpp` + `src/crypto/kems/mlkem.cpp`가 `MLKEM`을
  담으며, `crypto/asyms/`가 `IAsymmetric` 하나당 파일 하나를 두는 방식을
  반영합니다. `EKems`가
  `EKEM_MLKEM512`/`EKEM_MLKEM768`/`EKEM_MLKEM1024`를 얻었고, `CEcdsa`가 곡선들에
  걸쳐 하듯 파라미터 집합을 생성자 상태로 삼아 셋 모두 한 클래스로 디스패치됩니다.
  private `MlKemPublicKey`/`MlKemPrivateKey`/`MlKemContext`가 `CMlKem` 위에 앉아
  아무것도 다시 구현하지 않습니다. `crypto/kem.hpp`와 `crypto/kems/mlkem.hpp`는
  둘 다 `certpp.hpp`에 있습니다.
- `keySizes()`는 모듈러스 폭이나 보안 강도가 아니라 파라미터 집합 자체의
  수(512/768/1024)를 받습니다. ML-KEM에는 스케일하는 크기가 없고 그 세 수치는
  이름이기 때문입니다. 키는 FIPS 203 자체의 바이트 인코딩으로 직렬화됩니다.
  디캡슐화 키는 자기 캡슐화 키를 품고 있으므로 `publicKey()`는 다시 계산하지 않고
  그것을 읽어 내고, `checkPrivateKey()`/`createPrivateKey()`는 둘 중 어느 것도
  믿지 않고 품고 있는 `H(ek)`와 `ek`의 정규성을 검증합니다. 인증서용
  SubjectPublicKeyInfo 래핑은 여기가 아니라 6단계입니다.
- CSPRNG가 들어오는 곳도 여기이고, 들어오는 유일한 곳입니다.
  `CMlKem::generateKeyPair()`/`encapsulate()`는 시드와 메시지를 파라미터로 받는데,
  이것이 그 둘을 벡터에서 재현 가능하게 만듭니다. `IKemContext::encapsulate()`에는
  그런 파라미터가 없으므로 `MLKEM`이 `CRng`에서 채웁니다. 그 말은 이 계층에서는
  기지 응답 테스트를 쓸 수 없다는 뜻이기도 합니다. `tests/crypto/kems/mlkem.cpp`는
  래퍼가 추가하는 것을 다루며, 한 키에 대한 반복 `encapsulate()` 호출이 서로
  다르다는 것(키만의 함수인 공유 비밀이라면 세션마다 재사용될 것입니다)과,
  조작된 ciphertext가 오류 코드가 아니라 다른 비밀과 함께 `ERET_OK`로 돌아온다는
  것을 포함합니다.

여기서 틀리기 쉽고 늦게 발견하면 비용이 큰 세부 셋:

- **`G(d)`가 아니라 `G(d || k)`** (알고리즘 13 1단계): {2,3,4} 중 하나인 파라미터
  집합 바이트 `k`가 33번째 바이트로 덧붙습니다. 이것은 FIPS 203 최초 공개 초안
  *이후에* 추가되었으므로, 라운드 3 Kyber 코드나 최종 전 구현은 이를 빼먹습니다 —
  어느 쪽에서 복사해도 완벽히 자기 일관적인 상태로 세 파라미터 집합 전부가 조용히
  깨집니다.
- **`SampleNTT(rho || j || i)`** (알고리즘 13 5단계 / 알고리즘 14 6단계): 인덱스
  바이트가 루프 순서에 대해 **전치**되어 있고, 명세 자신의 여백 주석이 이를 명시적으로
  말합니다. 암호화는 행렬의 전치를 쓰지만 샘플링은 같은 바이트 순서로 합니다.
- **`ByteDecode_12`는 mod q로 축약하므로 단사가 아닙니다**: 3329..4095의 12비트
  세그먼트가 존재하지만 `ByteEncode_12`에서 나올 수는 없습니다. 그 비대칭성
  *자체가* `encapsulationKeyCheck` 테스트입니다 — ACVP의 실패 케이스는
  `reason: "noisy linear system values too large"`를 담고 있습니다.
  `decapsulationKeyCheck` 실패는 대신 품고 있는 `SHA3-256(ek)` 필드인
  `reason: "modified H"`를 씁니다.

둘 다 실제로 유효했습니다. `eta`는 `PRF_eta`에서 출력 길이일 뿐 도메인 분리가
**아니므로**, 동일 입력에 대한 `PRF_2`와 `PRF_3`는 접두사를 공유합니다 — 구현은
`eta`를 길이로만 넘기고 그 외에는 아무것도 하지 않습니다.

`Decaps_internal`이 반환하기 전에 암묵적 거부 플래그와 그 주변 값들이 파괴되어야
한다는 FIPS 203의 요구는 이를 위해 추가된 `CSecure::zero()`(`utils/secure.hpp`)로
충족됩니다. `decapsulate()`는 탈출 지점이 하나이므로 오류 경로가 소거를 건너뛸 수
없습니다. 같은 패스가 빠진 영 소거보다 더 나쁜 것을 찾아 고쳤습니다. 재암호화
검사가 `std::memcmp`였는데, 이는 첫 불일치에서 멈추므로 실행 시간을 통해 일치하는
접두사의 길이를 누출했고, 그 판정이 다시 삼항 연산자를 구동했습니다. 둘 다 이제
`CSecure::equalsMask` + `CSecure::select`이므로, 비교도 선택도 비밀인 무엇에
대해서도 분기하지 않습니다.

같은 프리미티브는 그 뒤 양자 이전 알고리즘들에도 적용되었습니다 — ECDSA/DSA 서명
nonce, EdDSA의 nonce와 확장된 시드, X25519의 스칼라와 공유 비밀, RSA의 CRT
중간값 — `CSecure::zero()`와 `CBigNum::secureClear()`를 통해서입니다.

### 5단계 — ML-DSA (새 `IAsymmetric`) — **완료**

아래 계획이 예측한 것과 실제로 달랐던 것을, 중요했던 순서대로:

- **내부/외부 인터페이스 구분이 이 계획이 아예 언급하지 않은 것**이고, 실제
  인증서가 검증되는지를 결정하는 바로 그것입니다. FIPS 204에는 두 가지 메시지
  관례가 있습니다. 내부 인터페이스(알고리즘 7–8)는 `M'`을 그대로 서명하고, 외부
  것(알고리즘 2–3)은 먼저
  `IntegerToBytes(0, 1) || IntegerToBytes(|ctx|, 1) || ctx`를 앞에 붙입니다.
  RFC 9881의 `id-ml-dsa-*` OID는 빈 context를 가진 **외부** 인터페이스를 뜻하므로,
  X.509 서명은 `0x00 || 0x00 || tbsCertificate`를 덮습니다. 두 형태 모두
  `MlDsaScheme`에 있고, `CMlDsa`는 외부 것만 노출합니다. 모든 X.509, CMS, TLS
  호출자가 원하는 것이 그것이기 때문입니다. 대신 내부 형태를 쓴 구현은 자기가
  가진 모든 왕복 테스트를 통과하고, ACVP sigGen 그룹의 절반(`signatureInterface:
  "internal"`인 열두 개)과 일치하며, 모든 진짜 인증서를 거부합니다. 이제 그 마지막
  성질을 암시로 두지 않고 양방향으로 직접 단정합니다.
- **서명 루프는 constant-time이 아니고 그렇게 만들 수도 없습니다.** "반복 횟수가
  키 재료에 의존하는 조기 탈출 없음"을 요구하는 아래 항목은 aborts 있는
  Fiat-Shamir에서는 달성할 수 없습니다. 루프는 `z`, `r0`, `c*t0`, hint 가중치에
  대한 네 경계가 모두 성립할 때까지 재시도하고, 성립 여부는 비밀 벡터와 메시지에
  의존합니다. FIPS 204도 그것을 요구하지 않습니다 — 부록 C가 실제로 요구하는 것은
  루프에 상한이 *없어야* 한다는 것(또는 표 3보다 더 촘촘하지 않게 제한할 것)과,
  어떤 상한이 있고 그것을 초과하면 그런 모든 실행에 대해 동일한 결과를 내야
  한다는 것입니다. 여기의 루프는 상한이 없으므로 그 질문 자체가 사라집니다.
- **hint 인코딩 함정은 정확히 예측한 곳에 있었고**, `MlDsaCodec`을 쓸 때 이미
  처리되어 있었습니다. ACVP의 "modified signature - hint" 36개 케이스가 통과하고,
  그중 12개가 `tests/crypto/asyms/kat_mldsaver.cpp`에 고정되어 있습니다.
- **길이만으로 거부**(3.6.2)가 모든 진입점에 있고, 연속된 OID 혼동을 안전하게
  만드는 것도 그것입니다. 세 파라미터 집합은 키 *와* 서명 길이가 다르므로,
  ML-DSA-65 바이트를 ML-DSA-87에 주면 어떤 연산 전에 거부됩니다.
- **어디에도 부동소수점 없음**, 요구대로입니다. 영 소거(3.6.3)는 시드와 서명이
  보유하는 비밀 벡터들 — rho, K, tr, mu, rho'', s1/s2/t0와 그 NTT 형태, 그리고
  마스킹 벡터 — 를 RAII 스크러버로 덮으므로, 거부 루프의 `continue` 경로가 그것을
  건너뛸 수 없습니다. 표준이 또한 언급하는 검증 중간값까지는 **확장되지
  않습니다**. 검증이 다루는 모든 것은 공개(공개키, 서명, 그리고 그것들에서 유도된
  값)이므로 보호할 것이 없습니다.
- `skDecode`의 s1/s2 범위 검사(알고리즘 25의 9–10행)는 별도 검증 호출에서만이
  아니라 개인키를 디코드하는 모든 진입점에서 강제됩니다 — `2*eta + 1`은 5 또는
  9이고 둘 다 2의 거듭제곱이 아니므로, 그 필드는 범위가 포함하지 않는 값을 진짜로
  인코딩할 수 있습니다.
- 관문은 전부 충족되었습니다. ACVP keyGen 75/75, sigGen은 24개 그룹 전부에서
  360/360 바이트 단위 일치(결정론적·hedged, 내부·외부, pure·pre-hashed),
  sigVer 180/180 판정. 그 완전한 실행들은 C++를 쓰기 전에 명세 본문에서 작성한
  독립 Python 참조를 거쳤고, 같은 벡터의 대표 부분집합이
  `tests/crypto/asyms/kat_mldsa.cpp`와 `kat_mldsaver.cpp`에 고정되어 있습니다.
- 의도적 누락 하나: **pure 변형만 구현되어 있습니다.** HashML-DSA는 Python
  참조에서 검증했지만(ACVP의 `preHash` 그룹 열두 개 전부 일치) C++에는 없습니다.
  RFC 9881 8.3이 그 OID는 X.509 인증서에 나타나서는 안 된다(MUST NOT)고 하고,
  트리의 다른 무엇도 그것을 필요로 하지 않기 때문입니다.

기록을 위한 원래 계획:

- `include/certpp/crypto/asyms/mldsa.hpp` + `src/crypto/asyms/mldsa.cpp`.
  `EAsymmetrics`가 `EASYM_MLDSA44`, `EASYM_MLDSA65`, `EASYM_MLDSA87`을 얻고
  `IAsymmetric::builtIn()`에서 디스패치됩니다. 인터페이스 변경 없음 —
  `sign()`/`verify()`에 그대로 맞습니다.
- 명시적으로 정리할 모양 불일치 하나: ML-DSA는 digest가 아니라 *메시지*를
  서명합니다(내부적으로 자기 해싱을 합니다). 따라서 `Ed25519`/`Ed448`처럼
  그 둘이 이미 정착시킨 `sizeOfDigest() == 0`, "digest 파라미터가 원시 메시지"
  관례에 속하며 — `CCert`의 `EHASH_UNKNOWN`은-자기-해싱을-뜻한다 경로들이 EdDSA로
  추론하지 말고 이것을 배워야 합니다.
- 서명 재시도 루프는 비밀에 대해 constant-time이어야 합니다. 반복 횟수가 키
  재료에 의존하는 조기 탈출 없음. **FIPS 204 부록 C가 권위입니다**: 네 개의
  비결정적 루프(`Sign_internal`, `RejBoundedPoly`, `RejNTTPoly`, `SampleInBall`)에
  상한을 두지 *않아야 한다*(should not)고 하고, 둔다면 그 한계는 최소한 표 3의
  것(각각 814 / 481 / 298 / 121 반복)이어야 한다고 합니다. 최댓값이 초과되면
  모든 중간 결과가 파괴되어야(shall) 하고 반환값이나 예외가 그런 모든 실행에서
  동일해야(shall) 합니다 — 거기서 관측 가능한 차이가 바로 누출입니다. 세 `Rej*`
  샘플러 모두 증분 XOF(§3.7)를 읽으므로, 2단계가 편의가 아니라 엄격한 선행
  조건이었던 이유입니다.
- **hint 인코딩(알고리즘 20/21)이 가장 날카로운 디코드 함정입니다.**
  `HintBitUnpack`은 세 가지 서로 다른 조건에서 실패를 반환해야 합니다. 범위를
  벗어난 누적 인덱스, 한 다항식 안에서 엄격히 증가하지 않는 위치, 그리고 0이 아닌
  남은 바이트. 셋보다 적게 구현하면 가변적인 서명이 수락되며 — 그것이 바로 ACVP의
  "modified signature - hint" 36개 케이스가 겨냥하는 것입니다.
- **검증은 길이만으로 거부해야(shall) 합니다**(§3.6.2): 크기가 표준의 것과 다른
  서명이나 공개키는 어떤 연산이 돌기 전에 무효입니다. 값싸고, 필수이며, 빼먹기
  쉽습니다.
- **어디에도 부동소수점 연산 없음**(§3.6.4), 그리고 민감한 중간값은 더 필요하지
  않게 되는 즉시 파괴되어야 합니다(§3.6.3) — 명세는 이를 서명만이 아니라 *검증*
  중간값에도 확장합니다. 두 가지 예외는 시드(키 재생성을 위해 보관할 수 있음)와
  확장된 행렬(공개이므로 보호가 필요 없음)입니다.
- ML-DSA의 환은 *다른* 환입니다. q = 8380417이고 zeta = 1753으로 1의 512제곱근이므로
  `zetas[0..255] = zeta^BitRev8(k)`입니다. **FIPS 204 부록 B가 그 표 전체를
  인쇄하므로** 직접 단정할 수 있습니다 — 그리고 부록 A는 그 배열이 보통 Montgomery
  형태로 저장된다고 경고하므로, 거기서의 표현 불일치가 또 그 자기
  일관적이지만-틀린 실패 양상입니다.
- 관문: 세 파라미터 집합 전부에 대한 ACVP keygen/sigGen/sigVer 벡터. prompt가
  `rnd`를 제공하므로 결정론적 그룹과 hedged 그룹 모두 바이트 단위로 비교 가능합니다
  — 따라서 결정론적 열두 개만이 아니라 24개 sigGen 그룹 전부가 셉니다.

### 6단계 — X.509 통합 (여기서 쓸모 있게 만드는 것) — **ML-DSA에 대해 완료**

아래의 모든 예측이 유효했고, 픽스처에 대해서만 확인할 수 있었던 둘도
포함합니다. `parameters`는 그 세 AlgorithmIdentifier 전부에서 부재하고, BIT
STRING들은 내부 래퍼 없이 원시 FIPS 204 공개키와 서명을 담습니다(정확히 2592와
4627바이트인데, 이는 레지스트리와 독립적으로 파라미터 집합이 ML-DSA-87임을
식별해 주는 것이기도 합니다). 따라서 `CCert`는 DSA의 분리된 `Dss-Parms`와 달리
ML-DSA에 대해 재구성 단계가 필요 없습니다.

알고리즘 표 외에 필요했던 것이 둘 있습니다.

- `CCert::signsMessageDirectly(which)`가 네 개의 검증 경로
  (`CCert::verifyBy()`, `CCrlReader::verifyBy()`, 그리고 두 OCSP
  `verifySignature()`)에 복사되어 있던
  `keyAlgo == EASYM_ED25519 || keyAlgo == EASYM_ED448` 술어를 대체했습니다.
  다섯째와 여섯째 알고리즘이 생기면서 네 사본을 맞춰 두는 일은 "하느냐"가 아니라
  "언제냐"의 문제가 되었고, 하나를 놓친 지점은 원시 TBS 바이트를 hash-then-sign
  검증에 건네거나 digest를 ML-DSA에 건네게 되며 — 어느 쪽이든 조용히 실패합니다.
  *서명* 쪽의 `sigIsEddsa` 지역 변수들은 같은 이유로 `sigIsSelfHashing`으로
  이름을 바꿨습니다. 거기서는 `sigHash == EHASH_UNKNOWN` 검사가 모호하지 않은데,
  `resolveSigAlgoForSigning()`이 모르는 알고리즘에 대해 EHASH_UNKNOWN이 아니라
  false를 반환하기 때문입니다.
- `resolveSigAlgoForSigning()`이 EdDSA 분기들이 하듯 요청된 `digestAlgo`를
  완전히 무시하는 ML-DSA 분기를 얻었습니다. 그것으로 `CCertBuilder`는 빌더 변경
  없이 ML-DSA 인증서를 발급하며, `tests/x509/cert.cpp`가 세 파라미터 집합 전부에
  대해 이를 수행합니다(빌드, 재임포트, 검증).

수락 테스트는 통과했습니다. `tests/x509/realcerts.cpp`의 IdenTrust ML-DSA 루트가
`certs/implemented/`에 있고, 그 `keyAlgo()`/`signAlgo()`가 `ML-DSA-87`로
해석되며, `cert.verifyBy(cert)`가 `ERET_OK`를 반환합니다. 동반 케이스가 TBS에서,
서명에서, 공개키에서 각각 한 비트를 뒤집고 각각 실패해야 한다고 요구하므로 그
성공은 공허하지 않습니다.

기록을 위한 원래 계획:

- `src/x509/cert.cpp`의 `SIG_ALGOS`와 키 알고리즘 표에 OID를 등록합니다. 이것들은
  이제 추론할 필요 없이 발행된 RFC로 고정되어 있습니다.
  **RFC 9881**이 `sigAlgs`(2.16.840.1.101.3.4.3) 아래에 ML-DSA를 `.17` =
  ML-DSA-44, `.18` = ML-DSA-65, `.19` = ML-DSA-87로 배정하고, **RFC 9935**가
  `kems`(2.16.840.1.101.3.4.4) 아래에 ML-KEM을 `.1`/`.2`/`.3` = 512/768/1024로
  배정합니다.
- 따라서 OID가 `2.16.840.1.101.3.4.3.19`인 트리 내 IdenTrust 픽스처는
  **ML-DSA-87**입니다 — 그것을 `certs/implemented/`로 옮기려면 "어떤 ML-DSA"가
  아니라 그 파라미터 집합이 구체적으로 필요합니다.
- `AlgorithmIdentifier.parameters`는 둘 다에 대해 NULL이 아니라 **부재해야
  합니다**(MUST, RFC 9881 §2, RFC 9935). `cert.cpp`가 이미 구현하고 있는
  RSA/DSA 관례가 아니라 ECDSA/EdDSA 관례와 일치합니다. 픽스처가 이를 확인합니다.
  그 세 알고리즘 식별자 각각이 OID만 담은 11바이트 SEQUENCE입니다.
- `subjectPublicKey`는 OCTET STRING 래퍼 없이 **원시** FIPS 204 공개키 바이트를
  담고, `signatureValue`는 원시 서명을 담습니다.
- HashML-DSA OID(`sigAlgs .32`–`.34`)는 등록하지 **마십시오**. RFC 9881 §8.3이
  그것들은 X.509 인증서에 나타나서는 안 된다(MUST NOT)고 합니다.
- 수락 테스트: `tests/x509/realcerts.cpp`의 IdenTrust ML-DSA 루트가
  `certs/unimplemented/`에서 `certs/implemented/`로 옮겨 가고, 그 알고리즘이
  해석되며 — [`architecture.ko.md`](architecture.ko.md)의 "이것이 자라날 곳"에서
  없다고 적어 둔 서명 검증 API가 생기면 — 자기 서명이 실제로 검증됩니다. 그 픽스처
  하나가 옮겨 가는 것이 이 작업의 완료 정의로서 가장 분명한 것입니다.
- `CCertBuilder`가 ML-DSA로 서명한 인증서를 발급할 능력을 얻는데, 이는 알고리즘
  표를 넘어서는 빌더 변경 없이 `IAsymmetric` 구현에서 따라옵니다.

### 7단계 — 나머지 재평가

3–6단계가 견고해지고 이 검토의 "진짜로 어려운" 위험들이 여기서 실적을 갖게 되면
SLH-DSA, FN-DSA, HQC를 다시 보십시오. 2026-10-02 재확인 기준으로 FN-DSA에는 공개
초안이 없고 HQC는 초안 전이므로, 둘 다 구현 대상으로 삼을 것이 없습니다.

하이브리드/복합 인증서는 상황이 다릅니다. `draft-ietf-lamps-pq-composite-sigs`는
IESG 승인을 받고 RFC 편집자 큐에 있으므로 **인코딩은 사실상 동결**되었고, 열린
질문은 명세가 아니라 수요입니다. 범위 산정에 참고할 것: CA/Browser 포럼은
S/MIME에 대해 PQ를 허용하지만(ballot SMC013, 2025-08-22 발효) **공개 TLS에
대해서는 아직** 허용하지 않으므로, PQ TLS 루트는 파일럿으로 남아 있습니다 — 이
저장소의 IdenTrust 픽스처가 정확히 그 상태입니다.

모든 단계는 `tests/crypto/`(또는 `tests/x509/`) 아래에 자체 doctest 모음을 갖고,
다른 모든 알고리즘의 KAT 기반 테스트를 반영합니다. 4단계와 5단계는 추가로 기능
테스트 패스와 별개로 데이터 의존적 분기와 비밀로 인덱싱되는 테이블 조회에 대한
전용 검토 패스를 갖습니다 — 그 검토는 단계의 후속이 아니라 단계의 일부입니다.
