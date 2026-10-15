# 기반 구축과 초기 강화

[English](01-foundations.md)

## `crypto/syms`: AES, DES, 3DES, ChaCha20

← [변경 이력](../HISTORY.ko.md)

기존 `IHasher`/`IAsymmetric` 인터페이스와 나란한, 대칭 암호 모듈을 밑바닥부터
추가했습니다.

- `ISymmetric`/`ISymmetricContext`/`ISymmetricKey`/`ISymmetricTransformer`
  (`include/certpp/crypto/sym.hpp`, `include/certpp/crypto/transform.hpp`):
  공유 인터페이스 표면과, 생성 진입점인 `ISymmetric::builtIn(ESymmetrics)`.
- `AES`(FIPS-197. non-equivalent-inverse cipher, 자체 S-box/InvS-box/Rcon
  테이블), `DES`/`TripleDES`(FIPS 46-3. 완전한 Feistel 네트워크, 둘이 공유하는
  `DesCore`, 2키 또는 3키 스케줄의 Encrypt-Decrypt-Encrypt로서의 3DES),
  그리고 `ChaCha20`(RFC 8439. 256비트 키, 96비트 nonce, 32비트 카운터)을
  `include/certpp/crypto/syms/` + `src/crypto/syms/` 아래에 추가했습니다.
- AES/DES/3DES는 블록 함수와 블록 크기로 파라미터화된, PKCS#7
  padding(RFC 5652 6.3)을 갖춘 CBC 모드를 구현하는 단일
  `CbcTransformer`(`src/crypto/syms/cbctransformer.hpp/.cpp`)를 공유합니다.
- 모든 알고리즘이 자기 발행 기지 응답 벡터에 대해 검증됩니다.
  NIST SP 800-38A(AES), 고전적인 FIPS-46 벡터(DES), DES 합성 교차
  확인(3DES), RFC 8439 부록 A.1(ChaCha20), 그리고 CBC 왕복/조작/오류 경로
  테스트입니다. `tests/crypto/syms/{aes,des,des3,chacha20}.cpp`를 보십시오.
- 이 작업 중에 잡힌 버그: `CbcTransformer`의 복호 경로가 원래 내놓을 전체
  블록 수를 `final ? fullBlocks : fullBlocks - 1`로 계산했는데, 이는 마지막
  ciphertext 블록을 padding 제거를 위해 붙들어 두는 대신 평범한 평문처럼
  내놓았습니다. 마지막으로 완성된 블록을 무조건 붙들어 두도록
  고쳤고(`src/crypto/syms/cbctransformer.cpp`), CBC 왕복 테스트가
  `transformFinal`에서 실패하면서 잡혔습니다.
- 이후 constant-time padding 검증을 위해 하드닝되었습니다 — 아래 "보안 감사"를
  보십시오.

## 보안 감사 (CVE 기반)

← [변경 이력](../HISTORY.ko.md)

이름이 붙은 CVE 11개(POODLE, Logjam, CurveBall, Heartbleed, libksba CVE 둘,
Psychic Signatures, SECT 곡선 부분군 검증 CVE, ECDSA nonce 편향 CVE, OpenSSL
RNG CVE, 그리고 GnuTLS 길이 처리 CVE)에 대해 전체 보안 감사를 수행하며, CVE
이름만으로 추측하는 대신 각각을 직접 해당, 간접 해당, 해당 없음, 또는
미확인으로 분류했습니다. 실제 취약점 셋을 찾아 고쳤습니다. 그 결과 설계 메모는
`docs/CONCEPTS.ko.md`의 `CEcCurve`/`CEc2Curve`/`Ed25519`/`Ed448` 절을
보십시오. 앞으로 이 프로젝트에서 그냥 "보안 테스트"라고 요청하면 기본적으로
같은 작업 흐름을 뜻합니다(CVE 조사 → 해당 여부 분류 → 적대적 테스트 → 근본
원인 수정 → 보고).

#### EC/EC2 점 디코딩 공백 (SECT 곡선 부류, CWE-345)

`CEcCurve::decodePoint()`(소수/short-Weierstrass 곡선)과
`CEc2Curve::decodePoint()`(이진/Lopez-Dahab 곡선) 둘 다 무한점 인코딩을
유효한 "공개키"로 받아들였고, 어느 쪽도 부분군 위수 검사를 하지 않았습니다.
특히 `CEc2Curve`에 대해서는 직접 악용 가능합니다. 그 이진 곡선들은 cofactor가
2 또는 4이므로, 주 부분군 밖에 곡선 위에 진짜로 존재하는 작은 부분군 점이
있습니다 — `tests/crypto/ec2curve.cpp`에서 `(0, sqrt(b))`를 구성해 구체적으로
증명했습니다(`x=0`이 곡선 방정식을 `y^2=b`로 무너뜨리므로 항상 곡선 위에
있고, 표수 2에서 부정이 `-P=(x,x+y)`이므로 `x=0`인 점은 자기 자신의 부정이고
따라서 위수가 항상 정확히 2입니다). 그것이 `isOnCurve()`를 통과하면서 부분군
검사에 실패함을 보였습니다. `CEcCurve`의 소수 곡선들은 모두 cofactor 1이므로
거기서의 부분군 검사는 수학적으로 중복이지만, 다층 방어와 일관성을 위해
그래도 추가했습니다. `src/crypto/eccurve.cpp`와 `src/crypto/ec2curve.cpp`에서
고쳤습니다. `decodePoint()`는 이제 무한점을 거부하고, 체 범위
검사(`x,y < p`. `CEcCurve`만 — 이진체 원소에는 그에 해당하는 범위 문제가
없습니다)를 추가하고, 부분군 위수 스칼라 곱이 무한점이 아닌 어떤 점도
거부합니다.

#### Ed25519/Ed448 보편적 서명 위조 (Psychic-Signatures 부류)

가장 심각한 발견입니다. `Ed25519`/`Ed448`이 공유하는 `decodePoint()` 보조
함수 — `createPublicKey()`를 통해 신뢰할 수 없는 공개키를 들여올 때와
`verify()`에서 서명 자신의 `R` 성분을 디코드할 때 둘 다에 쓰입니다 — 가
항등점이나 다른 낮은 위수 점을 거부하지 못했습니다. 이것이 보편적 위조를
허용했습니다. 공개키를 항등점으로 인코드해 등록하고, 그 다음 *어떤* 메시지에
대해서든 서명 `(R=항등점, S=0)`을 제출하는 것입니다. 검증 식
`S*B == R + k*A`가 메시지별 해시 `k`와 무관하게 `O == O + k*O == O`로
무너지기 때문입니다. `src/crypto/asyms/ed25519.cpp`/`ed448.cpp`에서 두 검사로
고쳤습니다(`checkPrivateKey()`에 이미 있고 올바른 로직을 반영한 것입니다).
항등점을 곧바로 거부하고(그 위수가 1이고 그것은 군 위수를 자명하게 "나누므로"
부분군 검사만으로는 잡을 수 없습니다), 부분군 위수 스칼라 곱이 항등점이 아닌
어떤 점도 거부합니다. `tests/crypto/asyms/ed25519.cpp`/`ed448.cpp`의 회귀
테스트가 `createPublicKey`가 항등점을 거부하는 것과 `verify`가 실재하는 키에
대한 위조 `(R=항등점, S=0)` 서명을 거부하는 것 둘 다를 덮습니다.

#### CBC padding 타이밍 (POODLE/Lucky13 부류)

`CbcTransformer`의 PKCS#7 padding 검사(복호 경로)를 constant-time이 되도록
다시 작성했습니다. 호출마다 마지막 블록의 모든 바이트를 무조건 스캔하고,
첫 불일치에서 분기하거나 이른 탈출을 하는 대신 결과를 비트 연산으로
결합합니다. 그것이 Vaudenay 식 CBC padding oracle이 악용하는 교과서적 구조입니다.
`src/crypto/syms/cbctransformer.cpp`의 "Constant-time PKCS#7 validation"
주석을 보십시오.

#### 수정: RSA PKCS#1 v1.5 복호 타이밍 (Bleichenbacher 부류)

`src/crypto/asyms/rsa.cpp::decryptBlock()`의 padding 제거 스캔이
교과서적인 Bleichenbacher oracle 모양이었습니다. 데이터 의존 길이 루프(첫
`0x00` 구분자 바이트에서 멈춤)에 더해 선두 바이트와 구분자의 위치/최소
오프셋에 대한 이른 반환 분기였습니다. 모든 실패 경로가 이미 균일한
`ERET_BADREQ`를 반환했지만, 거기 도달하는 데 *걸린 시간*이 여전히 어느 검사가
어디서 실패했는지를 누출했습니다. 블록 전체를 무조건 스캔하고(항상
`keyBytes - 2`회 반복) 모든 검사 — 선두 바이트, 구분자 발견 여부, 최소
8바이트 padding 길이 — 를 분기의 연쇄가 아니라 비트 AND/OR로 하나의
비트마스크에 접도록 다시 작성했습니다. `CbcTransformer`의 PKCS#7 검사가 이미
적용하는 같은 규율입니다. 이것이 주변의 `modExp`/CRT 경로 자체를
constant-time으로 만들지는 않습니다 — 그것은 큰 수 연산에 대한 이 프로젝트의
받아들여진 타이밍-하드닝보다-정확성 입장으로 남아 있고(`CEcCurve`의 doc 주석
참고) 여기 범위에 있던 적이 없습니다 — 복호 타이밍 oracle로 실제로 악용
가능했던 부분인 padding 제거 스캔 자신의 데이터 의존 분기만입니다.
`tests/crypto/asyms/rsa.cpp`의 기존 암복호 왕복과 잘못된 padding 테스트로
검증했습니다.

#### 수정: DSA 고정 기저 서명 속도 향상

`DsaContext::sign()`의 `g^k mod p` 항이 이제
`DsaPrivateKey::fixedBaseModExpG()`를 거칩니다. 지연 생성되어 키별로 캐시되는
`g^0..g^15 mod p` 테이블에 대한 좌에서 우로의 windowed 거듭제곱이며 —
`CEcCurve::scalarMulBase()`가 고정 기저 EC 서명에 이미 쓰는 것과 같은 16항목
window 기법을 점 덧셈/배가에서 모듈러 곱셈/제곱으로 옮긴 것입니다. 순전히
내부 성능 변경입니다(인터페이스/ABI 영향 없음, 보안 요구 변경 없음). 서명별
nonce `k`는 여전히 호출마다 달라지지만 `g`/`p`는 주어진 키에 대해 고정되므로,
테이블은 한 번 만들어져 그 키가 하는 모든 `sign()` 호출(그리고 재시도)에 걸쳐
재사용됩니다. `tests/crypto/asyms/dsa.cpp`의 기존 서명/검증 모음으로
검증했습니다.

#### 같은 패스에서 나온 그 외 하드닝

- `IExtension`이 `critical()` 플래그를 얻었습니다
  (`include/certpp/x509/ext.hpp`). `CCert::parseExtensions()`
  (`src/x509/cert.cpp`)는 이미 DER에서 `Extension.critical`을 파싱하고 있었지만
  버렸습니다 — 이제 기록합니다. 별도로, `CCertBuilder::build()`가 인증서를
  만들 때 `critical` BOOLEAN TLV를 아예 내놓지 않는다는 것이 발견되었습니다.
  `extnID`와 `extnValue` TLV 사이에 그것을 조건적으로 내놓도록
  고쳤습니다(false일 때는 DER 정규적으로 생략합니다).
- RFC 5280 4.2의 "특정 확장의 인스턴스를 둘 이상 포함해서는 안 된다(MUST
  NOT)"가 이제 강제됩니다. `parseExtensions()`는 이미 수집된 것과 중복되는
  확장 OID를 건너뛰고 첫 등장만 유지합니다.
- ASan으로 계측한 Debug 빌드와 테스트 실행(`/fsanitize=address /EHsc`)으로
  검증했습니다 — 80/80 테스트 통과, 발견 사항 0건.

## 프로젝트 전반 리팩터링: `src/`에 자유 함수 없음

← [변경 이력](../HISTORY.ko.md)

코드베이스 전체(약 20개 파일)의 모든 파일 스코프 또는 익명 네임스페이스 자유
함수를, 그것을 소유하는 클래스의 private 정적 메서드로 바꾸거나, 또는 —
자연스러운 소유자 하나가 없이 번역 단위들에 걸쳐 진짜로 공유되는 로직에
대해서는 — 그 디렉터리에 지역적인 헤더+cpp 쌍으로 된 `src/` 아래의 평범한
`PascalCase`(타입 접두사 없음) private 클래스로 바꾸었습니다. 주목할 만한
사례들: `RsaContext`의 PKCS1/PSS 보조 함수들,
`Edwards25519`/`Edwards448`/`Curve25519`의 곡선 연산 블록을 클래스로 통합,
`MD5`/`SHA1`/`SHAKE256`의 transform 루틴들, 두 SHA-2 비트 폭 사이에 공유되는
`Sha2_32Core`/`Sha2_64Core`, `CBigNum`/`CGf2m`의 hwaccel/limb 보조 함수들,
`CHex`, `SDateTime`의 C 라이브러리 래핑 보조 함수들,
`CEncoder`/`CDecoder`의 고정 자릿수 날짜 보조 함수들, `DSA`의 도메인 파라미터
생성, `CRng`의 대체 fill, 그리고 NameConstraints 확장의 subtree 코덱입니다.
동작 변화 없음 — 쓸고 난 뒤 전체 테스트 모음 통과(80/80)로 검증했고, 마지막
grep으로 `src/`에 남은 자유 함수가 0개임을 확인했습니다.

## 문서화

← [변경 이력](../HISTORY.ko.md)

- `docs/CONCEPTS.md`의 `IExtension`과 `_extensions` 절을 `critical()`과
  중복 OID 건너뛰기에 맞춰 갱신했습니다. `crypto/syms` 모듈 전체를 문서화하는
  새 절을 추가했습니다(constant-time padding 근거를 포함하며,
  `CEcCurve`/`CBigNum` 자신의 설계상-non-constant-time 입장과 명시적으로
  대비했습니다). `Sha2_32Transform`/`Sha2_64Transform`을 자유 함수로 설명하던
  낡은 주석 둘을 현재의 클래스 메서드 이름으로 고쳤습니다. 그리고 최상위
  개요 단락(이전에는 `common`/`version`/`utils`/`io`/`asn1`/`crypto`만
  설명하고 `x509`와 `crypto/syms`를 완전히 빠뜨렸습니다)을 라이브러리의 현재
  상태를 덮도록 다시 썼습니다.
- 그 목적을 할 git 역사가 아직 없으므로, 이 파일을 프로젝트의 작업 역사
  기록으로 추가했습니다.

## Linux에서의 `CRng`: `getrandom(2)`

← [변경 이력](../HISTORY.ko.md)

`CRng::fill()`의 Linux 분기가 이제 `/dev/urandom`으로 바로 가는 대신
`getrandom(2)` 시스템 콜을 직접 호출하고(`EINTR`과 짧은 읽기를 넘어
반복합니다), 시스템 콜 자체가 노골적으로 실패할 때(`ENOSYS`,
`EPERM`/seccomp 차단)에만 `/dev/urandom`으로 돌아가며, 거기서 다시
`CERTPP_RNG_FALLBACK` 뒤의 기존 `fillFallback()`/`std::random_device`
경로로 돌아갑니다. `docs/CONCEPTS.md`의 `CRng` 절과 `docs/BUILDING.md`의
`CERTPP_RNG_FALLBACK` 행을
3단 연쇄를 설명하도록 갱신했습니다.

## RSA: CRT로 가속한 개인키 연산

← [변경 이력](../HISTORY.ko.md)

`RsaContext::privateExp()`가 이제 키가 자기 `p`/`q`/`dp`/`dq`/`qInv`
파라미터를 담고 있을 때마다 전체 모듈러스 하나에 대한 `modExp(x, d, n)` 대신
CRT(Garner의 공식: `m1 = x^dp mod p`, `m2 = x^dq mod q`를 `qInv`로 결합)를
씁니다 — 두 거듭제곱 각각이 `n`의 비트 폭 약 절반인 모듈러스에 대해 돌므로
대략 4배 빠릅니다. 필수 재암호화 검사(`modExp(m, e, n) == x`)로 보호되며,
그것은 표준적인 Lenstra/Bellcore 결함 공격 대응책이면서 동시에 CRT 파라미터가
`checkPrivateKey()`로 검증된 적 없는, 들여온 키에 대한 정확성 대체책
역할을 합니다 — 불일치가 있거나 CRT 파라미터가 없으면 평범한 `modExp`로
돌아갑니다. `sign()`, `signPss()`, `decryptBlock()`에 배선했습니다. 전체
설명은 `docs/CONCEPTS.ko.md`의 `crypto/asyms/rsa.hpp` 절을 보십시오.

## AES: 하드웨어 가속 (AES-NI)

← [변경 이력](../HISTORY.ko.md)

`AesCore`가 x86-64 AES-NI
경로(`AESENC`/`AESENCLAST`/`AESDEC`/`AESDECLAST`/`AESIMC` intrinsic)를
얻었습니다. SHA-1/SHA-256에 이미 쓰이던 것과 같은 런타임 CPUID 디스패치
모양입니다(`hasAesNi()`. leaf 1, ECX 비트 25,
`encryptBlockAccelerated`/`decryptBlockAccelerated` 대
`encryptBlockPortable`/`decryptBlockPortable`). 복호는 기존 정방향 라운드 키
스케줄을 변경 없이 재사용할 수 있도록 Equivalent Inverse Cipher 구성을
씁니다. 새 `CERTPP_DISABLE_HWACCEL_AES` CMake 옵션(기본 `OFF`)으로 관문이
걸려 있고 `docs/BUILDING.md`에 문서화되어 있습니다. 이 모듈의 기존 SP 800-38A
기지 응답 벡터로 검증했으며, AES-NI를 지원하는 하드웨어에서는 그것들이 가속
경로를 자동으로 거칩니다.

## 포스트 양자 암호: 사전 검토와 KEM 인터페이스 설계

← [변경 이력](../HISTORY.ko.md)

- [`docs/PQC.ko.md`](../PQC.ko.md)를 추가했습니다. 표준화된 PQC
  알고리즘들(ML-KEM/FIPS 203, ML-DSA/FIPS 204, SLH-DSA/FIPS 205, 그리고
  덜 정해진 상태인 FN-DSA/HQC)에 대한 구현 전 검토, 각각이 이 라이브러리의
  기존 `IAsymmetric` 모양 인터페이스에 어떻게 맞는지(혹은 맞지 않는지),
  어떤 기반이 이미 있고 어떤 것을 만들어야 하는지, 그리고 `SHAKE128`과
  `IKem` 인터페이스 설계로 시작하는 작업 순서 제안입니다.
- `IKem`/`IKemContext`(`include/certpp/crypto/kem.hpp`, 신규)와 세 번째 KEM
  키 계열(`EKems`/`IKemKeyBase`/`IKemPublicKey`/`IKemPrivateKey`/
  `SKemKeyPair`. `include/certpp/crypto/keys.hpp`에 추가)을 설계했습니다.
  `sign()`/`verify()`와 `createEncrypter()`/`createDecrypter()`를
  `encapsulate()`/`decapsulate()`가 대체하는 것을 빼면
  `IAsymmetric`/`IAsymmetricContext`의 모양을 반영합니다. KEM은 호출자가 준
  평문을 암호화하는 것이 아니라 공유 비밀을 ciphertext와 함께 만들어
  내기 때문입니다. 이 단계에서는 설계상 헤더 전용입니다 — `.cpp`도 없고,
  엄브렐라 헤더에 배선되어 있지도 않고, 구체 알고리즘도 아직 없습니다.
  `docs/CONCEPTS.ko.md`의 `crypto/keys.hpp`/`crypto/kem.hpp` 절을
  보십시오.
- `SHAKE128`(`include/certpp/crypto/hashers/shake128.hpp` /
  `src/crypto/hashers/shake128.cpp`, `EHASH_SHAKE128`)을 첫 구체 PQC 기초
  단계로 추가했습니다. FIPS 203/204 둘 다 행렬/벡터 확장에 필요로 하는
  것입니다. 이전에 `SHAKE256`에 private이었던 Keccak-f[1600] permutation과
  스펀지 로직을 공유 `KeccakCore`(`src/crypto/hashers/keccakcore.hpp`/`.cpp`)로
  빼내어, `SHAKE128`(rate 168)과 `SHAKE256`(rate 136)이 그것을 중복하는 대신
  구현 하나를 공유합니다. Python `hashlib`으로 생성한 벡터(rate 경계 케이스
  포함)와, PDF 전사 오류를 배제하기 위해 `hashlib.shake_128`과 교차 확인한
  NIST CSRC 발행(`SHAKE128_Msg0.pdf`) 빈 메시지 벡터 하나로 검증했습니다.

## 프로젝트 전반 리팩터링: 버퍼 일괄 연산 (`memcpy`/`memmove`/`memset`)

← [변경 이력](../HISTORY.ko.md)

`src/` 전체에서 `TArray`/`CBuffer`/원시 배열 바이트 범위에 대한 모든 원소
단위 fill 또는 copy 루프(처음에는 `rsa.cpp`의 PSS/PKCS1 파이프라인에서
발견되었고, 그 다음 ASN.1, DSA/ECDSA, 대칭 암호, 곡선 연산/utils, x509에
걸쳐 다섯 번의 병렬 패스로 프로젝트 전반을 쓸었으며, 더해서 첫 패스의 패턴이
놓친 `.data[i]` 식 필드 접근 복사를 잡아낸 두 번의 추가 표적 정규식 패스가
있었습니다)를 원시 포인터
`std::memset`/`std::memcpy`/`std::memmove` 호출로 바꾸었고, (서로 구별되는
원소들의 수열로서가 아니라) 버퍼 역할로 쓰이던 모든 `TArray<uint8_t>`를
`CBuffer`로 타입을 바꿨습니다. 의도적으로 건드리지 않은 것:
constant-time/분기 없는 코드(`CbcTransformer`의 padding 검사, EC/EdDSA 스칼라
ladder), 뒤집기와 제자리 swap(`CBigNum::reverseBytesInPlace`, DES/3DES의 복호
쪽 키 스케줄 뒤집기 — 어느 것도 순서를 보존하는 `memcpy`/`memmove`로 표현되지
않습니다), 조건부/필터링 복사(`CRng::fillNonZero`의 0 바이트 거부 루프),
그리고 기존 공개 헤더 함수 시그니처가 요구하는 모든 `TArray<uint8_t>&`
파라미터(`CEcCurve::encodePoint`, `CGf2m::toBigEndian`, `CHex::decode`)입니다.
이제 [`docs/RULES.ko.md`](../RULES.ko.md)의 "버퍼 처리"
절에 상시 프로젝트 관례로 문서화되어 있습니다. 어디에도 동작 변화 없음 —
매 회차 뒤 전체 테스트 모음 81/81 통과로 검증했습니다.
