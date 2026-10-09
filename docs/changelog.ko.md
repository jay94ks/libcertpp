# 변경 기록

[English](changelog.md)

이 저장소의 git 역사는 늦게 시작합니다. 최초 소스 커밋까지의 모든 것이 커밋되지
않은 작업 트리 상태로 개발되었으므로, `git log`는 그중 무엇이 어떻게 생겨났는지
아무것도 말해 주지 않습니다. 이 파일이 대신 그 기록이며, 역사보다 앞서는
작업의(그리고 커밋 메시지가 너무 짧게만 말한 것의) 근거를 찾을 곳으로 남아
있습니다. 항목은 날짜가 아니라 주제로 묶여 있고, 한 주제 안에서는 오래된 것이
먼저입니다. 라이브러리가 *지금* 어떤 모습인지는
[`docs/architecture.ko.md`](architecture.ko.md)를 보십시오 — 이 파일은 그것이
거기까지 어떻게 왔는지에 대한 것입니다.

## `crypto/syms`: AES, DES, 3DES, ChaCha20

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

이름이 붙은 CVE 11개(POODLE, Logjam, CurveBall, Heartbleed, libksba CVE 둘,
Psychic Signatures, SECT 곡선 부분군 검증 CVE, ECDSA nonce 편향 CVE, OpenSSL
RNG CVE, 그리고 GnuTLS 길이 처리 CVE)에 대해 전체 보안 감사를 수행하며, CVE
이름만으로 추측하는 대신 각각을 직접 해당, 간접 해당, 해당 없음, 또는
미확인으로 분류했습니다. 실제 취약점 셋을 찾아 고쳤습니다. 그 결과 설계 메모는
`docs/architecture.ko.md`의 `CEcCurve`/`CEc2Curve`/`Ed25519`/`Ed448` 절을
보십시오. 앞으로 이 프로젝트에서 그냥 "보안 테스트"라고 요청하면 기본적으로
같은 작업 흐름을 뜻합니다(CVE 조사 → 해당 여부 분류 → 적대적 테스트 → 근본
원인 수정 → 보고).

### EC/EC2 점 디코딩 공백 (SECT 곡선 부류, CWE-345)

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

### Ed25519/Ed448 보편적 서명 위조 (Psychic-Signatures 부류)

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

### CBC padding 타이밍 (POODLE/Lucky13 부류)

`CbcTransformer`의 PKCS#7 padding 검사(복호 경로)를 constant-time이 되도록
다시 작성했습니다. 호출마다 마지막 블록의 모든 바이트를 무조건 스캔하고,
첫 불일치에서 분기하거나 이른 탈출을 하는 대신 결과를 비트 연산으로
결합합니다. 그것이 Vaudenay 식 CBC padding oracle이 악용하는 교과서적 구조입니다.
`src/crypto/syms/cbctransformer.cpp`의 "Constant-time PKCS#7 validation"
주석을 보십시오.

### 수정: RSA PKCS#1 v1.5 복호 타이밍 (Bleichenbacher 부류)

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

### 수정: DSA 고정 기저 서명 속도 향상

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

### 같은 패스에서 나온 그 외 하드닝

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

- `docs/architecture.md`의 `IExtension`과 `_extensions` 절을 `critical()`과
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

`CRng::fill()`의 Linux 분기가 이제 `/dev/urandom`으로 바로 가는 대신
`getrandom(2)` 시스템 콜을 직접 호출하고(`EINTR`과 짧은 읽기를 넘어
반복합니다), 시스템 콜 자체가 노골적으로 실패할 때(`ENOSYS`,
`EPERM`/seccomp 차단)에만 `/dev/urandom`으로 돌아가며, 거기서 다시
`CERTPP_RNG_FALLBACK` 뒤의 기존 `fillFallback()`/`std::random_device`
경로로 돌아갑니다. `docs/architecture.md`의 `CRng` 절과 `docs/build.md`의
`CERTPP_RNG_FALLBACK` 행을
3단 연쇄를 설명하도록 갱신했습니다.

## RSA: CRT로 가속한 개인키 연산

`RsaContext::privateExp()`가 이제 키가 자기 `p`/`q`/`dp`/`dq`/`qInv`
파라미터를 담고 있을 때마다 전체 모듈러스 하나에 대한 `modExp(x, d, n)` 대신
CRT(Garner의 공식: `m1 = x^dp mod p`, `m2 = x^dq mod q`를 `qInv`로 결합)를
씁니다 — 두 거듭제곱 각각이 `n`의 비트 폭 약 절반인 모듈러스에 대해 돌므로
대략 4배 빠릅니다. 필수 재암호화 검사(`modExp(m, e, n) == x`)로 보호되며,
그것은 표준적인 Lenstra/Bellcore 결함 공격 대응책이면서 동시에 CRT 파라미터가
`checkPrivateKey()`로 검증된 적 없는, 들여온 키에 대한 정확성 대체책
역할을 합니다 — 불일치가 있거나 CRT 파라미터가 없으면 평범한 `modExp`로
돌아갑니다. `sign()`, `signPss()`, `decryptBlock()`에 배선했습니다. 전체
설명은 `docs/architecture.ko.md`의 `crypto/asyms/rsa.hpp` 절을 보십시오.

## AES: 하드웨어 가속 (AES-NI)

`AesCore`가 x86-64 AES-NI
경로(`AESENC`/`AESENCLAST`/`AESDEC`/`AESDECLAST`/`AESIMC` intrinsic)를
얻었습니다. SHA-1/SHA-256에 이미 쓰이던 것과 같은 런타임 CPUID 디스패치
모양입니다(`hasAesNi()`. leaf 1, ECX 비트 25,
`encryptBlockAccelerated`/`decryptBlockAccelerated` 대
`encryptBlockPortable`/`decryptBlockPortable`). 복호는 기존 정방향 라운드 키
스케줄을 변경 없이 재사용할 수 있도록 Equivalent Inverse Cipher 구성을
씁니다. 새 `CERTPP_DISABLE_HWACCEL_AES` CMake 옵션(기본 `OFF`)으로 관문이
걸려 있고 `docs/build.md`에 문서화되어 있습니다. 이 모듈의 기존 SP 800-38A
기지 응답 벡터로 검증했으며, AES-NI를 지원하는 하드웨어에서는 그것들이 가속
경로를 자동으로 거칩니다.

## 포스트 양자 암호: 사전 검토와 KEM 인터페이스 설계

- [`docs/pqc-review.ko.md`](pqc-review.ko.md)를 추가했습니다. 표준화된 PQC
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
  `docs/architecture.ko.md`의 `crypto/keys.hpp`/`crypto/kem.hpp` 절을
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
이제 [`docs/coding-conventions.ko.md`](coding-conventions.ko.md)의 "버퍼 처리"
절에 상시 프로젝트 관례로 문서화되어 있습니다. 어디에도 동작 변화 없음 —
매 회차 뒤 전체 테스트 모음 81/81 통과로 검증했습니다.

## 프로젝트 전반 감사: 메모리 안전성, DER 엄격성, 서명 검증

다섯 부분으로 나눈 읽기 전용 감사(utils/io/asn1, hashers/RNG/대칭,
비대칭/곡선, x509/examples, 그리고 문서를 코드에 대조)가 아래의 수정들을
만들어 냈습니다. 두 조각이 독립적으로 같은 결함 둘 — digest 절단 버그와
최소가 아닌 INTEGER 수락 — 을 보고했는데, 그것이 둘 다를 여기 자세히
설명하는 이유의 일부입니다.

### 메모리 안전성

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

### 신뢰할 수 없는 경계에서의 DER 엄격성

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

### 서명 검증

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

### 그 외 정확성

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

문서의 모든 주장을 코드에 대조해 감사하고 어긋난 것을 고쳤는데, 라이브러리의
가장 새로운 경계에 집중되어 있었습니다.

- **`architecture.md`의 확장 클래스 이름 일곱 개가 존재하지 않았습니다**(16회
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
- `build.md`가 빠져 있던 `CERTPP_BUILD_EXAMPLES` 행, Examples
  절(`CERTPP_EXAMPLE_OUTPUT_DIR`과 예제들이 왜 의도적으로 CTest 케이스가
  아닌지를 포함), 그리고 `build-asan/`이 암시하지만 아무것도 문서화하지 않던
  AddressSanitizer 레시피를 얻었습니다.
- `coding-conventions.md`의 버퍼 처리 규칙이 이제 두 절반을 구분합니다.
  일괄 호출 절반에는 예외가 있고, 원시 포인터 절반은 루프로 남아야 하는
  코드에도 적용됩니다. `CbcTransformer`가 그 작업 예제입니다.
- README 둘 다 `CBuffer`를 "고정 크기 소유 바이트 버퍼"라고 불렀는데 — 그것은
  크기 조절 가능한 작업용 버퍼이고 `COctet`이 고정 크기 쪽입니다 —
  `COctet`/`CBase64`를 완전히 빠뜨렸습니다. `changelog.md`와 README 둘의
  "아직 git 역사 없음" 전제가 이제 거짓이 아니라 그-당시-참으로 되어 있습니다.
- `CLAUDE.md`가 `x509`를 "파싱한다(아직 생성하지 않는다)"고 주장했고, 대칭
  암호도 CRL/OCSP도 나열하지 않았고, 다섯 문서 중 셋만 링크했습니다.

## 포스트 양자: 검토 정리, 구현 계획 추가

`docs/pqc-review.md`는 PQ 코드가 하나도 없던 때 작성되어 자기 첫 단계에서부터
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

## 서명 검증, 외부 KAT 벡터, 그리고 x509 파서 하드닝

위의 감사는 패치가 아니라 결정이 필요한 네 가지를 남겨 두었습니다. 넷 모두
이 순서로 처리했습니다 — 테스트가 먼저인데, 그것이 나머지를 안전하게 바꿀 수
있게 해 주는 것이기 때문입니다.

### 외부 기지 응답 벡터 (그리고 그것이 곧바로 증명한 것)

테스트 모음에는 RSA, DSA, 또는 36개 곡선 어느 것에 대해서도 외부 벡터가
없었습니다. 곡선별 테스트가 모두 메시지에 서명하고 그 다음 자기 출력을
검증했으며, 그것이 바로 위의 FIPS 186-4 digest 절단 버그가 존재하는 동안 줄곧
녹색 테스트 모음을 살아남은 이유입니다. `tests/crypto/asyms/` 아래에
추가했습니다.

- `kat_ecdsa.cpp` — K-163/SHA-256, B-163/SHA-256, K-163/SHA-512,
  B-233/SHA-256, K-283/SHA-384, B-283/SHA-384, 그리고 대조군으로
  P-256/SHA-256에 대한 NIST CAVP 186-4 `SigVer` 레코드 28개(양성 7, 음성 21).
- `kat_dsa.cpp` — CAVP 186-3 `SigVer` 레코드 4개(L=1024/N=160,
  L=2048/N=256).
- `kat_rsa.cpp` — CAVP 186-3 `SigVer15` 레코드 2개(2048비트, SHA-256).

서명 벡터가 아니라 검증 벡터인 것은 의도적입니다. 이 라이브러리는 무작위
`k`를 뽑으므로 서명 벡터의 기대 `(r, s)`는 재현 불가능한데, 검증 벡터는
외부 oracle에 대해 절단하고-검증하는 경로 전체를 거치게 하고 — 그것이 깨져
있던 경로입니다.

**가장 중요한 결과: 34개 레코드 전부가 통과하며, 바이트 정렬되지 않은 모든
이진 곡선을 포함합니다.** 그 벡터들이 식별력을 가진다는 것도 보였습니다.
옛 바이트 단위 절단에 대해 다시 돌리면, 바이트 정렬되지 않은 양성 여섯 개가
모두 실패합니다. 그래서 절단 수정은 이제 산술로-논증된 것이 아니라 외부적으로
확인되었고, 영향받은 다섯 곡선이 CAVP 서명을 올바르게 검증합니다. 전사는
독립적인 밑바닥부터의 Python 구현에 교차 확인했으며, 그것이 커밋 전에 벡터
자체에 있던 잘못된 위수 리터럴 하나를 잡아냈습니다.

### 적대적 DER 테스트

x509 테스트 모음에는 잘못된 DER 테스트가 하나도 없었고, ASN.1 디코더의 DER
엄격성 관문들이 거의 전혀 거쳐지지 않았습니다 — 하나뿐인 long-form 길이
테스트가 BER를 썼으므로 모든 DER 특정 관문이 테스트되지 않은 상태였습니다.
`tests/asn1/malformed.cpp`(23 케이스)와
`tests/x509/malformed.cpp`(15 케이스)를 추가해, 파서에 거부해야 하는 바이트를
먹입니다.

ASN.1 계층은 이것을 잘 통과했습니다. `0xFF` 예약 길이 횟수, 최소가 아니고
과도하게 긴 long-form 길이, 128 미만 값에 대한 long form, `sizeof(size_t)`를
넘는 옥텟 수, 잘린 헤더, 버퍼를 넘어 흐르는 길이, DER 아래에서의 비확정
형식(최상위뿐 아니라 중첩된 것도), 64단 중첩 가드, 최소가 아닌 high-tag-number
형식, BIT STRING의 사용하지 않는 비트 규칙, *두* 정수 파서 모두에서의
INTEGER 중복 선행 옥텟 규칙, OID 최소성, 그리고 UTCTime/GeneralizedTime
유효성과 pivot 연도 표 전체가 이미 올바르게 강제되고 있습니다.

x509 계층은 그렇지 않았고, 그 공백들이 아래에 있습니다. 아직 열려 있는 공백을
문서화하는 테스트는 `known gap:`으로 이름 붙이고 `WARN`으로 단정하므로,
테스트 모음이 녹색으로 남아 있으면서 실행마다 그것들을 보고합니다. 셋이
남아 있습니다(빈 `Extensions` SEQUENCE, `cA`가 FALSE인 채로 살아남는
`pathLenConstraint`, 그리고 발급자 이름으로 받아들여지는 빈 `RDNSequence`).

### x509 파서 하드닝

아래의 각각은 전에는 받아들여졌고 지금은 거부되며, 해당 테스트가 `WARN`에서
`CHECK`로 승격되었습니다.

- **바깥 SEQUENCE 뒤에 붙은 바이트** — 인증서, CRL, 그리고 네 OCSP 디코더
  전부입니다. 이 집합에서 가장 나쁜 것입니다. `importDer()`가 자기 입력을
  `_rawData`로 그대로 유지하므로, 접미사가 하나의 인증서에 서로 다른
  `thumbprint()` 값을 무한히 주었고 — 서명된 필드를 건드리지 않고 그것으로
  키를 매긴 어떤 차단 목록, 폐기 기록, 중복 제거 캐시도 비켜 갑니다 —
  `exportDer()`는 그 DER가 아닌 접미사를 자기가 직렬화하는 상대가 누구든
  그에게 다시 내놓았습니다.
- **잘못된 `extensions [3]` 래퍼가 모든 확장을 조용히 버렸습니다.** 태그
  비교가 `isConstructed()`를 요구했지만 불일치는 "확장 없음"으로 취급되었고,
  `parseExtensions()`는 `void`를 반환하므로 import를 실패시킬 수 없었습니다.
  따라서 비트 하나를 지우는 것(`0xA3` → `0x83`)이 BasicConstraints, KeyUsage,
  EKU, NameConstraints를 담은 인증서를 아무것도 담지 않은 인증서로 바꾸면서도
  여전히 `ERET_OK`로 import되고, 진짜로 확장이 없는 인증서와 구별되지
  않았습니다. 과도하게 긴 `[3]` 길이 변종도 같은 분기에 도달했는데, "읽을 것이
  남지 않았다"와 "다음 원소가 파싱되지 않는다"가 뒤섞여 있었기 때문입니다 —
  `readNextElement()`가 둘 다 false로 보고합니다. 이제 `atEnd()`를 먼저 확인해
  분리했으므로, 파싱 실패가 import를 실패시킵니다.
- **`TBSCertificate.signature`가 `Certificate.signatureAlgorithm`과 비교된
  적이 없었습니다**(RFC 5280 4.1.1.2). 내부 사본은 서명된 바이트 안에 있고
  외부 것은 아닙니다 — 그런데
  `signAlgo()`/`createHasher()`/`verifyBy()`가 작용하는 것은 외부이므로,
  인증되지 않은 필드가 인증된 필드들을 검증하는 데 쓰이는 digest를 골랐습니다.
  실제 세상의 발급자들이 같은 알고리즘에 대해 두 사본 사이에서 부재 대 NULL로
  실제로 다르므로, 파라미터가 아니라 OID만 비교합니다.
- **`signatureValue`의 BIT STRING 사용하지 않는 비트 수가 읽히고
  버려졌습니다** — 인증서, CRL, 그리고 두 OCSP 경로에서입니다. 모든 서명에
  최대 여덟 개의 추가 인코딩을 준 것입니다. 마흔 줄 위의
  `SubjectPublicKeyInfo` BIT STRING은
  항상 검사되고 있었는데, 그것이 이것을 결정이 아니라 빠뜨림처럼 보이게 만든
  요소입니다.
- **음수인 `pathLenConstraint`**(`INTEGER (0..MAX)`, RFC 5280 4.2.1.9)가 더
  이상 쓸 수 있는 제약으로 보고되지 않습니다.

`tests/x509/realcerts.cpp`의 실재하는 상용 발급 인증서들은 이 모든 규칙
아래에서도 여전히 파싱되며, 그것이 중요한 검사입니다. 엄격화가 실재하는
무엇도 거부하지 않으면서 가변적인 인코딩을 거부합니다.

### 인증서와 CRL 서명 검증

`CCert`는 `_signature`를 파싱했지만 그것을 읽는 것이 하나도 없었습니다. 그에
대한 접근자도 없고 TBS 바이트 범위에 대한 것도 없었으므로, 인증서를 그
발급자에 대해 확인할 수 있는 것이 없었습니다. 증거가 테스트 모음 자체에
있었습니다 — `tests/x509/cert.cpp`가 그 바이트들을 되찾기 위해 약 50줄의
DER 재순회를 손으로 만들어 두었습니다. 추가했습니다.

- `CCert::signature()`, `CCert::tbsCertificate()`, `CCert::verifyBy(issuer)`.
- `CCrlReader::signature()`, `CCrlReader::tbsCertList()`,
  `CCrlReader::verifyBy(issuer)` — CRL은 이전에 두 필드 모두를 버렸으므로,
  `decode()`가 이제 서명을 유지하고 그 알고리즘을 해석합니다.

`tbsCertificate()`/`tbsCertList()`는 파싱된 필드를 다시 인코드한 것이 아니라
`rawData()`에서 온 *원래* TBS TLV를 반환합니다. 서명이 발급자의 바이트를
덮으므로, 다시 인코드하면 그것이 담고 있는 어떤 특이점도 조용히 고쳐 버릴
것입니다. 길이는 내용 span에 대한 포인터 연산이 아니라
`readEncodedValue()` 자신의 `bytesRead`에서 옵니다. `TSpan::slice()`가 끝에
도달하면 `{nullptr, 0}`을 반환하기 때문인데 — 다른 곳에서도 알아 둘 만한
날카로운 모서리입니다.

두 `verifyBy()` 구현 모두 `_sigHashAlgo == EHASH_UNKNOWN`이 아니라 *발급자 키*
자신의 알고리즘에서 해시 여부를 결정합니다 — 위의 OCSP 버그를 만들어 낸 그
모호성입니다. 설계상 링크 하나 단위 검사입니다. 이름 연결도, 유효 기간도,
제약 강제도 없습니다. `tests/x509/verify.cpp`를 보십시오. RSA/ECDSA/
Ed25519/Ed448에 걸친 진짜 자기 서명, CA가 발급한 leaf를 실제 발급자에 대해
그리고 낯선 이의 키에 대해, 그리고 조작된 서명 바이트 하나를 덮습니다.

## 성능: Knuth-D 나눗셈과 워드 단위 GF(2^m) 축약

연산 계층의 체계적인 선택 둘이 각각 대략 한 자릿수의 비용을 들이고
있었습니다. 둘 다 다른 모든 것 아래에 앉은 비트 직렬 알고리즘이었고, 둘 다
인터페이스 하나도 건드리지 않고 교체할 수 있었습니다.

**결과, 전체 테스트 모음에서 측정: 1243초에서 140초로, 전반적으로 8.9배
속도 향상.** 개별적으로 `crypto_asyms_rsa`가 85.7초에서 6.1초(약 14배),
`crypto_asyms_x25519`가 445.6초에서 39.5초(약 11배),
`crypto_asyms_dsa`가 64.4초에서 8.5초(약 7.5배)가 되었습니다. 88개 테스트
전부가 여전히 통과합니다.

### `CBigNum::divMod()` — Knuth의 알고리즘 D

옛 구현은 비트 직렬 복원 나눗셈이었습니다. *피제수의 비트마다* 시프트 한 번,
비교 한 번, 그리고 *제수 버퍼 전체*에 걸친 조건부 뺄셈 한 번이었습니다.
`modExp()`가 수천 번의 축약을 수행하고 라이브러리의 모든 비대칭 알고리즘이
`modExp()`를 거치므로, 이 루틴 하나가 RSA, DSA, ECDSA 모두에서 지배적인
비용이었습니다 — 2048비트 `mod` 한 번이 그것이 뒤따르는 곱셈의 약 50배
비용으로 측정되었습니다.

기수 2^32의 알고리즘 D(TAOCP 2권, 4.3.1)로 교체했는데, 그것은 비트 하나가
아니라 몫 *limb* 하나를 한 번에 만들어 냅니다. 제수를 그 최상위 limb의
최상위 비트가 설정되도록 정규화하고, 진행 중인 나머지의 상위 두 limb에서 각
몫 limb를 추정하고, 추정을 아래로 보정하고, 드물게 그래도 하나 컸던 경우에
제수를 다시 더합니다. 단일 limb 제수는 별도의 평범한 긴 나눗셈 경로를 타며,
거기서는 추정이 정확하고 보정 기계 중 어느 것도 적용되지 않습니다.

검증이 흥미로운 부분인데, 알고리즘 D에는 평범한 사용으로는 전혀 도달하지
못하는 두 곳이 있기 때문입니다.

- C++를 먼저 limb 단위로 Python에 옮기고 정확한 정수 연산에 대해
  퍼징했습니다 — 8,686쌍 그 다음 추가로 80,000쌍, 불일치 0건이고, 전수
  작은 값들, limb 경계, `2^k - d` 제수, 그리고 현실적인 2048비트 모듈러스
  모양을 덮었습니다. 컴파일 *전에* 이것을 한다는 것은 전사를 시도하기도 전에
  알고리즘이 올바름이 알려졌다는 뜻입니다.
- 그 훑기는 **D5/D6 add-back 분기가 다중 limb 나눗셈 72,695회에서 0번
  발동했다**는 것을 보였는데, 이는 이론(몫 limb당 약 2/2^32)과 일치하며
  무작위 테스트가 그것을 결코 덮을 수 없다는 뜻입니다. 그것은 또한 두 limb
  제수에 대해서는 *불가능*한 것으로 드러났습니다. 두 limb 추정 검사가 그
  경우 제수 전체를 보므로 추정이 정확하고 분기에 도달할 수 없습니다. 세 limb
  이상이 필요합니다.
- 그래서 그 입력은 샘플링되지 않고 구성되었습니다. 같은 알고리즘의 4비트
  limb 모델에서 그 분기를 전수로 거쳤고(발동 53,587회, 정확한 연산과 불일치
  0건), 발동시키는 limb 패턴을 각 32비트 limb의 상위 니블로
  확대했습니다 — 그것이 추정과 그 보정이 의존하는 모든 비율을 보존합니다.
  확인된 기수 2^32 발동 일곱 개가 이제 테스트 모음에 있습니다.

`tests/utils/divmod.cpp`가 이 모두를 담고 있습니다. 기대값을 단정하지 않고
독립적인, 의도적으로 소박한 비트 직렬
참조 — `CBigNum`의 공개 연산만으로 쓴 것이며, 이 변경이 대체한
알고리즘입니다 — 에 대조하고, 추가로 `remainder < divisor`인 상태로
`quotient * divisor + remainder == dividend`를 확인합니다. 어느 구현이 어떻게
거기 도달했든 올바른 나눗셈이라면 성립하는 것입니다.

### `CGf2m::reduceWide()` — 워드 단위 다항식 축약

한 계층 위의 같은 모양의 문제입니다. 축약은 곱의 비트를 `2m-2`에서 `m`까지
내려가며 걸었고, 설정된 비트마다 `1 + termCount`개 비트를 개별적으로
토글했으며, 각 토글이 자기 limb를 찾기 위해 자기 나눗셈과 나머지 연산을
치렀습니다. B-571에 대해서는 약 570회 반복과 수천 번의 토글입니다. 곱셈 전체
비용의 95–98%로 측정되었는데, 그 말은 그 위의 PCLMULQDQ로 가속된 캐리 없는
곱이 사 주는 것이 거의 없었다는 뜻입니다.

수정은 항등식 자체에서 따라옵니다. `x^m == x^terms[0] + ... + 1`이 *모든*
초과 비트를 같은 양만큼 밀어내므로 초과분 전체가 한 단계에 접힙니다 —
`hi = wide >> m`을 취하고, 비트 `m`부터 위를 전부 지우고, 그 다음 `hi`를
오프셋 0과 각 항 오프셋에 다시 XOR합니다. 접는 것이 다시 `m` 이상에 비트를
남길 수 있으므로 반복합니다. 이 라이브러리가 담고 있는 다섯 체 모두에 대해
정확히 두 번의 접기로 수렴하지만, 어떤 축약 다항식에 대해서도 올바르게 남도록
루프로 작성되어 있습니다.

컴파일 전에 같은 방식으로 검증했습니다. 워드 단위 접기를 다섯 체
(163/233/283/409/571) 전부에 걸친 무작위 곱 20,030개와 각 체의 극단값에
대해 기존 비트 직렬 구현에 대조했고 불일치는 0건이었으며, 두 번의 접기로
수렴하는 것을 가정하지 않고 체마다 확인했습니다.

어느 변경도 공개 시그니처를 건드리지 않고, 둘 위의 하드웨어 가속 곱셈 경로도
건드리지 않았습니다.

## 포스트 양자 기초: ML-KEM의 기반, 그리고 SHA-3

[`pqc-review.ko.md`](pqc-review.ko.md) 계획의 1–3단계, 그리고 그 계획이 놓친
선행 조건 하나입니다.

### 증분 SHAKE 스퀴징 (2단계)

`SHAKE128`/`SHAKE256`은 인스턴스가 생성될 때 받은 고정 `byteWidth()` 하나만
만들어 낼 수 있었지만, FIPS 203의 `SampleNTT`와 FIPS 204의 챌린지/마스크
확장은 충분한 후보가 수락될 때까지 SHAKE 스트림에서 거부 샘플링을 하며 길이를
미리 알 수 없습니다. 이제 둘 다 `squeeze()`를 가지고, 그것이 연속 chunk를
반환하며 스펀지를 전진시킵니다. `finish()`는 고정 길이이고 반복 가능한
관점으로 남아 사본에서 짜냅니다. 테스트는 1바이트부터 시작하는 모든 chunk
크기에 걸쳐 chunk 무관성을 단정하며, 각 rate 경계에 정확히 걸치는·바로
앞인·바로 뒤인 분할을 포함합니다 — 스펀지가 permute하는 유일한 곳이고,
따라서 커서 off-by-one이 드러날 유일한 곳입니다. 그것을 쓰는 동안 버그 하나가
나왔습니다. 가드가 null 검사보다 `if (out.empty()) return true;`를 앞에
두었는데, `TSpan::empty()`는 크기 0뿐 아니라 null 포인터에 대해서도 참이므로,
바이트를 담을 곳 없이 바이트를 요청한 호출자가 명랑한 성공을 받았습니다.

### SHA3-256과 SHA3-512 — 놓친 선행 조건

ML-KEM은 `H = SHA3-256`과 `G = SHA3-512`를 필요로 하는데, 이 라이브러리에는
SHAKE는 있었지만 고정 출력 SHA-3가 전혀 없었습니다. 계획이 그것을 기록해 두지
않았으므로, 4단계가 시작되려는 시점에야 드러났습니다.

둘 다 이제 `EHashers` 멤버입니다. SHA-3는 SHAKE와 같은 스펀지이므로
`KeccakCore`를 재사용하고 서로는 새 private `Sha3Core`를 공유합니다 —
`Sha2_32Core`가 SHA-224와 SHA-256 사이에 이미 갖는 배치이며, 각 공개 헤더가
`src/` 아래의 무엇에도 의존하지 않고 자기 컨텍스트를 선언하도록 원시 배열에
대한 연산으로 작성되어 있습니다. SHAKE와의 유일한 차이는
rate(`200 - 2*digestWidth`)와, SHAKE가 `0x1F`를 쓰는 자리의 `0x06` 도메인
바이트입니다 — 바이트 하나이고, 동일한 스펀지 위에서 같은 길이의 SHA-3
digest와 SHAKE 출력 사이의 구분 전부입니다. 그래서 테스트가 벡터만 확인하는
것이 아니라 그 둘이 진짜로 다르다는 것을 단정합니다. `finish()`는 SHA-2의
관례를 따릅니다. 스펀지를 건드리지 않는 조회이므로 반복되고 그 뒤에도 흡수가
이어집니다.

### ML-KEM 환 연산, 샘플러, 와이어 인코딩 (3단계)

새 private 단위 집합이 `MlKemRing`(R_q = Z_q[X]/(X^256+1), q=3329. NTT,
역 NTT, 기본 경우 곱셈, 그리고 나머지를 확인하기 위해서만 존재하는
schoolbook negacyclic 곱셈), `MlKemCodec`(ByteEncode/ByteDecode,
Compress/Decompress), `MlKemSampler`(SampleNTT, SamplePolyCBD)를 담고
있습니다. PQ 작업에 private이므로 `CERTPP_API`도 타입 접두사도 없습니다.

FIPS 203은 NTT의 동작만이 아니라 정확한 *표현*을 고정합니다 — 캡슐화 키가
NTT 영역 계수의 ByteEncode이므로 그 값들이 와이어에 올라갑니다. 올바르게
왕복하지만 트위들 순서가 다른 변환은 자기 일관적이면서 아무것과도
상호운용하지 않는데, 그것이 바로 위에 기록된 바이트 단위 ECDSA digest 절단을
숨겼던 그 실패 양상입니다. 그래서 테스트는 의도적으로 왕복에 의존하지
않습니다. 모든 트위들을 구현이 만드는 방식과 독립적으로
`17^BitRev7(i)`에서 재유도하고, NTT 영역 곱셈을 schoolbook 합성곱에
대조하고, `X^256 == -1`을 직접 단정하고, 256개 계수 배열을 체크섬과 양 끝점으로
고정하므로 어디서의 전치든 실패합니다.

그 과정에서 기록할 만한 것이 둘 있습니다.

- 여기의 모든 알고리즘은 C++를 쓰기 *전에* 명세 본문에 대조해 Python으로
  검증했습니다. 그것이 결과로 나온 zeta와 gamma 테이블이 별도 경로로
  FIPS 203 부록 A에 교차 확인되게 된 방식이기도 합니다.
- 압축 라운딩이 추측하지 않는 편이 나은 세부를 정리했습니다. q는
  홀수이므로, 흔히 쓰는 `(x*2^d + q/2)/q`는 `q/2`를 절단하고 half-up 반올림
  규칙을 운에 맡깁니다. 그 형태와 증명 가능하게 올바른
  `(2*x*2^d + q)/(2*q)` 둘 다를 모든 폭에서 `[0, q)` 안의 모든 계수에 대해
  정확한 유리수 정의에 대조해 보니 모든 곳에서 일치했습니다 — 그러나 둘 중
  하나만이 구성적으로 옳고, 구현된 것은 그쪽입니다.

`MlKemSampler::sampleNtt()`가 `squeeze()`의 첫 실제 소비자이고 그것을
구체적으로 정당화합니다. 시드에 따라 453–498바이트의 스트림을 소비합니다.
그 인덱스 바이트는 주어진 순서대로 덧붙으며, 테스트가 그것을 뒤바꾸면 결과가
달라진다고 단정합니다. FIPS 203의 행렬 확장이 의도적으로 그것들을 전치해
넘기므로, 그러지 않으면 전치된 호출을 탐지할 수 없기 때문입니다.

`CMakeLists.txt`는 그 private 단위들을, 그것들을 거치는 테스트에 직접 컴파일해
넣습니다. 그 코드가 의도적으로 export되지 않아 링크로 도달할 수 없기
때문입니다. 그 한 디렉터리에 국한됩니다. 그 외 모든 것은 `DesCore`와
`KeccakCore`가 그런 것처럼 여전히 공개 표면을 통해 테스트됩니다.

### 계획 자체에 대한 정정

준비 작업 셋을 명세들과 표준화 기록에 대조해 돌렸고, 계획이 여러 곳에서
틀렸음을 발견했습니다.

- 그 3단계 관문은 NTT를 "표준의 작업 예제"에 대조해 단정하라고 했습니다.
  **FIPS 203에는 작업 예제도 중간값도 전혀 없습니다** — 그 부록은 zeta
  테이블, SampleNTT의 루프 경계, 그리고 CRYSTALS-KYBER와의 차이입니다 —
  그리고 NIST는 ML-KEM용 예제 값 페이지를 발행하지 않습니다. FIPS 204도
  같지만, 그 부록 B는 전체 zetas 표를 인쇄합니다. 그 관문은 이제 실제로
  달성 가능한 것을 진술합니다.
- X.509 프로파일은 "표준화가 시작되는 중"이 아니라 **발행되었습니다**.
  RFC 9881(ML-DSA), RFC 9909(SLH-DSA), RFC 9935(ML-KEM)입니다. 그래서 OID가
  정해졌고, `2.16.840.1.101.3.4.3.19` — 트리 내 IdenTrust 픽스처의 OID —
  은 구체적으로 **ML-DSA-87**인데, 그것이 그 픽스처를
  `certs/implemented/`로 넘기는 파라미터 집합이 어느 것인지 결정합니다.
- 2030/2035 폐기 날짜는 SP 800-131A가 아니라 **NIST IR 8547**이고, 두 문서
  모두 아직 초안입니다.
- ML-DSA의 가장 큰 서명은 4595가 아니라 **4627**바이트입니다(그것은 IPD
  수치였습니다).
- FIPS 206은 FIPS 204로부터 25개월이 지난 지금도 공개 초안이 없습니다. HQC는
  FIPS 207로 계획되어 있고 여전히 초안 전입니다. SP 800-227(KEM 권고)은 최종
  확정되었고 `IKem`에 대해 규범적입니다.
- hedged ML-DSA 서명은 결국 바이트 단위로 재현 가능한데, ACVP의 prompt가
  `rnd`를 제공하기 때문입니다 — 그래서 5단계의 관문은 결정론적 열두 개만이
  아니라 24개 sigGen 그룹 전부를 덮습니다.

두 알고리즘에 대한 ACVP 벡터는 코드보다 먼저 찾아 리비전을 고정하고
검증했으며, 출처를 계획에 기록해 두었습니다 — ML-KEM의 암묵적 거부 케이스가
진짜 Fujisaki-Okamoto oracle이라는 것(45개 전부가 `k == SHAKE256(z||c, 32)`를
만족하고 유효한 케이스는 하나도 만족하지 않음)과, ML-DSA 벡터가 독립 구현
아래에서 바이트 단위로 재현된다는 것을 포함합니다. 어느 알고리즘을 쓰기
전에든 알아 둘 만한 명세 함정들 — ML-KEM의 `G(d||k)` 파라미터 바이트와
전치된 `SampleNTT` 인덱스, ML-DSA의 hint 디코드 거부 조건들과 부록 C 루프
경계 — 은 다시 발견되도록 남겨 두는 대신 해당 단계에 적어 두었습니다.

## 포스트 양자: ML-KEM 자체 (FIPS 203)

[`pqc-review.ko.md`](pqc-review.ko.md) 4단계의 전반부 — 알고리즘이고, NIST의
벡터에 대해 검증했습니다. 그것을 라이브러리 자신의 인터페이스 어휘로 도달
가능하게 만드는 `IKem` 래퍼가 나머지 절반이고, 아직 할 일입니다.

`crypto/kems/mlkem.hpp`가 `CMlKem`(K-PKE, 알고리즘 13–15, 그리고 그 위의
Fujisaki-Okamoto 변환, 알고리즘 16–18), `SMlKemParams`, `CMlKemSampler`,
`SMlKemPoly`를 공개합니다. 샘플러와 파라미터/다항식 타입들은 그것들이 기반일
뿐이던 동안 `src/` 아래에 private이었습니다. 원시 span 형태가 그 자체로
유용한 쪽으로 드러났기 때문에 공개 헤더로 옮겼습니다 — 그것은 테스트
벡터에서 바로 구동할 수 있는데 `IKem` 모양 API는 그럴 수 없고, 이미 자기
버퍼를 소유한 호출자나 KEM이 아니라 K-PKE를 원하는 호출자가 손을 뻗을
것이기 때문입니다.

`decapsulate()`가 모든 미묘함이 앉은 자리입니다. 복호한 것을 다시 암호화해
자기가 건네받은 ciphertext와 비교하고, 불일치하면 오류가 아니라 개인키 자신의
거부 시드에서 유도된 `J(z || c)`를 반환합니다. 그래서 잘못된 ciphertext가
제대로 생긴, 그러나 무관한 공유 비밀을 만들어 내고 호출자는 두 경우를 구별할
수 없습니다. 거기서 실패를 보고하거나 재암호화를 건너뛰는 것은 이 변환이
존재해서 막으려는 바로 그 복호 oracle을 건네주는 일이고 — 그래서 이 함수에는
나쁜 ciphertext에 대한 실패 모드가 아예 없고, 구조적으로 크기가 틀린 것에
대해서만 있습니다. ACVP가 자기 `modified ciphertext` 레코드에 기대 공유
비밀을 발행하는 것도 같은 이유입니다. 암묵적 거부는 오류 경로가 아니라
정의된 출력입니다.

### 그 승격이 열어 놓은 구멍

`SMlKemParams`를 공개로 만든 것이 그것을 호출자 제공 값으로 만들었고,
`CMlKem`은 고정 용량 버퍼 크기를 `MAX_K`와 `maxCiphertextBytes()`에서
잡습니다. 따라서 손으로 만든 `SMlKemParams{9, …}`가 그 전부를 넘치게 했을
것입니다. 그 구조체가 `src/` 아래에 살던 동안에는 괜찮았습니다 — 라이브러리
자신의 코드만 그것을 생성했습니다 — 그리고 헤더를 옮기는 일의 어느 부분도
그 산술을 바꾸지 않는데, 그것이 바로 놓치기 쉬웠던 이유입니다.

`SMlKemParams::isValid()`가 이제 어떤 집합이 FIPS 203의 셋 중 하나인지
보고하고, 여덟 개 `CMlKem` 진입점 전부가 `params`에서 무엇이든 유도하기 전에
그것을 호출합니다. 필드마다 범위를 검사하는 대신 발행된 세 집합으로 제한하는
것이 더 안전하면서 더 정직합니다. 네 번째 집합은 없고, `k ≤ 4` 하나만으로는
ciphertext 버퍼를 넘치게 할 만큼 넓은 `du`/`dv`를 여전히 허용할 것입니다.
테스트 케이스는 길이 검사가 거부 이유가 될 수 없도록 모든 span을 *그 엉터리
집합에 맞게* 정확히 잡고, `maxCiphertextBytes()`는 1568로 적히는 대신
`mlKem1024()`에서 유도되는데, 그것이 구현에서 손으로 쓴 마지막 두 크기도
없애 주었습니다.

### 테스트

`tests/crypto/kems/kat_mlkem.cpp`가 세 파라미터 집합 전부에 대한 ACVP keyGen,
캡슐화, 디캡슐화 레코드와, 더해서 `encapsulationKeyCheck`("noisy linear system
values too large")와 `decapsulationKeyCheck`("modified H") 음성 레코드를
박아 두고 있습니다. FIPS 203은 작업 예제도 중간값도 발행하지 않으므로 그
벡터들이 존재하는 유일한 외부 oracle이며 — ML-KEM은 그것이 절실히
필요합니다. 그 세부 중 적어도 셋(`G(d || k)`의 `k` 바이트,
`SampleNTT(ρ || j || i)`의 전치된 인덱스, `ByteDecode_12`의 mod q 축약)이
잘못 구현되었을 때 완벽히 자기 일관적이면서 아무것과도 상호운용하지 않는
스킴을 내놓기 때문입니다. 어떤 왕복 테스트도 그중 어느 것도 볼 수 없습니다.

FIPS 203 표 2의 크기는 런타임 검사가 아니라 `static_assert`로 고정되어
있습니다. `SMlKemParams`가 그 전부를 컴파일 시점에 유도하기 때문입니다.
keyGen 벡터는 K-PKE.KeyGen 벡터 역할도 겸합니다. ML-KEM의 키 생성이 K-PKE의
것에 `H(ek)`와 `z`를 덧붙인 것이므로, 같은 레코드가 둘 다를 못 박습니다.

전체를 환 연산과 같은 방식으로 검증했습니다 — 명세 본문에서 먼저 독립
Python 구현을 쓰고, 그것이 C++가 존재하기도 전에 180개 ACVP 벡터 전부와
바이트 단위로 일치했습니다. 이후 네거티브 컨트롤로 `G(d || k)`의 도메인 분리
바이트를 하나 바꾸자 두 테스트 케이스에 걸쳐 단정 12개가 깨졌고, 그 벡터들이
자기가 잡으려고 존재하는 세부에 실제로 물린다는 것을 확인했습니다.

### 적어 두었으나 고치지 않음

FIPS 203은 암묵적 거부 플래그와 그 주변 값들이 `Decaps_internal`이 반환하기
전에 파괴될 것을 요구합니다. 그렇게 되어 있지 않습니다. 이 라이브러리에는 영
소거 프리미티브가 아예 없고, 어떤 RSA, DSA, EC 개인키 연산도 자기 중간값을
지우지 않습니다. 따라서 ML-KEM은 새로 결함이 있는 것이 아니라 코드베이스의
나머지와 일관됩니다 — 그러나 그것은 그 전부에서 실재하는 공백이고, 수정은
여기서 손으로 만드는 것이 아니라 공유되는 `utils/` secure-zero 하나에
속합니다. 계획에 기록해 두었습니다.

## 포스트 양자: `IKem`으로서의 ML-KEM

4단계의 나머지 절반이고, 그것으로 4단계가 완료됩니다. `crypto/kem.hpp`는
어떤 격자 암호보다 먼저 설계되고 커밋되었으며 `EKems`는 비어 있고
`IKem::builtIn()`은 모든 것에 null을 반환했습니다. 이제 그 뒤에 ML-KEM이
있고 엄브렐라 헤더에 합류합니다.

`MLKEM`(`crypto/kems/mlkem.hpp`)이 파라미터 집합을 생성자 상태로 삼아 한
클래스로 세 파라미터 집합 전부를 담당합니다 — `CEcdsa`가 자기 곡선들에 걸쳐
이미 갖는 배치입니다. 암호학적인 것은 아무것도 구현하지 않습니다. `CMlKem`이
알고리즘이고, 이것은 키 객체들, `IKemContext`가 노출하는 크기 장부, 그리고
그 주변의 CSPRNG 추출입니다.

기록할 만한 결정이 둘 있습니다.

`keySizes()`는 파라미터 집합 자신의 수 — 512, 768, 1024 — 를 받아들이고,
모듈러스 폭이나 주장되는 보안 강도를 받지 않습니다. 라이브러리의 다른 모든
알고리즘에는 자연스러운 크기 파라미터가 있고(RSA의 모듈러스, X25519의
256비트 키) ML-KEM에는 없습니다. 세 집합은 모듈 랭크 `k`와 다른 네
파라미터에서 다르고, 그 숫자들은 이름입니다. 그 이름을 쓰면
`generateKeyPair(keySize, …)`가 다른 모든 알고리즘의 것과 같은 방식으로 쓸 수
있게 유지되면서, 뜻이 있는 것처럼 읽히는 수치를 만들어 내지 않아도 됩니다.
대안 — NIST 보안 범주에 대한 128/192/256 — 은 더 원칙적으로 보이면서 더
오해를 불렀을 것입니다. 구현의 어느 부분도 그것으로 파라미터화되지 않기
때문입니다.

`MLKEM`은 또한 ML-KEM 구현에서 CSPRNG를 건드리는 유일한 계층이고, 그것이
이 분리의 요점입니다. `CMlKem::generateKeyPair()`와 `encapsulate()`는 시드와
메시지를 파라미터로 받는데, 바로 그것이 그 둘을 ACVP에 대해 검증할 수 있게
한 요소입니다. `IKemContext::encapsulate()`에는 그런 파라미터가 없으므로
래퍼가 `CRng`에서 채웁니다. 그 대가로 이 계층에서는 기지 응답 테스트가
불가능하므로, `tests/crypto/kems/mlkem.cpp`는 대신 래퍼가 추가하는 것을
테스트합니다. 하나의 공개키에 대해 `encapsulate()`를 네 번 호출하면 서로 다른
ciphertext 넷과 서로 다른 비밀 넷이 나온다는 것(키만의 함수인 비밀이라면
세션마다 재사용될 것이고, 각각은 여전히 올바르게 디캡슐화됩니다), 한 키에
대한 ciphertext가 다른 키 아래에서는 오류가 아니라 *다른 비밀*로만 열린다는
것, 그리고 조작된 ciphertext가 `ERET_OK`를 반환한다는 것 — Fujisaki-Okamoto
요구이고, 이제 `CMlKem` 내부에서뿐 아니라 인터페이스 경계에서도 확인됩니다.

디캡슐화 키는 자기 캡슐화 키를 품고 있으므로,
`IKemPrivateKey::publicKey()`는 그것을 다시 계산하지 않고 오프셋
`dkPkeBytes()`에서 읽어 냅니다. 그 다음 `checkPrivateKey()`와
`createPrivateKey()`가 품고 있는 `H(ek)`가 그 `ek`와 일치하는지, 연결된
공개키가 바이트 단위로 그 품고 있는 것인지, 그리고 그 `ek`가 정규적인지를
검증합니다 — 셋 중 어느 것도 믿는 대신입니다. `createPrivateKey()`에 도달한
키는 외부에서 왔기 때문입니다. 키에는 ASN.1 래핑이 전혀 없습니다. 인증서가
필요한 SubjectPublicKeyInfo 형태는 6단계입니다.

## `CSecure`: 영 소거와 constant-time 비교/선택

`utils/secure.hpp`를 추가했고 — `CSecure::zero()`, `equalsMask()`,
`select()` — 그것으로 ML-KEM의 공백 둘을 닫았는데, 그중 하나는 원래
기록해 둔 것보다 나빴습니다.

### 실제 발견: FO 검사의 `memcmp`

앞 항목은 ML-KEM의 빠진 영 소거를 알려진 공백으로 적어 두었습니다. 그것을
고치려고 `decapsulate()`를 다시 보다가 몇 줄 떨어진 곳에서 더 심각한 것을
찾았습니다.

```cpp
const bool matches = std::memcmp(reencrypted, ciphertext.data, ciphertext.size) == 0;
std::memcpy(sharedSecret.data, matches ? candidateSecret : rejectionSecret, 32);
```

`memcmp`는 처음 다른 바이트에서 멈추므로, 그 실행 시간이 **재암호화된
ciphertext의 접두사가 얼마나 길게 일치했는지**를 드러냅니다 —
Fujisaki-Okamoto 변환이 숨기려고 존재하는 한 비트보다 훨씬 많은 정보이고,
KyberSlash 계열 공격의 모양입니다. 그 다음 삼항 연산자가 판정에 대해
분기하는데, 그것이 *바로* 그 한 비트입니다. FIPS 203은 암묵적 거부 플래그가
"어떤 형태로도" 노출되지 않을 것을 요구하고, 분기는 그것을 노출합니다.

둘 다 이제 `CSecure::equalsMask` 다음 `CSecure::select`입니다. 비교는 결과가
무엇이든 모든 바이트를 읽고 `0xFF`/`0x00`을 내놓으며, 그 mask가 바이트 단위
선택을 구동하므로 비밀인 무엇에 대해서도 분기하는 것이 없습니다. ACVP
디캡슐화 벡터 — 바로 거부 경로인 `modified ciphertext` 레코드 전부를 포함해
— 가 여전히 바이트 단위로 통과하며, 그것이 이 재작성이 양쪽 경로의 출력을
보존했음을 확인해 주는 것입니다.

`equalsMask`가 bool이 아니라 완전한 mask를 반환하는 것은 의도적이고,
테스트는 그 값이 단지 참스러운 것이 아니라 `0xFF`임을 단정합니다. `select`가
그것과 AND하므로, mask가 `1`이면 선택된 각 바이트의 최하위 비트만 조용히
남길 것입니다. 또한 누적된 차이를 `diff == 0`이라고 쓰는 대신 산술적으로
mask로 접으므로, 정확성이 컴파일러가 거기서 분기 대신 플래그 설정을 고르는
데 의존하지 않습니다.

### 최적화기를 살아남는 영 소거

`CSecure::zero()`는 `memset`을 volatile 함수 포인터를 통해 보냅니다. 이것은
가정이 아니라 그렇지 않았다면 동일한 두 함수에 대한 MSVC의 `/O2` 출력을 읽어
검증했습니다. 평범한 `std::memset`을 쓴 쪽에서는 그 지우기가 **완전히
삭제되었습니다** — 저장도 호출도 없습니다 — 반면 `CSecure::zero` 호출은
살아남았고, `zero` 안에서 컴파일러는 포인터를 메모리에서 적재해 그것을 통해
tail-jump하며 직접 `memset`으로 되접지 않습니다.

`decapsulate()`는 탈출 지점 하나로 재구성되었으므로 오류 경로가 지우기를
건너뛸 수 없습니다. 그것이 규범적인 FIPS 203 요구이기 때문입니다.
`kpkeKeyGen()`, `kpkeDecrypt()`, `encapsulate()`, 그리고 `MLKEM`의 CSPRNG
추출은 재구성 없이 성공 탈출 지점에서 지웁니다 — 그것들의 이른 반환은 모두
hasher나 샘플러가 고정되고 올바른 크기에서 실패해야 하므로 어느 것도 도달
가능하지 않고, 그 루프들에 상태를 엮어 넣는 것은 얻는 것보다 명료함을 더
많이 쓸 것입니다. 그 차이는 의도적이고 코드에 적어 두었습니다.

### 이것이 의도적으로 건드리지 않는 것

RSA의 EME-PKCS1-v1_5 unpadding과 `CbcTransformer`의 PKCS#7 padding 검사에
있는 인라인 mask 연산은 그대로 둡니다. 어느 것도 "두 버퍼를 비교"하거나
"두 버퍼 중 선택"이 아니며 — 둘 다 masking을 padding 스캔과 엮어
놓았습니다 — 따라서 그것들이 호출할 것이 `CSecure`에 없고, 통합된 모양새를
위해 동작하며 테스트된 constant-time 코드를 다시 쓰는 것은 나쁜 거래가 될
것입니다.

여전히 미결: 어떤 RSA, DSA, EC 개인키 연산도 자기 중간값을 지우지 않습니다.
이제 그것을 위한 프리미티브가 있습니다.

## 개인키 중간값 지우기

`CSecure`는 존재했지만 ML-KEM만 쓰고 있었습니다. 이것은 그것을 양자 이전
알고리즘들에 걸쳐 적용하고, 그렇게 할 수 있기 위해 필요했던 큰 수 대응물을
추가합니다.

### `CBigNum::secureClear()`, 그리고 소멸자가 그것을 하지 않는 이유

개인키와 서명 nonce는 `CBigNum` 값이므로, 스택 버퍼만 지우는 것은 중요한
모든 것을 놓쳤을 것입니다. `secureClear()`는 limb 할당을 지우고 — 그 용량
전체이므로 절단된 길이보다 위의 limb도 함께 — 값을 0으로 되돌립니다.

`~CBigNum()`이 그것을 무조건 하게 하는 것이 훨씬 더 견고할 것이므로, 질문은
그 비용이 얼마인가였습니다. 추측하지 않고 측정했으며, 추측이 틀렸습니다.
1–3%로 추정했는데 **비대칭 테스트 모음 전체에서 +22%, X25519 하나에서는
+32%**였습니다. 스칼라 곱은 아주 많은 단명 임시 객체를 만들고 그 대부분이
공개 중간값을 담고 있으며, 각 지우기가 인라인될 수 없는 간접 호출입니다.
그래서 선택적으로 남았습니다. 이름이 붙은 비밀에만 적용하는 것은 그에 비해
측정되지 않습니다 — 지우기가 없는 빌드가 어떤 실행에서는 그것이 있는 빌드보다
실제로 *더 빨리* 측정되었는데, 그것이 그 비용이 노이즈 바닥보다 얼마나 아래에
있는지를 보여 줍니다.

그 대가로 실재하는 한계가 생기고, 암시로 두는 대신 헤더에 진술했습니다.
`secureClear()`는 호출자가 이름을 댄 값에만 도달합니다. 표현식 안에서, 또는
`modExp()`/`modInverse()` 안에서 만들어진 임시 객체는 지워지지 않고
해제됩니다. 이것은 비밀이 해제된 메모리에 앉아 있는 창을 좁힙니다. 닫지는
않습니다.

### 무엇이 지워졌고, 왜 그것들인가

기준은 "비밀인가"가 아니라 "노출이 치명적인가"였습니다.

- **ECDSA/ECDSA2/DSA 서명**: nonce `k`와 그 옆의 `d*r`/`x*r` 곱입니다. 어느
  하나든 발행된 서명에서 개인키를 곧바로 내놓습니다 —
  `d = (s*k - z)/r mod n`, 또는 `d = dr/r mod n`입니다. 재시도 루프를 나가는
  모든 경로에서 지우며, 재시도 경로 자체도 포함합니다. 그쪽은 0인 `r`이나
  역원이 없는 `k`가 필요하므로 깨진 CSPRNG가 아니면 도달 불가능합니다. 각각
  세 줄이고, 그것을 다시 따져 보지 않아도 된다는 값을 합니다.
- **Ed25519/Ed448 서명**: nonce와 그 뒤의 확장된 시드입니다. EdDSA는 `k`가
  공개인 상태로 `S = r + k*s mod L`을 발행하므로, 서명 하나에 대해 `r`을
  알아내면 `s`가 복구됩니다 — nonce가 키와 정확히 같은 정도로 민감하고,
  그것이 `prefix`와 `rHash`를 같은 비밀로 만듭니다. 그것들이 nonce를
  결정하기 때문입니다. `k*s` 곱도 함께인데, `k`가 공개이므로 그것이 `s`를
  건네줍니다. 각각은 필요하지 않게 되는 자리에서 지워지며, 그래서 무엇이든
  살아 있는 탈출 지점이 정확히 하나 남습니다.
- **X25519**: clamp된 스칼라(인코딩만 빼면 개인키이고, 모든 스칼라 곱에서
  다시 계산됩니다)와 공유 비밀입니다.
- **RSA**: CRT 중간값들입니다. 이것들은 계산되는 값보다 덜이 아니라 *더*
  민감합니다. `m1`은 `m mod p`이므로 `m - m1`은 `p`의 배수이고
  `gcd(m - m1, n)`은 정확히 `p`입니다 — 그리고 서명할 때 `m`은 발행되는
  서명입니다. `decryptBlock`의 padding된 평문 버퍼도, 그 세 탈출 지점
  전부에서 함께입니다. 그것이 위의 constant-time unpadding에 식별자를
  추가하는 대신 경로들이 같은 일을 하게 유지합니다.

### 아무것도 깨뜨리지 않았다는 증거

여기서 중요한 검사는 결정론적 기지 응답 테스트입니다. 과도하게 적극적인
지우기는 아직 쓰이는 값을 망가뜨릴 것이고, RFC 8032의 EdDSA 벡터, CAVP의
ECDSA/DSA 벡터, 그리고 RSA KAT 모두가 정확한 기대 바이트를 재현합니다. 그
전부가 Debug와 Release 양쪽에서 나머지 95개 테스트 모음과 함께 여전히
통과합니다.

## 포스트 양자: ML-DSA의 환 연산

5단계의 시작입니다. `src/crypto/asyms/mldsaring.hpp`/`.cpp`가 `MlDsaRing`을
담고 있습니다. q = 8380417인 R_q = Z_q[X]/(X^256 + 1), 그 위의 NTT, 그리고
ML-DSA의 서명 루프가 의존하는 두 계수 연산입니다.

`MlKemRing`의 파라미터화가 아니라 별개 단위이며, 그 이유는 상수보다 깊습니다.

- **전체적으로 `int64_t`.** q = 2^23 − 2^13 + 1이므로 두 계수의 곱이 약
  7.0e13에 이릅니다 — `int32_t`를 네 자릿수 지나칩니다. ML-KEM의 환에서는
  같은 곱이 `int32_t`에 넉넉히 들어가므로, 그 습관을 그대로 가져오는 것은
  스타일 차이가 아니라 조용한 wraparound가 될 것입니다. 트위들 테이블
  생성기도 물리는데, 거기서 `ZETA * acc`가 약 1.5e10에 이릅니다.
  `MlKemRing`의 대응물은 거기서 `int32_t`를 아주 안전하게 쓰므로, 그것을
  복사하는 것은 틀렸을 것입니다.
- **NTT가 완전합니다.** ζ = 1753의 위수가 256이 아니라 정확히 **512**이므로
  X^256 + 1이 끝까지 256개 1차 인자로 쪼개집니다. 8단, 256개 독립 평가점입니다.
  ML-KEM의 변환은 한 단 앞에서 멈추고 128개 1차 블록을 남기는데, 그것들은
  기본 경우 곱셈과 두 번째 트위들 테이블이 필요합니다. 그래서 여기의
  `multiplyNtt()`는 평범한 pointwise 곱셈이고 `gammas()`는 아예 없습니다.
- **`bitRev7`이 아니라 `bitRev8`.**

더해서 `centered()`(FIPS 204의 `mod±`. (−q/2, q/2] 안의 대표원)와
`infinityNorm()`이 있습니다. 그 norm이 호출자가 아니라 환에 속하는 이유는
ML-DSA의 서명 루프가 정확히 그 양을 기준으로 거부하기 때문입니다 — 그리고
그것은 *중심화된* 대표원에 대해 취해져야 하므로, 중심화를 건너뛴 구현은
답이 3인 자리에서 q−1을 보게 되고, 그 다음 모든 것을 거부하거나 아무것도
거부하지 않을 것입니다.

### C++를 쓰기 전에 검증

ML-KEM의 환과 같은 규율이고, 같은 방식으로 값을 했습니다 — 구현이 첫 실행에서
올바랐습니다. 명세 본문에서 만든 Python 참조가 미리 확립한 것:

- ζ = 1753의 위수가 정확히 512이고 ζ^256 = −1(그래서 변환이 끝까지
  진행됩니다),
- FIPS 204 부록 B에 인쇄된 zeta 255개 전부가 ζ^BitRev8(k) mod q와
  일치한다는 것 — 표는 전사된 것이 아니라 발행물 자체에서 추출했습니다,
- 알고리즘 42의 상수 8347681이 단순히 256⁻¹ mod q라는 것. 복사하지 않고
  유도했습니다,
- NTT가 왕복하고 그 pointwise 곱이 schoolbook negacyclic 합성곱과
  일치한다는 것. 무작위 다항식 쌍 200개에 걸쳐서입니다,
- 그리고 그 변환이 무작위 다항식 50개에 대해 dilithium-py 1.4.0과
  일치한다는 것.

### 테스트는 의도적으로 왕복에 의존하지 않습니다

FIPS 204는 NTT의 종단 동작만이 아니라 정확한 표현을 고정하므로, 자기 자신을
역으로 돌리면서 계수를 표준과 다르게 순열하는 변환은 자기 일관적이면서
아무것과도 상호운용하지 않습니다. 테스트 모음은 그 표를 부록 B에 인쇄된 값에
대조하고 *그리고* square-and-multiply로 다시 유도하며(구현은 반복 곱셈을
씁니다), X^256 = −1을 직접 단정하고, NTT 영역 곱셈을 schoolbook 합성곱에
대조합니다.

실패할 수 없는 테스트 모음은 값이 거의 없으므로, 네거티브 컨트롤 둘이 그것이
물린다는 것을 확인합니다.

- 변환을 8단 대신 **7단**으로 만드는 것 — ML-KEM의 모양이고, 그래도 완벽히
  왕복합니다 — 은 테스트 케이스 4개에 걸쳐 단정 4개를 실패시킵니다.
- zeta를 **Montgomery 형태로** 저장하는 것, 즉 FIPS 204 부록 A가 구현들이
  보통 그렇게 한다고 경고하는 것은 5개를 실패시킵니다.

테스트 케이스 13개, 단정 108,974개.

## ML-KEM을 `crypto/kems`로, ML-DSA를 `crypto/asyms`로 통합

배치 변경이고 동작 변화는 없습니다. `crypto/pq/`는 없어졌습니다.

`include/certpp/crypto/pq/mlkem.hpp`를
`include/certpp/crypto/kems/mlkem.hpp`에 합쳤으므로, 이제 공개 헤더 하나가
`SMlKemPoly`, `SMlKemParams`, `CMlKemSampler`, `CMlKem`, `MLKEM`을 선언합니다
— 알고리즘과 그 `IKem` 형태를 함께입니다. 공개 헤더당 `.cpp` 하나가
컨벤션이므로 두 `.cpp` 파일도 거기에 맞춰 합쳤습니다.
`src/crypto/kems/mlkem.cpp`는 이제 약 1,050줄이고, 알고리즘과 래퍼 사이를
배너 주석으로 나눕니다. `mlkemsampler.cpp`, `mlkemring.*`,
`mlkemcodec.*`가 그 옆으로 `src/crypto/kems/` 아래로 옮겨 갔습니다.

**ML-DSA는 `crypto/kems/`가 아니라 `crypto/asyms/`로 갔습니다.** 지시는
`src/crypto/pq/`에서 모든 것을 옮기라는 것이었고, `mldsaring`을 `kems/`
아래에 두는 것은 *서명* 알고리즘의 환을 키 캡슐화 이름으로 부르는 일이 될
것이었습니다 — 그래서 5단계의 `mldsa.hpp`가 향하는 곳으로 갔고, 그것도
`crypto/pq/`를 똑같이 비웁니다.

파생 변경들:

- private 헤더 가드를 새 경로에 맞춰 이름을 바꿨습니다
  (`__SRC_CRYPTO_KEMS_MLKEMRING_HPP__`,
  `__SRC_CRYPTO_ASYMS_MLDSARING_HPP__`).
- 테스트를 거울처럼 옮겼습니다.
  `tests/crypto/kems/{mlkemring,mlkemcodec}.cpp`와
  `tests/crypto/asyms/mldsaring.cpp`입니다. ACVP 벡터 테스트가 기존 `IKem`
  테스트의 이름과 충돌했으므로 `tests/crypto/kems/kat_mlkem.cpp`가
  되었습니다 — `crypto/asyms/`에 이미 있는 `kat_rsa`/`kat_dsa`/`kat_ecdsa`
  명명과 맞춥니다.
- `CMakeLists.txt`의 private 테스트 소스 규칙이 더는 한 디렉터리를 기준으로
  동작하지 않습니다. 그 단위들이 이제 두 곳에 살기 때문입니다. 대신 두
  조건에서 목록을 만듭니다. `tests/crypto/kems/` 아래의 것은 무엇이든
  ML-KEM의 ring과 codec을 받고, `crypto/asyms/mldsaring`만이 ML-DSA의 ring을
  받습니다 — 그것을 컴파일해 넣을 이유가 없는 다른 스물몇 개를 담고 있는
  `crypto/asyms/`가 아니라 그 테스트 하나에 국한됩니다.

조용히 건너뛴 테스트도 녹색일 것이므로, 녹색 체크만이 아니라 단정 개수로
검증했습니다. 영향받은 실행 파일 다섯 개 전부가 옮기기 전과 정확히 같은
합계를 보고하고(kat_mlkem 2464, mlkem 232, mlkemring 1566, mlkemcodec
104056, mldsaring 108974), 테스트 모음은 96/96입니다.

## 포스트 양자: ML-DSA의 라운딩과 hint 기계

FIPS 204 7.4이고, `MlDsaRounding`(`src/crypto/asyms/mldsarounding.hpp`)
입니다. `power2Round`, `decompose`, `highBits`/`lowBits`, `makeHint`,
`useHint`이고 스칼라 버전과 다항식별 버전이 있습니다. 옆의 ring처럼 `src/`에
private입니다.

hint 메커니즘이 이 전부가 존재하는 이유입니다. 서명은 w1 자체가 아니라 계수당
한 비트를 담고, 검증자는 자기 근사와 그 비트들로
`HighBits(w − c·s2 + c·t0)`를 재구성합니다 — 이는 `useHint()`가
`makeHint()`를 정확히 역으로 돌릴 때만, 그리고 교란이 γ₂ 안에 머무는 동안만
동작하며, 그 경계는 서명 루프가 그것을 호출하기 전에 강제해야 합니다. Python
패스는 그 경계가 장식이 아니라 중요하다는 것을 확인했습니다. 그 밖에서는
항등식이 약 3분의 2의 경우 실패합니다.

### 검증이 잡아낸 틀린 가정

주석에, `decompose()`의 `(q−1)` 예외가 `r == q − 1` "외에는 아무 데서도
물지 않는다"고 적어 두었습니다. 데이터는 다르게 말했고, 그 실수가 솔깃한
것이므로 기록할 만합니다.

FIPS 204 알고리즘 36은 `r+ − r0 == q − 1`로 분기합니다. 그것은 단일 값
`q − 1`에 대한 검사처럼 읽히고, 그것을 `r == q − 1`로 단순화하는 것은 당연해
보이는 정리입니다. 틀렸습니다. 그 조건은 폭 γ₂의 최상단 구간 전체에서
성립합니다 — γ₂ = (q−1)/88에서 **95,232개 값(q의 1.14%)**, (q−1)/32에서는
**261,888개(3.1%)**입니다. 그 구간의 모든 계수는 버킷 0에 떨어져야 합니다.
점 비교는 그중 95,231개를 한 버킷 높게 놓을 것입니다. 결과가 자기 일관적으로
남으므로, 외부 벡터나 버킷 범위 단정 외에는 아무것도 알아차리지 못할 것입니다.

헤더에 문서화된 두 번째 함정: 여기의 `mod±`는 `MlDsaRing::centered()`가
**아닙니다**. 그쪽은 홀수인 q로 축약하므로 분기점이 (q−1)/2에 있습니다.
이쪽은 둘 다 짝수인 2^d와 2γ₂로 축약하고, 범위는 (−m/2, m/2]이며 m/2 자체는
양수로 남습니다. 같은 정의(FIPS 204 2.3), 다른 모듈러스, 다른 경계 —
그래서 이 단위는 ring의 것에 손을 뻗는 대신 자기 `modPm()`을 지닙니다.
거기서의 off-by-one은 2γ₂마다 계수 값 하나를 잘못 분류합니다.

### 먼저 검증하고, 그 다음 함정에 대해 테스트

다섯 연산 전부가 파라미터 집합당 값 100,000개에 걸쳐 dilithium-py 1.4.0과
일치했고, 역변환 항등식은 집합당 무작위 (r, z) 쌍 200,000개에 걸쳐
일치했습니다. C++를 쓰기 전에 말이고 — 그것이 다시, 첫 실행에서 올발랐던
이유입니다.

테스트는 깨지기 쉬운 케이스에 무작위 샘플링에 의존하지 않습니다. 모든 버킷
경계를 z = ±γ₂와 ±1에 대해 열거하고, 예외 구간을 걸으며, `r0 == 0` 동점을
명시적으로 확인합니다(그것은 "양수가 아님"으로 세어지므로, 설정된 hint가
*아래로* 내려갑니다. 그것을 반대로 가르면 경계에 앉은 계수들이 정확히
깨집니다). 네거티브 컨트롤 둘이 테스트 모음이 물린다는 것을 확인합니다.

- 예외를 `rp == q − 1`로 단순화하면 케이스 4개에 걸쳐 단정 4개가 실패합니다.
- `r0 == 0` 동점을 위로 올라가게 뒤집으면 2개 케이스에 걸쳐 5개가 실패합니다.

테스트 케이스 9개, 단정 1,849,585개.

## 포스트 양자: ML-DSA의 비트 패킹과 hint 인코딩

FIPS 204 7.1–7.2이고, `MlDsaCodec`(`src/crypto/asyms/mldsacodec.hpp`)입니다.
[0, b]의 계수를 위한 `simpleBitPack`/`simpleBitUnpack`, [−a, b]를 위한
`bitPack`/`bitUnpack`(`b − w_i`를 인코드하는데, 그것이 부호 없는 비트 필드가
부호 있는 범위를 담을 수 있게 하는 요소입니다), 그리고
`hintBitPack`/`hintBitUnpack`입니다.

### 디코딩은 범위를 함의하지 않습니다

FIPS 204가 알고리즘 17 바로 아래의 산문에서 이것을 스스로 경고합니다. 어떤
(a, b)에 대해서는 명목 범위 밖의 계수로 디코드되는 바이트 문자열이
존재하고, 그것은 신뢰할 수 없는 출처의 입력에 대해 우려할 일입니다. Python
패스는 ML-DSA의 용도 중 정확히 어느 것이 영향을 받는지 알아냈는데, 그 답이
호출자가 어디서 검사해야 하는지를 결정하기 때문입니다.

| 필드 | (a, b) | 폭 | 디코드되는 범위 | 안전? |
|---|---|---|---|---|
| `t1` | b = 2¹⁰−1 | 10 | [0, 1023] | 예 |
| `t0` | 2¹²−1, 2¹² | 13 | [−4095, 4096] | 예 |
| `z` | γ₁−1, γ₁ | 18 또는 20 | 정확 | 예 |
| `s1`/`s2`, η=2 | 2, 2 | 3 | **−5**까지 | **아니오** |
| `s1`/`s2`, η=4 | 4, 4 | 4 | **−11**까지 | **아니오** |
| `w1`, γ₂=(q−1)/88 | b = 43 | 6 | **63**까지 | **아니오**. 단 디코드되는 일이 없음 |

따라서 `skDecode`는 s1/s2의 범위를 검사해야 하며 — 그것이 FIPS 204 자신의
버전이 그렇게 하는 이유입니다 — t0/t1/z는 검사가 전혀 필요 없고, w1은
인코드만 됩니다(해시에 먹여집니다. 상대에게서 도착하는 일이 없습니다).
필요한 경우를 위해 `inRange()`가 있습니다. ML-KEM의 `ByteDecode_12`와 같은
모양의 위험입니다.

### hint 디코더, 그리고 거부가 왜 셋으로 분리되어 있는가

`hintBitUnpack`은 표준에서 가장 날카로운 디코드 함정입니다. 세 가지 *서로
다른* 조건에서 거부해야 하며, 각각이 이 인코딩을 단사로 유지하기 위해
존재합니다 — 그리고 단사가 아닌 인코딩은 무효화되지 않고 변경될 수 있는
서명입니다.

1. 뒤로 가거나 ω를 넘는 누적 인덱스,
2. **한 다항식 안에서** 엄격히 증가하지 않는 위치(같은 것은 증가하지 않는
   것으로 세어지는데, 그러지 않으면 한 계수가 두 번 지칭될 수 있습니다),
3. 마지막으로 읽은 위치 이후 첫 ω 안에 남은 0이 아닌 바이트 — 이것이 없으면
   쓰이지 않는 꼬리에 임의의 데이터를 채워 넣을 수 있습니다.

(2)의 범위는 양쪽으로 작용하며, 그것이 내재화할 만한 부분입니다. 비교는 각
다항식 경계에서 초기화되므로, 위치는 `h[i]`의 끝에서 `h[i+1]`의 시작으로
갈 때 정당하게 *감소*합니다. 배열 전체에 걸쳐 단조성을 검사하는 구현은 더
엄격해 보이면서 그냥 깨진 것입니다 — 유효한 서명을 거부합니다.

네거티브 컨트롤 넷, 각각 동작 하나를 끈 것입니다.

| 변경 | 결과 |
|---|---|
| (1) 누적 인덱스 검사 제거 | 단정 1개 실패 |
| (2) 엄격 증가 검사 제거 | 2개 실패 |
| (3) 남은 바이트 검사 제거 | 4개 실패 |
| (2b) 배열 전체에 걸친 단조성 | 2개 실패, 그리고 단정 14,629개 중 6,339개만 통과 — 유효한 입력을 거부합니다 |

거부된 디코드는 또한 호출자의 다항식들을 반쯤 쓴 상태가 아니라 건드리지 않은
상태로 남깁니다. 호출자가 `false`를 "이 서명은 무효"로 취급하려는
중이고, 부분적으로 채워진 hint 벡터는 나중에 우연히 쓰이게 되는 종류의
것이기 때문입니다.

### 검증

명세 본문에 대조해 Python으로 먼저 쓰고 dilithium-py 1.4.0에 교차
확인했습니다. 패킹은 ML-DSA가 쓰는 모든 (a, b)에 걸쳐 다항식 2,400개에서
일치했고, 언패킹은 1,500개에서, hint 왕복은 세 파라미터 집합의 (k, ω) 전부에
걸친 무작위 hint 벡터 6,000개에서 일치했습니다. 바이트 배치는 추가로 C++
테스트에서 손으로 계산한 바이트에 대해 못 박혀 있으며, 바이트 경계에 걸친
10비트 계수 하나를 포함합니다 — 각 바이트 안에서 비트를 빅엔디언으로
담으면 그래도 왕복하면서 아무것과도 상호운용하지 않을 것입니다.

테스트 케이스 9개, 단정 14,629개. Debug와 Release에서 98/98입니다.

## 포스트 양자: ML-DSA의 거부 샘플러

FIPS 204 7.3이고, `MlDsaSampler`입니다. `SampleInBall`, `RejNTTPoly`,
`RejBoundedPoly`, 그리고 그것들 위에 만들어진
`ExpandA`/`ExpandS`/`ExpandMask` 절차, 더해서 7.1의 두 계수 추출기입니다.

세 샘플러 모두 시드에 따라 달라지는 양의 XOF 스트림을 소비합니다 — 그것이
거부 샘플링이 뜻하는 것입니다 — 그래서 `finish()`에 고정 길이를 요청하는
대신 `squeeze()`로 읽습니다. ML-KEM의 `SampleNTT`에 이어 증분 스퀴징의 두
번째 구체적 소비자입니다.

외부 벡터 없이는 보이지 않는 세부 셋:

- **XOF는 교체 가능하지 않습니다.** `RejNTTPoly`와 `ExpandA`는
  SHAKE128(표준의 `G`)을 쓰고, `SampleInBall`, `RejBoundedPoly`, `ExpandS`,
  `ExpandMask`는 SHAKE256(`H`)을 씁니다.
- **`ExpandA`의 시드가 전치되어 있습니다.** `A[r][s]`에 대해
  `rho || s || r`로, 행 바이트 앞에 *열* 바이트가 오며, ML-KEM의
  `SampleNTT(rho || j || i)`와 정확히 같습니다. 거꾸로 하면 행렬이 전치되고
  모든 키 바이트가 달라집니다.
- **`CoeffFromHalfByte`의 두 경우는 대칭이 아닙니다.** η = 2에서는 b < 15에
  대해 `2 − (b mod 5)`이고 — 입력 15개가 출력 5개로, 각각 셋씩 — η = 4에서는
  b < 9에 대해 `4 − b`입니다. 첫 번째를 "b < 5"로 읽으면 유효한 입력의 3분의
  2를 거부합니다.

자신도 dilithium-py 1.4.0에 교차 확인된 Python 참조가 생성한 기지 응답에
대해 고정했으며, 그것이 SampleInBall, 완전한 ExpandA 행렬, 그리고 세 파라미터
집합 전부에 대한 두 ExpandS 벡터에서 일치했습니다. 테스트는 또한 ExpandA
바이트 순서를 지문만을 통해서가 아니라 직접 증명하고, `s2[0]`이 `s1[0]`과
다른지 확인합니다 — ExpandS가 `r + l`에서 이어 가는 대신 인덱스 카운터를
다시 시작했다면 그 둘이 동일할 것입니다.

테스트 케이스 9개, 단정 8,004개.

## 이식성: Linux/GCC에서 빌드하기, 그리고 `find_package` 지원

다운스트림에서 보고되었습니다 — cppskit의 libcskcwk가 P2P 노드 인증서 인증을
위해 libcertpp를 설치된 static 패키지로 소비하는데, GCC 13.3을 쓰는 Ubuntu
24.04에서 빌드할 수 없었습니다. 서로 다른 문제 넷이고, 전부 MSVC가 가리고
있던 것들입니다.

### 1. 의존 멤버 템플릿에 `template`이 빠짐

`TString`의 변환 생성자와 그 교차 타입 `append()` 둘 다 객체의 타입이 템플릿
파라미터에 의존하는 상태로 `cStr.convertTo<T>()`를 호출합니다. 표준 C++는
`cStr.template convertTo<T>()`를 요구합니다. 그것이 없으면 `<`가 작다로
파싱됩니다. MSVC는 벌거벗은 형태를 받아들이고 GCC와 Clang은 거부하며,
`string.hpp`가 거의 모든 곳에 포함되므로 이것이 대부분의 번역 단위를
실패시켰습니다. 보고는 한 지점을 지목했지만, 둘이었습니다.

### 2. `SByteSpan&`에 묶인 임시 객체 (호출 지점 13곳)

`hasher->finish(SByteSpan(...))`는 임시 객체를 const가 아닌 lvalue 참조에
넘기며, MSVC는 그것을 확장으로 허용하고 GCC/Clang은 거부합니다.

13개 지점마다 지역 변수에 이름을 붙이는 대신, `IHasher::finish()`가 이제
`const SByteSpan&`를 받습니다. 그것이 편의적인 수정이 아니라 올바른
수정입니다. 어떤 구현도 그 span을 다시 대입한 적이 없고, 같은 클래스의 형제
`SHAKE*::squeeze()`가 이미 `const SByteSpan&`를 받고 있었고, 이 라이브러리의
더 새로운 API들(`CSecure::zero`, `CMlKem`, `MlDsaCodec`)이 모두 const 형태를
씁니다. span의 `data`는 `uint8_t*`이므로 버퍼는 여전히 쓸 수 있습니다. 다시
대입하는 것만 막힙니다.

그 구분은 일괄적이 아니라 원칙적입니다. `IAsymmetricContext::sign()`과
`CBase64::finish()`는 자기 span을 쓴 바이트로 진짜로
절단하므로(`out = SByteSpan(out.data, n)`), 그쪽은 `SByteSpan&`를 유지합니다.

이것은 라이브러리 밖에서 `IHasher`를 구현하는 사람에게는 API 변경입니다 —
override의 시그니처가 일치해야 합니다.

보고된 것보다 더 많은 것을 고치는 것으로도 드러났습니다. `src/`의 13개 지점은
보고자가 부딪친 것들이었지만, `tests/`와 `examples/`가 7곳 더에서 `finish()`에
임시 객체를 넘깁니다 — `-DCERTPP_BUILD_TESTS=OFF
-DCERTPP_BUILD_EXAMPLES=OFF`였던 그들의 빌드에서는 보이지 않았던 것입니다.
13개 호출 지점을 손으로 패치하면 그것들이 깨진 채 남았을 것이고 다음
비-MSVC 빌드가 그것들에 부딪쳤을 것입니다. 시그니처 변경이 20개 전부를
고칩니다.

### 3. ADX/BMI2 경로에서의 `uint64_t*` 대 `unsigned long long*`

`_mulx_u64`/`_addcarry_u64`는 `unsigned long long*`으로 선언되어 있습니다.
LP64 타깃에서 `uint64_t`는 `unsigned long`입니다 — 같은 폭의 *구별되는*
타입입니다 — 그래서 `&x`를 넘기는 것이 거기서는 명백한 오류이면서, 그 둘이
일치하는 Windows에서는 잘 컴파일됩니다. `mulAccelerated()`의 packed 64비트
배열과 지역 변수들을 이제 `unsigned long long`으로 바로 선언합니다. 포인터를
캐스팅하는 대신인데, 그쪽은 컴파일은 되지만 한 정수 타입을 다른 것으로
aliasing하는 일입니다.

### 4. 설치 후 `find_package(certpp)`가 동작하지 않음

install이 `certpp-targets.cmake`만 썼고, CMake는 `certpp-config.cmake`라는
이름을 찾습니다. `CMakePackageConfigHelpers`를 통해 그것과
`SameMajorVersion` `certpp-config-version.cmake`를 추가했습니다. config
파일은 의도적으로 최소한입니다 — 첫 초안에는 투기적인
`find_dependency(Threads)`가 있었는데, grep으로 라이브러리가 스레딩을 전혀
쓰지 않음을 확인한 뒤 제거했습니다. 하나뿐인 실제 시스템 의존성인 `bcrypt`는
이미 export된 타깃에 `$<LINK_ONLY:bcrypt>`로 담겨 있습니다.

### 이것들을 어떻게 검증했는가

눈으로 보아서가 아닙니다. Clang을 `-fno-ms-compatibility
-fno-delayed-template-parsing`으로 돌렸는데, 그것은 Clang이 GCC가 거부하는
것과 같은 구문을 거부하게 만듭니다. 라이브러리의 *모든* 소스 파일에
걸쳐서였고 — 보고된 rvalue 바인딩 오류 13개를 정확히 재현했고, 보고가 짚지
않은 두 번째 `template` 지점을 찾았으며, 지금은 아무것도 보고하지 않습니다.
문제 1, 2, 4는 추가로 종단 간으로 덮여 있습니다. 라이브러리를 보고자의
정확한 옵션(`-DCERTPP_BUILD_SHARED=OFF -DCERTPP_BUILD_TESTS=OFF
-DCERTPP_BUILD_EXAMPLES=OFF`)으로 구성하고, 어떤 prefix에 설치하고, 그 다음
별개 프로젝트가 `find_package(certpp REQUIRED)`를 통해 소비하게 했습니다 —
P-256 노드 키로 해시하고 서명하고 검증하며, 임시 객체를 넘기는
`finish(SByteSpan(...))` 호출, 즉 전에 실패했던 바로 그 구문을 포함해서입니다.

문제 3은 `uint64_t`가 `unsigned long long`*인* Windows에서는 재현할 수
없으므로, 타입 분석과 더불어 그 경로를 연습하는 독립 참조 곱셈에 대조하는
기존 `mul()` 교차 확인 테스트에 의존합니다.

## 포스트 양자: ML-DSA의 파라미터 집합

`MlDsaParams`(`src/crypto/asyms/mldsaparams.hpp`)가 FIPS 204 표 1을 담고
있고, `SMlKemParams`가 그러는 방식으로 거기서 모든 길이를 유도합니다 — 그리고
같은 이유에서입니다. 잘못 타이핑한 키나 서명 길이가 내부적으로는 일관된
상태로 남아 외부 벡터에 대해서만 드러나기 때문입니다.

유도된 수치들은 FIPS 204 표 2에 대조해 `static_assert`되어 있으므로, 불일치가
테스트 실행이 아니라 빌드를 실패시킵니다. 아홉 개 전부 일치합니다. 공개키
1312/1952/2592, 개인키 2560/4032/4896, 서명 2420/3309/4627입니다. 테스트는
추가로 각 크기를 *두 번째* 방식으로 다시 유도하는데 — 키나 서명이 실제로
구성되는 부분들을 합해서입니다 — 자기가 검사하는 공식을 다시 적는 대신
말입니다.

표의 항목 둘은 독자가 기대하는 대로 동작하지 않으며, 어느 쪽 가정이든
조용할 것이므로 둘 다 명시적으로 단정되어 있습니다.

- **η는 보안 수준에 대해 단조가 아닙니다**: 2, 4, 그리고 ML-DSA-87에서 다시
  **2**로 돌아갑니다. 그것을 오르는 것으로 읽으면 ML-DSA-87에 틀린 개인키
  범위*와* 틀린 `sk` 길이를 줍니다. 순전히 다음 독자에게 그것을 명시하기
  위해 `static_assert(P87.eta < P65.eta)`가 있습니다.
- **γ₁은 두 집합 사이에 공유됩니다**: ML-DSA-44에서 2^17, ML-DSA-65와
  ML-DSA-87 *둘 다*에서 2^19이므로, 그것으로는 뒤의 둘을 구별할 수 없습니다.

`maxSignatureBytes()`는 4627이며, 적어 넣은 것이 아니라 ML-DSA-87에서
유도했습니다 — 최종 표준의 수치이고, 4595는 최초 공개 초안의 것이면서 여전히
돌아다니는 값입니다.

테스트는 또한 표를 이미 만들어진 단위들에 대조해 교차 확인합니다.
`highBitsRange()`는 γ₂만으로 계산한
`MlDsaRounding::highBitsRange(gamma2)`와 일치해야 하고(한 숫자에 이르는 두
독립 경로), 모든 집합의 `k`/`l`/`tau`가 샘플러 자신의 최대치에 맞아야 하며,
`omega`가 `HintBitPack`이 그것을 써 넣는 단일 바이트에 맞아야 합니다.

## HMAC과 HKDF, 다운스트림 링크 암호화 핸드셰이크를 위해

다운스트림에서 요청되었습니다. cppskit의 libcskcwk가 노드 대 노드 메시 링크를
암호화해야 합니다. libcertpp에는 이미 키 합의(X25519)와 암호들이 있었고,
빠진 것은 KDF와 AEAD였습니다. 이것이 KDF 쪽 절반입니다.

`CHmac`(`crypto/hmac.hpp`)은 이 라이브러리의 고정 출력 hasher 아무것에
대해서나 RFC 2104를 구현하며, `IHasher`가 쓰는 스트리밍 모양 — 키를 넣는
`reset()`, `push()`, `finish()` — 과 일회성 `compute()`를 지닙니다. 기존
인스턴스에 다시 키를 넣으면 밑의 hasher를 재사용하므로, HKDF의 expand 루프가
출력 블록마다 할당하지 않습니다.

`CHkdf`(`crypto/hkdf.hpp`)는 RFC 5869를 진입점 세 개로 구현합니다.
`extract()`, `expand()`, 그리고 둘을 함께 하는 `derive()`입니다. `IKdf`
계열의 한 구현이 아니라 구체적인 유틸리티이며, `CRng`의 선례를 따릅니다 —
HKDF의 2단계 모양은 어느 쪽에도 맞지 않는 인터페이스 없이는 password 기반
KDF(salt 더하기 반복 횟수, `info` 없음)로 일반화되지 않으므로, 지금 그것을
도입하는 것은 투기적일 것입니다.

### 기록할 만한 결정 둘

**`verify()`는 호출자가 `memcmp`에 손을 뻗지 않게 하려고 존재합니다.** 처음
다른 바이트에서 멈추는 MAC 비교는 공격자에게 자기가 맞힌 접두사가 얼마나
길었는지를 알려 주며, 그것으로 태그를 한 바이트씩 위조하기에 충분합니다.
`CHmac::verify`는 `CSecure::equalsMask`를 거치고, 호출자가 제시한 바이트만
비교하여 RFC 2104 4절의 절단된 태그도 함께 처리합니다.

**블록 크기는 `IHasher`가 아니라 `CHmac`에 있습니다.** HMAC은 해시의 블록
크기(64, 128, 또는 SHA-3의 rate)가 필요하고 `IHasher`는 `byteWidth()`만
노출합니다. 그것을 인터페이스에 올리는 것은 `IHasher`의 생성자와 구현 열
개 전부를 바꾸는 일 — `finish()`의 `const`를 막 흡수한 다운스트림 소비자에게
연달아 두 번째 API 변경 — 이 될 것입니다. 그것을 지역에 유지하는 비용은
나중에 추가된 hasher가 누군가 `blockBytesOf()`를 확장하기까지 HMAC에서
지원되지 않는다는 것이며, 그것은 조용히 틀린 태그를 계산하는 대신 `reset()`
에서 시끄럽게 실패합니다. 두 번째 소비자가 언제든 블록 크기를 필요로 하게
되면, 중복되는 대신 `IHasher`로 옮겨 가야 합니다.

SHAKE128/SHAKE256은 거부됩니다. 그것들은 호출자가 출력 길이를 고르는
XOF이고, RFC 2104는 고정 출력 해시 위에서 정의됩니다. SHA3-256/512는 자기
sponge rate를 써서 받아들여지지만, NIST가 SHA-3에 대해 실제로 권고하는 것은
KMAC입니다.

### 테스트가 내 전사 오류를 두 번 잡아냈습니다

두 모음 다 첫 실행에서 실패했고, 두 경우 모두 구현이 옳고 테스트 데이터가
틀렸습니다. 오타보다 진단한 방식이 더 중요하므로 기록할 만합니다.

- **HMAC**: 전사한 벡터 열다섯 개 중 하나(RFC 4231 케이스 4, SHA-512)가
  틀렸습니다. 추측하는 대신 모든 벡터를 Python의 `hmac` 모듈에 대조했고 —
  14개가 일치했는데, 그것이 오류를 즉시 짚어 내고 C++가 옳음을 증명했습니다.
- **HKDF**: 부록 A 케이스 여섯 개 중 셋이 실패했고, 그 패턴이 단서였습니다 —
  A.2, A.4, A.5가 통과하는 동안 A.1, A.3, A.6이 실패했고, 그 셋은 입력
  하나를 공유합니다. IKM이 RFC 5869가 **22**로 명세하는 곳에서 `0x0b` 21
  옥텟으로 적혀 있었습니다. 기대값은 처음부터 옳았고, 입력이 한 바이트
  짧았습니다. 21, 22, 23 옥텟을 RFC의 발행된 PRK에 대조해 시험하자 한
  단계로 확인되었습니다.

기대값이 전사된 것이 아니라 이 구현에서 생성된 것이었다면, 두 오류 모두
보이지 않았을 것입니다 — 그것이 외부 벡터에 대한 논거 전부입니다.

SHA-1/256/384/512에 걸친 RFC 4231의 케이스 일곱 개와 RFC 5869 부록 A의 여섯
케이스 전부가 이제 통과하며, 각각은 일회성 경로, 서로 다른 네 청크 크기에서의
스트리밍 경로, 그리고 모든 태그 위치에서의 단일 비트 조작을 통해
검사됩니다.

## ChaCha20-Poly1305 AEAD, 다운스트림 링크 암호화를 위해

libcskcwk 요청의 나머지 절반입니다. HMAC/HKDF가 이미 들어와 있으므로, 이것이
노드 대 노드 메시 레코드를 암호화하는 데 필요한 것을 완성합니다. 합의를 위한
X25519, 공유 비밀을 방향별로 쪼개는 HKDF, 그리고 레코드당 인증 암호입니다.

- `CPoly1305`(`crypto/poly1305.hpp`) — RFC 8439 2.5절.
- `CChaCha20Poly1305`(`crypto/aeads/chacha20poly1305.hpp`) — RFC 8439 2.8절.
- `ChaCha20Core`를 `crypto/syms/chacha20.cpp`에서 자기 private 단위로
  추출했습니다. `DesCore`와 `KeccakCore`가 이미 그랬던 방식입니다.

### 코어를 추출해야 했던 이유

AEAD는 ChaCha20 블록 함수를 *서로 다른* 두 카운터에서 필요로 하고,
`ISymmetric`은 어느 쪽도 표현할 수 없습니다. 처음 32바이트가 일회용
Poly1305 키(RFC 8439 2.6절)인 카운터 0과, 블록 0이 그 키에 쓰이므로
페이로드를 위한 카운터 1 이후입니다. 스트림 암호는 항상 0에서 시작하므로
공개 인터페이스를 통해 재사용하는 것은 선택지가 아니었고, 블록 함수를
중복시키는 것은 더 나빴을 것입니다.

### API가 보장하는 것, 그리고 그 이유

요청은 제자리 연산, 재사용 가능한 컨텍스트, 그리고 constant-time `open`을
요구했습니다. 셋 다 들어 있고, 그중 하나는 명시할 만한 결과를 지닙니다.

**`open()`은 평문 바이트를 하나라도 쓰기 전에 검증합니다.** 태그가
ciphertext를 덮으므로 입력이 아직 온전한 동안 검사할 수 있습니다 — 그리고
`out`이 `in`과 aliasing할 수 있으므로, 당연해 보이는 복호화-후-검증 순서는
위조를 알아차리기 *전에* 호출자의 유일한 ciphertext 사본을 인증되지 않은
평문으로 덮어쓸 것입니다. 따라서 실패한 `open()`은 버퍼를 정확히 있던 대로
남기며, 테스트가 모든 단일 비트 태그 변경(128개)과 모든 단일 바이트
ciphertext 변경에 대해 그것을 단정합니다.

태그 비교는 `memcmp`가 아니라 `CSecure::equalsMask`를 거칩니다. 첫 차이에서
멈추는 비교는 위조된 태그의 얼마가 맞았는지를 드러내며, 그것으로 하나를 한
바이트씩 구성하기에 충분합니다.

`CPoly1305::finish()`는 `IHasher::finish()`처럼 반복 가능한 질의가 아니라
의도적으로 상태를 *소비*합니다. Poly1305는 일회용 MAC입니다 — 한 키 아래의
두 메시지는 공격자가 `r`을 풀어 마음대로 위조하게 합니다 — 그래서 인스턴스를
쓸 수 있는 상태로 두는 것은 바로 그것을 깨뜨리는 오용을 초대할 것입니다.
또한 HMAC과 나란히 공유 MAC 인터페이스를 구현하지 않습니다. HMAC은 키가
들어가고 재사용 가능하며, 이쪽은 둘 다 아니고, 그 둘이 한 인터페이스 뒤에서
교체되게 하는 것은 그 차이를 호출 지점에서 보이지 않게 만들 것입니다.

`padToBlock()`이 자기 연산으로 존재하는 것은 RFC 8439 2.8절의 `pad16`이
메시지를 연장하는 것이 아니라 부분 블록을 닫기 때문입니다. 대신 0을 밀어
넣는 것은 필드 자체가 0으로 끝나는 것과 구별할 수 없을 것이고, AEAD의 네
필드가 서로에게 흘러 들지 않게 유지하는 것이 padding의 요점 전부입니다.

### 발행된 모든 단계에서 RFC에 대조해 검증

여기서는 왕복이 사실상 아무것도 증명하지 않습니다. 있을 법한 오류 각각이
자기 일관적입니다. 그래서 테스트는 RFC 8439 2.5.2(Poly1305), 2.6.2(일회용
키 유도), 2.8.2(완전한 AEAD)를 검사합니다 — 종단 간 것만이 아니라 중간
벡터도 포함해서입니다.

네거티브 컨트롤 넷, 각각이 벡터가 물린다는 것을 확인합니다.

| 변경 | 결과 |
|---|---|
| 키스트림을 1 대신 카운터 0에서 | 단정 3개 실패 |
| MAC 길이 꼬리말 필드를 교환 | 2개 실패 |
| aad와 ciphertext 사이의 `pad16` 생략 | 2개 실패 |
| Poly1305의 `r` clamping을 mask 하나만큼 약화 | 4개 실패 |

그것들 전부가 자기 자신에 대해서는 완벽하게 seal되고 open되는 출력을
만듭니다. RFC의 바이트만이 그것들을 잡아냅니다.

테스트 모음은 또한 cskcwk의 실제 프로토콜 모양을 한 통합 케이스도
포함합니다 — HKDF로 유도한 키 위에 방향당 컨텍스트 하나, 4바이트 접두사
더하기 64비트 카운터 nonce, 제자리에서 seal된 레코드 여덟 개 — 그리고 모든
레코드의 ciphertext와 태그가 다르다는 것, 틀린 카운터 아래에서 재생된
레코드가 거부된다는 것, 반대 방향의 키로는 그것을 열 수 없다는 것을
단정합니다.

새로 추가되거나 변경된 단위 여섯 개 전부를 추가로 Clang에서
`-fno-ms-compatibility`로 검사했으므로, `d297767`에서 고친 이식성 파손을
반복하지 않습니다.

## XChaCha20-Poly1305, nonce가 무작위일 수 있도록

위의 AEAD는 한 키 아래에서 절대 반복되지 않는 nonce가 필요하고, 96비트는
무작위로 골라서 그것을 얻기에는 너무 짧습니다. 생일 충돌이 레코드 약 2^48개
뒤에 일어날 법해지므로 nonce가 카운터여야 하고, 카운터는 재시작을 살아남아야
하며 송신자들 사이에 공유되어서는 안 됩니다.
XChaCha20-Poly1305(draft-irtf-cfrg-xchacha, WireGuard와 libsodium이 쓰는
변종)는 192비트 nonce를 받으며, 그것은 어떤 현실적인 레코드 수에 대해서도
무작위 nonce가 안전할 만큼 깁니다 — 그래서 카운터를 아예 조율할 수 없는
당사자들이 한 키를 쓸 수 있습니다.

- `ChaCha20Core::hchacha20()` — 초안의 nonce 확장 함수.
- `CXChaCha20Poly1305`(`crypto/aeads/xchacha20poly1305.hpp`) — 래퍼로서의
  AEAD입니다. `subkey = HChaCha20(key, nonce[0:16])`, 그 다음 96비트 nonce
  `00000000 || nonce[16:24]`로 그 subkey 아래의 `CChaCha20Poly1305`입니다.

RFC 8439 2.8절을 다시 구현하는 대신 위임하므로, 제자리 aliasing, 카운터 1
시작, MAC 필드 순서, constant-time 쓰기-전-검증이 기존 AEAD의 것이며, 다시
진술된 것이 아니라 물려받은 것입니다. subkey가 nonce에 의존하므로 재사용된
컨텍스트는 아무것도 캐시할 수 없습니다. 그것은 스택 `CChaCha20Poly1305`에
키를 넣고 자기 소멸자에서 스스로를 0으로 만드는 스택 구조체에 들어가며,
그것이 `mutable` 멤버나 const가 아닌 `seal()` 없이 호출당 할당 없음 계약을
유지합니다.

### HChaCha20은 블록 함수가 아닙니다

20라운드를 공유하며, 그것이 `ChaCha20Core`에 사는 이유입니다. 그리고 두
가지로 다른데, 각각이 잘못되면 *자기 일관적인* 무언가를 만들어 냅니다.
128비트 nonce가 워드 12–15를 채우고(카운터가 없습니다), 그리고 **feed-forward가
없습니다** — 라운드의 출력이 그대로, 워드 0–3 그 다음 12–15로 나옵니다.
`block()`을 그대로 재사용하면 자기 자신에 대해서는 완벽히 왕복하면서 다른
어떤 구현과도 일치하지 않는 subkey가 나옵니다.

구성 전체를 C++가 존재하기 전에 Python으로 먼저 쓰고 초안의 벡터에 대조해
검사했습니다 — 2.2.1절(HChaCha20), A.3.1(AEAD), 그리고 A.3.2.2(카운터 1에서의
XChaCha20 스트림. MAC과 독립적으로 내부 nonce를 고정합니다)입니다.

### 네거티브 컨트롤

| 변경 | 결과 |
|---|---|
| HChaCha20에 feed-forward를 되돌려 추가 | 테스트 케이스 5개 실패 |
| subkey를 0–3 ‖ 12–15 대신 출력 워드 0–7로 취함 | 5개 실패 |
| 내부 nonce를 `nonce[16:24] ‖ 00000000`으로 구성 | 3개 실패 |
| `open()`이 true를 반환하도록 강제 | 2개 실패(조작된 AAD 케이스 포함) |

세 번째가 교훈적인 것입니다. subkey가 어느 쪽이든 동일하므로 HChaCha20
벡터는 여전히 통과하고 AEAD ciphertext만이 그것을 잡아냅니다. 그것이
테스트가 종단 간만이 아니라 subkey를 ciphertext와 별도로 검사하는
이유입니다 — 종단 간 벡터가 실패할 때, subkey 단정이 어느 쪽 절반이
틀렸는지를 말해 줍니다.

## Fe25519: X25519를 위한 constant-time 필드

AEAD 요청과 함께 다운스트림에서 제기되었습니다. X25519 자신의 테스트 주석이
그 밑의 큰 수 산술이 constant-time이 아니라고 적어 두고 있는데, 그것은
임시 키를 쓰는 온라인 핸드셰이크에 대해서는 이론적인 것이 아니라 살아 있는
side channel입니다. 이것이 그것을 고치기 위한 기반이고, ladder 재작성이
뒤따릅니다.

`Fe25519`(`src/crypto/asyms/fe25519.hpp`)는 GF(2^255 − 19)를 radix 2^25.5의
부호 있는 limb 열 개로 구현하며, 데이터에 의존하는 분기, 메모리 인덱스,
나눗셈이 없습니다.

### `CBigNum`으로는 이것을 하게 만들 수 없는 이유

`CBigNum`은 *정규* limb 배열을 저장합니다 — 앞쪽 0 limb이 잘려 나갑니다 —
그래서 limb 개수, 따라서 수행되는 작업량이 값에 의존합니다. 그것에 대한
모든 덧셈, 곱셈, 축약이 타이밍을 통해 자기 피연산자에 대해 무언가를
흘립니다. 인증서 검증에 대해서는 그것이 용인될 만하고, 핸드셰이크에
대해서는 아닙니다. `Fe25519`의 limb 개수는 값과 무관하게 열 개로
고정됩니다.

`CBigNum::condSwap`이 가장 날카로운 예입니다. 그 자신의 문서가 그것이
평범한 분기임을 인정합니다. Montgomery ladder에서 swap 조건은 개인 스칼라의
한 비트*이므로*, 그 분기가 반복마다 키를 한 비트씩 흘립니다.

### 왜 2^51이 아니라 radix 2^25.5인가

51비트 radix가 더 빠른 배치이고 대부분의 64비트 구현이 쓰는 것이지만, 그
곱은 128비트 산술을 필요로 하고 **MSVC에는 `__int128`이 없습니다**. 26비트와
25비트 limb을 번갈아 쓰면 모든 곱이 `int64_t`에 들어갑니다. 최악의 경우
곱셈 누산기가 10 × (2^26−1)² × 38 = **2^60**이고, 여유 세 비트이며, 테스트가
그 경계를 단정하므로 나중에 radix를 바꾸는 것이 그것을 조용히 넘칠 수
없습니다.

limb은 *부호 있는* 것이고, 그것은 우연이 아니라 하중을 받는 부분입니다.
그러면 `sub()`에 borrow 처리가 전혀 필요 없습니다. limb이 그냥 음수가 되고
다음 carry 패스가 산술 시프트를 통해 그것을 전파하기 때문입니다. 부호 없는
limb이라면 모든 뺄셈 전에 p의 배수를 더하거나 부호에 대해 분기해야 할
것이고 — 두 번째는 바로 이 클래스가 피하려고 존재하는 것입니다.

### Python 패스가 잡아낸 오류

C++를 쓰기 전에 정확 산술에 대조해 검증했고, 곱셈의 첫 버전이 **모든**
입력에서 틀렸습니다. radix가 정수 비트가 아니므로, 두 인덱스가 *둘 다*
홀수일 때마다 `OFFSET[i] + OFFSET[j]`가 `OFFSET[i+j]`보다 한 비트
위입니다 — 반 비트 오프셋 둘이 더해져 온전한 하나가 됩니다. 저는 그 두
배화를 2^255를 넘어 감기는 곱들에만 적용했는데, 거기서도 필요하긴 하지만
나머지에는 적용하지 않았습니다. 정확 산술이 한 번 실행으로 그것을
찾았습니다. 왕복 테스트는 절대 못 찾았을 것입니다. 같은 방식으로 일관되게
틀린 packer와 unpacker는 서로 일치하기 때문입니다.

### 테스트

`CBigNum`이 oracle입니다 — 많이 테스트되었고, 이 단위와 코드를 공유하지
않으며, 정확합니다. `add`/`sub`/`mul`/`square`/`mulA24`/`invert`를 그것에
대조해 무작위 쌍 3000개에 걸쳐 검사하고, 더해서 **열 개 경계값의 모든
쌍**(0, 1, 2, 19, 38, p−1, p−2, 2^254, 2^128, (p−1)/2)에서도 검사하는데,
그곳이 carry 연쇄와 19× 감김이 가장 긴장되는 곳이고 무작위 샘플링이
사실상 절대 닿지 않는 곳입니다.

왕복을 살아남기 때문에 특별히 검사하는 케이스 둘:

- `toBytes()`의 조건부 p 뺄셈은 [p, 2^255)의 값에 대해서만 중요한데,
  그것들은 어느 쪽이든 같은 원소로 디코드됩니다. 테스트는 축약되지 않은
  대표원을 직접 먹이고 정규 바이트를 요구합니다.
- `invert()`는 참조 역원에 대조하는 대신 `x · x⁻¹ == 1`로 검사하므로, 틀린
  덧셈 연쇄가 구성상 자기 자신과 일치할 수 없습니다 — 그리고 그 다음
  `CBigNum::modInverse`에도 대조합니다.

테스트 케이스 7개, 단정 32,468개. Clang에서 `-fno-ms-compatibility`로
검사했으므로 `d297767`에서 고친 이식성 파손을 반복하지 않습니다.

## X25519: constant-time ladder, 그리고 부수 효과로 5–7배 빨라짐

`Curve25519`의 Montgomery ladder가 이제 `CBigNum` 대신 `Fe25519` 위에서
돌아가며, 그것이 다운스트림 소비자가 보고한 타이밍 채널을 닫습니다.
`x25519.cpp`의 어떤 것도 더는 `CBigNum`을 건드리지 않으므로, 비밀 스칼라가
가변 시간 산술에 닿는 경로가 없습니다.

필드 타입을 교체한 것 너머로 바뀐 것:

- **스칼라 비트를 바이트에서 직접 읽습니다.** 값의 limb 개수에 비용이
  의존하는 `CBigNum::testBit()`를 통하지 않습니다.
- **조건부 교환이 산술 mask 아래의 `Fe25519::condSwap`입니다.** 자기 문서가
  평범한 분기임을 인정하는 `CBigNum::condSwap`을 대체합니다. ladder에서 그
  조건은 개인 스칼라의 한 비트*입니다*.
- **clamping이 `CBigNum`이 아니라 바이트를 만들어 냅니다.** 그리고
  `scalarMult()`가 반환 전에 자기 clamp된 사본을 지웁니다.
- **`checkPrivateKey()`의 cofactor 검사가 `scalarMult()`가 아니라
  `ladder()`를 호출합니다.** 의도적입니다. 그 스칼라는 작은 공개 상수 8이고
  clamp되어서는 *안 됩니다*. clamping이 그것을 다른 스칼라로 바꿔 놓을
  것이기 때문입니다. 그 구분은 검사가 가공되지 않은 `CBigNum`을 넘기던
  이전에는 암묵적이었습니다. 이제는 이름 붙은 두 진입점 사이의 보이는
  차이입니다.

검사 하나는 테스트되는 것이 아니라 구조적인 것이 되었습니다. 옛 코드는
유도된 u 좌표가 정규적으로 축약되었음을 검증했습니다(`u >= p`를 거부).
`Fe25519::toBytes()`는 구성상 [0, p)의 정규 대표원을 내놓으므로, 그것은 더는
실패할 수 없습니다. 그 자리에 비트 255 mask가 단정되는데, 그것이 32바이트
인코딩이 여전히 담을 수 있는 한 가지이기 때문입니다.

### 측정된 효과

변경의 요점은 아니었지만, `CBigNum`이 연산마다 할당하고 런타임에 계산된
소수에 대해 축약하고 있었으므로 기록할 만합니다.

| | 이전 | 이후 |
|---|---|---|
| `generateKeyPair` | 4.7 ms | **0.907 ms** |
| `deriveSharedSecret` | 2.0 ms | **0.287 ms** |

X25519 테스트 케이스 12개와 단정 4217개 전부가 변경 없이 통과하며, RFC
7748의 벡터도 포함됩니다 — 그것이 중요한 검사입니다. 미묘하게 틀린 ladder도
자기 자신의 두 사본 사이에서는 일관된 키 합의를 만들어 내기 때문입니다.

소비자가 요청한 연산당 100 µs에는 여전히 못 미칩니다. 원인 둘이 확인되었고
아직 처리되지 않았습니다. `Fe25519::mul`이 컴파일러가 풀어낼 것 같지 않은
10x10 루프 안에서 부분 곱마다 분기 둘을 지니고, `generateKeyPair`는 이미
첫 결과를 손에 들고 있는 자리에서 ladder 셋을 돌립니다(공개키를 유도하는 하나,
그 다음 그것을 다시 계산하는 `checkPrivateKey` 더하기 cofactor 검사).

## 성능 패스, 숫자를 담은 다운스트림 보고가 이끈

cppskit의 libcskcwk가 링크 암호화 경로에 대해 구체적인 수치와 목표를
보고했습니다. 이것은 무엇이 움직였고, 무엇이 움직이지 않았으며, 보고가
예상하지 못한 작업 없이는 목표가 도달 불가능한 것으로 드러난 한 곳을
기록합니다.

| | 보고된 값 | 현재 | 목표 |
|---|---|---|---|
| X25519 `generateKeyPair` | 4.7 ms | **333 µs** | ≤100 µs |
| X25519 `deriveSharedSecret` | 2.0 ms | **167 µs** | ≤100 µs |
| AEAD seal, 64 KiB | ~300 MiB/s | 331 MiB/s | ≥1.5 GiB/s |
| AEAD seal, 64 B | 507 ns | ~440 ns | ≤150 ns |

### AEAD 시간이 실제로 어디로 가는가

64 KiB에서 뺄셈으로 분리했습니다. Poly1305 60.6 µs, ChaCha20 128.4 µs입니다.
따라서 ChaCha20이 지배한다는 보고의 진단은 옳았습니다 — 그러나 그 산술에는
보고가 닿지 못한 결과가 있습니다.

- ChaCha20: **487 MiB/s**, 바이트당 약 5.9 사이클.
- Poly1305: **1032 MiB/s**, 바이트당 약 2.8 사이클.

바이트당 2.8 사이클은 스칼라 26비트 limb Poly1305가 들어야 할 비용과 대략
같으므로, MAC은 이 표현에 대해 이미 자기 천장에 가깝습니다 — 그리고 그 둘이
`1/total = 1/cipher + 1/mac`로 합성되므로, **암호가 얼마나 빨라지든
Poly1305 하나가 AEAD를 1032 MiB/s로 묶어 둡니다.** 1.5 GiB/s에 이르려면
*둘 다*가 필요합니다. MAC이 3 GiB/s면 암호가 3 GiB/s에 이르러야 하고, MAC이
2 GiB/s면 암호는 6에 이르러야 합니다. 그것은 양쪽에 SIMD를 쓰거나,
`_umul128`을 통해 Poly1305를 64비트 limb으로 하는 것을 뜻합니다. 누군가
ChaCha20에만 한 주를 쓰고 1 GiB/s에 착륙하기 전에 알아 둘 만한 가치가
있습니다.

### 무엇을 했는가

**ChaCha20: 준비된 상태, 워드 단위 XOR.** 블록 함수가 호출마다 키와 nonce를
받았으므로 64바이트마다 리틀엔디언 워드 열한 개를 다시 파싱했습니다.
`ChaCha20Core::SState`가 이제 그것을 메시지당 한 번으로 끌어올립니다.
`xorStream()`은 온전한 블록을 바이트 단위가 아니라 32비트씩 결합하며,
`ISymmetric` transformer가 블록 정렬된 벌크를 그것을 통해 보내면서 가장자리를
위한 호출 간 커서는 유지합니다. 측정값: 286 → 331 MiB/s.

그것은 변경이 시사하는 것보다 작은 이득이고, 그 이유가 유용한 부분입니다.
상태 설정도 바이트 단위 XOR도 지배적이지 않았습니다 — **20라운드가**
블록당 ~376 사이클로 지배적입니다. 더 나아간 암호 이득은 부기가 아니라 SIMD를
필요로 합니다.

**Fe25519: 풀어낸 곱셈.** 10x10 루프가 부분 곱마다 분기 둘(홀수/홀수 두
배화와 감김)을 지녔습니다. 피연산자를 미리 스케일하면 두 상수가 모두 접혀
나가면서 순수한 multiply-accumulate가 남습니다 — 그리고 그 식은 손으로
타이핑한 것이 아니라 Python 참조가 검증한 바로 그 규칙에서 *생성*되었으므로,
100개 항이 그것으로부터 떠내려갈 수 없습니다. 측정값: derive 287 → 167 µs.

**X25519 키 생성: 유도 둘 대신 하나.** `generateKeyPair`가 공개키를 유도하고,
그 다음 `checkPrivateKey()`를 호출했는데, 그것이 순전히 방금 계산한 값과
비교하려고 그것을 다시 유도했습니다. 유효성 검사 셋이 두 경로가 모두 호출하는
공유 `validatePublicValue()`로 옮겨 갔으므로 약해진 것은 없습니다 — 떨어져
나간 비교는 한 값과 그 자신 사이의 것이었습니다. 측정값: 540 → 333 µs로,
ladder 셋이 둘이 되는 것과 일치합니다.

### 시도했고 되돌린 것

`carryPass()`를 리터럴 시프트 양으로 풀어냈습니다. `widthOf(i)`의 modulo가
ladder가 하는 ~50,000회 호출에 걸쳐 비용을 들이고 있다는 이론에서였습니다.
실행 간 약 11%의 편차 안에서 **아무** 차이도 만들지 않았습니다 —
`widthOf()`가 `constexpr`이고 경계가 고정이므로 컴파일러가 이미 그것을 하고
있었습니다. 루프가 돌아왔고, 아무도 이것을 반복하지 않도록 음성 결과를
주석에 기록했습니다.

전용 제곱은 의도적으로 쓰지 *않았습니다*. 그것은 ladder 반복마다 있는 제곱
네 번의 부분 곱을 절반으로 줄일 것입니다 — 아마 30% — 그러나 그것은 radix의
것과 상호작용하는 자기만의 두 배화 규칙을 지닌 두 번째 100항 식이고,
틀렸더라도 ladder는 여전히 자기 자신과 일치할 것입니다. 이득을 가정하는
대신 귀속시킬 수 있을 때까지 남겨 두었습니다.

### 100 µs를 위해 남은 것

derive가 1.7배 벗어나 있습니다. 남은 지배적 비용은 2^25.5 radix가 limb 곱셈
**100개**를 필요로 하는 반면 2^51 radix는 25개를 필요로 한다는 것입니다 —
그것이 진짜 4배이고, 64비트 구현들이 그것을 쓰는 이유입니다. 그것은 128비트
곱을 필요로 하는데, MSVC는 `__int128` 없이도 `_umul128`을 통해 그것을 할 수
있습니다. 그것 더하기 제곱이 있으면 100 µs는 넉넉히 도달 가능하고, 그것이
없으면 아닙니다.

### P4: 전용 `square`를 시도하고 되돌렸습니다

P3의 교훈대로 먼저 측정했습니다. 필드는 X25519의 **53%**입니다 (255번 ladder
반복, 각각 제곱 4회와 곱셈 4회, `mul` 38.71 ns와 `square` 36.16 ns 대
143 µs 연산). 전용 제곱은 부분 곱을 절반으로 줄입니다 — 모든 비대각 항이 두 번
나타나므로 100개가 55개가 됩니다 — 이것이 X25519의 약 **12%**입니다.

병합 형태를 유도하려는 시도를 두 번 했고 둘 다 틀렸습니다. 그 이유는 분명한
것이 아니므로 기록할 가치가 있습니다: 2^25.5 radix는 보정을 **비대칭적으로**
적용합니다. 홀수 인덱스 두 배는 첫 번째 연산자에, 19-fold는 두 번째 연산자에
속합니다. 그래서 곱 행렬은 값은 대칭이지만 보정은 대칭이 아니며, 쌍의 병합
인수는 두 단일 항 인수의 *합*이고 둘 중 하나의 두 배가 아닙니다.

실패 양상은 이 클래스가 존재하는 이유 그 자체입니다: 자기 자신과는 일치하고
다른 것과는 일치하지 않는 `square()`. 라이브러리의 테스트가 즉시 잡았습니다.
`mul(a, a)`로 되돌렸습니다. 이것은 올바르고 X25519의 12%, 즉 TLS 핸드셰이크의
1% 미만이라는 알려진 bounded 비용이 듭니다. 병합 인수를 mul()과 기계적으로
대조하는 도구로 유도할 때까지 남겨 두었습니다.

2^51-radix 절반은 시작하지 않았고, 이것을 정당화할 측정은 가정보다 덜
유리합니다: 2^51에서는 각 곱이 64x64→128 곱셈을 필요로 하고, 현재 26x26과
측정 대조하면 **2.5~3.1배 느립니다**. 그래서 25개의 넓은 곱은 약 78개의 좁은
곱만큼 비쌉니다 — limb 수가 암시하는 75%가 아니라 곱셈 작업의 22% 감소입니다.
헤더가 밝힌 차단 요인(MSVC에 `__int128`이 없다는 것)도 보이는 것보다 좁습니다:
MSVC x64에는 `_umul128`이 있어 같은 128비트 곱을 생성합니다.

## AES-GCM과 padding 없는 CBC, IKEv2 소비자를 위해

IKEv2 구현은 RFC 7296/4106/5282가 실제로 협상하는 변환 둘을 필요로 합니다.
AEAD로서의 AES-GCM, 그리고 프로토콜이 이미 스스로 padding한 페이로드에 대한
AES-CBC입니다.

- `CAesGcm`(`crypto/aeads/aesgcm.hpp`) — NIST SP 800-38D, AES-128/192/256,
  96비트 IV, 96–128비트 태그입니다. 그 API는 의도적으로
  `CChaCha20Poly1305`의 것과 맞춰져 있습니다. 같은 소비자가 협상으로 둘 중
  하나를 고르고, 그 선택을 둘러싸고 구조를 다시 짜야 하지 않아야 하기
  때문입니다.
- `Ghash`(`src/crypto/aeads/ghash.hpp`) — GHASH와 GCM의 `GF(2^128)`이고,
  `src/`에 private입니다.
- `AesCore`를 `crypto/syms/aes.cpp`에서 자기 private 단위로 추출했습니다.
  `DesCore`와 `ChaCha20Core`가 이미 그랬던 방식입니다.
- `ISymmetricContext`의 `ESymPaddings` — `ESYMPAD_PKCS7`(기본값, 변경 없음)
  또는 `ESYMPAD_NONE`입니다.

### GHASH가 `CGf2m`이 아닌 이유

`CGf2m`은 이미 PCLMULQDQ 경로로 `GF(2^m)`에서 곱하고, GHASH의 모듈러스
`x^128 + x^7 + x^2 + x + 1`은 그 pentanomial `SGf2mField`에 들어가기까지
합니다. 그래도 틀린 도구였고, 독립적인 이유 셋 때문이며, 첫 번째가 중요한
것입니다.

**GCM의 필드는 비트가 반사되어 있습니다.** 블록 첫 바이트의 최상위 비트가
`x^0` 계수입니다(SP 800-38D 6.3절) — `CGf2m`과 이 라이브러리의 나머지가 쓰는
다항식 기저 관례의 반대입니다. `CGf2m`에 바이트를 도착한 대로 건네면
교환적이고 결합적이고 분배적이며 완벽하게 자기 일관적이면서, GHASH는 아닌
곱이 나옵니다. 발행된 벡터 말고는 아무것도 그것을 잡아내지 못하며, 그것이 이
저장소의 반복되는 실패 양식입니다(전치된 SHA-3 회전 표, 전사된 P-521 자릿수,
어떤 RFC 벡터도 닿을 만큼 길지 않았던 ChaCha20 벡터 경로).

나머지 둘: `H`가 비밀이므로 곱셈이 constant-time이어야 하는데, `CGf2m`은
자기가 전혀 경화되지 않았다고 문서화합니다 — ECDSA의 공개 곡선 산술에는
올바른 거래이고, MAC 키에는 틀린 거래입니다. 그리고 `CGf2m`은 limb 열여덟
개짜리 곱에 대한 일반 pentanomial 축약을 통해 limb 아홉 개를 나르는데,
GHASH는 고정 모듈러스 하나를 지닌 64비트 워드 둘이고 16바이트마다 한
번입니다.

### Python 먼저, 그 다음 C++

SP 800-38D를 Python으로 구현했고 — AES도 포함해서, 그래서 아무것도 신뢰로
받아들이지 않았습니다 — C++ 한 줄을 쓰기 전에 GCM 명세 부록 B의 테스트
케이스에 대조해 검사했습니다. 96비트 IV를 쓰는 케이스 열두 개 전부(1–4,
7–10, 13–16: 키 크기 셋, 빈 평문, 빈 AAD, 그리고 20바이트 AAD를 지닌
60바이트 평문)가 일치했고, 각 케이스의 발행된 subkey `H`도 포함됩니다. 같은
스크립트는 또한 그 벡터들에 의존하기 전에 그것들이 각 오류 부류를 볼 수
*있다*는 것도 확인했습니다. 그 다음 C++가 첫 실행에서 열두 개 전부를
통과했습니다.

### 가속 경로는 반사된 관례를 쓰지 않습니다

교과서적인 PCLMULQDQ GHASH는 GCM 자신의 반사된 표현에서 곱하는데, 그것은
256비트 곱에 걸친 1비트 시프트 더하기 상수들(`slli_epi32`로 31, 30, 25, 그
다음 1, 2, 7)을 지닌 축약을 필요로 하고, 그 상수들은 전사하기는 쉽고 눈으로
검사하기는 불가능합니다. 이쪽은 대신 두 피연산자를 SSE2 명령 열두 개로
반사된 관례에서 꺼냅니다 — 각 바이트 안에서 비트를 역순으로 하는 것이고,
그것이 변환의 전부입니다. 리틀엔디언 바이트 순서는 적재가 이미 주는 것이기
때문입니다 — 그리고 축약이 교과서적인 `x^128 = x^7 + x^2 + x + 1`(`0x87`)인
평범한 관례에서 곱한 다음, 곱을 되돌려 변환합니다. 원리상으로는 거울 형태보다
느립니다. 종이 위에서 유도할 수 있고, 그것이 더 값졌습니다.

발행된 벡터는 두 경로를 구별할 수 없습니다. dispatch가 런타임 CPUID 검사이므로,
이 CPU가 어느 쪽을 택하든 그것이 벡터들이 닿는 유일한 것입니다. 따라서
`tests/crypto/aeads/ghash.cpp`가 무작위 피연산자 쌍 2048개 더하기 모든 단일
비트 블록에 걸쳐 그 둘을 직접 비교하고, 필드 항등식으로 비트 순서를 못
박습니다 — GCM의 순서에서 곱셈 항등원은 블록 `80 00 … 00`이므로,
`X ⊗ 80 00 … 00 == X`는 다른 곳에서 얼마나 자기 일관적이든 반사되지 않은
곱셈이면 실패합니다. `Ghash`는 공개 헤더도 `CERTPP_API`도 없으므로, 그
테스트는 `CERTPP_TEST_PRIVATE_SOURCES`를 통해 `ghash.cpp`를 자기 안으로
컴파일해 넣습니다.

### 네거티브 컨트롤

각각을 도입하고, 빌드하고, 테스트를 실패시키는 것을 확인한 다음 되돌렸습니다.

| 파손 | 잡아낸 것 |
| --- | --- |
| 페이로드 카운터가 `J0 + 1`이 아니라 `J0`에서 시작 | `aesgcm`(부록 B의 ciphertext) |
| 길이 블록을 비트가 아니라 바이트 단위로 | `aesgcm` |
| 길이 블록을 빅엔디언이 아니라 리틀엔디언으로 | `aesgcm` |
| 이식 가능한 곱셈에서 반사를 떨어뜨림 | `ghash`(항등식 + 차분) |
| PCLMULQDQ 곱셈에서 반사를 떨어뜨림 | `ghash` *그리고* `aesgcm` |
| AAD를 해시에서 빠뜨림 | `aesgcm`(조작된 AAD 하위 케이스) |

le64 대 be64 건은 적어 둘 만합니다. 그 밖에는 유사한
ChaCha20-Poly1305의 길이 꼬리말은 리틀엔디언(RFC 8439 2.8절)이고 GCM의 것은
빅엔디언입니다. 같은 모양의 꼬리말과 반대 엔디언을 지닌 AEAD 둘이 한
디렉터리에 있는 것은 바로 복사를 초대하는 종류의 이웃입니다.

### 이미 동작하던 것을 바꾸지 않으면서, padding 없는 CBC

`CbcTransformer`는 항상 padding했고, SP 800-38A 테스트와 다른 모든 호출자가
그것에 의존하므로, `ESYMPAD_NONE`은 기본값의 변경이 아니라 opt-in입니다.
padding이 없으면 아무것도 보류되지 않고 아무것도 벗겨지지 않습니다. 모든
온전한 블록이 완성되는 대로 나오고, `transformFinal()`은
길이를 조용히 올려 맞추는 대신 부분 블록에 대해 `ERET_BADREQ`를 반환합니다.

`padding()`은 키, IV, 블록 크기와 달리 `reset()`이나 `key()`에 의해
의도적으로 지워지지 *않습니다*. 그것은 키 자료가 아니라 모드 선택이고,
그것을 지우면 `padding(ESYMPAD_NONE)` 다음의 `key(...)`가 조용히 PKCS#7로
되돌아가게 할 것입니다 — 상대가 거부하는 ciphertext를 내놓는 아주 조용한
방법입니다.

부수적 이득: padding 없는 CBC는 이 라이브러리에서 SP 800-38A F.2의 *네 블록*
CBC 벡터에 견주어 볼 수 있는 첫 번째 것입니다. padding된 CBC는 전부 16인
다섯 번째 블록을 덧붙이므로, 지금까지는 F.2의 단일 블록, 전부 0인 IV 축소만
검사되었고, 그것은 chaining을 전혀 연습하지 않습니다.

## GOST R 34.11-2012 (Streebog)과 GOST R 34.10-2012

러시아 연방 해시 및 서명 표준을 새 `IHasher`와 `IAsymmetric` 구현으로
추가했습니다. 알고리즘만이고, `x509/`의 어떤 것도 아직 그것들을 알지
못합니다(아래 "X.509 배선이 여전히 필요로 할 것" 참조).

### Streebog (`EHASH_STREEBOG256` / `EHASH_STREEBOG512`)

`Streebog256`/`Streebog512`(RFC 6986)이고, SHA-384/SHA-512가 `Sha2_64Core`를
공유하는 방식으로 `src/` 아래의 `StreebogCore`를 공유합니다. 코어가 라운드
함수 `g_N`과 2^512 모듈러 누산기를 지니고, 각 digest가 자기 컨텍스트, IV,
padding, 출력 조각을 지닙니다.

**바이트 순서가 문제의 전부였고, 그것은 읽기가 아니라 증거로
정리되었습니다.** RFC 6986은 `V_512` 벡터의 바이트를 0에서 시작해 *오른쪽*
에서부터 번호 붙이고 벡터를 최상위 바이트 먼저로 인쇄하므로, 그 예시
메시지와 해시 코드가 둘 다 바이트 스트림에 대해 거꾸로 쓰여 있습니다. C++를
쓰기 전에 Python에서 검사한 독립적인 확인 둘:

- RFC의 예시 2 hex는 오른쪽에서 왼쪽으로 읽을 때만 읽을 수 있는 CP1251
  러시아어 텍스트(〈이고르 원정기〉의 한 줄)로 디코드되고, 그러면 예시 1은
  ASCII 문자열 `012345678901...012`입니다.
- 그 ASCII 문자열의 Streebog-512는 널리 발행된 digest이며, RFC 자신의
  `H(M1)`을 **바이트 단위로 역순으로 한 것**과 같습니다.

따라서 구현은 모든 64바이트 버퍼를 명세 자신의 바이트 위치로 인덱싱합니다 —
인덱스 0이 `a_0`이고, 그것은 또한 메시지 블록의 첫 바이트입니다. 그러면
메시지 바이트가 증가하는 인덱스로 곧바로 흘러 들고, digest가 다른 모든
구현이 쓰는 순서로 나오며, `MSB_256`은 최종 상태의 앞쪽 절반이 아니라
*위쪽* 절반(인덱스 32..63)이 됩니다.

물리는 것 둘 더:

- **256비트 digest는 절단이 아닙니다.** RFC 6986 6.1절은 512비트 함수가
  `0^512`를 받는 곳에서 그것에 `IV = (00000001)^64`를 줍니다. 그래서 그 둘이
  첫 블록부터 갈라집니다. 틀린 IV를 쓰면 완벽하게 자기 일관적이고 보편적으로
  틀린 해시가 나옵니다.
- **길이가 정확히 64바이트의 배수인 메시지도 padding되고 완전히 빈 마지막
  블록을 받습니다.** 2.1단계의 루프가 `|M| < 512`에서 나가고 `|M| == 0`이
  그것을 만족하기 때문입니다. **RFC 6986의 어떤 벡터도 이 경우에 닿지
  않습니다** — 발행된 모든 벡터가 너무 짧았기 때문에 그것들을 통과했던
  ChaCha20 벡터 경로와 같은 모양의 공백입니다. 거기에 닿는 벡터는 RFC 9385
  부록 A.1.1에서 왔습니다.
  `SKEYSEED = HMAC_GOSTR3411_2012_512(Ni | Nr, K)`는 64바이트 키와 64바이트
  데이터를 지니므로, 내부 해시와 외부 해시가 모두 정확히 128바이트를 봅니다.
  그것은 `CHmac::blockBytesOf()`가 SHA-512의 128을 복사하는 대신 `B = 64`
  (RFC 7836 4.1.1/4.1.2절)를 보고한다는 검사도 겸합니다.

**상수 표는 타이핑한 것이 아니라 생성했습니다.** `Pi'`, 행렬 `A`의 64개 행,
그리고 열두 개의 `C[i]`를 Python 참조가 `rfc6986.txt`에서 파싱해 C++ 소스
텍스트로 내보내므로, 잘못될 전사 단계가 존재하지 않습니다. `Tau`는 아예
저장되지 않습니다. `transformLps()`가 항등식
`Tau(8w + t) == w + 8t`를 쓰는데,
`tests/crypto/hashers/streebogcore.cpp`가 그것을 검사하려고 `Tau`를 독립적으로
전사합니다. 16 KiB 결합 S/P/L 조회 표는 첫 사용 시 `Pi'`와 `A`에서
*유도*되며, 같은 테스트가 그것을 의도적으로 느리고 문자 그대로인 7절의 3패스
읽기에 대조해 pseudorandom 상태에서 비교합니다 — 그러지 않으면 아무것도 그
표의 자기 일관성만이 아니라 그 유도를 검사하고 있지 않을 것입니다.

### GOST R 34.10-2012 (`CGost3410`)

파라미터 집합 아홉 개에 대한 `CGost3410`(RFC 7091)이며, 기존 `CEcCurve` 군
산술이 그것들을 받칠 수 있도록 전부 `EEcKnownCurves`/`EAsymmetrics`에
추가되었습니다.

| 식별자 | 파라미터 집합 | 출처 |
| --- | --- | --- |
| `ECURVE_GOST256TEST` | `id-GostR3410-2001-TestParamSet` | RFC 7091 7.1절 (= RFC 4357 11.4절) |
| `ECURVE_GOST256A` | `id-tc26-gost-3410-2012-256-paramSetA` | RFC 7836 A.2 |
| `ECURVE_GOST256B` | `...-256-paramSetB` (= CryptoPro-A) | RFC 4357 11.4절, RFC 9215 부록 C에 따라 |
| `ECURVE_GOST256C` | `...-256-paramSetC` (= CryptoPro-B) | RFC 4357 11.4절, RFC 9215 부록 C에 따라 |
| `ECURVE_GOST256D` | `...-256-paramSetD` (= CryptoPro-C) | RFC 4357 11.4절, RFC 9215 부록 C에 따라 |
| `ECURVE_GOST512TEST` | `id-tc26-gost-3410-2012-512-paramSetTest` | RFC 9215 E |
| `ECURVE_GOST512A` | `id-tc26-gost-3410-12-512-paramSetA` | RFC 7836 A.1 |
| `ECURVE_GOST512B` | `id-tc26-gost-3410-12-512-paramSetB` | RFC 7836 A.1 |
| `ECURVE_GOST512C` | `id-tc26-gost-3410-2012-512-paramSetC` | RFC 7836 A.2 |

모든 집합을 스크립트로 RFC 텍스트에서 파싱한 다음 검사했습니다 — 기준점이
곡선 위에 있는지, `q*P == O`인지, 판별식이 비특이인지 — `eccurve.cpp`의 hex
리터럴로 내보내기 전에 말입니다. RFC 4357의
`GostR3410-2001-ParamSetParameters`는 자기 정수들을 `a, b, p, q, x, y`로
순서 짓는데(10.9절), 그것들을 `p, a, b, ...`로 읽으면 그럴듯해 보이는 곡선이
나오므로 알아 둘 만합니다. `XchA`/`XchB`는 생략되었습니다. RFC 9215 부록 C가
그것들이 CryptoPro-A와 CryptoPro-C와 같은 곡선이라고 말합니다.

그 집합 중 둘은 cofactor가 1이 아니라 **4**입니다. 그것이 `decodePoint()`와
`checkPrivateKey()`의 위수 `q` 부분군 검사를 이 라이브러리에서 처음으로
진짜 하중을 받게 만듭니다 — 그 전에 들어온 모든 곡선에 대해서는 곡선 위의
점이 필연적으로 부분군 안에 있었고, 그 검사 자신의 주석이 그렇다고 말했습니다.

**이것은 다른 곡선을 쓰는 ECDSA가 아닙니다.** `s = (r*d + k*e) mod q`이고,
`k`의 역원이 없습니다. 검증은 `s`가 아니라 *해시*를 역으로 돌립니다
(`v = e^-1`). 그리고 `e`는 GOST 자신의 규칙으로 해시에서 오는데, 스트림
순서의 Streebog digest가 주어지면 그것은 그것을 **리틀엔디언**으로 읽는 것을
뜻합니다 — ECDSA의 최좌측 비트 빅엔디언 절단이 아닙니다. 0인 `e`는 그대로
남겨지는 대신 1이 됩니다. `CEcdsa`의 산술을 재사용하면 자기 자신에 대해서만
검증되고 다른 아무것에도 검증되지 않는 서명이 나왔을 것입니다.

**직렬화 바이트 순서가 "자기 자신에 대해서는 동작함"이 숨는 곳이므로**, 그것을
RFC 9215 부록 D의 인증서들에서 경험적으로 결정한 *다음* 그 문서의 규범
본문(2.3/2.4절 — 일치합니다)에 맞춰 보았습니다.

- 공개키: `x || y`, 각각 고정 폭 **리틀엔디언**(64 또는 128바이트).
- 서명: `s || r`, 각각 고정 폭 **빅엔디언**, `s`가 먼저, DER `SEQUENCE` 래퍼
  없음.

서명의 두 절반은 빅엔디언인데 공개키의 두 절반은 리틀엔디언입니다. 그것은
실수가 아니라 GOST의 것이고, 둘 다 사용 지점에 주석되어 있습니다.

개인키는 `d` 하나만으로, 리틀엔디언으로 직렬화되며, 공개키의 좌표 순서와
맞습니다. `createPrivateKey()`는 `Q = d*P`를 나르는 대신 다시 유도하므로,
맞지 않는 쌍을 가져오는 것이 불가능해집니다. RFC 9215는 여기에 맞출 개인키
인코딩을 정의하지 않습니다.

### 검증

모든 것을 C++가 존재하기 전에 Python에서 구현하고 발행된 벡터에 대조해
검사했으며, C++ 테스트는 그 참조가 내놓은 값을 씁니다.

- RFC 6986의 예시 digest 네 개(메시지 둘 × 길이 둘), 더해서 독립적인 방향
  확인으로서 발행된 빈 메시지 digest와 ASCII 문자열 digest.
- 정확한 블록 배수 경우를 위한 RFC 9385 부록 A.1.1의 `SKEYSEED`, 그리고
  `paramSetC`의 생성원을 독립적으로 다시 유도하는 그 (4)단계 공개키.
- RFC 7091 7절의 `(r, s)` — 이 방식에 대해 발행된 유일한 서명 쌍이고, 틀린
  검증 식이나 뒤바뀐 서명 절반을 잡아낼 수 있는 유일한 것입니다. nonce가
  무작위이고 왕복은 어느 쪽이든 자기 자신과 일치할 것이기 때문입니다.
- RFC 9215 부록 D의 테스트 인증서 셋을 종단 간으로 검증했습니다. 실제
  `tbsCertificate` 바이트에 대한 Streebog, 그 다음 인증서 자신에 내장된
  공개키에 대조하는 GOST R 34.10입니다. 파라미터 집합 셋, 두 digest 길이,
  회선에서 나온 모든 바이트입니다.

네거티브 컨트롤, 각각을 도입하고 다시 빌드하고 실패를 확인하고
되돌렸습니다. 256비트 digest에 512비트 IV(잡힘), 역순 메시지 블록 바이트
순서(잡힘), 역순 digest 출력 순서와 틀린 절반에서 취한 `MSB_256`(둘 다
잡힘), `verify()`가 `s || r` 대신 `r || s`를 읽기(잡힘), 그리고 `verify()`가
무조건 `ERET_OK`를 반환하기인데, 그것은 틀린 키, 조작된 메시지, 조작된 서명,
뒤바뀐 절반, 역순 digest, 틀린 길이 단정 전부를 발화시켰습니다 — 즉 그
음성들은 공허하게 통과하는 것이 아니라 이빨이 있습니다.

### X.509 배선이 여전히 필요로 할 것

여기서는 의도적으로 범위 밖입니다. 기록을 위해, 그것은 알고리즘이 아니라
OID와 인코딩입니다.

- `CCert`의 서명 알고리즘 표에 있는
  `id-tc26-signwithdigest-gost3410-12-256`(1.2.643.7.1.1.3.2)과
  `-512`(1.2.643.7.1.1.3.3)이며, `parameters` 필드는 **생략**됩니다(RFC
  9215 2절).
- `SubjectPublicKeyInfo` 알고리즘으로서의 `id-tc26-gost3410-12-256` /
  `-512`이고, 그 `parameters`는
  `SEQUENCE { publicKeyParamSet OID, digestParamSet OID OPTIONAL }`입니다 —
  그래서 파라미터 집합이 AlgorithmIdentifier에서 오며, 그것은 각
  `ECURVE_GOST*`를 자기 OID로, 그리고 거꾸로 매핑하는 것을 뜻합니다. 키
  비트는 이 라이브러리가 파싱하는 다른 모든 키와 달리 *OCTET STRING을
  감싸는* BIT STRING입니다.
- 서명 값은 DER `SEQUENCE { r, s }`가 아니라 가공되지 않은 64/128바이트
  `s || r` blob이므로, `CCert::verifyBy()`의 경로가 이것들에 대해 ECDSA
  모양을 가정하기를 멈춰야 할 것입니다.
- DNSSEC(RFC 9558)은 추가로 DNSKEY/RRSIG 회선 형식을 필요로 할 것이고, 그것은
  또 X.509의 것들과 다릅니다.

## `dnssec` 모듈, 그리고 그 벡터들이 볼 수 없었던 것

DNSSEC는 X.509의 인코딩을 하나도 공유하지 않으며, 그것이 이것이 `x509`의 한
구석이 아니라 별개 모듈인 이유 전부입니다. 인증서는 공개키를
`SubjectPublicKeyInfo`로, ECDSA 서명을 DER `SEQUENCE { r, s }`로 나릅니다.
DNSSEC는 벌거벗은 키 자료와 벌거벗은 연결 `r | s`를 씁니다. 그래서 DNSKEY를
`IAsymmetric::createPublicKey()`에 건넬 수 없고 RRSIG 서명을 `verify()`에
건넬 수 없습니다 — 그 사이에서 무언가가 다시 인코드해야 하고, `CDnssecKeys`가
그 무언가입니다.

알고리즘별로: RSA(RFC 3110)는 지수 길이, 지수, 그 다음 모듈러스를 쓰는데,
이 라이브러리가 원하는 것은
`SEQUENCE { INTEGER modulus, INTEGER exponent }`입니다 — 두 피연산자가 반대
순서로 나타나므로, 그것을 거꾸로 하면 모듈러스가 3인 키가 나옵니다.
ECDSA(RFC 6605)는 `x | y`를 쓰는데, 그것은 SEC1 비압축 점에서 `0x04`
접두사를 뺀 것입니다. EdDSA(RFC 8080)는 이미 올바른 형태이고 기본값이 아니라
명시적 case로 처리되므로, 아무도 구현하지 않은 알고리즘은 조용히 가공되지
않은 것으로 취급되는 대신 거부됩니다.

서명 방향에는 건너뛸 수 없는 단계가 하나 있습니다. DER `INTEGER`는 앞쪽 0
옥텟을 나르지 않으므로, 각각을 곡선의 필드 크기로 왼쪽 padding하지 않고 `r`과
`s`를 다시 써 내보내면 `r`이 짧았던 만큼의 옥텟 수대로 `s`가 왼쪽으로
밀립니다. RFC 6605 2절이 고정 폭을 요구합니다. 그것을 위한 테스트는 두 절반
모두에 앞쪽 0이 있고 *그리고* 뒤쪽 0도 있는 서명을 구성하는데, 마침 전체
폭인 값들에 대한 왕복은 아무것도 증명하지 않기 때문입니다.

### 네거티브 컨트롤이 벡터 집합 자체에서 찾은 공백 둘

발행된 예시 여덟 개가 들어갔습니다 — RFC 6605 6.1/6.2, RFC 8080의 EdDSA
예시 넷, RFC 5702의 RSA 둘 — 모든 키 태그(55648, 10771, 3613, 35217, 9713,
38353, 9033, 3740)와 모든 DS digest를 재현합니다. 키 태그와 DS digest가 둘 다
*전체* RDATA에 대해 취해지므로, 필드 순서, 필드 폭, 소유자 이름 정규화의
어떤 오류도 그것들을 살아남지 못합니다. 그래서 강한 벡터입니다.

그러나 의도적인 파손 둘은 살아남았고, 그것이 그것들을 시도하는 요점입니다.

- **flags 필드의 바이트를 교환해도 아무것도 바뀌지 않았습니다.** 모든 ECDSA와
  EdDSA 예시가 flags 257을 쓰고, 257은 `0x0101`입니다 — 어느 바이트 순서에서나
  동일합니다. 여덟 벡터 중 여섯이 flags 필드의 엔디언을 전혀 제약할 수
  없습니다. RFC 5702의 RSA 예시는 256(`0x0100`)을 쓰고 제약할 수 있는데,
  그것이 검사할 DS 레코드를 발행하지 않는데도 그것들이 테스트 모음에 있는
  이유입니다.
- **대소문자 접기 테스트가 공허했습니다.** 내부적으로 접는 헬퍼에 넘기기 전에
  소유자 이름을 대문자로 만들었으므로, 정규 형태를 자기 자신과 비교했습니다.
  이제 접지 않는 표기에 대조해 비교하는데, 그것이 그 접기가 DS digest에 대해
  하중을 받는다는 것을 실제로 보여 주는 것입니다.

### RFC 4034 부록 B.1은 자기 자신과 모순됩니다

알고리즘 1(RSA/MD5) 키 태그가 거기서 "공개키 모듈러스의 최하위 24비트 중
최상위 16비트"로 정의되고, "뒤에서 4번째와 뒤에서 3번째 옥텟"으로
풀이됩니다. 그 둘은 하나만큼 어긋납니다. 풀이가 지목하는 옥텟은 비트
16..31인데 그것은 최하위 24비트 안에 전혀 없고, 규범 조항은 비트 8..23 —
뒤에서 세 번째와 두 번째 옥텟 — 을 뜻합니다. 구현된 것은 산술적 정의이고
코드가 그렇다고 말하는데, 그러지 않으면 풀이만 확인하는 나중 독자가 그것을
버그로 "교정"할 것이기 때문입니다. 어떤 발행된 벡터에도 검증되지 않았는데
그런 것이 없기 때문입니다. 알고리즘 1은 RFC 8624가 금지합니다. 건너뛰는 대신
구현된 것은 resolver가 막 거부하려는 레코드의 태그를 여전히 계산해야 하기
때문입니다.

## 알고리즘 여덟 개를 한꺼번에 병합하기: 통합이 잡아낸 것

요청된 알고리즘 여덟 개를 병렬로, 각각 자기 worktree에서 구현했는데, 그것은
각각이 다른 일곱 개를 담지 않은 트리에 대해 쓰였다는 뜻입니다. 그 비용의
대부분은 등록 지점에서의 병합 충돌입니다. 두 가지는 그 이상이었습니다.

### `EHashers`가 ABI 경계를 넘어 번호가 다시 매겨졌습니다

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

### 낡은 정당화, 그리고 아무것도 테스트한 적 없던 검사

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

`tests/x509/certs/unimplemented/`는 실제로, 현재 유효한 상용 중간
인증서 — QuoVadis Root CA 1 G3가 발행한 "DigiCert QV G3 TS EUR RSA4096
RSASSA-PSS 2025 CA1" — 를 담고 있었고, `importDer()`가 그것에 대해
`ERET_BADREQ`를 반환했기 때문에 거기 보관되어 있었으며, 정확히 그것을 단정하는
테스트 케이스가 있었습니다. 디렉터리 이름과 테스트 자신의 제목이 둘 다 서명
알고리즘을 탓했습니다. 둘 다 실제로 어떤 공백이 가져오기를 실패시켰는지에
대해 틀렸고, 그 틀림은 기록할 만한 방식으로 틀렸습니다. 그 오귀속이 세 곳에
적히는 것을 살아남았기 때문입니다.

### 실제로 가져오기를 실패시킨 공백

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

### RSASSA-PSS, 디렉터리 이름이 가리켰던 공백

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

### 테스트가 증명할 수 있는 것과 할 수 없는 것

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

## Ed25519를 `Fe25519` 위로: 100배 격차는 마이그레이션되지 않은 파일 하나였습니다

다운스트림 소비자가 Ed25519를 서명 1.84 ms, 검증 8.78 ms(GCC/Linux)로
측정했는데, 최적화된 구현이 드는 50–100 µs에 대비한 값입니다. 이 기계에서는
같은 빌드가 더 나쁘게 측정되었고 — 그 옆에서, 같은 빌드에서, *같은 곡선*에서,
X25519는 공유 비밀을 246 µs에 유도했습니다.

그 비교가 진단의 전부입니다. `x25519.cpp`는 `Fe25519` 위로 마이그레이션되어
있었고(위의 자기 항목 참조), `ed25519.cpp`는 아니었습니다. 그것은 `Fe25519`를
0번, `CBigNum`을 118번 썼습니다. 그리고 `CBigNum::mulMod()`는 `mul()` 다음
`mod()`이고, `mod()`는 `divMod()`를 호출합니다 — 그래서 **점 산술의 모든 필드
곱셈이 완전한 큰 수 나눗셈을 수행했고**, 서명당 수만 번이었습니다.

다른 것은 아무것도 틀리지 않았습니다. 다운스트림 보고가 추가하라고 제안한 두
가지는 이미 있었습니다. `EdPointProj`는 이미 `T = X·Y/Z`인 확장 좌표를
나르고 있었으므로 `pointAddProj()`는 이미 역원이 필요 없었고,
`scalarMulBase()`는 이미 지연 캐시되는 고정 기저 window 표를 만들고
있었습니다. 이것은 그 밖에는 건전한 곡선 구현 안에서의 필드 교체였습니다.

| 12회 실행의 최소, 각각 3 × 20 반복의 최소 | 이전 | 이후 | |
|---|---|---|---|
| `sign` | 5.96 ms | **0.306 ms** | 19.5× |
| `verify` | 29.4 ms | **1.36 ms** | 21.5× |

부하가 걸린 4코어 노트북, Release, 양쪽 모두 같은 harness에서 측정했습니다 —
기준선은 원래 보고에서 인용한 것이 아니라 동일한 harness로 `HEAD`에서 다시
측정했습니다. 여기서의 실행 간 편차가 한 실행과 한 실행을 비교하는 것이
무의미했을 만큼 넓기 때문입니다(이전에 sign은 5.96–9.90 ms, verify는
29.4–40.1 ms 범위였습니다).

### 함정: Ed25519에는 모듈러스가 둘 있고 그중 하나만이 `Fe25519`의 것입니다

- **p = 2^255 − 19**, 필드 소수이고, 점 좌표를 위한 것입니다. 이것이
  `Fe25519`가 구현하는 것입니다.
- **L = 2^252 + 27742317777372353535851937790883648493**, 군의 위수이고,
  스칼라를 위한 것입니다. clamp된 개인 스칼라, 서명의 nonce `r`, 축약된 해시
  `k`, 그리고 서명의 `S`입니다.

스칼라를 `Fe25519`에 통과시키면 자기 자신에 대해서는 검증되고 세상의 다른
아무것에도 검증되지 않는 서명이 나옵니다. 어떤 왕복 테스트도 그것을 볼 수
없고, 기지 응답 벡터만이 볼 수 있습니다.

그래서 그 분리는 주의가 아니라 타입 시스템이 나릅니다.
`EdPoint`/`EdPointProj`는 `Fe25519` 말고는 아무것도 담지 않고, 스칼라는
`groupOrder()`로 축약된 `CBigNum`으로 남으며, `Fe25519`에는 어느 방향으로도
`CBigNum`을 수반하는 생성자, 변환, 대입이 없습니다 — 그 유일한 외부 표현은
32바이트이고, `ed25519.cpp`의 어떤 코드도 그 둘 사이를 변환하지 않습니다.
그것들을 섞으면 컴파일되지 않습니다. 그 둘이 만나는 한 곳은
`scalarMul()`/`scalarMulBase()`인데, 그것들은 mod-L 스칼라를 받아 mod-p 점을
반환하며, 스칼라를 비트의 열로만 읽습니다.

`Edwards25519::fieldPrime()`은 완전히 없어졌고, 그것이 요점의 일부입니다.
스칼라가 우연히 그것에 대해 축약될 수 있는 p의 `CBigNum` 사본이 파일에 더는
없습니다.

### `Fe25519`에 빠져 있던 연산 셋

`Fe25519`는 Montgomery ladder를 위해 존재했고, 그것은 제곱근도, 부정도,
동등성 테스트도 필요 없습니다. 꼬인 Edwards 점 디코딩은 셋 다 필요합니다.

- **`squareRoot()`**. p ≡ 5 (mod 8)이므로 `a^((p+3)/8)`은 `a`의 근이거나
  근의 `sqrt(−1)`배입니다. (p+3)/8 = 2^252 − 2이고, p − 2 = 2^255 − 21이며,
  **두 지수가 모두 같은 1비트 250개로 시작합니다** — 그래서
  `a^(2^250 − 1)`을 위한 40줄짜리 덧셈 연쇄를 `invert()`에서 둘 다 쓰는 파일
  지역 `powTwo250Minus1()` 하나로 뽑아냈습니다. 그것은 투기적인 헬퍼가 아니라
  실제 호출자 둘을 지닌 공유 계산입니다. 역원과 같은 방식으로 연쇄를 틀리게
  한 제곱근은 모든 자기 일관성 검사에서 여전히 자기 자신과 일치할 것입니다.

  두 후보 모두 하나를 신뢰하는 대신 다시 제곱해 비교됩니다. 지수화는 스스로
  잉여와 비잉여를 구별할 수 없습니다 — 비잉여에 대해서는 아무것의 근도 아닌
  완벽히 평범해 보이는 원소를 반환하며, 그것을 점 디코딩에 건네는 것은 잘못된
  형태의 공개키를 받아들이는 것을 뜻합니다.

  `sqrt(−1)`은 전사된 것이 아니라 유도됩니다. 2는 mod p에서 비잉여이므로
  `2^((p−1)/4)`가 −1의 근이고, (p−1)/4 = 2^253 − 5는 같은 1의 연속이 세
  자리 위로 밀린 것의 2^3배입니다 — 제곱 셋과 세제곱에 의한 곱셈 하나입니다.
  `ed25519.cpp`가 255비트 리터럴을 하드코딩하는 대신 이미 `d`와 기준점을
  유도하는 방식과 일관됩니다.
- **`neg()`**, 0에서의 뺄셈입니다. 부호 있는 limb이 그것을 특별할 것 없게
  만들며, 그것이 또한 `isOnCurve()`가 `CBigNum::modNeg()`를 피하려고만 썼던
  재배열에서 문자 그대로의 `−x² + y² == 1 + d·x²y²`로 되돌아가게 했습니다.
- **`isEqual()`과 `isOdd()`**, 둘 다 limb이 아니라 *정규* 값을 거쳐야 합니다.
  표현이 중복적입니다. 두 limb 배열이 다르면서도 같은 원소를 뜻할 수 있으므로,
  `isEqual()`은 빼고 0인지 테스트하며, `isOdd()` — RFC 8032 5.1.2절의 좌표
  "부호" — 는 먼저 인코드합니다. 축약되지 않은 limb 0은 같은 원소를 뜻하면서
  어느 쪽 패리티든 가질 수 있기 때문입니다.

넷 다 `Fe25519`의 나머지가 그랬던 방식으로 `CBigNum`에 대조해 검증되며,
`CBigNum::modExp()`의 Legendre 기호에 대조하는 `squareRoot()`도 포함되는데,
그것은 반환된 모든 근이 근이라는 것만이 아니라 근이 존재할 때 *정확히* 그때
근이 반환된다는 것을 검사합니다. 테스트는 두 분기가 모두 취해졌다고
단정하며, 그러지 않으면 그 일치가 공허할 것입니다.

### 구조적인 것이 된 검사 둘, 그리고 더 엄격해진 것 하나

`checkPrivateKey()`의 "0 ≤ x, y < p" 테스트는 없어졌습니다. 좌표가
`Fe25519`이고, 그것은 GF(p) 밖의 표현을 지니지 않습니다. 이것은 X25519가
마이그레이션될 때 그 `u >= p` 검사에 일어났던 것과 같은 일입니다.

그에 대응하는 *입력* 검사는 그러나 약해지는 대신 더 엄격해졌습니다. RFC 8032
5.1.3절은 p 이상인 y를 축약하는 대신 **거부합니다** — X25519 u 좌표에 대한
RFC 7748의 규칙과 반대입니다. 파일에서 p가 없어졌으므로 대조할 것이 없고,
그래서 `decodePoint()`는 이제 디코드된 y를 다시 인코드해 그것이 온 바이트와
일치할 것을 요구합니다. `Fe25519::toBytes()`가 정규 대표원을 내놓으므로,
정규가 아닌 입력은 그것을 살아남을 수 없습니다.

`encodePoint()`도 자기 반환값을 잃었습니다. `CBigNum::toLittleEndian()`은
32바이트에 너무 큰 값을 보고할 수 있었습니다. `Fe25519::toBytes()`는 항상
정확히 32개의 정규 바이트를 내놓으므로, 죽은 오류 경로 둘이 그것과 함께
갔습니다.

### 그것과 함께 간 side channel

변경의 이유는 아니었지만 기록할 만합니다.

- ladder의 조건부 교환이 `CBigNum::condSwap`, 자기 문서에 따르면 **평범한
  분기**였고, 비밀 스칼라의 한 비트*인* 조건에 대해서였습니다 — 반복마다 키의
  한 비트가 새어 나갔습니다. 이제 산술 mask 아래의 `Fe25519::condSwap`입니다.
- 모든 필드 연산이 가변 시간이었습니다. `CBigNum`이 앞쪽 0 limb을 잘라 내고
  그래서 값에 비례하는 작업을 하기 때문입니다. `Fe25519`는 limb 열 개로
  고정되어 있습니다.
- 두 스칼라 곱셈 모두 `CBigNum::bitLength()`에 걸쳐 루프했으므로, *반복
  횟수*가 스칼라의 최상위 설정 비트 위치를 흘렸습니다. clamp된 개인 스칼라는
  구성상 항상 255비트지만, 서명의 nonce `r`은 mod L로 축약되고 변합니다 —
  그리고 `r`은 키와 같은 정도로 민감합니다. 서명이 `k`가 공개인 상태로
  `S = r + k·s`를 발행하기 때문입니다. 두 루프 모두 이제 256비트로
  고정되었습니다. `CBigNum::testBit()`은 최상위 limb을 지나면 false를 읽고,
  앞쪽 0 비트는 항등원을 더하고 `r1 − r0 == P` ladder 불변식을 온전히
  남기므로, 추가 두 단계는 아무 비용도 들이지 않고 아무것도 바꾸지 않습니다.

누출 하나가 남아 있고 여기서는 의도적으로 처리되지 않습니다.
`scalarMulBase()`가 비밀 스칼라의 window로 `baseTable()`을 인덱싱하는데,
그것은 비밀에 의존하는 메모리 접근입니다. 표는 80바이트 항목 16개이고
현실적으로 L1에 머물며, 그것을 제대로 고치는 것은 constant-time 표 스캔을
뜻합니다 — 측정할 자기 비용을 지닌 별개 변경입니다. 그것은 이 작업보다
앞서고, 이 작업이 도입한 것이 아닙니다.

### 검증

이제 TEST 1만이 아니라 RFC 8032 7.1절의 벡터 다섯 개 전부가 검사됩니다. 빈
메시지, 1바이트, 2바이트, 64바이트(`SHA(abc)`), 그리고 **1023바이트**입니다.
그것들은 타이핑된 것이 아니라 RFC 텍스트에서 추출되었고, 각각이 세 방식으로
검사됩니다 — 시드가 열거된 공개키를 유도하고, 서명이 열거된 64바이트를 정확히
만들어 내며, 검증이 개인키 자신의 공개키를 통해서도 `createPublicKey()`로
따로 가져온 것을 통해서도 성공합니다. 그래서 깨진 `decodePoint()`가 동작하는
`scalarMulBase()` 뒤에 숨을 수 없습니다.

Ed25519는 바이트 단위로 정확하고, 그것이 네거티브 컨트롤을 유별나게 깔끔하게
만듭니다. 각각을 깨뜨리고, 다시 빌드하고, 되돌렸습니다.

| 파손 | 잡힘 |
|---|---|
| `k·s`를 mod L 대신 `Fe25519`를 통해 mod p로 계산 — *그 함정* | Ed25519 케이스 17개 중 7개 실패 |
| `toBytes()`의 조건부 p 뺄셈을 떨어뜨림 | Ed25519 케이스 17개 중 13개, 그리고 `Fe25519` 케이스 9개 중 3개 |
| `recoverX()`에서 부호 비트 테스트를 뒤집음 | Ed25519 케이스 17개 중 7개 실패 |

두 번째가 흥미로운 것입니다. 17개 중 13개는 정규가 아닌 인코딩 하나로
설명되는 것보다 훨씬 많고, 그 이유는 `isEqual()`입니다. 그것은 빼고 0인지
테스트하므로, p로 표현된 0인 차이는 같다고 비교되기를 멈춥니다 — 떨어진
축약은 단지 정규가 아닌 바이트 문자열을 흘리는 것이 아니라, *같은 값*에
대해 동등성을 깨뜨리고, 그것과 함께 하류의 거의 모든 것을 깨뜨립니다.

기존 Ed25519 케이스 13개와 `Fe25519` 케이스 7개는 변경 없이 통과합니다.
어떤 기대값도 편집되지 않았습니다.

### 여전히 100 µs는 아닙니다

검증 1.36 ms는 21배 더 좋고 여전히 최적화된 구현보다 한 자릿수 벗어나
있습니다. 대략 어디로 가는가: `verify`는 스칼라 곱셈을 둘이 아니라 셋
수행합니다 — `decodePoint()`가 서명의 R에 대해 완전한 `L·point` 부분군 검사를
돌리는데, 그것이 서명 검증 자체만큼 비용이 듭니다. 남은 여유는
`Fe25519`(전용 제곱, 그리고 MSVC에 없는 `__int128`이 현재 배제하는 2^51
radix 배치), 전용 두 배화 공식, 그리고 더 싼 cofactor 검사에 있습니다 — 모두
별개 항목이고, 어느 것도 이것은 아닙니다.

## 포스트 양자: ML-DSA 자체(FIPS 204), 그리고 검증된 첫 실제 PQ 인증서

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

### 검증이 먼저 왔고, Python으로

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

### 이 계획이 결코 이름 대지 않았던 것: 메시지 관례 둘

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

### `2.16.840.1.101.3.4.3.19`는 ML-DSA-87입니다

그 arc는 ML-DSA-44/65/87에 대해 `.17`/`.18`/`.19`로 가며, 그 셋이 연속이라는
것이 off-by-one을 가설적인 것이 아니라 현실적인 오류로 만듭니다. 인증서가
레지스트리를 참조하지 않고 그것을 정리해 줍니다. 그 `SubjectPublicKeyInfo`
BIT STRING이 2592바이트를 담고 그 `signatureValue`가 4627을 담는데, 그 짝은
ML-DSA-87 하나에만 속합니다(ML-DSA-65의 것은 1952와 3309입니다).

모든 파라미터 집합이 다른 키 길이*와* 서명 길이를 지니므로, 혼동은 틀린
답이 아니라 깔끔한 거부입니다 — `createPublicKey()`가 그 바이트를 곧바로
거부합니다. 정확히 그 이유로 테스트가 ML-DSA-65 키를 ML-DSA-87에
제시합니다.

### 인수 테스트

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

### `signsMessageDirectly()`, 그리고 그것이 함수 하나인 이유

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

### 메시지에 서명하는 것을 위한 digest 모양 인터페이스

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

### 서명은 hedged이며, 그것이 KAT가 가공되지 않은 층을 거치는 이유입니다

`CMlDsa`는 서명마다 새 32바이트 `rnd`를 뽑으므로(FIPS 204의 권고
기본값), 한 메시지에 대한 두 서명이 다르고 어느 것도 고정된 답과 비교될 수
없습니다. 결정론적 서명 — `rnd`가 전부 0 — 은 테스트용 장치가 아니라 표준
자신의 변종이고, 모든 ACVP `deterministic: true` 그룹이 쓰는 것입니다. 그것은
`MlDsaScheme`을 통해 도달 가능하고 의도적으로 `CMlDsa`를 통해서는 아니므로,
호출자가 그것을 우연히 고를 수 없습니다.

### 영 소거, 그리고 그것이 덮지 않는 것

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

### 네거티브 컨트롤

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

### 의도적으로 여기 없는 것

순수 변종만입니다. HashML-DSA는 Python 참조에서 검증되었지만(ACVP의
`preHash` 그룹 열두 개가 모두 일치) C++에는 없습니다. RFC 9881 8.3절이 그
OID들이 X.509 인증서에 나타나서는 안 된다(MUST NOT)고 말하고, 트리의 다른
어떤 것도 그것들을 필요로 하지 않습니다. `MlDsaScheme`도 ML-KEM의 공개
`CMlKem`과 달리 `src/`에 private으로 남습니다 — 모든 진입점이
`MlDsaParams`로 파라미터화되어 있고, 그 시그니처들을 내보내는 것은 이미
테스트된 그 private 헤더를 공개 API로 옮기거나 중복시키는 것을 뜻할
것입니다. 호출자가 필요로 하지 않는 표면을 위해서요.

## `CMontgomery`: 모든 모듈러 곱셈에서 긴 나눗셈을 빼내기

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
[architecture.md](architecture.ko.md)의 항목을 보십시오. 결정 셋이 여기
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

### 무엇이 변환되었는가

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

### 측정된 효과

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

### 검증

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

CSR 지원은 [`CLAUDE.md`](../CLAUDE.md)와
[`docs/roadmap.md`](roadmap.ko.md) 양쪽에서 의도적으로 범위 밖이라고
열거되어 있었습니다. 그것이 저장소 소유자의 결정으로 바뀌었고, 착륙한 것은
이것입니다. `x509/csr.hpp`의 `CCertRequest`/`CCertRequestBuilder`, 더하기
CA 쪽의 `CCertBuilder::subjectFrom()`입니다.

### 결정 넷, 그리고 이유

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

### 가져오기는 검증합니다. 단지 `verify()`를 제공하는 것이 아닙니다

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

### 리팩터

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

### `attributes`는 선택이 아닙니다

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

### 테스트: 자기 자신하고만 말하는 것은 아무것도

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

## `x509/chain/pem`: PEM 컨테이너 형식, 그리고 `CCert`에서 빠져나온 PEM

`include/certpp/x509/chain.hpp`는 `IChainFormat`을 — `CCertCollection`을
컨테이너 파일로 읽고 쓰기 — 정의했고, `builtIn()`은 모든 형식에 대해 null을
반환했습니다. 이것이 그 PEM 절반입니다.
`CPemChainFormat`(`include/certpp/x509/chain/pem.hpp`,
`src/x509/chain/pem.cpp`)이고, `builtIn(ECHAINFMT_PEM)`에 배선되었습니다.

분명하지 않은 부분은 의존성의 방향입니다. `CCert`에는 이미 PEM이
있었습니다. 다중 블록 스캔, 라벨 처리, base64 프레이밍, 그리고 개인키 블록을
인식하는 네 방법(PKCS#1, DSA traditional, SEC1, PKCS#8 — 그중 마지막은 차례로
네 방법을 시도했습니다)입니다. 그 전부가 *컨테이너* 작업이면서 인증서 클래스에
앉아 있었는데, `CCertCollection`이 존재하기까지 그것을 둘 다른 곳이 없었기
때문입니다. 그래서 그것은 감싸이는 대신 옮겨 갔습니다. `CPemChainFormat`이
이제 라이브러리의 유일한 PEM 처리이고,
`CCert::importPem()`/`exportPem()`/`detectCertFormat()`은 얇은
위임입니다 — `importPem()`은 항목 하나짜리 컬렉션을 적재해 첫 항목을 유지하고,
`exportPem()`은 하나를 저장하고, `detectCertFormat()`은
`IChainFormat::detect()`에 묻습니다. 기존 `CCert` PEM 테스트 케이스 15개가
그 뒤에 수정 없이 통과했는데, 그것이 이 모양의 리팩터를 하기에 안전한 유일한
이유입니다. `tests/x509/chain/pem.cpp`의 새 케이스가 추가로 `exportPem()`의
바이트를 형식 자신의 `save()` 출력에 바이트 단위로 못 박으므로, 그 위임이
조용히 두 번째 구현이 될 수 없습니다.

`CCert`가 유지하고 형식이 friendship을 통해 닿는 것 둘: `_asym`(후보 키
블록이 그 아래에서 파싱되어야 하는 알고리즘이고, 이미 `importDer()`가
해소한 것)과 기존 `KEY_ALGOS` 표에 대한 새 private `lookupKeyAlgoOid()`
입니다 — PKCS#8 키 블록이 나르는 OID는 `importDer()`가 인증서의 알고리즘을
해소한 바로 그 표에서 와야 하고, 떠내려갈 수 있는 두 번째 사본에서 와서는
안 됩니다.

인터페이스가 어느 답이든 허용했으므로, 기록할 만한 결정들:

- **`save()`는 요청받지 않으면 개인키를 쓰지 않습니다.** PEM에는 암호화가
  없으므로, 써 내보낸 키는 평문 상태의 키입니다. `builtIn()`은 인증서 전용
  형태를 반환하고 `CPemChainFormat(true)`가 opt-in입니다(
  `exportPem(out, /*includePrivateKey=*/true)`가 구성하는 것입니다). 평문
  상태의 키는 때로 호출자가 원하는 것입니다. 아무도 요청하지 않은 평문
  상태의 키는 아닙니다. `password` 인자는 양방향에서 *곧바로 무시*되며 —
  보호처럼 읽힐 받아들이고-검사하기가 아닙니다 — 헤더, doc 주석, 테스트가
  모두 그렇다고 말합니다.
- **이 라이브러리가 알고리즘을 해소할 수 없는 인증서는 거부되는 것이 아니라
  적재됩니다.** `importDer()`가 그것을 완전히 파싱하고
  `keyAlgo()`/`signAlgo()`를 가공되지 않은 OID 텍스트로 남깁니다. 그것을
  떨어뜨리는 것은 파일이 진짜로 담고 있고 컬렉션의 이름 기반 조회가 여전히
  동작하는 인증서를 잃는 일이 될 것입니다. 그 키만 쓸 수 없으므로, 어떤
  개인키도 그것과 짝지어지지 않습니다. SPKI 알고리즘 OID의 한 바이트가 바뀐
  실제 인증서에 대조해 테스트되었습니다.
- **키 블록은 위치가 아니라 암호학적으로 짝지어집니다.** 파일 전체를 먼저
  스캔하고, 그 다음 각 인증서에
  `CCert::privateKey(IPrivateKeyPtr&)` 자신의 공개키 비교가 하나를
  받아들이기까지 소비되지 않은 모든 키 블록을 제시합니다. 자기 인증서 앞의
  키, 뒤의 키, 그리고 어느 쪽에도 속하지 않는 키가 모두 올바르게 동작하는데,
  위치 기반 짝짓기는 그것을 해낼 수 없습니다.
- **구조적으로 깨진 블록은 컨테이너 전체를 실패시킵니다**(`ERET_BADREQ`).
  `CCert::importPem()`은 그 지점에서 스캔을 멈추고 이미 찾은 것으로 성공을
  보고했습니다. 그것이 이 이동이 의도적으로 바꾸는 유일한 문서화된
  동작입니다. 스캔을 조용히 절단하는 것은 파일이 아무도 듣지 못한 채 인증서나
  키를 잃는 방식입니다. 그것은 `importPem()` 자신의 doc 주석에 짚여
  있습니다.
- **password로 암호화된 키 블록은 `ERET_BADREQ`가 아니라 `ERET_NOTSUP`
  입니다** — `ENCRYPTED PRIVATE KEY` 라벨(PKCS#8)이나 openssl이 여전히 쓰는
  RFC 1421의 `Proc-Type: 4,ENCRYPTED` 헤더 중 하나입니다. 파일은 제대로 된
  형태이고, 그것이 필요로 하는 것은 이 형식이 받아들일 방법이 없는
  password입니다. `Proc-Type` 검사가 없으면 레거시 형태는 "잘못된 형태"를
  보고했을 것입니다.
  그 헤더는 base64가 아니기 때문입니다.
- **PKCS#9 속성이 openssl 자신의 `Bag Attributes` 모양으로 함께
  실립니다**(`friendlyName:`/`localKeyID:`가 encapsulation 경계 밖에 있는데,
  거기서 RFC 7468 5.2절이 임의 텍스트를 허용하고 다른 모든 독자가 그것을
  건너뜁니다). 그래서 `IChainFormat` 자신의 doc 주석이 두 형식에 대해
  약속하는 대로 `SCertEntry`의 속성이 PFX → PEM → PFX 여행을 살아남습니다.
  줄바꿈을 담은 `friendlyName`은 그것이 넘쳐 나올 헤더에 쓰이는 대신
  거부됩니다.

옛 `CCert` 버전이 하지 않았고 이것이 하는 것 하나: 디코드된 키 블록은
`load()`를 나가는 길에, 그 반환 경로 중 어느 것이 취해지든 영 소거됩니다
(`CSecure::zero`) — 그것들은 평문 개인키이고, 이 함수 자신의 사본을 해제된
힙 메모리에 남기는 것은 공짜로 피할 수 있습니다. 어떤 사본도 살아남지 않는다는
주장은 아닙니다. 호출자의 PEM 텍스트가 같은 바이트를 base64로 담고 있고,
그것은 호출자가 지울 몫입니다.

`load()`는 지역에 쌓아 올리고 파일 전체가 파싱된 뒤에만 컬렉션에 커밋합니다.
인터페이스가 덧붙이기를 요구하고 *그리고* 실패가 컬렉션을 건드리지 않은 채
남길 것을 요구하기 때문입니다 — 스캔이 진행되면서 출력에 쓰는 것은 분명한
구현으로 읽히고, 바로 그 문장이 금지하려고 존재하는 버그입니다.

테스트는 의도적으로 구현을 자기 자신에 대조해 증명하는 것을 피합니다.
`tests/x509/chain/certs/` 아래의 픽스처는 전부 OpenSSL 3.4.0이 썼습니다.
`openssl x509 -inform DER`로 변환한 `tests/x509/certs/implemented/`의 실제
상용 인증서 셋, 각 키가 자기가 속하지 *않는* 인증서 옆에 앉도록 끼워 넣은
`openssl req -x509 -newkey ...`에서 나온 일회용 RSA와 P-256 자기 서명 쌍,
같은 EC 키를 전통적인 SEC1 블록으로 한 것, `Bag Attributes` 파싱을 위한
`openssl pkcs12 -nokeys` bag 덤프, 그리고 openssl이 암호화할 수 있는 두 방식
모두로 암호화한 키입니다. 실제 인증서 셋이 openssl의 base64에서 디스크의
`.der` 파일과 바이트 단위로 동일하게 다시 나오는데, 그것이 중요한 상호운용성
주장입니다. 네트워크에서 가져온 것은 아무것도 없습니다.

네거티브 컨트롤, 각각을 주입하고 다시 빌드하고 되돌렸습니다.

| 주입된 결함 | 잡아낸 것 |
|---|---|
| `load()`가 끝에서가 아니라 파싱하면서 각 항목을 출력 컬렉션에 커밋 | 실패 9개: 손상된 컨테이너 하위 케이스 네 개 전부가 컬렉션이 반쯤 채워진 채 남았다고 보고하고, 키 짝짓기 케이스 셋도 깨집니다(커밋된 사본이 키를 결코 받지 못합니다) |
| `load()`가 추가하기 전에 컬렉션을 지움, 즉 덧붙이는 대신 교체 | 병합 케이스에서 실패 5개(개수가 7 대신 6, 모든 인덱스가 밀림) |
| 페이로드가 디코드되지만 인증서가 아닌 블록을 컨테이너를 실패시키는 대신 건너뜀 | 실패 4개: 손상된 페이로드와 그룹 전체 절단 하위 케이스가 둘 다 `ERET_OK`를 보고하고, 컬렉션에는 살아남은 항목들이 남습니다 |

세 번째 컨트롤은 또한 테스트 첫 초안의 공백을 찾았습니다. "절단된 페이로드"
케이스는 base64 본문 끝에서 40문자를 제거했는데, 그것은 부분적인 4문자 그룹을
남깁니다 — 그래서 *디코더*가 그것을 거부했고 인증서 파싱이 결코 돌지 않았으며,
이는 DER 검사가 비활성이어도 그 테스트가 통과했을 것이라는 뜻입니다. 고침은
base64 그룹의 온전한 개수만큼 절단하는 두 번째 하위 케이스였고, 그것은
깔끔하게 디코드되며 DER 파싱으로만 잡힐 수 있습니다. 두 층, 두 하위
케이스입니다.

## PBKDF2, 그리고 첫 컨테이너 형식으로서의 PKCS#12/PFX

`x509/chain.hpp`는 `IChainFormat`과 `ECHAINFMT_PFX`를 정의했고 `builtIn()`은
모든 형식에 대해 null을 반환했습니다. 이것이 PFX를 채웠습니다. 전제 조건은
PKCS#12에 대한 무엇이 아니라 빠진 프리미티브로 드러났습니다.

### `CPbkdf2`(RFC 8018 5.2), 그리고 `CHkdf`가 대신할 수 없었던 이유

라이브러리에는 `CHkdf`가 있었고 password 기반 KDF는 아예 없었습니다. HKDF는
대체물이 아니고 그 이유는 기술적 세부가 아닙니다. 그것은 이미 완전한
엔트로피를 지닌 입력에 대해 HMAC 둘을 돌리고, 그 입력을 맞히는 것이 절망적이기
때문에 빠른 것이 아무 비용도 들지 않습니다. password는 완전한 엔트로피를
지니지 않으므로, 그것에 대한 KDF가 지닌 유일한 방어는 각 추측을 비싸게 만드는
것입니다 — 그것이 바로 HKDF에 없는 성질입니다. `CHkdf`에 password를 먹이면
올바르게 유도되고 공격자의 회선 속도로 깨지는 키가 나옵니다.

그래서 `CPbkdf2`가 PFX 코드 안에 숨는 대신 `CHkdf` 옆의
`include/certpp/crypto/pbkdf2.hpp` + `src/crypto/pbkdf2.cpp`에
착륙했습니다 — 그것은 범용 프리미티브이고 호출자들이 그것을 단독으로 원할
것입니다. `CHkdf`의 doc 주석은 PBKDF2가 언젠가 도착하면 `IKdf` 인터페이스가
그것과 함께 도입되어야 한다고 예측했습니다. 그 예측은 다시 검토되고
사양되었습니다. 그 둘이 공유하는 것은 "span을 받는 static `derive()`" 뿐이고,
그것은 모양이지 추상이 아니기 때문입니다. 그 주석은 지켜지지 않은 의도로
읽히게 남겨지는 대신 그렇게 말하도록 갱신되었습니다.

파라미터 결정 셋이 헤더에 진술되어 있는데, 각각이 구현이 조용히 잘못되는
곳이기 때문입니다.

- **반복 횟수 0은 "반복 없음"이 아니라 `ERET_BADREQ`입니다.** RFC 8018은
  `c`를 양수로 정의하고 `T(i)`는 적어도 `U(1)`의 XOR이므로, 0은 그 블록을
  정의되지 않은 채 남깁니다. 더 요점은, 호출자가 공급한 컨테이너에서 파싱된
  횟수가 그 유도를 공짜 유도로 바꿀 수 있어서는 결코 안 된다는 것입니다.
- **출력은 `(2^32 - 1) * hLen`으로 제한됩니다.** `INT(i)`가 32비트
  카운터이기 때문입니다. 그것을 지나면 블록 1로 되감기고 출력이 반복됩니다.
  `maxDeriveBytes()`는 그 경계를 64비트로 계산하고 포화시키는데, 32비트
  `size_t`에서는 실제 값이 들어가지 않고 되감긴 경계는 경계가 아닐 것이기
  때문입니다.
- salt는 비어 있을 수 있습니다. RFC 8018 4.1절은 무작위 출처에서 64비트를
  요청하지만, 다른 누군가의 컨테이너를 재현하는 호출자는 그 안에 있는 어떤
  salt든 받아들여야 하므로, 최소값은 문서화되고 강제되지 않습니다.

#### 검증

모든 기대값을 테스트에 적어 넣기 전에 Python의 `hashlib.pbkdf2_hmac`에서
재현했고, 그 단계가 곧바로 자기 값을 했습니다. RFC에서 기억해 낸 값 둘이
틀렸습니다. RFC 6070의 네 번째 케이스는 `...8b291a964fe0858c`가 아니라
`...8b291a964cf2f07038`로 끝나고, RFC 7914 11절의 첫 SHA-256 케이스는 둘로
타이핑하기 쉬운 곳에 `5`가 하나인 `...fec1691c22544b60...`을 지닙니다. 그것들이
적힌 대로 들어갔다면, 구현이 그것들을 재현하기까지 "고쳐졌을" 것입니다.

`tests/crypto/pbkdf2.cpp`는 RFC 6070의 HMAC-SHA1 케이스 다섯 개 전부(NUL이
박힌 password와 salt, 그리고 `INT(i)`를 조금이라도 연습하는 유일한 것인
25바이트 출력을 포함합니다. `dkLen <= hLen`에서는 카운터가 항상 1이고 그것의
틀린 인코딩이 보이지 않기 때문입니다)와 RFC 7914 11절의 HMAC-SHA256 케이스
둘을 덮습니다.

RFC 6070의 16777216 반복 케이스는 **의도적으로 빠져 있고**, 그 이유는
실행 시간입니다. 그것은 더 큰 `c`를 지닌 4096 반복 케이스와 같은
유도이고, 이 라이브러리의 처리량(release 빌드에서 HMAC-SHA256 연산당 0.50 µs로
측정)에서 그것은 루프 하나를 다시 테스트하려고 모든 `ctest` 실행에 몇 분을
더할 것입니다. 그것은 대역 밖에서 한 번 검증되었고 — Python의 C 기반
hashlib이 그것에 17.3초가 걸리며 RFC와 일치합니다 — 4096과 80000 반복
케이스가 테스트 모음에서 같은 루프를 나릅니다.

### `CPfxFormat`(RFC 7292)

`include/certpp/x509/chain/pfx.hpp` + `src/x509/chain/pfx.cpp`이고,
`IChainFormat::builtIn()`에 배선되었습니다. `docs/architecture.md`가 형식
결정들을 기록합니다(PBES2/AES-256-CBC만, MAC에 HMAC-SHA-256, 600,000 반복,
복호화 전 MAC, 두 password 인코딩). 뒤따르는 것은 그 작업이 드러낸
것입니다.

**레거시 PKCS#12 KDF를 결국 구현해야 했고, 간신히 그렇습니다.** 계획은
PBES2를 택해 RFC 7292 부록 B를 완전히 피하는 것이었습니다. 그것은
*암호화*에 대해서는 가능합니다 — OpenSSL 3이 AES-256-CBC를 지닌 PBES2를
기본값으로 하므로, 레거시 RC2/3DES 암호는 그냥 `ERET_NOTSUP`으로 거부할 수
있습니다. *무결성*에 대해서는 가능하지 않습니다. RFC 7292 4절은 `MacData`의
키가 purpose 바이트 3을 지닌 부록 B KDF에서 온다고 명세하고, RFC에 대안이
없으며, 따라서 모든 실제 컨테이너가 그것을 씁니다. (2024년의 RFC 9579
PBMAC1은 거기서 PBKDF2를 허용합니다. 아직 그것을 쓰는 것은 없습니다.) 그래서
그 KDF는 구현되었고, 정확히 그 키 하나로 범위가 제한되었으며, `CPbkdf2`
옆의 `crypto/`에 놓이는 대신 `pfx.cpp`의 파일 지역 헬퍼로 유지됩니다 —
그것은 레거시 PKCS#12 전용 구성이고 다른 어떤 것도 그것에 손을 뻗어서는
안 됩니다. 어떤 PBES1 키나 IV도 그것으로 유도되지 않고, 어떤 RC2나 3DES도
읽히거나 쓰이지 않습니다.

**password가 같은 파일 안에서 두 가지 다른 방식으로 인코드됩니다.** PBES2는
PKCS#5이고 password 바이트를 주어진 대로 받습니다. 부록 B의 KDF는 PKCS#12
자신의 것이고 그것들을 NUL로 끝나는 빅엔디언 UTF-16 BMPString으로 받습니다.
이것들을 같은 방향으로 하면 다른 어떤 것도 읽을 수 없는 컨테이너가
나오고 — 이것이 함정입니다 — 쓰는 구현은 그것을 완벽하게 다시 읽습니다. 둘
다 C++가 쓰이기 전에 실제 OpenSSL 컨테이너에 대조해 Python에서 못
박았습니다. 부록 B 유도는 픽스처의 HMAC을 다시 계산해 그 저장된 MAC과 바이트
단위로 맞춰 검사했고, PBES2 쪽은 키를 두 방식으로 유도해 각각을
`openssl enc -d`에 건네 어느 것이 인증서 bag을 복호화하는지 보아
검사했습니다. 동작하는 것은 가공되지 않은 바이트 키입니다.

UTF-8에서 UTF-16으로의 방향도 중요합니다. 더 오래된 OpenSSL의
`OPENSSL_asc2uni`는 각 바이트를 Latin-1 식으로 0 확장했습니다. OpenSSL 3은
UTF-8을 변환합니다. ASCII password에 대해서는 그 둘이 일치하는데, 그것이
`fixtures/openssl-utf8-password.p12`가 트리에 있는 이유입니다 —
`passwörd` 아래에서 다른 곳에서 쓰인 컨테이너가 그 둘을 구별하는 유일한
것이고, 이 라이브러리를 통한 왕복은 그럴 수 없습니다. 어느 쪽이든 자기
자신과 일치할 것이기 때문입니다.

#### `CCert`를 복사하는 대신 리팩터하기

PFX는 키를 PKCS#8로 저장하고 `CCert`에는 이미 들어오는 절반이
`unwrapPkcs8PrivateKey()`와 `importPem()`이 쓰는 알고리즘별 변환에
있었습니다. 그중 어떤 것도 있는 그대로는 재사용할 수 없었습니다.
`tryAttachPrivateKey()`는 무언가가 파싱되기까지 blob을 한 인증서 자신의
알고리즘 아래에서 시도해 그 모양을 추측하는데, 키 bag은 그럴 수
없습니다(그것은 어느 인증서와 짝지어지는지 알려지기 전에 읽을 수 있어야
합니다). 그리고
`buildSec1PrivateKey()`/`convertPkcs8DsaInnerToNative()`는 자기 입력을
`CCert` 자신의 파싱된 필드에서 읽습니다.

두 번째 사본을 쓰는 대신 공개 static 둘이 추가되었고 —
`CCert::exportPkcs8PrivateKey()`와 `importPkcs8PrivateKey()` — 상태에
의존하는 헬퍼 둘이 쪼개져 두 호출자가 모두 인코더 하나에 닿습니다.

- `buildSec1FromNative(native, curveOid, publicPoint, out)`은 세 입력이
  넘겨진 `buildSec1PrivateKey()`의 몸체입니다. native blob이 하나를 박아 넣고
  있지만 공개 점은 명시적 인자로 남으므로, 그 리팩터가 `exportPem()`이 늘
  써 온 것을 바꿀 수 없습니다.
- `buildDsaNative(dssParms, y, innerX, out)`은
  `convertPkcs8DsaInnerToNative()`와 새 가져오기 경로의 공유 몸체입니다. 그
  둘은 `y`가 어디서 오는지에서만 다르고, 그 차이 자체가 기록할 만합니다.
  인증서는 `y`를 나르고, PKCS#8 DSA 키는 그것을 아예 나르지 않으므로, 하나를
  단독으로 읽는 것은 `CBigNum::modExp()`를 통한 `g^x mod p` 비용을
  들입니다.

ML-DSA는 감싸이는 대신 거부됩니다(`ERET_NOTSUP`). 그 PKCS#8 형태는 32바이트
시드와 완전히 확장된 키 사이의 CHOICE이고, 이 라이브러리 자신의 키 blob은 어느
모양도 아니므로, 하나를 쓰는 것은 아무것도 읽지 않는 인코딩을 추측하는 일이
될 것입니다. `CCert`의 기존 테스트는 수정 없이 통과합니다.

#### 검증: 이 라이브러리가 쓰지 않은 것을 읽기

이 코드가 쓰고 다시 읽은 PFX는 버그 둘이 상쇄된다는 것을 증명합니다.
`openssl`이 PATH에 있었으므로, 컨테이너 다섯 개를 `openssl pkcs12 -export`로
한 번 만들어 `tests/x509/chain/fixtures/` 아래에 체크인했습니다(그래서 테스트
모음 자체는 openssl이 필요 없습니다). OpenSSL 3 자신의 기본값 아래의 EC 키,
RSA 키, 인증서 둘짜리 체인, 명시적 SHA-1 `MacData`, 그리고 `ERET_NOTSUP`으로
돌아와야 하는 `-legacy -certpbe PBE-SHA1-3DES` 컨테이너입니다. 여섯 번째가
ASCII가 아닌 password를 위해 추가되었습니다. 그중 어느 것도 픽스처로 쓰이기
전에, `openssl asn1parse`와 손으로 쓴 Python 디코더가 첫 번째 것을 TLV 단위로
걸었으므로, C++가 기대하는 구조는 문법을 읽어서가 아니라 실제 파일에서
유도되었습니다.

그 첫 실행이 그 연습이 존재하는 이유인 버그를 찾았고, 돌아보면 미묘하지
않았습니다. `parsePbes2()`는 모든 호출자에게서 PBES2-params SEQUENCE의
*내용*을 건네받았는데(그것들 모두 `readNextElement()`를 통해 거기 닿습니다)
또 다른 `readSequence()`로 시작했으므로, `keyDerivationFunc`를 PBES2-params
전체인 것처럼 읽고 한 층 더 아래에서 실패했습니다. 모든 픽스처의 모든 적재가
`ERET_BADREQ`를 반환했습니다. 자기 왕복 테스트 모음도 동일하게 실패했을
것이므로, 이것은 그 자체로 상호운용 픽스처에 대한 증거는 아닙니다 — 그러나
파일의 다른 어떤 것도 *어느* 쪽이 틀렸는지를 말해 주지 않았을 것입니다.

반대 방향은 손으로 검사했습니다. 테스트가 셸로 나갈 수 없기 때문입니다. 왕복
케이스가 작업 디렉터리에 `pfx-written-by-certpp.p12`를 쓰고, 그것에 대한
`openssl pkcs12 -info`가 MAC을 검증하고, 인증서 bag과 가려진 키 bag 둘 다를
복호화하고,
`PBES2, PBKDF2, AES-256-CBC ... PRF hmacWithSHA256`과 `MAC: sha256`을
보고하고, `friendlyName`과 `localKeyID`를 인쇄하며, 그 `localKeyID`로 leaf를
CA 인증서 둘에서 분리합니다. 추출된 키의 공개 점은 leaf 인증서의 것과 동일하게
해시되고, `openssl`은 그 파일에 대한 틀린 password를
`Mac verify error: invalid password?`로 거부합니다.

#### 네거티브 컨트롤, 각각을 주입하고 다시 빌드하고 되돌렸습니다

| 주입된 결함 | 잡아낸 것 |
|---|---|
| MAC 판정을 AuthenticatedSafe가 파싱되고 복호화된 뒤로 미룸 | tamper 일소 케이스에서 실패 605개 — 대부분의 뒤집기가 `ERET_BADREQ`가 됩니다 |
| MAC에 `CSecure::equals()` 대신 `std::memcmp` | **아무것도** — 아래 참조 |
| 유도된 PBES2 키에서 `CSecure::zero()` 제거 | **아무것도** — 아래 참조 |
| `save()`에서 빈 password 거부 제거 | 실패 2개, 그리고 password 없이 컨테이너를 썼습니다 |

잡히지 않은 둘은 정직한 놓침이고, 둘 다 그럴 것으로 예상되었습니다.
`memcmp`는 `CSecure::equals()`와 같은 답을 반환합니다. 다른 양의 시간이
걸릴 뿐이고, 어떤 기능 테스트도 그것을 볼 수 없습니다. 빠진
`CSecure::zero()`는 키 바이트를 해제된 힙에 남기는데, 그것 역시 테스트 모음이
단정할 수 있는 어떤 것에도 보이지 않습니다. 어느 것도 테스트로 방어되지
않으며, 그렇지 않은 척하는 것은 남길 틀린 기록이 될 것입니다. 그것들은 리뷰,
그 프리미티브들이 손을 뻗기에 분명한 것이라는 사실, 그리고 이유를 말하는 doc
주석으로 방어됩니다. 타이밍 쪽은 PFX MAC이 공격자가 이미 가진 값에 대조해
비교되더라도 유지할 만합니다 — 이것은 라이브러리이고, `load()`를 업로드된
파일에 노출하는 호출자는 그것을 constant-time 비교가 대비하는 바로 그 온라인
oracle로 바꿔 놓습니다.

tamper 일소 자체가 이 작업 중에 날카로워졌습니다. 그것은 "파일 뒤쪽
3분의 2에서 일곱 번째 바이트마다 뒤집고 `ERET_KEY_ERROR`를 기대"로
시작했는데, 오프셋 셋에서 실패했습니다 — 그리고 그것들을 조사하는 것이
고치는 것보다 더 유용했습니다. 셋 다 MAC이 덮을 수 없는 `MacData`에
있는데, `MacData`가 MAC이 있는 곳이기 때문입니다. 둘은 손상된
`DigestInfo`(`ERET_BADREQ`)와 인식되지 않는 digest OID(`ERET_NOTSUP`)였습니다.
세 번째는 digest `AlgorithmIdentifier`의 무시되는 `parameters` 필드에서
`NULL` 태그를 뒤집었고 아무것도 바꾸지 않았으므로, 컨테이너가 적재되었습니다 —
올바르게도, 그것이 여전히 진정했기 때문입니다. 일소는 이제
AuthenticatedSafe를 찾아 그 바이트 **전부**(1048개이고, 그것이 그 케이스를
표본에서 공격자가 페이로드를 넣을 수 있는 범위의 전수 커버리지로 만든
것입니다)를 뒤집으며, 주석은 파일 전체가 보호된다고 암시하는 대신 MAC의
범위가 무엇인지 진술합니다.

#### 리뷰가 찾았고 테스트는 찾지 못한 것 둘

둘 다 "MAC이 무엇이든 보증하기 전에 무엇이 돌아가는가?"와 "이 버퍼 타입이
실제로 무엇을 하는가?"를 묻는 데서 나왔고, 어느 것도 실패하는 단정으로
나타나지 않았을 것입니다.

**`CBuffer::resize()`는 제자리에서 절단하지 않습니다.** `aesCbc()`는 여유
블록을 할당하고(암호화는 항상 pad 블록을 덧붙입니다) 원래는 결과를
`out.resize(total)`로 다듬었습니다. 그러나 `resize()`는 *항상* 새 블록을
할당하고, 유지할 부분을 복사하고, 옛 것을 `delete[]`합니다 — 그것을 지우지
않고요. 복호화 경로에서 그 옛 블록은 완전한 평문을 담고 있고, 그것은
`pkcs8ShroudedKeyBag`에 대해서는 개인키이므로, 다듬기가 그 키를 평문 상태로
할당기에 건네고 그 다음 호출자 자신의 `CSecure::zero()`는 대신 살아남은
사본을 지웠습니다. 이제 정확한 길이를 밖으로 복사하고, 초과 크기 블록을
지우고, 그것을 swap해 치웁니다(이 라이브러리의 컨벤션에 따라 move 대입이
swap하므로, 지워진 블록이 파괴되는 쪽입니다).

**`MacData`의 반복 횟수가 MAC이 검사되기 전에 작업을 구동합니다.** MAC을
검사하려면 MAC 키가 유도되어야 하고, 그 횟수는 파일에서 나오므로, 그것은 그
형식에서 공격자가 고르는 하나뿐인 반복 횟수입니다. 원래 경계는
`0x7FFFFFFF`였는데, 그것은 200바이트 파일에 대해 CPU 약 18분입니다.
`CPfxFormat::MAX_MAC_ITERATIONS`는 이제 10,000,000이며 — RFC 7292의 1024,
OpenSSL의 2048, 이 라이브러리 자신의 600,000보다 훨씬 위이므로 상호운용성
비용이 들지 않습니다. 그것을 위한 테스트는 그 필드만 바꾼 실제 컨테이너를
다시 만들고 결과 셋을 검사하는데, 흥미로운 부분이 그것들이 다르다는
것이기 때문입니다. 천장을 지난 것과 0은 `ERET_BADREQ`이고, 천장 안이면서
그 컨테이너에 대해 그냥 틀린 횟수는 `ERET_KEY_ERROR`입니다. 일괄 거부는 앞의
둘을 통과하고 세 번째를 실패시킬 것입니다.

여기 있는 동안, `CCert`의 PKCS#8 메서드 둘의 개인키 지역 변수가 작은 TU 지역
`ScopedWipe` 위로 옮겨 갔습니다. 둘 사이의 `return` 문 스물 개가 각각 버퍼
둘이나 셋에 키를 담고 있었고, 각각 옆에 써 둔 지우기는 분기가 추가되는
첫 순간 틀려지는 지우기입니다. 그것은 자라는 `CBuffer`의 *중간* 상태에는
닿지 않습니다 — `resize()`가 각 이전 블록을 지우지 않고 해제합니다 — 그것은
버퍼 타입의 성질이고, `exportPem()` 자신의 키 경로와 공유되며, 여기가
아니라 `CBuffer`에 속합니다.

#### 틀렸던 주석, 그리고 틀리지 않았던 수명

`SBag`은 원래 자기 bag 값을 복호화된 `SafeContents` 평문으로의 span으로
담았고, 평문들은 `TArray<CBuffer>`에 살려 두었습니다. 그것은 dangling span
버그처럼 보였고 — 배열을 키우면 그 원소들이 재배치됩니다 — bag당 소유하는
`COctet`으로 바뀌었습니다. 그 뒤에 `TArray::reserve()`를 확인하자 원래가
실은 안전했음이 드러났습니다. 그것은 move 생성으로 재배치하고, `CBuffer`의
move는 같은 힙 블록을 건네주므로, 주소가 살아남습니다. 그래도 변경은 더
작지만 실재하는 이유로 유지되었습니다 — 각 평문이 이제 `load()` 끝까지
사는 대신 자기 bag들이 읽히는 즉시 지워질 수 있습니다 — 그리고 주석은
거기 없던 버그를 주장하는 대신 그렇게 말하도록 교정되었습니다. `SBag`의
소멸자가 그 지우기를 하는데, 암호화된 `SafeContents`가 평범한 `keyBag`을
담을 수 있고 그것을 읽은 뒤부터 메서드 끝까지 오류 반환이 여섯 개쯤
있기 때문입니다.

#### 검증

기존 테스트 케이스 123개가 어떤 기대값도 편집되지 않은 채 통과합니다.
`tests/crypto/pbkdf2.cpp`와 `tests/x509/chain/pfx.cpp`가 테스트 모음을
실행 파일 125개로 만들고, 전부 통과합니다(PFX 파일 하나만 케이스 22개와
단정 ~4,500개이며, 대부분이 tamper 일소입니다).

#### 하지 않은 것

- **레거시 PKCS#12 암호**(RC2-40-CBC, PBES1 아래의
  `pbeWithSHAAnd3-KeyTripleDES-CBC`)는 읽히는 것이 아니라 거부됩니다. 대략
  2021년보다 오래된 도구나 `openssl pkcs12 -legacy`가 쓴 컨테이너는 그것들을
  필요로 합니다. 픽스처가 그 `ERET_NOTSUP`을 단정하며 트리에 있으므로, 나중에
  지원을 추가하는 것에는 뒤집히기를 기다리는 테스트가 있습니다. 반쯤 된
  것이 아니라 후속 작업으로 범위가 정해졌습니다.
- **공개키 무결성 및 프라이버시 모드**(`signedData` `authSafe`, 또는
  `envelopedData` ContentInfo)는 `ERET_NOTSUP`을 반환합니다.
- **RFC 9579 PBMAC1**은 `MacData`의 키가 부록 B의 KDF 대신 PBKDF2에서 오게
  할 것인데, 어느 방향으로도 구현되지 않았습니다.

## 위키의 예제 코드가 드러낸 API 공백 셋

모든 공개 타입에 대해 컴파일되는 예제를 쓰는 것은 문서화 작업인 만큼이나
감사로 드러났습니다. 예제는 호출자가 할 방식으로 타입을 얻어야 하는 첫
호출자이고, 타입 셋이 그 방식으로 쓰일 수 없었습니다. 각각은 그 예제를
쓰려 시도하고 실패하는 데서 찾아졌습니다.

### `EDecoderStatus`는 공개인 것이 아무것도 만들어 낼 수 없는 공개 enum이었습니다

`asn1/decoder.hpp`는 상태 값 일곱 개를 내보냅니다. 그것들을 만들어 내는
유일한 것인 `decodeLength()`는 private이었고, 모든 공개 `CDecoder` 진입점이
`bool`을 반환했습니다. 그래서 그 enum이 나르기 위해 존재하는 하나뿐인
구분 — `EDEC_NEED_MORE`, "절단됨, 바이트를 더 보내라" 대
`EDEC_RESERVED`/`EDEC_TOO_BIG`/`EDEC_PROHIBITED`, "잘못된 형태, 포기하라" —
이 그것을 가장 필요로 하는 호출자들, 소켓이나 스트림에서 디코드하는 누구에게도
쓸 수 없었습니다.

그 상태는 계산되고 그 다음 버려지고 있었습니다. `readIndefiniteContent()`와
깊이를 추적하는 `readEncodedValue()`가 이제 `bool` 대신 `EDecoderStatus`를
반환하므로, `EDEC_NEED_MORE`가 잘못된 형태인 것과 같은 실패로 납작해지는
대신 중첩된 값에서 전파되며, 새 공개 `tryReadEncodedValue()`가 그것을
호출자에게 건넵니다. `bool readEncodedValue()`는 자기 정확한 시그니처를
유지하고 이제 `tryReadEncodedValue(...) == EDEC_OK`이므로, 서로 떠내려갈 수
있는 둘이 아니라 구현이 하나입니다.

기계적 변환이 아니라 판단을 필요로 한 곳 둘:

- **디코드되지 않을 태그.** `CTag::decode()`는 "바이트가 아예 없음",
  "high-tag-number 형태가 span 끝을 지나 달림", "태그가 아님"을 무효 태그
  하나로 접고, 그 뒤에 구별 가능한 것은 첫 번째뿐입니다. 빈 소스는
  `EDEC_NEED_MORE`를 보고하고, 그 밖의 것은 `EDEC_BAD_ARGS`를 보고합니다.
  진짜로 잘못된 형태의 태그에 바이트를 덧붙이라고 호출자에게 말하는 것은
  지킬 수 없는 약속이기 때문입니다.
- **`MAX_NESTING_DEPTH`를 지난 무한 길이 중첩**은 `EDEC_PROHIBITED`가 아니라
  `EDEC_TOO_BIG`을 보고합니다. 그 인코딩은 합법적인 BER이고, 더 깊이 가기를
  사양하는 것은 이 디코더이며, 그 두 상태는 그것이 누구의 잘못인지에 대해
  다른 것을 말합니다.

네거티브 컨트롤: 절단된 값을 `EDEC_BAD_ARGS`로 되접기, end-of-contents 경우를
일반 실패로 되돌리기, 그리고 옛 코드가 그랬듯 `decodeLength()` 자신의 상태를
버리기를 각각 따로 주입했고, 각각 잡혔습니다.

이 타입이 위키에 나르는 예제는 길이 옥텟을 손으로 분류했는데, 그것이 가능한
유일한 예제였기 때문입니다. 이제 실제 읽기 루프를 구동하며, 그것이 그 enum이
대비했던 것입니다.

### `COctet`은 `const_cast` 없이 자기 비밀을 지울 수 없었습니다

`COctet`의 바이트는 읽기 전용 `toPtr()`/`toSpan()`을 통해서만 닿을 수 있으므로,
`CSecure::zero()`를 그것들에 조준할 수 없었습니다. 그것은 그중 하나가 키
자료를 나르는 모든 곳에서 물리고 — `CCertRequest::attributeOf()`에서 나온
PKCS#9 `challengePassword`, 디코드된 개인키 blob — 호출자가 손을 뻗을 우회책은
`const_cast`인데, 그것은 비밀을 다루는 집안 스타일로 발행할 것이 아닙니다.

`secureClear()`는 `CBigNum::secureClear()`의 선례를 따라 영 소거한 다음
해제합니다. 변경 가능한 `toPtr()`가 대안이었고 거부되었습니다. 그것은 무엇이든
소유된 버퍼를 조금씩 다시 쓰게 할 것인데, 그것이 바로 `store()`의 내용
전체를 교체하는 설계가 막는 것입니다. 그 연산에 이름을 붙이는 것이 그 능력을
그것을 필요로 하는 하나뿐인 용도에 묶어 둡니다.

그 doc 주석은 한계가 없다고 암시하는 대신 한계를 진술합니다. 그것은 호출된
순간 *이* 인스턴스가 소유한 바이트에 닿고, 이전 대입이 만든 사본이나
`store()`가 다른 크기의 내용으로 교체할 때 해제하는 블록에는 닿지 않습니다.
비밀이 해제된 메모리에 머무는 창을 좁힙니다. 닫지는 않습니다.

그 테스트 케이스는 자기가 검사할 수 없는 것을 분명히 말합니다. 영 소거는
관측 가능하지 않습니다 — 블록이 바로 뒤에 해제되고, 해제된 메모리를 읽는 것은
지우기가 아니라 할당기를 측정할 것입니다 — 그래서 그 케이스는 관측 가능한
계약을 덮고 나머지는 `CSecure::zero()` 자신의 테스트에 기댑니다. 네거티브
컨트롤(지우지만 결코 해제하지 않기)은 잡힙니다.

### `ParseFixedDigits`, `ValidateTimeFields`, `WriteFixedDigits`

PascalCase인 private static 멤버인데,
[coding-conventions.md](coding-conventions.ko.md)는 멤버에 `camelCase`를
요구하고 PascalCase는 자유 함수에 예약합니다. 호출 지점 32곳에 걸쳐 이름을
바꿨습니다. 동작 변화는 없습니다.

## `RSA::checkPrivateKey`가 모든 OpenSSL 및 BIND 개인키를 거부했습니다

다운스트림에서 보고되었습니다. cppskit의 cskdns_certpp가 BIND의
`dnssec-keygen`이 만들어 낸 DNSSEC 키를 가져오는데, `checkPrivateKey()`가
그것들 전부에 대해 `ERET_KEY_PARAM`을 반환했습니다 — 바로 그 같은 키에 대한
서명/검증 탐침은 성공하는 동안에요. 다운스트림의 우회책은 대신 그 탐침으로
검증하는 것이었는데, 그것은 결함이 어디 있었는지에 대한 건전한 진단입니다.

그 검사는 `phi = (p-1)*(q-1)`을 계산하고 `d == e^-1 mod phi`를 정확히
요구했습니다. 그러나 RFC 8017 3.2절은 `d`를 `lambda(n) = lcm(p-1, q-1)`
**또는** `phi(n)` 모듈러의 `e` 역원으로 정의하고, 그 두 값은
`gcd(p-1, q-1) > 2`일 때마다 다릅니다. `lambda`가 `phi`를 나누므로
`lambda(n)` 값이 더 작은 쪽이고, `phi`에 대조해 쓰인 검사는 그것을 거부합니다.

그것은 아무것도 쓰지 않는 표준의 한 구석이 아닙니다. OpenSSL 3.2로 키를
생성하고 그 파라미터를 다시 읽으면 그 갈림이 바로 드러납니다.

| `openssl genrsa` | `d == e^-1 mod lambda` | `d == e^-1 mod phi` |
|---|---|---|
| 2048비트 | 예 | **아니오**(표본 키 4개 중 3개) |
| 1024비트 | — | 예 |

2048비트 이상에서 OpenSSL은 `d < lambda(n)`을 요구하는 FIPS 186-4를 따르고,
그 아래에서는 역사적인 `phi(n)` 값을 유지합니다. 그래서 RSA 키를 만드는 단일
최다 방법인 `openssl genrsa 2048`이 거부되었고, 아무도 더는 써서는 안 되는
크기만이 통과했습니다. `dnssec-keygen`과 ldns도 `lambda(n)` 형태를 만들어
냅니다.

고침은 특정 대표원이 아니라 합동을 검사합니다. `e*d ≡ 1 (mod p-1)`과
`e*d ≡ 1 (mod q-1)`이며, 그 둘이 함께 `e*d ≡ 1 (mod lambda(n))`입니다. 그것은
두 형태를 받아들이고 — 그리고 `lambda`의 어떤 배수만큼 어긋난 `d`도요.
그것은 똑같이 유효하고 똑같이 기능합니다 — 동시에 역원이 아예 아닌 `d`는
여전히 거부합니다. 그 위의 `gcd(e, phi) == 1` 테스트는 변경이 필요 없습니다.
`phi`와 `lambda`가 같은 소인수를 지니기 때문입니다. 그 아래의 CRT 검사들도
필요 없었습니다. `dP = d mod (p-1)`이 두 형태 모두에 대해 성립하는데, 그
항등식이 애초에 CRT 지수를 동작하게 만드는 것이기 때문입니다.

### 테스트가 못 박는 것

서명/검증 왕복은 이것을 잡아내지 못했을 것이고 못 했습니다. 버그가 산술이
아니라 검증자에 있었기 때문입니다. 그래서 회귀 테스트는 실제 1024비트
`openssl genrsa` 키 하나를 PKCS#1 `RSAPrivateKey`로 두 번 인코드해
나릅니다 — 같은 `n`, `e`, `p`, `q`에 `d`는 각 형태로 — 그리고
`gcd(p-1, q-1) = 24`가 되도록 골라 두 `d` 값이 일치하는 대신 진짜로 24배
떨어져 있게 했습니다. gcd가 2일 때는 그것들이 절반쯤 일치합니다. 이제 둘 다
검증을 통과해야 하고, 두 가져오기가 자기 공개 절반에 대해 일치해야 하며,
그것이 그것들이 무관한 둘이 아니라 같은 키라는 것을 증명하는 것입니다.

세 번째 벡터는 `lambda(n)` 키의 `d` 더하기 1이고, 합동만이 틀린 것이 되도록
`dP`/`dQ`를 맞춰 다시 계산했습니다. 그것은 여전히 거부되어야 합니다 —
단순히 `d` 검사를 떨어뜨린 고침은 앞의 두 케이스를 통과하고 그 뒤에 아무것도
남기지 않을 것입니다.

네거티브 컨트롤로 확인했습니다. 한 줄짜리 조건을 되돌리면 `lambda(n)`
케이스가 실패하고 `phi(n)`과 역원 아님 케이스는 여전히 통과하는데, 그것이
정확히 보고된 버그의 지문입니다.

## 두 툴체인에서 이 라이브러리 측정하기, 그리고 둘이 어긋나는 지점

`README.md`의 Performance 절에는 Release/MSVC 한 번의 실행에서 나온 단일
수치 집합이 실려 있었습니다. `examples/05_benchmark.cpp`를 두 툴체인 모두에서
한 세션 안에 다시 돌려서(Windows의 MSVC 19.36과 WSL2 위 Ubuntu 24.04의 GCC
13.3, 동일한 4코어 i7-11370H) 그 한 열이 두 열이 되었습니다. 그리고 두 번째
열은 첫 번째 열의 복사본이 아닙니다.

여기서는 비교 자체가 목적이었으므로 방법론이 평소보다 더 중요했습니다. 두
툴체인은 동시에가 아니라 순차로 실행했습니다. 8코어에서 코어들을 다 점유하는
컴파일러와 함께 동시에 돌리면 서로 상대 컴파일러를 측정하게 되기 때문입니다.
각 수치는 여전히 하네스 자체의 반복 20회 배치 3개 중 최선이면서 세 번 실행
중 최선입니다.

### 두 툴체인이 어긋나는 지점

GCC는 라이브러리 대부분에서 같거나 빠르고, 그 폭이 큰 곳이 여럿입니다 —
SHA3-256은 2.8배, Streebog-256은 42%, ML-KEM은 30%, AES-256-GCM은 28%,
Ed25519 서명은 18%. 반대로 가는 항목이 둘인데, 중요한 쪽은 RSA입니다.

| | MSVC | GCC |
|---|---|---|
| RSA-2048 sign | **8.06 ms** | 19.1 ms |
| RSA-2048 verify | **0.145 ms** | 0.392 ms |
| MD5, 64 KiB | **593 MiB/s** | 455 MiB/s |

RSA의 양쪽이 함께 느려지는 반면 모든 소수체 곡선은 GCC에서 *더 빠른* 것은
결과의 형태가 꽤 특정된다는 뜻입니다. 큰 수(big-number) 백엔드가 전반적으로
느리다는 가능성을 배제하고, RSA가 `mulMod()`의 비중이 그만큼 커서 codegen
차이가 결과 전체를 지배하는 유일한 지점이라는 쪽을 가리킵니다.

### 뻔한 설명과, 그것이 틀린 이유

먼저 시도해 볼 것은 이 일을 무효화해 줄 뻔한 것이었습니다. GCC가 MSVC의
`_mulx_u64`/`_addcarry_u64`를 낼 수 없으니 portable 곱셈으로 되돌아간다는
것입니다. 틀렸고, `src/utils/bignum.cpp`가 직접 그렇게 말합니다.
`CBigNum::mul()`은 `hasAdxBmi2()`로 분기하고(`bignum.cpp:531`),
`mulAccelerated()`는 두 툴체인 모두에서 같은 MULX/ADCX 경로에 도달합니다 —
GCC는 함수 단위 `__attribute__((target("bmi2,adx")))`로, MSVC는 무조건적
intrinsic 사용으로 — 이 CPU는 두 기능을 모두 보고합니다. 리눅스가 그 코드에서
한 번 발견한 유일한 타입 불일치인 `uint64_t*` 대 `unsigned long long*`는
이미 고쳐져 있습니다.

차이는 codegen에 있고, 아직 프로파일하지 않았습니다. 무엇을 고치기 전에
측정해 볼 후보는 둘입니다. Montgomery 축약의 형태, 그리고 GCC가
`mulAccelerated()`의 Step A / Step B 경계를 넘어 `row[]`/`r64[]`를 레지스터에
유지하는지입니다. 이는 이제 `docs/roadmap.md`의 미해결 작업이 되었고,
배제된 가설이 다시 유도되지 않도록 그 경계를 명시해 두었습니다.

### 이 비교의 한계 두 가지

둘 다 독자가 스스로 알아내게 하지 않고 `README.md`에 적어 두었습니다.

- **WSL2는 bare metal이 아니라 VM입니다.** 이 하네스는 단일 스레드
  CPU-bound 암호 연산이므로 하이퍼바이저가 각 측정에서 차지하는 몫은 작아야
  합니다 — 하지만 그것은 작아야 *할*이라는 논지이지 실제로 작다는 것을
  보여 준 측정이 아닙니다. GCC 열은 "이 툴체인이 이 조건에서"의 결과이지
  리눅스 전반의 성능이 아닙니다.
- **"둘 다 Release"는 "같은 설정"이 아닙니다.** CMake의 Release 기본값은
  MSVC가 `/O2`, GCC가 `-O3`이므로 툴체인과 최적화 레벨이 함께 변합니다. RSA
  격차를 GCC 버그라고 부르려면 먼저 bare metal에서 다시 측정해야 합니다.

### 이전 수치는 부하가 걸린 상태에서 측정됐습니다

MSVC 열은 앞서 게시된 수치를 대체하는데, 그쪽 자체의 설명이 부하가 걸린
머신에서 측정했다고 적혀 있었습니다. 다시 측정하니 모든 행이 같거나 더
빠르며 대부분은 10~20% 빠릅니다. 가장 큰 변화는 ECDSA P-256 검증으로
3.53 ms에서 2.44 ms인데, 하네스가 스스로 밝힌 20~30% 편차를 아주 조금
넘습니다. 그것을 설명할 코드 변경은 없었고, 그것이 이 기록의 쓸모 있는 부분입니다.
측정 조건을 재는 것이지 라이브러리를 재는 것이 아니기 때문입니다. 그래서
표는 이제 그 조건과 편차를 명시하고 20~30%보다 작은 차이는 결과가 아니라는
기준을 적용합니다.

## 프로파일링: RSA는 한 번도 Montgomery 위에 없었고, small-record 비용은 블록 두 개다

roadmap의 P0와 P1을 따랐습니다. 둘 다 계획을 실행한 것에 그치지 않고 계획을
바꿨기 때문에 길게 기록합니다.

### P0 -- 측정 공백 둘, 그리고 그것을 메우며 나온 것

`examples/05_benchmark.cpp`가 ML-KEM-768 키 생성을 이제 재고 — `benchKem()`이
setup으로 한 번만 호출하고 재지 않던 것이며, `README.md` 표에 대시가 있던
이유입니다 — 새로 넣은 `benchSmallRecord()`가 small-record 목표가 쓰이는
단위인데 아무것도 재지 않던 64 B `seal()`을 보고합니다. 칸을 채울 수 있었던
단일 실행 하나로가 아니라 양쪽 툴체인을 각각 세 번 다시 측정했습니다.

그 반복문에서 키와 nonce 하나를 재사용하는 것이 수치를 유리하게 만들지는
않습니다. `CChaCha20Poly1305::seal()`이 호출마다 `ChaCha20Core::block()`으로
one-time key를 다시 유도하고 태그를 위해 새 `CPoly1305`를 만들기 때문에,
반복문이 데울 수 있는 크로스콜 상태가 없습니다. 반복문이 일정하게 유지하는
것은 키입니다.

결과는 표가 암시하던 순서를 뒤집습니다. **64 B에서 세 AEAD 중 가장 빠른 것이
64 KiB에서 가장 느린 것이며, 두 툴체인 모두에서 그렇습니다.**

| | MSVC | GCC |
|---|---|---|
| ChaCha20-Poly1305, 64 B | 410 ns | 332 ns |
| XChaCha20-Poly1305, 64 B | 545 ns | 449 ns |
| AES-256-GCM, 64 B | **225 ns** | **179 ns** |
| ChaCha20-Poly1305, 64 KiB | 578 MiB/s | 650 MiB/s |
| AES-256-GCM, 64 KiB | 370 MiB/s | 475 MiB/s |

(64 KiB 행은 뒤에 들어간 AVX2 키스트림이 736과 835로 바꾼 값이며, 64 B 행들은
그대로입니다. 의도한 대로입니다.)

AES-GCM은 블록 하나를 암호화하는데 ChaCha20은 두 개를 암호화하고, 두 번째가
counter 0에서 Poly1305 one-time key를 유도하는 블록입니다(RFC 8439 2.6).
따라서 대용량 송신자와 레코드 단위 호출자는 서로 다른 승자를 보고 있고,
roadmap의 ChaCha20-Poly1305 항목 하나(대용량 1.5 GiB/s 대 레코드당 150 ns라는
두 개의 목표)가 겹치지 않는 두 변경으로 갈라졌습니다. 레코드당 쪽을 먼저
배치했습니다 — key 유도를 네 폭 SSE2 한 패스로 접는 것은 AVX2 전체 재작성
대신 한 패스이고, 대용량이 아니라 레코드 크기의 모든 호출자에게 도움이
됩니다. **그 배치는 틀린 측정에 서 있었고, 그 교정은 아래 "small-record 비용은
생각했던 것이 아닙니다" 절에 기록되어 있습니다.**

ML-KEM-768 키 생성은 MSVC에서 0.193 ms, GCC에서 0.142 ms로, encapsulate나
decapsulate 어느 쪽보다도 느렸습니다.

### small-record 비용은 생각했던 것이 아닙니다

부분들을 더하는 대신 410 ns가 실제로 어디로 가는지 측정했는데, P0의 결론이 두
번 뒤집혔고 두 교정 모두 원래 주장에서 멀어지는 방향이었습니다.

아홉 개 크기로 훑어 보니 비용 곡선은 직선이 아니고 그 안에 계단이 있습니다.
64 B와 192 B에 직선을 맞춰 절편 0을 보고한 첫 해석이 틀린 이유는, 192 B가 곡선이
따르는 어떤 의미에서도 64 B보다 "블록 두 개가 더"가 아니기 때문입니다.
`xorStream()`은 온전한 4블록 그룹만 SSE2로 보냅니다
(`vectorBlocks = wholeBlocks & ~size_t(3)`, `chacha20core.cpp:225`) — 그래서
64/128/192 B는 모두 스칼라이고 256 B가 첫 벡터화 크기입니다. GCC에서 5×20000 중
최소값, 두 실행:

| 페이로드 | 블록 | 키스트림 경로 | `seal()` |
|---|---|---|---|
| 0 B | 0 | -- | **180~210 ns** |
| 64 B | 1 | 스칼라 | 340~352 ns |
| 128 B | 2 | 스칼라 | 485~488 ns |
| 192 B | 3 | 스칼라 | 634~639 ns |
| **256 B** | 4 | **SSE2** | **568~575 ns** |

256 B보다 192 B가 더 비싸고 매 실행 재현됩니다 — 직선 적합이 흡수하고 있던 것이
바로 이것입니다. 그러니 **약 200 ns의 고정 비용이 실제로 존재합니다.** one-time
key 블록과 AAD·길이 블록에 대한 Poly1305이며 64 B 레코드의 거의 절반입니다.
따라서 150 ns 목표는 one-time key 유도 자체를 없애지 않는 한 어떤 페이로드 크기에서도
도달할 수 없고 철회합니다.

제안했던 수정은 원래 말한 것보다 더 분명한 이유로 실패합니다. 그것은 counter
0~3을 SSE2 한 패스에서 생성하는 lane 계산 논증이었지만, 실제 문제는 256 B 미만
레코드가 아예 벡터화 경로에 닿지 않는다는 것입니다. *블록의 나열*을 벡터화하는 것을
먼저 시도했고 24% 느렸습니다. 출력이 바이트 단위로 동일한(4456 케이스로 확인)
`blockVectorized()`는 **1.43배 느렸습니다** — 버리는 lane이 SIMD shuffle와 레지스터
압박까지 그대로 지불하기 때문입니다. `chacha20core.cpp:235`의 스칼라 루프 형태를
같은 버퍼 위에서 제자리로 재현해 대조하니 — 1블록이 스칼라 142.9~151.4 ns 대
벡터화 177.8~212.7 ns로 **1.17~1.49배 느립니다** — 고립시킨 벤치마크가 과소평가한
것이 드러납니다. 스칼라 루프는 키스트림 블록을 아예 만들지 않고 워드 단위로
호출자의 버퍼에 바로 XOR하기 때문입니다.

4블록 임계값을 1로 낮추는 것은 뻔한 후속이고, 역시 같은 이유로 퇴행입니다.
직렬 경로에도 그것을 상쇄할 여유가 없습니다 — `twentyRounds()`는 **xmm 레지스터가
0개**로 컴파일되고(`rol` 32개, `xor` 32개, `add` 31개, 자동 벡터화 없음) `block()`은
100.5 ns, 3.92 GHz로 **6.2 cycles/byte**로 x86-64 스칼라 ChaCha20의 정상 공개
수준 정중앙입니다. 이 마지막 수치가 처음에는 이상해 보여 디스어셈블리를 확인했고,
컴파일러 사고가 아니라 올바른 값입니다.

### P3 대용량 -- AVX2 8블록 키스트림, 그리고 목표가 실제로 향한 곳

이 영역에서 시도한 일곱 건 중 이것이 처음 측정에서 살아남았습니다. ChaCha20
블록은 구성상 독립이므로 기존 SSE2 경로가 이미 네 lane으로 그것을 이용하고 있고,
이것은 그 폭을 두 배로 합니다. 64 KiB에서(GCC, 5×40 중 최소값, 두 실행) 키스트림이
**48.0에서 24.6 us로 1.95배**, AEAD 전체가 97.6에서 72.8 us로 1.34배가 됩니다.
프로젝트 하네스에서:

| | 이전 | 이후 |
|---|---|---|
| MSVC ChaCha20-Poly1305, 64 KiB | 578 MiB/s | 736 MiB/s |
| MSVC XChaCha20-Poly1305, 64 KiB | 577 MiB/s | 748 MiB/s |
| GCC ChaCha20-Poly1305, 64 KiB | 650 MiB/s | 835 MiB/s |
| GCC XChaCha20-Poly1305, 64 KiB | 648 MiB/s | 840 MiB/s |

AVX2는 어떤 x86-64 ABI의 일부도 아니므로 게이트는 아키텍처가 아니라 런타임 CPUID
검사이며, CPUID가 직렬화 명령이라 함수 지역 static에 캐시합니다. **512바이트
이상에만** 적용한 것도 의도적입니다. 여덟 lane을 계산하고 여섯을 버리는 것은 짧은
페이로드에서 손해이며, 이것이 4블록 경로가 256 B 미만에서 빠지는 바로 그 함정입니다.
작은 레코드는 410~440 ns로 변하지 않습니다.

8×8 transpose는 4블록 경로가 쓰는 shuffle 계열 대신 128비트 절반마다
`_mm256_permutevar8x32_epi32`가 필요했습니다. `_mm256_shuffle_epi32`와 unpack 계열은
각 128비트 lane 안에서만 동작하므로, 앞의 두 단계를 지나면 각 벡터에 두 행이 lane
단위로 엇갈려 들어 있고 어떤 half-select로도 분리할 수 없습니다 — `permute2x128`
즉시값 256개를 전부 탐색해 봐도 조합이 불가능함을 확인했습니다. 어떤 lane이 어떤
값을 가지는지는 항등행렬을 전치해 결과를 읽어 유도했습니다 — 열 k의 0~3행은
`u[k/2]`에, 4~7행은 `u[k/2 + 4]`에 있고, 짝수 k는 lane {0,1,4,5}, 홀수 k는
{2,3,6,7}을 읽습니다 — 손으로 유도한 두 번이 먼저 틀렸기 때문입니다.

**1.5 GiB/s 목표는 달성되지 않으며 그 이유는 산술입니다.** 64 KiB AEAD를 둘로
나누어 보면 두 절반이 같습니다 — 키스트림 48.0 us 대 Poly1305 48.2 us — 그래서
MAC이 비용의 50%이고 키스트림만 개선해서는 목표에 닿을 수 없습니다. 측정된 AVX2
키스트림에서 cipher와 MAC의 합 예산은 40.7 us이고 그중 cipher가 24.6를 쓰므로
MAC에 남는 것은 16.1 us, 현재 48.2 us인 MAC이 있습니다.

### P3 -- Poly1305, 그리고 목표가 열린 항목이 아니라 닫힌 항목인 이유

시도했고 측정했으며, 이 CPU에서는 값이 나오지 않습니다. 결론에 도달하기 전에
확인해야 했던 두 가지가 있고, 그중 첫 번째가 결정적이었습니다.

**스칼라 루틴은 지연이 아니라 처리량에 묶여 있습니다.** 이 구분이 모든 병렬 접근이
통할 수 있는지를 결정합니다. 직렬 의존성 체인이 비용이라면 독립 누적기를 겹쳐서 되돌릴
수 있어야 합니다. 그런데 같은 데이터에 독립 누적기 두, 세, 개를 흘려보냈을 때 각각
*단일 스트림 처리율*의 0.51배, 0.67배, 0.75배가 나오니, 포화되어 있는 것은 곱셈
처리량이고 채울 수 있는 유휴 체인은 없습니다.

**벡터 형태가 스칼라보다 느립니다.** 두 바닥을 측정했습니다(GCC, 5×60 중 최소값,
세 실행):

| | cycles/block |
|---|---|
| 스칼라 곱셈 25회, 덧셈·캐리 없음 | 24.1 |
| **실제 `absorbBlock()`** | **45.7** |
| 그 25개 곱을 담은 `vpmuludq` 13회 | 26.3 |

즉 곱셈의 벡터화는 1.06~1.09배의 비용이며 재현됩니다. 이것은 ChaCha20 시도들이
빠진 바로 그 함정입니다. 다만 다른 자리에서 — AVX2에는 64x64→128 곱셈이 없습니다
(그건 AVX512IFMA입니다) — 그래서 26×26 곱셈은 어느 쪽이든 `vpmuludq` 하나이고,
두 개를 한 명령에 넣어 명령 하나를 아끼려면 피연산자가 이미 `vpmuludq`가 읽는 lane에
있어야 합니다. 그렇지 않으므로 먼저 셔플해야 하고 그 비용이 아낀 곱셈보다 큽니다.
덧셈, 캐리 체인, reduction은 그 위에전히 더해질 비용으로 남습니다.

스칼라 바닥 아래로 내려가는 유일한 길은 곱셈을 싸게가 아니라 **덜** 하는 것이며,
그건 64x64→128 또는 이 roadmap이 이미 말하는 `r`의 사전 계산 거듭제곱을 요구하는데,
이 점화식에 대해 이 CPU에서 둘 다 쓸 수 있는 명령 경로가 없습니다. **따라서
ChaCha20-Poly1305 처리량 목표는 측정된 부정 결과로 닫힙니다.** 다른 하드웨어와 비교할
수 있도록 cycles/byte로 보면 — 들어간 AVX2 키스트림은 1.47, MAC은 2.88이고 1.5 GiB/s
목표는 둘 합쳐 2.43입니다 — MAC 쪽에서 약 0.45 cycles/byte만큼 부족하며 곱셈 쪽의
어떤 벡터화도 그 간극을 메우지 못합니다.

더 넓은 scalar 실험은 그대로 남아 있고 이 결과에 흔들리지 않습니다 — 44비트 3-limb에
블록당 64x64→128 곱셈 아홉 개를 쓰는 방식이 이식 가능한 5-limb 26비트 경로보다
빠르지 않았고 캐리를 `_addcarry_u64`로 보내면 더 느렸습니다.

여기서 배운 방법론 하나 — 이게 거의 잘못된 결론을 만들 뻔했습니다. 곱셈 바닥 probe의
첫 실행은 오버헤드 15%를, 뒤이은 실행은 67%를 보고했는데 측정 드리프트가 아니었습니다.
probe가 컴파일에 실패했고(`<immintrin.h>` 누락) 실행 스크립트가 앞선 편집에서 남아 있던
낡은 바이너리를 실행한 것이었습니다. 이제 여기서 쓰는 모든 benchmark 스크립트는
컴파일 전에 출력 바이너리를 지우고 빌드가 실패하면 종료합니다 — 편집한 것과 다른
프로그램을 재는 benchmark는 benchmark가 없는 것보다 나쁩니다.

### P1 -- RSA의 병목, 그리고 교정

WSL Release 빌드를 `perf`로 프로파일한 결과 **전체 사이클의 36.7%가
`CBigNum::divMod()`** 안에 있었고, 경로는 `RsaContext::sign` ->
`CBigNum::modExp` -> `CBigNum::mulMod` -> `CBigNum::mod` ->
`CBigNum::divMod`입니다. 소스도 같은 말 합니다.

- `CBigNum::modExp()`(`bignum.cpp:913`)는 평범한 정수 지수화이고,
  `CBigNum::mulMod()`(`bignum.cpp:763`)는 여전히 `mul()`에 `mod()`를
  부릅니다.
- `CMontgomery::modExp()`(`montgomery.cpp:444`)가 존재하고 Montgomery이며,
  그런데 프로파일에 전혀 나타나지 않습니다. 호출하는 쪽은 소수체 곡선
  (`eccurve.cpp:747`)과 Ed448(`ed448.cpp:65`)입니다.

즉 RSA는 개인 키 연산의 모듈러 곱셈마다 schoolbook 긴 나눗셈을 하고, 바로 옆
코드들은 Montgomery를 씁니다. 이것은 두 커밋 전 roadmap이 낸 진단을 교정합니다.
그때는 Montgomery 축약의 *형태* — 가산기가 한 단계당 조건부 뺄셈을 피하기에
충분한 폭인지 — 를 지목했는데, 이 문제에서 그 형태는 질문이 아닙니다. RSA는 그
코드에 도달하지도 않으니까요. 앞 절에 기록한 크로스-툴체인 격차도 다시 읽히게
됩니다. 2.4배 격차는 codegen 우연처럼 보이지만, 더 가능성 높은 것은 두
툴체인이 공통으로 치르는 비효율이 차이만 크게 나는 쪽이라는 것입니다. 두
컴파일러가 나눗셈에 대해 2.4배로 갈리지는 않지만, 둘 다 치르고 난 뒤 그 비용이
얼마인지는 갈릴 수 있습니다.

수정은 `rsa.cpp`의 `CBigNum::modExp` 호출(`rsa.cpp:433`, `:434`, `:444`,
`:463`, `:518`, `:627`, `:677`)을 `CMontgomery`로 보내는 것이며 작은 작업이
아닙니다. `rsa.cpp:417--444`의 CRT 블라인딩과 그 fault 공격 countermeasures에
닿고, CRT 상수 `dp`, `dq`, `qInv`는 `n`과 *다른* 소수에 대해 유도되므로 각
반쪽이 하나를 공유하는 것이 아니라 각자의 Montgomery 컨텍스트가 필요합니다.
`tests/`는 CRT 결과가 전체 재암호화와 여전히 일치함을 계속 증명해야 하는데,
그것이 CRT를 하는 이유인 countermeasures이기 때문입니다.

### 프로파일을 어떻게 채웠는지, 그것이 보여주지 않는 것

RSA 전용 작업부하를 새로 만든 것이 아니라 하네스 전체에 `perf record`를
걸었습니다. 그 실행에서 RSA가 벽시계 시간을 지배하므로 프로파일에서도
지배하지만, 36.7%는 RSA 서명만의 몫이 아니라 프로세스 전체의 몫입니다.
증거로 무게를 두는 것은 프로파일에 `CMontgomery::modExp`가 없다는 사실이고,
백분율은 보강입니다. `RsaContext::sign`만 격리한 전용 프로파일이 더 날카로운
수치를 줄 것이고, 그 작업을 시작할 때 가장 먼저 할 일입니다.
