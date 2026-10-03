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
