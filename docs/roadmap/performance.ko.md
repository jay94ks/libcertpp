# Constant-time 및 성능 작업

[English](performance.md)

이 문서에는 아직 남은 작업만 둡니다. 현재 벤치마크 결과와 방법론은
[성능](../concepts/performance.ko.md)에, 완료된 최적화·조사·부정적 결과는
[변경 이력](../HISTORY.ko.md)과 [계획에 없음](not-planned.ko.md)에 기록합니다.

## 보안 작업

- **portable constant-time 소수 곡선 fallback을 완성합니다.** 네이티브 x86-64
  Clang/GCC 빌드는 이제 체 좌표를 고정 폭 Montgomery limb에 유지하고 private window
  후보를 모두 스캔하며 전체 군 위수 폭을 처리합니다. portable fallback은 여전히 할당,
  limb 정리, 산술 비용이 피연산자에 따라 달라지는 `CBigNum`을 사용합니다. 플랫폼
  독립적인 주장을 하기 전에 이 fallback을 교체하거나 variable-time 경계를 명시적으로
  유지합니다.
- **ML-DSA 서명의 타이밍 누출을 감사합니다.** Fiat-Shamir-with-aborts의 재시도
  횟수는 설계상 데이터 의존적입니다. 현재 구현은 비밀 중간값을 지우고 한 반복
  안에서는 비밀에 따른 테이블을 피하지만, 공개된 Dilithium 공격을 기준으로 한
  전용 타이밍 부채널 검토는 아직 받지 않았습니다. [PQC 엔지니어링과
  위험](../pqc/engineering.ko.md)을 참고하십시오.

## 성능 조사

### OpenSSL 90% 프로그램

활성 성능 목표는 라이브러리가 구현한 모든 알고리즘과 연산을 대상으로 합니다.
직접 비교할 수 있는 행은 같은 조건의 OpenSSL 연산 대비 certpp가 90% 이상의 성능에
도달하면 완료됩니다. 처리량 행은 `certpp / OpenSSL`, 지연시간 행은
`OpenSSL / certpp`를 사용하여 비율이 클수록 항상 좋게 표시합니다. 같은 머신의
Release 빌드, 같은 입력과 키 크기, 서로 분리해 워밍업한 루프, 전체 하네스 최소
3회 실행을 사용합니다. 판단 값은 비율의 중앙값이며, 반복해서 0.90 아래로 나오는
실행을 최선값으로 숨기지 않고 조사합니다.

OpenSSL은 certpp가 구현한 모든 알고리즘이나 매개변수 집합을 제공하지 않습니다.
그런 행에는 해당 연산이 없는 OpenSSL 버전과 provider 구성을 기록하고, 확립된 대체
구현이 있으면 이름을 밝히며, 내부 변경 전후 기준값을 유지합니다. 사용할 수 없는
연산에 OpenSSL 비율을 만들어 내지 않습니다. 모든 직접 비교 행이 0.90 이상이고,
사용할 수 없는 모든 행에 이 근거와 대체 기준값이 있어야 목표가 완료됩니다. 자동
CI와 플랫폼 매트릭스는 이 목표의 범위 밖에 계속 둡니다.

다음 순서로 진행합니다.

1. `examples/05_benchmark.cpp`의 모든 행에 직접 OpenSSL 측정값이나 명시적인 사용
   불가 결과가 생길 때까지 `examples/06_openssl_compare.cpp`를 확장합니다.
2. 0.90 아래 행을 측정된 격차가 큰 순서로 최적화합니다. 대상 명령어 집합이 실제
   이득을 줄 때 하드웨어 경로를 추가하거나 강화하되 portable 폴백을 보존합니다.
3. 공개된 기지 응답, 상호운용성, 잘못된 입력, 네거티브 테스트를 계속 통과시킵니다.
   기본 연산을 변경하면 가속 구성과 portable 구성을 모두 실행합니다.
4. 동일 조건 결과로 [성능](../concepts/performance.ko.md)을 갱신하고 완료된 조사는
   [변경 이력](../HISTORY.ko.md)으로 옮깁니다.

첫 전체 해시/CBC 목록에서 SHA-1, SHA-224, SHA-256, SHA3-256, SHA3-512,
SHAKE-128, SHAKE-256, AES-128-CBC는 문턱 이상입니다. 이후 4-lane SSE2 압축 경로가
BLAKE2s를 약 0.74에서 0.96으로 높여 이제 이 알고리즘도 문턱을 충족합니다. 이어 전개한
MD4와 MD5 압축 kernel이 두 대응 실행 중앙값을 모두 약 0.90으로 높였습니다. 문턱을
근소하게 충족하므로 관련 변경 뒤에는 다시 측정해야 합니다. 이어 4-way AVX-512VL
스케줄 생성이 SHA-384/SHA-512를 약 0.90/0.91로 높였습니다. SHA-384도 관련 변경 뒤에
다시 측정해야 합니다. AVX-512VL register-resident permutation은 모든 SHA-3/SHAKE 행을
문턱보다 충분히 높였습니다. 이어 완전 블록 직접 streaming이 AES-128/192/256-CBC를 약
0.97/0.97/0.98로 높여 세 행 모두 문턱을 충족합니다. 이어 결합 S/P table, 회전 조회
키, TripleDES EDE 블록당 permutation 한 쌍, 직접 CBC streaming이 DES와 2-key
3DES-CBC를 약 1.04배와 1.01배로 높여 두 행도 문턱을 충족합니다. 이어 확장 32비트
S-box/diffusion 경로와 직접 CBC loop가 ARIA 세 행을 약 1.03--1.04배로 높여 모두 문턱을
충족합니다. 이어 혼합 precomputed 점 덧셈, 생성된 필드 제곱, 결합 검증, 공개키별 홀수
배수 표와 네이티브 radix-51 필드 경로가 Ed25519 서명/검증을 약 1.53/1.28배로 높여
두 행도 문턱을 충족합니다.
Streebog는 시험한
OpenSSL default와 legacy provider에서 사용할 수 없습니다. 다음 목록 단계에서 AEAD,
X25519, ML-KEM, Ed448, ML-DSA를 추가했습니다. 이어 고정 폭 Fe448 산술, 혼합 점
덧셈, 10열 comb 표가 동일 조건 WSL 비교에서 Ed448 서명/검증을 약 1.48/0.99배로
높여 두 행 모두 문턱을 충족합니다. 네이티브 radix-51 필드 경로와 flattened ladder는
X25519 키 생성/유도를 먼저 약 0.24/0.21배에서 0.77/0.62배로 높였습니다. 이어 두 carry
chain reduction, 전용 제곱, CPU별 전체 ladder dispatch, 바인딩 키 caching이 동일 조건
Windows 중앙값을 약 1.03/0.91배로 높여 두 행 모두 문턱을 충족합니다. 이어
bit-reservoir codec, 고정 lane CBD 샘플링, 제한 범위 NTT reduction,
준비된 키 재사용이 ML-KEM 키 생성/캡슐화/디캡슐화 9개 행의 7회 중앙값을
1.07--1.25배로 높여 세 파라미터 집합 모두 문턱을 충족합니다. 이어 고정 modulus
Montgomery NTT 곱, reservoir 비트 패킹, rate-block SHAKE 샘플링이 ML-DSA 서명/검증
6개 행의 7회 중앙값을 1.17--1.38배로 높여 세 파라미터 집합 모두 문턱을 충족합니다.
이어 16블록 결합 VAES/GHASH 처리가 AES-256-GCM 대용량과 짧은 레코드를 약
0.90/0.93배로 높였고, 32블록 IFMA 집계가 ChaCha20-Poly1305 대용량과 짧은 레코드를 약
0.92/0.97배로 높였습니다. 이 AEAD 행들은 이제 문턱을 충족하지만 재측정에 민감합니다.
고전 비대칭 행들이 가장 큰 직접 비교 격차에 남아 있습니다.
시험한 OpenSSL EVP 인터페이스에서는 XChaCha20-Poly1305를 사용할 수 없습니다. 다음 목록 단계에서 소수체 ECDSA/ECDH 곡선
20개와 이진 ECDSA 곡선 10개 모두의 양방향 상호운용을 다뤘고, 소수 곡선 ECDH는 정확한 교차 구현
비밀도 확인합니다. 공개 스칼라 동시 곱은 대표 소수 곡선의 ECDSA 검증을 약 2.3배,
대표 이진 곡선은 약 1.9--2.0배 개선했습니다. 이어 고정 폭 Montgomery 체와 private
window가 소수 곡선 80개 행 중 72개를 먼저 문턱까지 높였습니다. 고정 count 곱셈
kernel과 키 바인딩 폭 6 검증 표가 남은 P-256 이외 행도 모두 0.90배 위로 높였습니다.
이후 압축한 P-256 7비트 기저 표, 한쪽 방향 mask 선택, 폭 8 Montgomery-limb 검증 표가
P-256의 5회 중앙값을 0.318--0.614배로 높였습니다. 이후 필드 곱 inline, 4비트 공개 검증
comb, AVX-512 전체 스캔 private comb 선택, signed radix-256 기저 comb가 고정 기저 행을
높였습니다. 이어 peer에 바인딩한 private 전체 스캔 comb가 반복 ECDH를 높이고 P-256 nonce
묶음 준비가 반복 서명의 좌표·order 역원을 공유했습니다. 현재 균형 측정 중앙값은
0.980/0.990/0.983/1.168배이므로 소수 곡선 80개 행이 모두 통과합니다. 이어 고정 count
PCLMUL 곱·제곱
kernel, 높은 word부터 접는 축약, 혼합 Lopez-Dahab 덧셈, 생성 키의 중복 검증 제거가
이진 곡선 키 생성/서명/검증 30개 행의 5회 중앙값을 1.12--1.83배로 높였습니다. 다음 목록
단계에서 양방향 서명 상호운용과 변경된 digest 거부를 포함해 RSA-2048과 DSA-2048을
추가했습니다. Montgomery 기반 Miller--Rabin, sliding window, 공개 지수 결합 검증은
최초 측정을 크게 개선했습니다. 이어 RSA modulus context 캐시, 짧고 긴 지수를 위한
packed 64비트 체인, packed 두 밑수 DSA 검증, binary 모듈러 역원이 비교 결과를 먼저
크게 높였습니다. 이제 통합 CIOS 순회가 곱과 축약 캐리를 함께 진행하고 2비트 동시 DSA
window가 검증 곱셈 횟수를 줄입니다. 이어 16-limb·32-limb 별도 kernel과 최대 32-way loop
전개가 안정적인 서명/검증 중앙값을 RSA 0.316/0.668배, DSA 0.720/0.535배로
높였습니다. 같은 11회 실행의 키 생성 비율은 0.393배와 0.594배였습니다. 작은
소수 체의 제수를 32비트 곱으로 묶어 로컬 최악 2048비트 경로를 5.16배 빠르게 했습니다. 무작위
소수 탐색 때문에 키 생성 행은 서명과 검증보다 실행 간 편차가 훨씬 큽니다. OpenSSL
3.6.4의 시험한 default와 legacy provider는 GOST 서명 구현을 제공하지 않으므로,
GOST는 내부 변경 전후 기준값과 명시적인 사용 불가 결과를 유지합니다.

- **RSA/DSA Montgomery용 dual-carry kernel을 생성합니다.** packed 체인이 반복 32/64비트 변환을
  제거하고 통합 CIOS가 두 번째 누산기 순회를 없앴으며, 고정 count kernel이 흔한
  1024/2048비트 loop를 compiler에 노출하고 binary 역원이 몫 크기 확장 유클리드 작업을
  제거했습니다. Clang 18 `perf` 실행은 RSA 전체 비교 self cycle의 35.85%를 16-limb
  Montgomery kernel에 귀속했고, 호출 트리는 소수 판정과 private CRT 지수승을 모두
  포함했습니다. 별도의 RSA 검증 200,000회 프로파일은 32-limb kernel에 88.24%, 입력 domain
  변환에 6.95%를 귀속했습니다. 그 변환을 packed chain 안으로 옮긴 실험은 Montgomery 전체
  검사를 통과했지만 Montgomery 곱 하나를 다른 곱으로 바꾼 것뿐이어서 5회 검증 중앙값이
  5.48초로 같았고, 따라서 기각했습니다. wide-integer 표현을 `_mulx_u64`와
  `_addcarryx_u64`로 바꾼 실험은 정확했지만
  compiler가 곱·reduction chain 사이에서 교차 배치하던 carry를 직렬화해 7회 RSA 서명과
  DSA 서명/검증 중앙값을 5--8% 늦췄습니다. 이전 full-square REDC 실험도 RSA 서명을 두 배
  넘게 느리게 했습니다. 고정 count 제곱 wrapper에서 입력 포인터 하나를 재사용한 변경은 CIOS
  body를 유지하면서 RSA·DSA 서명/검증을 작지만 반복 가능한 2.5--4.2%만큼 개선했습니다.
  현재 WSL 서명/검증 비율은 RSA 0.310/0.628배, DSA 0.758/0.562배로 여전히 문턱 아래이므로,
  다음 시도에는 intrinsic chain이나 일반 full-product buffer가 아니라 생성한 ADCX/ADOX
  dual-carry schedule이 필요합니다. 기존 CRT fault 검사와 문서화된 variable-time 경계를
  보존합니다.
- **남은 곡선의 검증용 공개 키 테이블을 평가합니다.** Ed25519는 공개키마다 홀수
  배수 8개를, Ed448은 더 큰 comb 표를 저장합니다. ECDSA, DSA 등 남은 가변 기저
  서명 구현에서 준비 시간, 메모리, 반복 검증의 같은 tradeoff를 측정합니다.

모든 최적화는 재현 가능한 기준값과 프로파일에서 시작합니다. 벤치마크 머신의
실행 간 편차보다 작은 변화는 개선으로 간주하지 않습니다. 받아들인 변경은 관련
기지 응답 및 네거티브 테스트를 계속 통과해야 합니다.
