# 성능

[English](performance.md)

[`examples/05_benchmark.cpp`](../../examples/05_benchmark.cpp)와
[`examples/06_openssl_compare.cpp`](../../examples/06_openssl_compare.cpp)로 측정했으므로,
주장이 아니라 재현 가능합니다. 그것들을 빌드해 여러분 하드웨어에서 돌려 보십시오.
두 툴체인, 둘 다 Release이고, 4코어 i7-11370H(3.30 GHz 베이스,
이 부하에서 지속 약 3.92 GHz) 한 대에서
한 세션 안에 Windows의 MSVC 19.36(VS 2022 17.6)과 **WSL2 위** Ubuntu 24.04의
GCC 13.3으로 측정했습니다. 각 수치는 반복 20회 배치 3개 중 가장 빠른 것이며,
세 번 실행 중 최선이고, 둘은 동시에가 아니라 순차로 실행해 어느 쪽도 다른
쪽의 컴파일러를 측정하지 않게 했습니다. 실행 간 편차가 20~30%이므로 그보다
작은 것은 결과가 아닙니다. 굵게는 그 행에서 더 빠른 값입니다.

표는 이 라이브러리가 구현한 모든 알고리즘을 대상으로 합니다. 해시 14종,
블록 암호 구성 8종, KEM 매개변수 집합 3종, 서명 및 키 합의 방식 34종입니다.
하네스 출력의 어떤 행도 "(unavailable)"를 보고하지 않으며, 전부를 다루게 한
이유가 그것입니다.

GF(2^m) 곡선은 서명 아래에는 나타나고 키 합의 아래에는 없는 것인데, 그것이
이들이 구현하는 바입니다. ECDSA는 하고 ECDH는 하지 않습니다.

## 현재 최적화 확인

OpenSSL 90% 프로그램은 2026-10-19에 완료 기준을 충족했습니다. 직접 비교할 수 있는 모든
연산의 동일 조건 중앙 비율이 이제 0.90 이상입니다. Streebog, GOST 서명, 이진 곡선 ECDH,
XChaCha20-Poly1305는 시험한 OpenSSL 3.6.4 default/legacy provider에서 명시적인 사용 불가
행으로 남으며, 아래 내부 GCC/MSVC 비교가 대체 기준값을 유지합니다. 자동 CI와 더 넓은
플랫폼 매트릭스는 별도 향후 과제로 [로드맵](../PLANS.ko.md#자동-ci와-플랫폼-매트릭스)에
계속 둡니다.

### 현재 AEAD 비교

AEAD 행은 2026-10-18에 같은 i7-11370H Windows 호스트에서 Clang 22.1.8, Ninja,
Release 빌드와 같은 프로세스의 OpenSSL 3.6.4를 사용해 갱신했습니다. Poly1305는 이제
AVX512-IFMA 곱 결과를 스칼라 누산기로 줄이기 전에 32블록을 모읍니다. 기존 16블록
경로보다 수평 합산과 누산기 갱신 빈도를 절반으로 줄이면서 16블록과 8블록 꼬리 경로는
유지합니다. r^16까지는 8블록 그룹이 있을 때만 준비하고 r^17부터 r^32까지는 32블록
그룹이 있을 때만 확장하므로, 더 넓은 경로가 짧거나 중간 크기 레코드에 준비 비용을
추가하지 않습니다.

| 5회 대응 실행 중앙값 | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| ChaCha20-Poly1305 봉인, 64 KiB | **3796 MiB/s** | 4129 MiB/s | **0.92배** |
| ChaCha20-Poly1305 봉인, 64바이트 레코드 | 264 ns | 258 ns | **0.97배** |
| AES-256-GCM 봉인, 64 KiB | **10692 MiB/s** | 11800 MiB/s | **0.90배** |
| AES-256-GCM 봉인, 64바이트 레코드 | 83 ns | 75 ns | **0.93배** |

ChaCha20-Poly1305 대용량의 5회 대응 비율은 0.92, 0.92, 0.87, 0.92, 0.92배였고 중앙값은
현재 목표 문턱을 넘습니다. 32블록 Poly1305 집계 직전 세 번의 실행은 0.84--0.87배였습니다.
AES-GCM은 구현 변경 없이 다시 측정했으며 문턱에 가깝게 유지됩니다. 공개 RFC 벡터,
모든 넓은 Poly1305 경계를 지나는 긴 메시지, streaming chunk 경계, 제자리 연산, 위조
거부 테스트가 통과합니다. XChaCha20-Poly1305는 시험한 OpenSSL EVP 인터페이스에서 계속
사용할 수 없으며 내부 ChaCha20-Poly1305 연산과 같은 가속 경로를 사용합니다.

### Ed25519 점 연산

Ed25519는 이제 mask 기반 signed-radix-16 고정 기저 표, cached/precomputed 혼합 덧셈,
공개 이중 스칼라 곱의 completed 좌표, 생성기로 만든 55-product 필드 제곱, 점 복구의
단일 지수승을 사용합니다. 개인키는 RFC 8032 확장값을, 공개키는 반복 검증에 쓰는 홀수
배수들을 캐시합니다. 현재 동일 조건 결과와 방법은
[현재 Ed25519 비교](#현재-ed25519-비교)에 기록하고, 단계별 과거 측정은
[Fe25519 기반 Ed25519](../history/12-ed25519.ko.md)에 둡니다.

## OpenSSL과 비교

숫자는 혼자서는 아무 뜻이 없으므로, 저장소는
[`examples/06_openssl_compare.cpp`](../../examples/06_openssl_compare.cpp)로 같은 알고리즘을
같은 머신의 OpenSSL과도 측정합니다.

**양쪽 모두 단독으로, 각자의 루프에서 측정했습니다.** 두 구현을 한 루프에서 번갈아
돌리는 것은 — 공정을 지키는 뻔한 방법처럼 보이지만 — 알고 보면 둘 다 망칩니다.
certpp의 SHA-256이 1523에서 765 MiB/s로 떨어지고 OpenSSL의 것도 거의 절반으로
떨어집니다. 번갈아 실행하면 캐시와 분기 예측기가 서로를 방해해서, 교차 수치는 암호
연산의 비교가 아니라 측정 방법의 비교가 됩니다. OpenSSL은 이 라이브러리의
래퍼가 아니라 EVP를 직접 호출했는데, 이것은 `certpp`를 통해 오는 호출자가 더할
호출당 할당이 아니라 암호 연산 자체를 측정합니다. 양쪽 모두 먼저 워밍업합니다.
OpenSSL은 생성자를 게으르게 해석해서 64 KiB SHA-256 첫 호출이 워밍업 후
38.9 µs 대비 963 µs가 들므로, 차갑게 비교하면 실속의 4분의 1로 보고됩니다.

각 수치는 조용한 머신에서 하네스를 세 번 실행한 것 중 최선입니다. 실행 간 범위가
비율에 실질적인 영향을 주는 경우 아래의 최신 비교에 함께 기록했습니다. 한 실행의
절대값을 그 알고리즘의 보편적인 속도로 보아서는 안 됩니다.

### 현재 SHA-384와 SHA-512 비교

먼저 80워드 메시지 스케줄과 라운드마다 하던 상태 이동을 16워드 순환 스케줄과 회전된
라운드 인자로 바꾸고, 이어 AVX-512VL 라운드 kernel을 추가한 뒤 2026-10-16에
SHA-384/SHA-512 행을 다시 측정했습니다. 대용량 입력은 독립적인 메시지 스케줄 네 개를
YMM lane에서 함께 계산합니다. 첫 블록을 압축하면서 이 스케줄을 만들고, 나머지 세
블록은 `W[t] + K[t]`를 저장해 직렬 라운드 사슬에서 덧셈 하나를 제거합니다. 전체 입력에
런타임 dispatch 한 번만 수행하며 BMI2 RORX와 portable 경로도 유지합니다.

| 대응 실행 5회 중앙값, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| SHA-384, 이전 목록 | 550 MiB/s | 703 MiB/s | 0.79배 |
| SHA-384, 현재 | **632 MiB/s** | 700 MiB/s | **0.90배** |
| SHA-512, 최초 | 404 MiB/s | 704 MiB/s | 0.57배 |
| SHA-512, 순환 scalar 스케줄 | 551 MiB/s | 708 MiB/s | 0.78배 |
| SHA-512, 현재 | **632 MiB/s** | 695 MiB/s | **0.91배** |

최종 대응 실행 다섯 번의 반올림 비율은 SHA-384가 0.90, 0.90, 0.96, 0.86,
0.92배였고 SHA-512가 0.91, 0.89, 0.91, 0.93, 0.95배였습니다. 중앙값은 활성 문턱을
충족하지만 SHA-384는 경계에 가까워 관련 compiler나 dispatch를 바꾸면 다시 측정해야
합니다. FIPS 180-4, 백만 개 `a`, 분할 입력, 재설정, 경계, portable load 테스트가
통과합니다. 더 느리게 측정된 8블록 ZMM 스케줄과 묶은 variable-rotate 라운드는 최종
구현에 포함하지 않았습니다.

### 현재 BLAKE2s 비교

각 column 및 diagonal 단계의 독립적인 G 함수 네 개를 SSE2로 벡터화한 뒤 2026-10-16에
BLAKE2s 행을 다시 측정했습니다. x86-64 ABI는 SSE2를 보장하므로 이 경로에는 런타임
기능 분기가 필요하지 않습니다. `CERTPP_DISABLE_HWACCEL_SIMD=ON`은 이식 가능한 scalar
구현을 그대로 유지하고 시험합니다.

| 3회 실행 중앙값, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| 변경 전 | 406 MiB/s | 539 MiB/s | 0.74배 |
| 현재 | **512 MiB/s** | 533 MiB/s | **0.96배** |

현재 세 실행은 certpp가 512, 531, 502 MiB/s, OpenSSL이 533, 544, 533 MiB/s였고,
실행별 비율은 0.96배, 0.98배, 0.94배였습니다. 모든 측정 전에 비교 프로그램의 digest
동일성 검사를 통과했습니다. RFC 7693 비 keyed 벡터와 참조 keyed BLAKE2s KAT는 가속
빌드와 SIMD 비활성 빌드에서 모두 통과합니다. 따라서 이 비교 장비에서 BLAKE2s는 활성
0.90 문턱을 충족하며, 다른 알고리즘은 계속 진행 중입니다.

### 현재 MD4와 MD5 비교

모든 압축 단계를 컴파일 시간에 전개하고 다중 블록 루프 밖에서 기능을 선택하도록 한 뒤
2026-10-16에 MD4와 MD5 행을 다시 측정했습니다. MD4는 지원되는 경우 AVX-512VL ternary
logic과 vector rotate를 사용합니다. MD5는 BMI1 ANDN을 사용하지만 파괴적 scalar ROL은
의도적으로 유지합니다. 같은 코드에서 BMI2 RORX를 쓴 변형은 이 의존성 사슬에서 더
느렸습니다. 두 경로 모두 런타임 CPU 검사로 선택하며,
`CERTPP_DISABLE_HWACCEL_SIMD=ON`은 portable 구현을 유지합니다.

| 대응 실행 10회 중앙값, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| MD4, 변경 전 | 840 MiB/s | 1377 MiB/s | 0.61배 |
| MD4, 현재 | 약 1237 MiB/s | 약 1383 MiB/s | **0.90배** |
| MD5, 변경 전 | 674 MiB/s | 837 MiB/s | 0.81배 |
| MD5, 현재 | 약 758 MiB/s | 약 843 MiB/s | **0.90배** |

대응 실행 10회의 비율 중앙값은 MD4가 0.900배, MD5가 0.901배였습니다. 개별 반올림
비율은 MD4가 0.87--0.94배, MD5가 0.87--0.92배 범위였으므로 이 장비에서 두 행은
문턱을 근소하게 충족합니다. 관련 compiler나 dispatch를 바꾸면 다시 측정해야 합니다.
모든 측정 전에 digest 동일성 검사를 통과했고, 가속 기지 응답 테스트와 SIMD 비활성
portable 테스트도 모두 통과합니다.

### 현재 SHA-3와 SHAKE 비교

AVX-512VL permutation을 추가한 뒤 2026-10-16에 Keccak 행을 다시 측정했습니다. 확장된
vector register file에 lane 25개를 모두 유지하고, rho/pi를 제자리 24-lane 순환으로
처리하며, theta parity와 chi에 ternary logic을 사용합니다. 런타임 기능 검사는 기존
BMI1 및 portable 폴백을 유지합니다.

| 대응 실행 5회 중앙값, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| SHA3-256 | 약 580 MiB/s | 약 418 MiB/s | **1.40배** |
| SHA3-512 | 약 311 MiB/s | 약 228 MiB/s | **1.35배** |
| SHAKE-128, 64바이트 출력 | 약 724 MiB/s | 약 526 MiB/s | **1.38배** |
| SHAKE-256, 64바이트 출력 | 약 544 MiB/s | 약 399 MiB/s | **1.38배** |

FIPS SHA-3 벡터, 독립적으로 생성한 SHAKE 벡터, streaming 경계, 반복 finish, 다중 블록
squeeze 테스트가 가속 경로를 통과합니다. SIMD 비활성 빌드는 portable permutation을
계속 시험합니다. 직접 비교하는 네 행이 모두 0.90 문턱을 넘습니다.

### 현재 AES-CBC 비교

앞선 조각이 남아 있지 않을 때 안전한 완전 블록 입력 묶음을 `CbcTransformer`가 AES-NI
bulk 함수에 직접 넘기도록 바꾼 뒤 2026-10-16에 AES-CBC 행을 다시 측정했습니다. 이전에는
모든 `transform()` 호출이 완전한 입력 전체를 내부 staging buffer에 복사하고, 처리 뒤 빈
buffer를 다시 할당했습니다. 직접 경로는 처리하지 않은 나머지만 buffer에 보관합니다.
정확한 제자리 입출력과 입력보다 앞선 주소의 출력은 안전하며, 앞쪽으로 겹치는 출력은 아직
읽지 않은 평문을 암호문이 덮지 않도록 기존 buffered 경로를 유지합니다.

| 대응 실행 7회 중앙값, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| AES-128-CBC, 직접 streaming 전 | 1745 MiB/s | 1881 MiB/s | 0.93배 |
| AES-128-CBC, 현재 | **1818 MiB/s** | 1882 MiB/s | **0.97배** |
| AES-192-CBC, 직접 streaming 전 | 1495 MiB/s | 1576 MiB/s | 0.95배 |
| AES-192-CBC, 현재 | **1542 MiB/s** | 1586 MiB/s | **0.97배** |
| AES-256-CBC, 직접 streaming 전 | 1050 MiB/s | 1373 MiB/s | 0.76배 |
| AES-256-CBC, 현재 | **1346 MiB/s** | 1377 MiB/s | **0.98배** |

현재 대응 실행 7회의 반올림 비율은 AES-128이 0.94--0.98배, AES-192가 0.96--1.08배,
AES-256이 0.88--1.02배였고 중앙값은 모두 0.90 문턱을 넘습니다. AES-256의 낮은 한 번은
반복되는 결과가 아니었습니다. NIST SP 800-38A 벡터와 가속/portable bulk 비교가 통과하며,
분할 입력, 정확한 제자리 입력, 앞쪽 겹침, 완전 블록을 buffer에 남기는 제한된 출력도
포함합니다. AES 하드웨어 가속을 끈 구성에서도 같은 테스트가 통과합니다.

### 현재 DES와 TripleDES 비교

비트 단위 Feistel 확장과 P permutation을 생성된 S/P table과 회전된 라운드 키 워드
두 개로 바꾼 뒤 2026-10-16에 DES 행을 다시 측정했습니다. 완전한 CBC 입력도 직접
streaming 경로를 사용합니다. chaining 값은 지역 변수에 유지하고, TripleDES는 EDE
단계 사이에 permuted block을 유지하여 서로 상쇄되는 final/initial permutation 쌍을
세 번 적용하지 않습니다.

| 대응 실행 7회 중앙값, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| DES-CBC, 이전 | 약 6 MiB/s | 약 80 MiB/s | 0.07배 |
| DES-CBC, 현재 | **81 MiB/s** | 78 MiB/s | **1.04배** |
| 2-key 3DES-CBC, 이전 | 약 2 MiB/s | 약 30 MiB/s | 0.06배 |
| 2-key 3DES-CBC, 현재 | **30 MiB/s** | 약 30 MiB/s | **1.01배** |

현재 대응 실행 일곱 번 모두 두 cipher의 반올림 비율이 0.99배 이상이었습니다. 2-key 및 3-key EDE를
포함한 공개 DES·TripleDES 기지 응답 테스트도 통과합니다. 두 cipher는 호환성 전용이며,
성능 목표 달성이 보안 상태를 바꾸지는 않습니다.

### 현재 ARIA-CBC 비교

바이트 단위 diffusion을 RFC와 동등한 32비트 구성으로 바꾼 뒤 2026-10-16에 ARIA 행을
다시 측정했습니다. 확장 S-box 항목이 substitution과 첫 diffusion 단계를 함께 처리하고,
고정 byte permutation의 앞뒤에 word diffusion 두 단계를 둡니다. CBC bulk loop는 키
schedule을 한 번만 word로 바꾸고 chaining 상태를 word로 유지하며 각 블록의 round
경로를 inline합니다.

| 대응 실행 7회 중앙값, 64 KiB | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| ARIA-128-CBC, 이전 | 48 MiB/s | 157 MiB/s | 0.31배 |
| ARIA-128-CBC, 현재 | **154 MiB/s** | 149 MiB/s | **1.04배** |
| ARIA-192-CBC, 이전 | 42 MiB/s | 133 MiB/s | 0.31배 |
| ARIA-192-CBC, 현재 | **136 MiB/s** | 130 MiB/s | **1.03배** |
| ARIA-256-CBC, 이전 | 36 MiB/s | 119 MiB/s | 0.31배 |
| ARIA-256-CBC, 현재 | **117 MiB/s** | 115 MiB/s | **1.03배** |

현재 개별 실행의 반올림 비율은 0.98--1.09배였고 중앙값은 모두 0.90 문턱을 넘습니다.
RFC 5794 키 schedule, block, CBC 기지 응답 테스트가 기본 및 portable 빌드에서 통과합니다.

### 현재 AES-GCM 비교

앞선 8카운터와 4블록 GHASH 작업을 16블록 결합 kernel로 확장한 뒤 64 KiB
AES-256-GCM 행을 다시 측정했습니다. 512비트 VAES chain 네 개가 카운터 16개를 암호화하는
동안 GFNI/VPCLMULQDQ는 앞선 암호문 16블록의 GHASH 곱을 계산하고, 서로 독립적인 명령
흐름을 겹친 뒤 필드 reduction 한 번을 수행합니다. 카운터 블록은 레지스터에서
구성합니다. 짧은 레코드는 태그 mask와 payload 카운터 네 개를 함께 암호화하는 5-way
AES-NI 경로를 유지하며 긴 메시지용 거듭제곱 표 준비 비용을 피합니다.

| 동일 조건 비교 | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| 변경 전, 64 KiB | 517 MiB/s | 11608 MiB/s | 0.04배 |
| 이전 VAES/GHASH 경로, 64 KiB | **2953 MiB/s** | 10569 MiB/s | **0.28배** |
| 현재 5회 중앙값, 64 KiB | **10692 MiB/s** | 11800 MiB/s | **0.90배** |
| 현재 5회 중앙값, 64바이트 레코드 | 83 ns | 75 ns | **0.93배** |

certpp 대용량 처리량은 최초 구현보다 약 20.7배 높아졌습니다. 현재 5회 대응 대용량
비율은 0.90, 0.91, 0.93, 0.90, 0.90배이며 중앙값은 목표를 근소하게 충족합니다.
가속 경로는 모든 키 크기와 32비트 카운터 carry에서 portable AES와 비교하고, 긴 GHASH
입력은 서로 다른 분할 경계의 직렬 경로와 비교합니다. 가속 및 완전 portable 테스트
빌드가 모두 통과합니다.

### 현재 알고리즘 목록 비교

비교 하네스를 2026-10-16에 해시 6종과 CBC 구성 2종에서 구현된 해시 14종, CBC 구성
8종, AEAD 3종, X25519, ML-KEM 매개변수 집합 3종, RSA-2048, DSA-2048, EdDSA와
ML-DSA 서명, 소수체 ECDSA/ECDH 곡선 선택 20종과 이진체 ECDSA 선택 10종으로
확장했습니다. 직접
상호운용할 수 있는 행은 측정 전에 digest, 암호문, 태그, 서명 또는 공유 비밀이 같은지
검사합니다. EC 서명은 양방향 교차
검증과 변경된 digest 거부를 확인하고, 소수 곡선 ECDH는 정확한 공유 비밀을 비교합니다.
ML-KEM도 양방향으로 구현 경계를 넘겨 검사합니다. CBC는
이제 양쪽 구현을 하나의 연속 스트림으로 진행합니다. 이전 하네스는 호출마다
OpenSSL만 초기화해 context 설정 비용을 OpenSSL에만 부과했고 certpp의 상대 결과를
높게 표시했습니다. 표는 전체 실행 3회의 실행별 비율 중앙값을 보고합니다. 지연시간
비율은 `OpenSSL 지연시간 / certpp 지연시간`을 사용하므로 모든 비율의 방향이 같고
1.00배가 동률입니다.
RSA와 DSA 행은 처음에 정적 Clang 22.1.8 Release 빌드에서 OpenSSL 3.6.4를 상대로
`--classic-signatures`를 11회 실행해 갱신했습니다. 프로세스는 높은 우선순위로 논리
프로세서 하나에 고정했고 양쪽은 같은 설정 및 워밍업 규칙을 사용합니다. 그 snapshot에서
표시한 지연시간은 각 구현의 중앙값이고, 비율은 짝을 이룬 11개 실행별 비율의 중앙값입니다.
무작위 소수 탐색 때문에 키 생성 비율은 표시된 두 중앙값의 몫과 다를 수 있습니다.
측정 전에 양방향 교차 검증과 변경된 digest 거부를 확인합니다.
packed Montgomery engine은 이제 16-limb 체인과 32-limb 체인을 별도 컴파일한 kernel로
dispatch합니다. 이에 따라 Clang은 일반 fallback에 특정 modulus 폭을 강제하지 않으면서
곱·reduction loop를 최대 32 단위로 전개할 수 있습니다. 이어 고정 count 제곱 dispatch는
같은 CIOS body의 두 피연산자에 입력 포인터 하나를 재사용합니다. WSL Clang 18에서 기준과
변경 바이너리를 번갈아 7회 실행한 내부 중앙 지연시간은 RSA 서명 0.829에서 0.797 ms,
RSA 검증 0.025에서 0.024 ms, DSA 서명 0.447에서 0.436 ms, DSA 검증 0.543에서
0.529 ms로 바뀌어 2.5--4.2% 개선됐습니다. 그 WSL 빌드에서 현재 소스를 별도로 7회 비교한
RSA 서명/검증 비율은 0.310/0.628배였습니다. DSA context는 이제 바인딩한 생성자와 공개키의
위치별 4비트 Montgomery 표를 준비합니다. 한 코어에 고정한 7회 실행의 DSA 서명/검증
중앙값은 0.196/0.263 ms이고 OpenSSL은 0.330/0.289 ms였습니다. 실행별 비율 중앙값은
1.667/1.103배이고 범위는 1.603--1.726배와 1.083--1.143배입니다. 반복 연산 측정 전에
context 바인딩이 residue 1,920개를 만듭니다. 이 고정 base 최적화는 키 생성을 바꾸지 않으며
이번 7회 무작위 소수 탐색 비율은 0.573--1.838배로 넓게 흔들렸습니다. 이후 집중 키 생성
측정 결과가 아래 DSA 행의 근거입니다. RSA 소수 생성은 이제 무작위 seed 하나를 고른 뒤 그 seed의 묶음
작은 소수 나머지를 재사용하면서 가까운 홀수 후보를 순회합니다. 기존 Miller--Rabin 20회는
그대로 유지합니다. 변경 전 `HEAD`를 별도 빌드해 WSL Clang 18에서 한 코어에 고정한 15회
측정 결과, certpp RSA-2048 키 생성 중앙값은 63.937 ms에서 54.471 ms로 14.8%
줄었습니다. 현재 실행의 OpenSSL 대비 비율 중앙값은 1.824배였으며, 표에는 이 certpp
중앙값과 비율을 기록합니다. 무작위 소수 탐색 때문에 구현 간 키 생성 비율은 같은 구현의
변경 전후 결과보다 훨씬 크게 흔들립니다.
DSA 파라미터 생성도 제약된 탐색에 같은 나머지 재사용 방식을 적용합니다. 제한된
`p += 2q` 진행식을 순회하면서 모든 후보의 묶음 작은 소수 나머지를 갱신하고, 컴파일 시 만든
4096 미만 소수 표를 사용합니다. 채택한 `p`의 Montgomery context는 생성자 구성, 공개키 유도,
두 키 객체, 생성 키 검증에서 재사용하며 독립적인 Miller--Rabin 20회 판정 두 번은 유지합니다.
변경 전/현재 바이너리를 번갈아 실행한 21회에서 certpp 중앙값은 225.673 ms에서 178.276 ms로
줄었습니다. 현재 바이너리 추가 15회는 중앙값 158.894 ms였고, 현재 표본 36개를 합친 certpp
중앙값은 164.646 ms, OpenSSL 대비 실행별 비율 중앙값은 0.9015배입니다. 목표에는 도달했지만
무작위 분포가 넓어 특히 재측정에 민감합니다. 표는 이 현재 WSL 결과를 다른 연산의 최신 채택
측정값과 함께 기록하며, 각 행의 구성은 해당 설명 문단에서 밝힙니다.
RSA CRT 지수승은 이제 두 1024비트 branch를 하나의 고정 5비트 schedule로 함께 진행하고,
같은 thread에서 서로 독립인 CIOS carry chain을 교차 배치합니다. WSL Clang 18에서 한 코어에
고정해 변경 전후를 번갈아 15회 실행한 결과 certpp RSA-2048 서명 중앙값은 0.811 ms에서
0.772 ms로 4.8% 줄었습니다. 같은 실행의 OpenSSL 대비 비율 중앙값은 0.324배로 높아졌습니다.
이는 아래 현재 IFMA 측정값으로 대체된 중간 결과입니다.
공개 지수 경로는 이제 마지막 홀수 base 곱과 Montgomery domain 이탈을 한 번에 수행합니다.
한 코어에 고정한 11회 교대 실행에서 검증 중앙값은 0.024에서 0.023 ms로 줄고 OpenSSL 비율
중앙값은 0.640배에서 0.676배로 올랐습니다. 재암호화 검사를 공유하는 개인키 연산의 서명도
0.793에서 0.782 ms로 작게 줄었습니다. 별도 7회 현재 소스 snapshot의 RSA 서명/검증 비율
중앙값은 0.328/0.673배였습니다.
1024비트 CRT 곱셈은 이제 16개 열 전체에서 product와 accumulator carry를 CF와 OF에 유지하고,
Montgomery reduction에서도 지속되는 ADX chain 두 개를 다시 사용합니다. 변경 전 바이너리와
한 코어에서 번갈아 실행한 11회 결과 RSA-2048 서명 중앙값은 0.778에서 0.626 ms로 19.5%
줄었고 OpenSSL 대비 비율 중앙값은 0.330배에서 0.396배로 높아졌습니다. 같은 실행의 검증 비율
중앙값은 0.675배였습니다. 이 CRT 전용 kernel은 공개 지수 산술을 바꾸지 않습니다. 이는
아래 현재 IFMA 측정값으로 대체된 중간 결과입니다.
일반 고정 폭 Montgomery dispatcher도 같은 지속 dual-carry 설계를 16 및 32-limb 피연산자에
선택합니다. 32-limb 경로는 runtime BMI2/ADX gate와 portable fallback을 유지하면서 RSA-2048
공개 지수승을 가속합니다. 한 코어에 고정한 7회 교대 실행에서 검증 중앙값은 0.024에서
0.017 ms로 29.2% 줄고 OpenSSL 대비 비율 중앙값은 0.678배에서 0.913배로 높아졌습니다.
빨라진 공개 재암호화 검사로 서명 중앙값도 0.689에서 0.646 ms로 6.2% 줄었으며 비율
중앙값은 0.414배였습니다.
최종 개인키 연산 단계는 AVX-512F, AVX-512VL, AVX512-IFMA를 모두 사용할 수 있을 때만
쌍을 이룬 20-digit radix-52 Montgomery kernel을 선택합니다. ZMM 블록 세 개가 두 1024비트
CRT branch를 하나의 고정 6비트 window schedule로 진행합니다. 최상위 window는 누산기를
직접 초기화하고, 지수 비트는 한 번 packed 64비트 배열로 옮긴 뒤 읽습니다. 각 개인키는
radix-52 modulus, R-squared, Montgomery one을 한 번 준비하며 이 키 관련 배열은 키와 함께
영점화합니다. 다른 CPU와 AVX-512 또는 SIMD 비활성 빌드는 dual-carry 또는 portable 경로를
유지합니다. OpenSSL 3.6.4를 상대로 WSL2 Clang 22.1.8 Release 집중 실행 11회의 RSA-2048
서명 중앙값은 certpp/OpenSSL 0.285/0.257 ms, 실행별 비율 중앙값은 0.905배였습니다. 검증은
0.017/0.016 ms와 0.910배였습니다. 기존 CRT 재암호화 fault 검사는 그대로입니다.

| 연산(별도 표기가 없으면 64 KiB) | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| MD4 | 약 1237 MiB/s | 약 1383 MiB/s | 0.90배 |
| MD5 | 약 758 MiB/s | 약 843 MiB/s | 0.90배 |
| SHA-1 | 1709 MiB/s | 1839 MiB/s | 0.93배 |
| SHA-224 | 1532 MiB/s | 1601 MiB/s | 0.96배 |
| SHA-256 | 1536 MiB/s | 1598 MiB/s | 0.96배 |
| SHA-384 | 632 MiB/s | 700 MiB/s | 0.90배 |
| SHA-512 | 632 MiB/s | 695 MiB/s | 0.91배 |
| SHA3-256 | 약 580 MiB/s | 약 418 MiB/s | 1.40배 |
| SHA3-512 | 약 311 MiB/s | 약 228 MiB/s | 1.35배 |
| SHAKE-128, 64바이트 출력 | 약 724 MiB/s | 약 526 MiB/s | 1.38배 |
| SHAKE-256, 64바이트 출력 | 약 544 MiB/s | 약 399 MiB/s | 1.38배 |
| BLAKE2s | 512 MiB/s | 533 MiB/s | 0.96배 |
| Streebog-256 |  | 사용 불가 |  |
| Streebog-512 |  | 사용 불가 |  |
| AES-128-CBC | 1818 MiB/s | 1882 MiB/s | 0.97배 |
| AES-192-CBC | 1542 MiB/s | 1586 MiB/s | 0.97배 |
| AES-256-CBC | 1346 MiB/s | 1377 MiB/s | 0.98배 |
| DES-CBC | 81 MiB/s | 78 MiB/s | 1.04배 |
| 2-key 3DES-CBC | 30 MiB/s | 약 30 MiB/s | 1.01배 |
| ARIA-128-CBC | 154 MiB/s | 149 MiB/s | 1.04배 |
| ARIA-192-CBC | 136 MiB/s | 130 MiB/s | 1.03배 |
| ARIA-256-CBC | 117 MiB/s | 115 MiB/s | 1.03배 |
| RSA-2048 키 생성 | 54.471 ms | 무작위 편차 | 1.824배 |
| RSA-2048 서명 | 0.285 ms | 0.257 ms | 0.905배 |
| RSA-2048 검증 | 0.017 ms | 0.016 ms | 0.910배 |
| DSA-2048 키 생성(새 파라미터 포함) | 164.646 ms | 무작위 편차 | 0.9015배 |
| DSA-2048 서명 | 0.196 ms | 0.330 ms | 1.667배 |
| DSA-2048 검증 | 0.263 ms | 0.289 ms | 1.103배 |
| GOST R 34.10-2012 |  | 사용 불가 |  |
| Ed25519 서명, 32바이트 메시지 | 0.024 ms | 0.036 ms | 1.53배 |
| Ed25519 검증, 32바이트 메시지 | 0.077 ms | 0.098 ms | 1.28배 |
| ChaCha20-Poly1305 봉인, 64 KiB | 3796 MiB/s | 4129 MiB/s | 0.92배 |
| XChaCha20-Poly1305 봉인, 64 KiB |  | 사용 불가 |  |
| AES-256-GCM 봉인, 64 KiB | 10692 MiB/s | 11800 MiB/s | 0.90배 |
| ChaCha20-Poly1305 봉인, 64바이트 레코드 | 264 ns | 258 ns | 0.97배 |
| XChaCha20-Poly1305 봉인, 64바이트 레코드 |  | 사용 불가 |  |
| AES-256-GCM 봉인, 64바이트 레코드 | 83 ns | 75 ns | 0.93배 |
| X25519 키 생성 | 0.032 ms | 0.033 ms | 1.035배 |
| X25519 유도 | 0.032 ms | 0.029 ms | 0.909배 |
| ML-KEM-512 키 생성 | 0.025 ms | 0.032 ms | 1.24배 |
| ML-KEM-512 캡슐화 | 0.019 ms | 0.022 ms | 1.15배 |
| ML-KEM-512 디캡슐화 | 0.028 ms | 0.035 ms | 1.25배 |
| ML-KEM-768 키 생성 | 0.042 ms | 0.046 ms | 1.11배 |
| ML-KEM-768 캡슐화 | 0.029 ms | 0.031 ms | 1.10배 |
| ML-KEM-768 디캡슐화 | 0.040 ms | 0.048 ms | 1.18배 |
| ML-KEM-1024 키 생성 | 0.064 ms | 0.072 ms | 1.13배 |
| ML-KEM-1024 캡슐화 | 0.039 ms | 0.043 ms | 1.07배 |
| ML-KEM-1024 디캡슐화 | 0.053 ms | 0.064 ms | 1.19배 |
| Ed448 서명, 32바이트 메시지 | 0.139 ms | 0.200 ms | 1.48배 |
| Ed448 검증, 32바이트 메시지 | 0.191 ms | 0.188 ms | 0.99배 |
| ML-DSA-44 서명, 32바이트 메시지 | 0.394 ms | 0.541 ms | 1.38배 |
| ML-DSA-44 검증, 32바이트 메시지 | 0.090 ms | 0.118 ms | 1.31배 |
| ML-DSA-65 서명, 32바이트 메시지 | 0.705 ms | 0.942 ms | 1.32배 |
| ML-DSA-65 검증, 32바이트 메시지 | 0.145 ms | 0.182 ms | 1.26배 |
| ML-DSA-87 서명, 32바이트 메시지 | 0.858 ms | 1.000 ms | 1.21배 |
| ML-DSA-87 검증, 32바이트 메시지 | 0.253 ms | 0.301 ms | 1.17배 |

소수체 곡선 20개와 이진체 곡선 10개는 각 체·점 산술 변경 뒤 집중 실행을 각각 5회
수행해 갱신했습니다. 프로세스는 높은 우선순위로 논리 프로세서 하나에 고정했습니다.
아래의 압축 표는 `certpp / OpenSSL` 성능 비율 중앙값을 나타내며
`examples/06_openssl_compare.cpp`가 양쪽의 절대 지연시간을 출력합니다. `CEcdsa2`는
서명만 구현하므로 이진 곡선 ECDH는 사용 불가로 표시합니다.

| 곡선 | 키 생성 | ECDSA 서명 | ECDSA 검증 | ECDH 유도 |
|---|---:|---:|---:|---:|
| P-192 | 2.366배 | 2.115배 | 1.804배 | 2.115배 |
| P-224 | 2.006배 | 1.794배 | 1.663배 | 2.057배 |
| P-256 | 0.980배 | 0.990배 | 0.983배 | 1.168배 |
| P-384 | 1.803배 | 1.734배 | 1.457배 | 1.690배 |
| P-521 | 1.637배 | 1.718배 | 1.251배 | 1.684배 |
| secp256k1 | 2.088배 | 2.184배 | 1.784배 | 2.276배 |
| brainpoolP160r1 | 2.223배 | 2.022배 | 1.888배 | 2.094배 |
| brainpoolP192r1 | 2.250배 | 2.000배 | 1.830배 | 2.174배 |
| brainpoolP224r1 | 1.967배 | 1.816배 | 1.624배 | 1.912배 |
| brainpoolP256r1 | 2.073배 | 1.816배 | 1.708배 | 1.866배 |
| brainpoolP320r1 | 1.714배 | 1.680배 | 1.483배 | 1.674배 |
| brainpoolP384r1 | 1.710배 | 1.595배 | 1.417배 | 1.663배 |
| brainpoolP512r1 | 1.176배 | 1.091배 | 1.001배 | 1.200배 |
| brainpoolP160t1 | 2.182배 | 1.915배 | 1.879배 | 2.072배 |
| brainpoolP192t1 | 2.152배 | 1.977배 | 1.833배 | 2.100배 |
| brainpoolP224t1 | 2.041배 | 1.930배 | 1.636배 | 2.050배 |
| brainpoolP256t1 | 1.971배 | 1.831배 | 1.638배 | 1.905배 |
| brainpoolP320t1 | 1.803배 | 1.756배 | 1.441배 | 1.713배 |
| brainpoolP384t1 | 1.808배 | 1.666배 | 1.427배 | 1.706배 |
| brainpoolP512t1 | 1.278배 | 1.199배 | 1.012배 | 1.288배 |
| B-163 | 1.762배 | 1.188배 | 1.565배 | 사용 불가 |
| K-163 | 1.689배 | 1.121배 | 1.487배 | 사용 불가 |
| B-233 | 1.785배 | 1.191배 | 1.543배 | 사용 불가 |
| K-233 | 1.760배 | 1.165배 | 1.491배 | 사용 불가 |
| B-283 | 1.549배 | 1.205배 | 1.504배 | 사용 불가 |
| K-283 | 1.476배 | 1.130배 | 1.418배 | 사용 불가 |
| B-409 | 1.830배 | 1.434배 | 1.761배 | 사용 불가 |
| K-409 | 1.760배 | 1.371배 | 1.691배 | 사용 불가 |
| B-571 | 1.705배 | 1.489배 | 1.728배 | 사용 불가 |
| K-571 | 1.596배 | 1.404배 | 1.648배 | 사용 불가 |

ECDSA와 GOST 검증은 private-scalar ladder 두 개와 아핀 덧셈 대신 공개 스칼라용
`linearCombination()` 하나를 사용합니다. 이진체 경로는 이제 고정 count PCLMUL 곱·제곱
kernel, 높은 word부터 접는 축약, affine/Lopez-Dahab 혼합 덧셈을 결합합니다. 키 생성은
방금 생성한 스칼라와 점에 대해 공개키 검증을 다시 실행하지 않습니다. 직접 비교 가능한
이진 곡선 행 30개가 모두 문턱을 통과합니다. 5회 중앙값에서 B-163 키 생성/서명/검증은
0.099/0.148/0.219 ms이고 OpenSSL은 0.176/0.175/0.343 ms입니다. K-571은
0.876/1.057/1.764 ms이고 OpenSSL은 1.398/1.484/2.885 ms입니다. 두 검증 스칼라는
공개값이므로 공개 검증 경로는 의도적으로 variable-time이며, private scalar 경로는 기존
제어 흐름 정책을 유지합니다.

소수체 갱신으로 직접 비교 가능한 연산 80개 중 76개가 먼저 0.90 문턱 이상에 도달했습니다.
이후 단일 CPU에 고정하고 15회 번갈아 실행한 비교에서는 고정 폭
체 선택기와 희소 P-256 곱셈 본체를 각 점 공식 안으로 강제 inline했습니다. certpp의
키 생성/서명/검증/ECDH 중앙값은 0.037/0.047/0.149/0.141 ms에서
0.032/0.043/0.141/0.134 ms로 줄어 각각 15.6/9.3/5.7/5.2% 개선됐습니다. 쌍별 OpenSSL
비율은 0.797/0.477/0.406/0.322배였습니다. 필드 본체를
optimizer에 노출한 코드 크기 비용으로 벤치마크 실행 파일의 text는 81,060바이트, 즉
7.6% 늘었습니다. P-256은 압축한 33행 signed radix-256 affine 기저 표도 사용합니다. 중앙에
맞춘 digit의 크기는 최대 128이고, 추가 행 하나가 마지막 carry를 소비하며, mask 기반 Y 부호
반전이 부호를 처리합니다. private 조회는 계속 모든 후보 크기를 스캔합니다. P-256 검증
context는 이제
위치별 4비트 공개 스칼라 comb를 사용합니다. 프로세스 전역 기저 표 60 KiB와 context당
공개키 표 60 KiB를 두고, 공개값 직접 조회로 점 배가 256회를 모두 없애 최대 128회 mixed
덧셈만 수행합니다. private scalar 경로는 전체 스캔 선택을 유지합니다. 단일 CPU에서 21회
번갈아 실행한 결과 검증은 0.142 ms에서 0.058 ms로 2.45배 빨라져 OpenSSL의 0.999배에
도달했습니다. private P-256 comb는 이제 CPU와 운영체제가 필요한 상태를 제공할 때
AVX-512F 선택기를 사용합니다. 표 항목 하나가 정확히 64바이트이므로 행의 모든 항목을 ZMM
register 하나로 읽고 동등 mask로 요청한 점을 남깁니다. scalar 전체 스캔 선택기는
fallback으로 유지합니다. 직전 바이너리와 단일 CPU에서 21회 번갈아 실행한 결과 certpp 키
생성은 0.044 ms에서 0.038 ms로, 서명은 0.060 ms에서 0.055 ms로 줄어 각각 15.8%와
8.3% 개선됐고 검증과 ECDH는 변하지 않았습니다.

직전 unsigned 7비트 comb를 signed radix-256으로 바꾸어 표를 약 296 KiB에서 266 KiB로,
예상 mixed 덧셈을 36.7회에서 32.4회로, 스캔하는 0이 아닌 항목을 4,699개에서 4,224개로
줄였습니다. 단일 CPU에서 변경 전후를 7회 번갈아 실행한 certpp 키 생성 중앙값은 0.027
ms에서 0.025 ms로, 서명은 0.039 ms에서 0.037 ms로 줄었습니다. OpenSSL 대비 중앙 비율은
각각 0.890배에서 0.959배, 0.514배에서 0.535배로 높아졌습니다. 구성한 scalar 테스트는 양수
128 경계, 모든 바이트 사이의 carry 전파, 마지막 carry를 확인합니다.

P-256 ECDH context는 이제 현재 peer를 처음 사용할 때 위치별 4비트 comb를 준비하고 해당
peer가 선택된 동안 60 KiB Montgomery-limb 표를 보관합니다. private digit은 각 행의 0이 아닌
후보 15개를 모두 스캔해 mask로 선택합니다. 따라서 반복 유도 경로는 mixed 덧셈 64회만
수행하고 점 배가는 하지 않습니다. peer가 바뀌면 표를 다시 만들며 지원하지 않는 곡선은 일반
private window를 유지합니다. 단일 CPU에서 변경 전후를 7회 번갈아 실행한 certpp 반복 유도
중앙값은 0.140 ms에서 0.039 ms로 줄었고 OpenSSL 비율은 0.315배에서 1.164배로 높아졌습니다.
비교는 양쪽 모두 해당 peer로 이미 구성한 context를 재사용하므로 peer 바인딩과 상호운용
검사를 시간 측정 행보다 먼저 수행합니다.

P-256 서명은 새로 키를 바인딩한 context의 첫 서명에 일반 경로를 유지합니다. 이후 서명은
독립적인 무작위 nonce 8개를 함께 준비합니다. 각 projective `k*G` 결과가 field 역원 하나를
공유하고 `k^-1 mod n` 값들이 order 역원 하나를 공유하며, context에는 결과인 공개 `r`과
비밀 `k^-1`만 보관합니다. 항목을 사용할 때는 이동해 빼고, 키 reset과 context 파괴 시 쓰지
않은 역원을 모두 안전하게 지웁니다. 전체 스캔 signed radix-256 점 경로와 OS CSPRNG는 그대로
유지합니다. 벤치마크 준비 단계는 묶음 경계를 넘어서고 각 결과 서명을 OpenSSL로 검증한 뒤
시간을 측정합니다. 단일 CPU에서 변경 전후를 7회 번갈아 실행한 반복 certpp 서명 중앙값은
0.037 ms에서 0.020 ms로 줄었고 OpenSSL 비율은 0.531배에서 0.990배로 높아졌습니다. 묶음을
다시 채우는 호출의 지연은 더 크지만 그 비용 전체가 반복 서명 행에 포함되며, 한 번만 서명하는
context는 묶음을 만들지 않습니다.

현재 P-256 행은 batch마다 1,000회 연산하고 단일 CPU에서 전체 실행을 7회 수행했습니다.
각 측정은 양쪽을 모두 준비한 뒤 독립 batch 중 어느 쪽을 먼저 실행할지 번갈아, 모든 certpp
batch를 OpenSSL보다 먼저 실행했을 때 관측한 주파수 편향을 피합니다. 키
생성/서명/검증/ECDH 중앙 비율은 0.980/0.990/0.983/1.168배이고 실행별 범위는 각각
0.948--1.053, 0.931--1.027, 0.939--1.027, 1.150--1.297배입니다. 소수체 80개 행이 모두
문턱을 통과합니다. 키 생성, 서명, 검증 중앙값은 관련 변경 뒤 다시 측정해야 할 만큼
문턱에 가깝습니다.
다른 소수 곡선은 Montgomery limb 그대로 저장한 폭 8 affine 홀수 배수 표를 유지하므로,
반복 검증에서 좌표를 다시 만들거나 정규화하거나 `CBigNum`을 거쳐 변환하지 않습니다.

Ed448은 이제 고정 폭 Fe448 산술과 기준점·각 공개키용 10열 comb 표를 사용합니다.
현재 동일 조건 결과와 검증 방법은 [현재 Ed448 비교](#현재-ed448-비교)에 기록합니다.

X25519 키 생성은 새로 유도한 공개값에 cofactor를 곱하던 두 번째 255단계 ladder를
더는 실행하지 않습니다. 네이티브 radix-51 경로는 독립 carry chain, 10-product 제곱
schedule, 더 짧은 ladder live range, 그리고 generic AVX2/BMI2/ADX 또는 정확한 Tiger Lake
tuning으로 가는 캐시된 런타임 dispatch를 사용합니다. generic gate는 CPUID와 OS가 활성화한
XCR0 vector 상태를 직접 읽어 compiler 버전별 기능 문자열을 피하면서 필요한 AVX 운영체제
검사를 유지합니다. 개인키는 clamp된 scalar를 보관하고
context는 검사를 통과한 바인딩 키를 보관합니다. portable radix-2^25.5 경로도 유지합니다.
현재 동일 조건 측정과 검증은 [현재 X25519 비교](#현재-x25519-비교)에 기록합니다.

하네스는 OpenSSL 3.6.4의 default와 legacy provider를 명시적으로 불러 MD4와 DES도
측정합니다. Streebog에는 이 설치에 없는 provider가 필요하고 OpenSSL은 EVP를 통해
XChaCha20-Poly1305를 제공하지 않습니다. 이 사용 불가 행도 조용히 생략하지 않고 실행
목록에 계속 둡니다. ML-KEM 설정은 각 구현의 원시 공개 키를 다른 구현으로 가져와
`certpp 캡슐화 -> OpenSSL 디캡슐화`와 그 반대를 모두 검사한 뒤 측정합니다. RSA,
DSA는 certpp의 전통적 개인키 DER을 OpenSSL로 가져온 뒤 양쪽 서명과 변경된 digest
거부를 교차 검증합니다. OpenSSL 3.6.4의 시험한 default/legacy provider는 GOST 서명
구현을 제공하지 않으므로 그 행에는 임의의 비율을 만들지 않았습니다.

첫 고전 서명 직접 실행에서 RSA 키 생성/서명은 1522.626/5.831 ms, DSA 키
생성/서명/검증은 5162.961/8.089/18.882 ms였습니다. Miller--Rabin에서 Montgomery
reduction을 재사용하고, 긴 모듈러 지수에 sliding window를 쓰며, DSA 검증의 공개
지수 두 개를 결합해 감소분 대부분을 얻었습니다. 작은 소수 체는 이제 소수들을 32비트에
들어가는 곱으로 묶고 후보를 곱마다 한 번만 훑은 뒤, 그 나머지를 각 소인수로 검사합니다.
체에서 처음 만나는 약수가 997인 고정 2048비트 합성수에서 9회 중앙값은 호출당
86.687마이크로초에서 16.790마이크로초로 줄어 로컬 변경 전후 기준 5.16배 개선됐습니다.
현재 RSA와 DSA 집중 갱신 결과를 위 표에 기록했습니다. 키 생성은 무작위 소수 후보를 얼마나
빨리 찾는지에 따라 계속 편차가 있지만 반복 서명과 검증은 안정적입니다. RSA 키 생성과 모든
RSA/DSA 반복 연산의 실행별 중앙값이 이제 문턱을 넘습니다. 단계별 작업과 기각한 대안은
[변경 이력](../HISTORY.ko.md)에 유지합니다.

### 현재 ML-KEM 비교

2026-10-18에 Windows 검토 호스트에서 MinGW64 ABI를 대상으로 하는 Clang 22.1.8과
OpenSSL 3.6.4로 ML-KEM 행을 다시 측정했습니다. `--mlkem` 집중 하네스를 7회
실행했습니다. 각 실행은 먼저 양방향으로 원시 공개키를 가져와
`certpp 캡슐화 -> OpenSSL 디캡슐화`와 그 반대를 검사한 뒤, 워밍업한 독립 loop에서
각 구현을 측정했습니다. 양쪽 모두 출력 buffer를 측정 loop 전에 할당했습니다. 표는
반올림한 지연시간의 중앙값과 7개 실행별 성능 비율의 중앙값입니다.

| 연산 | certpp | OpenSSL EVP | certpp / OpenSSL 성능 |
|---|---:|---:|---:|
| ML-KEM-512 키 생성 | **0.025 ms** | 0.032 ms | **1.24배** |
| ML-KEM-512 캡슐화 | **0.019 ms** | 0.022 ms | **1.15배** |
| ML-KEM-512 디캡슐화 | **0.028 ms** | 0.035 ms | **1.25배** |
| ML-KEM-768 키 생성 | **0.042 ms** | 0.046 ms | **1.11배** |
| ML-KEM-768 캡슐화 | **0.029 ms** | 0.031 ms | **1.10배** |
| ML-KEM-768 디캡슐화 | **0.040 ms** | 0.048 ms | **1.18배** |
| ML-KEM-1024 키 생성 | **0.064 ms** | 0.072 ms | **1.13배** |
| ML-KEM-1024 캡슐화 | **0.039 ms** | 0.043 ms | **1.07배** |
| ML-KEM-1024 디캡슐화 | **0.053 ms** | 0.064 ms | **1.19배** |

구현은 이제 bit reservoir로 계수를 인코드·디코드하고, 고정 폭 bit lane에서 CBD 계수를
샘플링하며, NTT에서 제한 범위 Barrett reduction을 사용합니다. 또한
`IKemContext`를 reset할 때 바인딩된 키의 공개 행렬과 비밀 벡터를 한 번 확장합니다.
원시 `CMlKem` 진입점은 호출마다 전달받은 byte span을 계속 준비합니다. 변경 뒤 NIST
ACVP 벡터, 변경 ciphertext 암묵적 거부, 정규 키 음성 검사, ring 참조 검사, 양방향
상호운용이 통과했습니다. 직접 비교 가능한 ML-KEM 9개 행은 이 호스트에서 모두 0.90
문턱을 넘습니다.

### 현재 ML-DSA 비교

2026-10-18에 ML-KEM과 같은 Windows Clang 22.1.8 및 OpenSSL 3.6.4 환경에서
ML-DSA 행을 다시 측정했습니다. `--mldsa` 집중 하네스를 7회 실행했습니다. 각 실행은
키가 바인딩된 certpp context와 OpenSSL 키를 사용하고 양쪽을 독립적으로 워밍업한 뒤,
20회 연산 batch 다섯 개 중 가장 빠른 값을 택했습니다. 서명은 거부 샘플링을 사용하므로
nonce에 따라 편차가 있습니다. 표는 유리한 단일 실행을 고르지 않고 반올림한 지연시간의
중앙값과 7개 실행별 성능 비율의 중앙값을 보고합니다.

| 연산 | certpp | OpenSSL EVP | certpp / OpenSSL 성능 |
|---|---:|---:|---:|
| ML-DSA-44 서명, 32바이트 메시지 | **0.394 ms** | 0.541 ms | **1.38배** |
| ML-DSA-44 검증, 32바이트 메시지 | **0.090 ms** | 0.118 ms | **1.31배** |
| ML-DSA-65 서명, 32바이트 메시지 | **0.705 ms** | 0.942 ms | **1.32배** |
| ML-DSA-65 검증, 32바이트 메시지 | **0.145 ms** | 0.182 ms | **1.26배** |
| ML-DSA-87 서명, 32바이트 메시지 | **0.858 ms** | 1.000 ms | **1.21배** |
| ML-DSA-87 검증, 32바이트 메시지 | **0.253 ms** | 0.301 ms | **1.17배** |

NTT butterfly와 점별 곱은 이제 계수마다 64비트 나눗셈을 하는 대신 고정 modulus
Montgomery 곱을 사용합니다. 비트 패킹은 64비트 reservoir를 사용하고, SHAKE 거부
sampler는 바이트와 nibble 순서를 보존하면서 완전한 rate block을 소비합니다. 정확한
FIPS 204 부록 B twiddle table은 보통 형식으로 계속 노출하고, hot loop용 곱셈 형식은
별도로 한 번 유도합니다. 변경 뒤 공식 서명·검증 벡터, ring 참조 곱, codec 경계,
잘못된 서명, 공개 wrapper가 모두 통과했습니다. 직접 비교 가능한 ML-DSA 6개 행은 이
호스트에서 모두 0.90 문턱을 넘습니다. 이 성능 결과가 서명의 constant-time 동작을
뜻하지는 않습니다. 표준 거부 loop의 시도 횟수는 계속 nonce에 의존하며 별도의 timing
검토 항목으로 남습니다.

### 현재 Ed25519 비교

2026-10-18에 WSL2 Ubuntu의 GCC 13.3.0과 OpenSSL 3.0.13을 사용하는 Release 빌드로
Ed25519 행을 다시 측정했습니다. 빌드는 네이티브 radix-51 필드 경로를 활성화했습니다.
`--ed25519` 집중 하네스를
11회 실행했고, 각 실행은 양쪽을 독립적으로 측정하여 연산 200회 배치 다섯 개 중 가장
빠른 값을 택했습니다. 표는 반올림한 지연시간의 중앙값과 각 실행에서 보고한 성능
비율의 중앙값입니다.

| 연산 | certpp | OpenSSL EVP | certpp / OpenSSL 성능 |
|---|---:|---:|---:|
| Ed25519 서명, 32바이트 메시지 | **0.024 ms** | 0.036 ms | **1.53배** |
| Ed25519 검증, 32바이트 메시지 | **0.077 ms** | 0.098 ms | **1.28배** |

11회 certpp/OpenSSL 성능 비율의 중앙값은 서명 1.53배, 검증 1.28배였습니다. 아핀
precomputed 고정 기저점, 필드 곱셈이 즉시 소비하는 loose 덧셈, 생성된 제곱 kernel,
공유 배가 `S*B - k*A` 검증기, 공개키마다 저장하는 홀수 배수 표가 이 결과를 만듭니다.
가져온 공개키는 계속 소수 위수 부분군에 있어야 합니다. `A`가 이미 그 부분군에 있는
상태의 정확한 uncofactored 방정식은 같은 부분군의 `R`만 받아들일 수 있으므로 별도
`L*R` 곱은 생략합니다. 정규 디코딩, 곡선 위 점 복구, 항등원 거부를 유지하며 전용
2차수 `R` 음성 테스트가 이 경계를 검사합니다.

### 현재 X25519 비교

X25519 행은 2026-10-18에 Clang 22.1.8, 네이티브 radix-51 필드 경로, MSYS2 MinGW64의
OpenSSL 3.6.4를 사용한 정적 Windows x86-64 Release 빌드에서 다시 측정했습니다.
`--x25519` 집중 실행 15회는 프로세스를 논리 processor 0에 고정하고 high priority로
실행해 양쪽을 독립적으로 측정했습니다. 프로그램의 각 행은 양쪽 각각 연산 200회 배치
다섯 개 중 가장 빠른 값이며, 표는 반올림한 지연시간 중앙값과 15개 실행별 성능 비율의
중앙값을 기록합니다.

| 연산 | certpp | OpenSSL EVP | certpp / OpenSSL 성능 |
|---|---:|---:|---:|
| X25519 키 생성 | **0.032 ms** | 0.033 ms | **1.035배** |
| X25519 유도 | 0.032 ms | **0.029 ms** | **0.909배** |

이전 portable 측정 0.139/0.136 ms와 비교하면 radix-51은 먼저 WSL에서 0.049/0.048 ms에
도달했습니다. 이어 두 carry chain reduction과 전용 square schedule이 필드 연산을 줄였고,
전체 ladder 런타임 dispatch가 generic AVX2/BMI2/ADX body 또는 정확한 Tiger Lake body를
선택하며 portable fallback도 유지합니다. generic 결정은 CPUID와 OSXSAVE/XCR0를 사용하므로
`adx`를 builtin 기능 문자열로 허용하지 않는 Clang release도 이 경로를 컴파일할 수 있습니다.
키 생성 때 한 번 clamp하고 context가 검증된
바인딩 개인키와 상대 공개키 객체를 재사용합니다. 현재 키 생성과 유도 중앙값은 모두
90% 완료 문턱을 충족합니다. RFC 7748 기지 응답과 반복 벡터, exact-arithmetic 필드 검사,
교차 구현 공유 secret, 비정규 u 처리, 저차수 상대 거부는 이후 변경의 승인 경계로
유지합니다.

### 현재 Ed448 비교

2026-10-18에 WSL2 Ubuntu의 GCC 13.3.0과 OpenSSL 3.0.13으로 Ed448 행을 다시
측정했습니다. Windows MinGW64 컴파일러 설치는 `cc1plus.exe`를 시작하지 못하고
`0xC0000139`로 종료되어, 대신 양쪽을 같은 WSL 환경에서 빌드하고 측정했습니다.
`--ed448` 집중 실행을 11회 수행했고 각 실행은 양쪽을 독립적으로 측정하여 연산 20회
배치 다섯 개 중 가장 빠른 값을 택했습니다. 표는 반올림한 지연시간 중앙값과 실행별
성능 비율의 중앙값입니다.

| 연산 | certpp | OpenSSL EVP | certpp / OpenSSL 성능 |
|---|---:|---:|---:|
| Ed448 서명, 32바이트 메시지 | **0.139 ms** | 0.200 ms | **1.48배** |
| Ed448 검증, 32바이트 메시지 | 0.191 ms | **0.188 ms** | **0.99배** |

필드 구현은 네이티브 128비트 곱셈을 쓸 수 있으면 radix-2^56 limb 8개를, 그렇지
않으면 radix-2^28 limb 16개를 사용합니다. 고정 지수 체인이 일반 큰 수 필드 역원과
제곱근을 대체합니다. 혼합 precomputed 덧셈과 10열 comb 표는 기준점 곱과 결합
`S*B - k*A` 검증의 온라인 작업을 배가 45행으로 줄이며, 반복 검증을 위해 공개키
표를 보관합니다. 가져온 공개키는 계속 전체 부분군 검사를 받습니다. 서명 `R`은 정규
인코딩, 곡선 위 점, 항등원 검사를 유지합니다. 정확한 uncofactored 방정식 덕분에
중복 `L*R` 곱은 생략하고, 2차수 `R` 음성 테스트가 이 경계를 검사합니다. RFC 8032,
잘못된 입력, 변경된 메시지·서명, 다른 키, 필드 산술 테스트는 네이티브 WSL 배치와
16-limb MSVC fallback에서 통과합니다. Comb 조회 index가 스칼라에 따라 달라지므로
이 측정 결과로 서명의 constant-time을 주장하지 않습니다.

### 이전 전체 비교

아래의 더 넓은 표는 이전 OpenSSL 3.0.13 세션입니다. 최적화 순서의 과거 맥락으로
유지하며, 활성 비교는 위의 현재 목록이 소유합니다.

| | certpp | OpenSSL | certpp는 |
|---|---|---|---|
| SHA-256, 64 KiB | 1524 MiB/s | 1550 MiB/s | 0.98배 |
| SHA-1, 64 KiB | 1678 MiB/s | 1773 MiB/s | 0.95배 |
| MD5, 64 KiB | 673 MiB/s | 790 MiB/s | 0.85배 |
| SHA3-256, 64 KiB | 370 MiB/s | 400 MiB/s | 0.93배 |
| SHAKE-256, 64 KiB | 363 MiB/s | 392 MiB/s | 0.93배 |
| SHA-512, 64 KiB | 385 MiB/s | 655 MiB/s | 0.58배 |
| AES-256-CBC, 64 KiB | 1249 MiB/s | 1350 MiB/s | 0.93배 |
| ARIA-256-CBC, 64 KiB | 26 MiB/s | 101 MiB/s | 0.26배 |

SHA-256이 동률인 것은 양쪽이 모두 같은 SHA-NI를 부르기 때문입니다. 과거 SHA-512
행은 위의 현재 비교로 대체되었습니다. BMI2 RORX와 순환 스케줄이 격차를 줄였지만
결과는 아직 활성 목표보다 낮습니다.

**각 격차가 실제로 무엇인지, 어떤 것들이 왜 닫혔는지, 닫히지 않은 것들의 분해는
[`docs/PLANS.ko.md`](../PLANS.ko.md)에 있습니다** — 이 섹션의 커버리지가 찾아낸
크로스 툴체인 격차 둘(DSA-2048과 GF(2^m) 곡선), 느린 행들이 의미하는 것, 그리고
GCC 열에 대한 WSL2 주의사항과 함께.

### 서명

| | MSVC | GCC |
|---|---|---|
| RSA-2048 sign | **5.619 ms** | 5.250 ms |
| RSA-2048 verify | 0.143 ms | **0.150 ms** |
| DSA-2048 sign | 2.695 ms | **7.292 ms** |
| DSA-2048 verify | 6.581 ms | **18.069 ms** |
| Ed25519 sign | 0.198 ms | **0.201 ms** |
| Ed25519 verify | **0.873 ms** | 0.702 ms |
| Ed448 sign | **2.527 ms** | 2.499 ms |
| Ed448 verify | 10.661 ms | **10.758 ms** |
| ECDSA P-192 sign | **0.580 ms** | 0.520 ms |
| ECDSA P-192 verify | **1.448 ms** | 1.308 ms |
| ECDSA P-224 sign | **0.755 ms** | 0.670 ms |
| ECDSA P-224 verify | **1.945 ms** | 1.774 ms |
| ECDSA P-256 sign | **0.908 ms** | 0.862 ms |
| ECDSA P-256 verify | **2.428 ms** | 2.379 ms |
| ECDSA P-384 sign | **2.026 ms** | 2.016 ms |
| ECDSA P-384 verify | **5.694 ms** | 5.523 ms |
| ECDSA P-521 sign | **4.737 ms** | 4.379 ms |
| ECDSA P-521 verify | **13.545 ms** | 12.464 ms |
| ECDSA secp256k1 sign | **0.901 ms** | 0.843 ms |
| ECDSA secp256k1 verify | **2.435 ms** | 2.285 ms |
| Brainpool-160r1 sign | **0.462 ms** | 0.385 ms |
| Brainpool-160r1 verify | **1.078 ms** | 1.002 ms |
| Brainpool-192r1 sign | **0.569 ms** | 0.523 ms |
| Brainpool-192r1 verify | **1.407 ms** | 1.398 ms |
| Brainpool-224r1 sign | **0.705 ms** | 0.694 ms |
| Brainpool-224r1 verify | 1.888 ms | **1.980 ms** |
| Brainpool-256r1 sign | **0.919 ms** | 0.890 ms |
| Brainpool-256r1 verify | 2.412 ms | **2.415 ms** |
| Brainpool-320r1 sign | **1.412 ms** | 1.402 ms |
| Brainpool-320r1 verify | **3.741 ms** | 3.678 ms |
| Brainpool-384r1 sign | 2.004 ms | **2.186 ms** |
| Brainpool-384r1 verify | 5.369 ms | **5.908 ms** |
| Brainpool-512r1 sign | 4.007 ms | **4.314 ms** |
| Brainpool-512r1 verify | 11.341 ms | **11.553 ms** |
| Brainpool-160t1 sign | **0.412 ms** | 0.388 ms |
| Brainpool-160t1 verify | **1.074 ms** | 1.029 ms |
| Brainpool-192t1 sign | **0.546 ms** | 0.522 ms |
| Brainpool-192t1 verify | 1.361 ms | **1.381 ms** |
| Brainpool-224t1 sign | 0.708 ms | **0.712 ms** |
| Brainpool-224t1 verify | 1.851 ms | **1.918 ms** |
| Brainpool-256t1 sign | **0.903 ms** | 0.879 ms |
| Brainpool-256t1 verify | **2.414 ms** | 2.360 ms |
| Brainpool-320t1 sign | **1.400 ms** | 1.391 ms |
| Brainpool-320t1 verify | 3.815 ms | **3.887 ms** |
| Brainpool-384t1 sign | 2.086 ms | **2.147 ms** |
| Brainpool-384t1 verify | 5.484 ms | **5.902 ms** |
| Brainpool-512t1 sign | 4.086 ms | **4.166 ms** |
| Brainpool-512t1 verify | 11.223 ms | **11.557 ms** |
| ECDSA B-163 sign | 0.527 ms | **0.635 ms** |
| ECDSA B-163 verify | 1.760 ms | **2.282 ms** |
| ECDSA K-163 sign | 0.493 ms | **0.595 ms** |
| ECDSA K-163 verify | 1.681 ms | **2.214 ms** |
| ECDSA B-233 sign | 0.596 ms | **0.895 ms** |
| ECDSA B-233 verify | 1.983 ms | **3.296 ms** |
| ECDSA K-233 sign | 0.564 ms | **0.846 ms** |
| ECDSA K-233 verify | 1.971 ms | **3.023 ms** |
| ECDSA B-283 sign | 0.935 ms | **1.421 ms** |
| ECDSA B-283 verify | 3.112 ms | **5.049 ms** |
| ECDSA K-283 sign | 0.863 ms | **1.342 ms** |
| ECDSA K-283 verify | 2.910 ms | **4.731 ms** |
| ECDSA B-409 sign | 1.223 ms | **2.588 ms** |
| ECDSA B-409 verify | 4.057 ms | **9.392 ms** |
| ECDSA K-409 sign | 1.151 ms | **2.314 ms** |
| ECDSA K-409 verify | 3.834 ms | **8.651 ms** |
| ECDSA B-571 sign | 2.358 ms | **5.303 ms** |
| ECDSA B-571 verify | 7.586 ms | **19.857 ms** |
| ECDSA K-571 sign | 2.057 ms | **4.888 ms** |
| ECDSA K-571 verify | 7.161 ms | **18.295 ms** |
| GOST-256 Test sign | **0.822 ms** | 0.783 ms |
| GOST-256 Test verify | **2.372 ms** | 2.245 ms |
| GOST-256 A sign | 0.819 ms | **0.866 ms** |
| GOST-256 A verify | **2.495 ms** | 2.271 ms |
| GOST-256 B sign | **0.845 ms** | 0.816 ms |
| GOST-256 B verify | **2.391 ms** | 2.377 ms |
| GOST-256 C sign | **0.843 ms** | 0.794 ms |
| GOST-256 C verify | **2.325 ms** | 2.282 ms |
| GOST-256 D sign | 0.804 ms | **0.914 ms** |
| GOST-256 D verify | 2.370 ms | **2.381 ms** |
| GOST-512 Test sign | 3.820 ms | **3.949 ms** |
| GOST-512 Test verify | 11.152 ms | **11.435 ms** |
| GOST-512 A sign | **3.865 ms** | 3.829 ms |
| GOST-512 A verify | **12.447 ms** | 11.206 ms |
| GOST-512 B sign | **3.878 ms** | 3.817 ms |
| GOST-512 B verify | **11.184 ms** | 11.047 ms |
| GOST-512 C sign | **3.856 ms** | 3.806 ms |
| GOST-512 C verify | **11.117 ms** | 11.049 ms |
| ML-DSA-44 sign | 1.045 ms | **1.194 ms** |
| ML-DSA-44 verify | **0.346 ms** | 0.290 ms |
| ML-DSA-65 sign | 1.528 ms | **2.218 ms** |
| ML-DSA-65 verify | **0.565 ms** | 0.450 ms |
| ML-DSA-87 sign | **2.417 ms** | 2.232 ms |
| ML-DSA-87 verify | **0.903 ms** | 0.691 ms |

### 키 합의와 KEM

| | MSVC | GCC |
|---|---|---|
| X25519 keygen | **0.328 ms** | 0.284 ms |
| X25519 derive | **0.165 ms** | 0.156 ms |
| ECDH P-192 keygen | **1.722 ms** | 1.675 ms |
| ECDH P-192 derive | 0.796 ms | **0.805 ms** |
| ECDH P-224 keygen | 2.296 ms | **2.323 ms** |
| ECDH P-224 derive | 1.063 ms | **1.070 ms** |
| ECDH P-256 keygen | **3.066 ms** | 3.022 ms |
| ECDH P-256 derive | **1.390 ms** | 1.361 ms |
| ECDH P-384 keygen | 6.937 ms | **7.019 ms** |
| ECDH P-384 derive | 3.343 ms | **3.407 ms** |
| ECDH P-521 keygen | **16.959 ms** | 16.325 ms |
| ECDH P-521 derive | **8.059 ms** | 7.784 ms |
| ECDH secp256k1 keygen | **2.913 ms** | 2.892 ms |
| ECDH secp256k1 derive | 1.357 ms | **1.396 ms** |
| ECDH bp160r1 keygen | 1.253 ms | **1.320 ms** |
| ECDH bp160r1 derive | **0.596 ms** | 0.581 ms |
| ECDH bp192r1 keygen | 1.691 ms | **1.771 ms** |
| ECDH bp192r1 derive | **0.809 ms** | 0.793 ms |
| ECDH bp224r1 keygen | 2.255 ms | **2.426 ms** |
| ECDH bp224r1 derive | 1.096 ms | **1.182 ms** |
| ECDH bp256r1 keygen | 2.943 ms | **3.040 ms** |
| ECDH bp256r1 derive | 1.387 ms | **1.410 ms** |
| ECDH bp320r1 keygen | **5.773 ms** | 4.708 ms |
| ECDH bp320r1 derive | **2.610 ms** | 2.221 ms |
| ECDH bp384r1 keygen | 6.842 ms | **7.326 ms** |
| ECDH bp384r1 derive | 3.342 ms | **3.429 ms** |
| ECDH bp512r1 keygen | 14.789 ms | **16.070 ms** |
| ECDH bp512r1 derive | 6.868 ms | **7.252 ms** |
| ECDH bp160t1 keygen | **1.419 ms** | 1.370 ms |
| ECDH bp160t1 derive | **0.750 ms** | 0.586 ms |
| ECDH bp192t1 keygen | **2.450 ms** | 1.759 ms |
| ECDH bp192t1 derive | **0.834 ms** | 0.812 ms |
| ECDH bp224t1 keygen | **2.520 ms** | 2.411 ms |
| ECDH bp224t1 derive | 1.055 ms | **1.136 ms** |
| ECDH bp256t1 keygen | 2.973 ms | **3.108 ms** |
| ECDH bp256t1 derive | 1.374 ms | **1.438 ms** |
| ECDH bp320t1 keygen | 4.642 ms | **4.726 ms** |
| ECDH bp320t1 derive | 2.147 ms | **2.203 ms** |
| ECDH bp384t1 keygen | 6.873 ms | **7.339 ms** |
| ECDH bp384t1 derive | 3.308 ms | **3.449 ms** |
| ECDH bp512t1 keygen | 14.437 ms | **15.295 ms** |
| ECDH bp512t1 derive | 6.696 ms | **7.113 ms** |
| ECDH B-163 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-163 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-233 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-233 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-283 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-283 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-409 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-409 | (agreement unsupported) | (agreement unsupported) |
| ECDH B-571 | (agreement unsupported) | (agreement unsupported) |
| ECDH K-571 | (agreement unsupported) | (agreement unsupported) |
| ML-KEM-512 keygen | **0.124 ms** | 0.094 ms |
| ML-KEM-512 encapsulate | **0.101 ms** | 0.079 ms |
| ML-KEM-512 decapsulate | **0.114 ms** | 0.096 ms |
| ML-KEM-768 keygen | **0.194 ms** | 0.145 ms |
| ML-KEM-768 encapsulate | **0.158 ms** | 0.124 ms |
| ML-KEM-768 decapsulate | **0.183 ms** | 0.138 ms |
| ML-KEM-1024 keygen | **0.290 ms** | 0.216 ms |
| ML-KEM-1024 encapsulate | **0.236 ms** | 0.176 ms |
| ML-KEM-1024 decapsulate | **0.275 ms** | 0.190 ms |

### 해시, 64 KiB

| | MSVC | GCC |
|---|---|---|
| MD4 | **788.4 MiB/s** | 722.5 MiB/s |
| MD5 | 572.5 MiB/s | **716.2 MiB/s** |
| SHA-1 | **1782.1 MiB/s** | 1768.9 MiB/s |
| SHA-224 | **1552.2 MiB/s** | 1544.4 MiB/s |
| SHA-256 | **1556.5 MiB/s** | 1438.9 MiB/s |
| SHA-384 | 349.2 MiB/s | **361.3 MiB/s** |
| SHA-512 | 385 MiB/s | **361 MiB/s** |
| SHA3-256 | 107.7 MiB/s | **309.4 MiB/s** |
| SHA3-512 | 57.0 MiB/s | **163.6 MiB/s** |
| SHAKE-128 | 132.9 MiB/s | **381.3 MiB/s** |
| SHAKE-256 | 104.6 MiB/s | **309.7 MiB/s** |
| BLAKE2s | 410.6 MiB/s | **417.1 MiB/s** |
| Streebog-256 | 74.7 MiB/s | **107.3 MiB/s** |
| Streebog-512 | 71.5 MiB/s | **108.3 MiB/s** |

### 블록 암호, CBC, 64 KiB

| | MSVC | GCC |
|---|---|---|
| AES-128-CBC | 1442.4 MiB/s | **1717.9 MiB/s** |
| AES-192-CBC | 1234.9 MiB/s | **1515.3 MiB/s** |
| AES-256-CBC | 1111.9 MiB/s | **1319.9 MiB/s** |
| DES-CBC | **9.1 MiB/s** | 5.1 MiB/s |
| 3DES-CBC | **3.0 MiB/s** | 1.7 MiB/s |
| ARIA-128-CBC | **58.1 MiB/s** | 38.3 MiB/s |
| ARIA-192-CBC | **51.8 MiB/s** | 33.1 MiB/s |
| ARIA-256-CBC | **45.3 MiB/s** | 28.4 MiB/s |

### AEAD seal, 64 KiB

| | MSVC | GCC | MSVC/GCC |
|---|---|---|---|
| ChaCha20-Poly1305 | **999 MiB/s** | 835 MiB/s | 1.20x |
| XChaCha20-Poly1305 | **1005 MiB/s** | 840 MiB/s | 1.20x |
| AES-256-GCM | **520 MiB/s** | 465 MiB/s | 1.12x |

### AEAD seal, 64 B, 레코드당

| | MSVC | GCC | MSVC/GCC |
|---|---|---|---|
| ChaCha20-Poly1305 | **400 ns** | 330 ns | 1.21x |
| XChaCha20-Poly1305 | 400 ns | **450 ns** | 0.89x |
| AES-256-GCM | 215 ns | **235 ns** | 0.91x |


GCC 수치는 **WSL2 아래**에서 얻었습니다 — 베어 메탈이 아니라 VM 안의 실제 Linux
커널 — 이므로 그 열은 일반 Linux가 아니라 *이 설정의 이 툴체인*으로 읽어야 합니다.
하네스는 단일 스레드이고 CPU에 묶여 있으므로 하이퍼바이저의 몫은 작아야 하지만, 이
실행은 어느 쪽으로도 정량화하지 않았습니다. 그리고 "Release"는 하나의 설정이
아닙니다: CMake 기본값은 MSVC는 `/O2`, GCC는 `-O3`이므로, 툴체인과 최적화 수준이
함께 바뀝니다.
