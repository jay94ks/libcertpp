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

### AVX-512 AEAD

16블록 AVX-512F ChaCha20 경로를 추가하고 Poly1305의 AVX-512 벡터 인자 ABI 경계를
없앤 뒤 2026-10-16에 ChaCha20-Poly1305 대용량 결과를 다시 측정했습니다. 이 비교는
같은 i7-11370H 호스트의 Windows에서 MSVC ABI를 대상으로 하는 Clang 22.1.8, Ninja,
Release 빌드를 사용했습니다. [`examples/05_benchmark.cpp`](../../examples/05_benchmark.cpp)의
64 KiB 행을 실행했으며, 두 빌드 모두 그 밖의 하드웨어 가속은 활성화했습니다.

| ChaCha20-Poly1305 seal, 64 KiB | 처리량 | 상대 성능 |
|---|---:|---:|
| AVX-512F ChaCha20 + AVX512-IFMA Poly1305 | **1979.7 MiB/s** | **4.00배** |
| `CERTPP_DISABLE_HWACCEL_AVX512=ON` (AVX2/SSE2 유지) | 494.8 MiB/s | 1.00배 |

이 비교는 두 AVX-512 단계의 합산 효과를 분리합니다. ChaCha20과 Poly1305 각각의
향상분으로 나누지는 않습니다. 아래의 더 큰 표는 기존 전체 MSVC/GCC 교차 툴체인
측정으로 유지합니다. 서로 다른 컴파일러 버전의 결과가 한 열에 섞이지 않도록 측정
조건을 따로 명시했습니다.

### Ed25519 점 연산

같은 Windows/Clang 22.1.8 Release 하네스를, 통합 덧셈을 이용한 배가를 전용 공식으로
교체하고 검증의 공개 스칼라에 window를 적용하며 고정 기저 곱을 mask 기반
signed-radix-16 표로 바꾸기 전후에 실행했습니다.

| 연산 | 이전 | 현재 | 향상 |
|---|---:|---:|---:|
| Ed25519 서명 | 0.153 ms | **0.056 ms** | **2.73배** |
| Ed25519 검증 | 0.675 ms | **0.388 ms** | **1.74배** |

이 값들은 반복 20회 배치 3개 중 가장 빠른 값을 보고하는
[`examples/05_benchmark.cpp`](../../examples/05_benchmark.cpp)의 해당 행입니다. 서명
경로의 고정 기저 점 배가는 256회에서 4회로 줄었고 각 비밀 숫자마다 표의 모든 후보를
스캔합니다. 검증은 엄격한 부분군 검사를 유지하며 공개 값에만 window를 사용합니다.

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

카운터 8개 AES-CTR 처리, 256비트 VAES 단계, 4블록 GHASH 집계를 추가한 뒤 64 KiB
AES-256-GCM 행을 다시 측정했습니다. 카운터 블록은 레지스터에서 구성합니다. 바이트
배열 여덟 개를 만들고 각각 증가시키는 비용이 AES 라운드보다 더 큰 병목이었습니다.
GHASH는 재귀 4단계를 독립적인 carry-less 곱과 한 번의 reduction으로 접습니다. 짧은
레코드는 단일 블록 경로를 유지해 거듭제곱 표 준비 비용을 피합니다.

| 3회 실행 중앙값 | certpp | OpenSSL EVP | certpp / OpenSSL |
|---|---:|---:|---:|
| 변경 전, 64 KiB | 517 MiB/s | 11608 MiB/s | 0.04배 |
| 현재, 64 KiB | **2953 MiB/s** | 10569 MiB/s | **0.28배** |
| 현재, 64바이트 레코드 | 176 ns | **78 ns** | **0.43배** |

certpp 대용량 처리량은 5.71배 높아졌습니다. 현재 세 실행의 비율은 0.28배, 0.24배,
0.29배이며 중앙값은 0.90 목표보다 아직 낮습니다. 가속 경로는 모든 키 크기와 32비트
카운터 carry에서 portable AES와 비교하고, 긴 GHASH 입력은 서로 다른 분할 경계의 직렬
경로와 비교합니다. 가속 및 완전 portable 테스트 빌드가 모두 통과합니다.

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
RSA/DSA 행은 같은 설정 및 워밍업 규칙으로 `--classic-signatures`를 세 번 실행한
결과입니다. 측정 전에 양방향 교차 검증과 변경된 digest 거부를 확인합니다.

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
| RSA-2048 키 생성 | 266.524 ms | 15.088 ms | 0.05배 |
| RSA-2048 서명 | 4.340 ms | 0.260 ms | 0.06배 |
| RSA-2048 검증 | 0.148 ms | 0.016 ms | 0.11배 |
| DSA-2048 키 생성(새 파라미터 포함) | 1392.749 ms | 142.425 ms | 0.10배 |
| DSA-2048 서명 | 2.382 ms | 0.337 ms | 0.14배 |
| DSA-2048 검증 | 3.417 ms | 0.297 ms | 0.09배 |
| GOST R 34.10-2012 |  | 사용 불가 |  |
| Ed25519 서명, 32바이트 메시지 | 0.052 ms | 0.035 ms | 0.65배 |
| Ed25519 검증, 32바이트 메시지 | 0.369 ms | 0.097 ms | 0.26배 |
| ChaCha20-Poly1305 봉인, 64 KiB | 923 MiB/s | 4117 MiB/s | 0.22배 |
| XChaCha20-Poly1305 봉인, 64 KiB |  | 사용 불가 |  |
| AES-256-GCM 봉인, 64 KiB | 2953 MiB/s | 10569 MiB/s | 0.28배 |
| ChaCha20-Poly1305 봉인, 64바이트 레코드 | 363 ns | 255 ns | 0.70배 |
| XChaCha20-Poly1305 봉인, 64바이트 레코드 |  | 사용 불가 |  |
| AES-256-GCM 봉인, 64바이트 레코드 | 176 ns | 78 ns | 0.43배 |
| X25519 키 생성 | 0.139 ms | 0.034 ms | 0.24배 |
| X25519 유도 | 0.136 ms | 0.029 ms | 0.21배 |
| ML-KEM-512 키 생성 | 0.079 ms | 0.032 ms | 0.40배 |
| ML-KEM-512 캡슐화 | 0.063 ms | 0.028 ms | 0.44배 |
| ML-KEM-512 디캡슐화 | 0.067 ms | 0.035 ms | 0.52배 |
| ML-KEM-768 키 생성 | 0.125 ms | 0.047 ms | 0.37배 |
| ML-KEM-768 캡슐화 | 0.094 ms | 0.030 ms | 0.32배 |
| ML-KEM-768 디캡슐화 | 0.100 ms | 0.047 ms | 0.47배 |
| ML-KEM-1024 키 생성 | 0.186 ms | 0.069 ms | 0.37배 |
| ML-KEM-1024 캡슐화 | 0.140 ms | 0.042 ms | 0.30배 |
| ML-KEM-1024 디캡슐화 | 0.143 ms | 0.063 ms | 0.44배 |
| Ed448 서명, 32바이트 메시지 | 2.855 ms | 0.191 ms | 0.08배 |
| Ed448 검증, 32바이트 메시지 | 6.055 ms | 0.183 ms | 0.03배 |
| ML-DSA-44 서명, 32바이트 메시지 | 0.733 ms | 0.523 ms | 0.78배 |
| ML-DSA-44 검증, 32바이트 메시지 | 0.159 ms | 0.118 ms | 0.74배 |
| ML-DSA-65 서명, 32바이트 메시지 | 1.217 ms | 0.883 ms | 0.71배 |
| ML-DSA-65 검증, 32바이트 메시지 | 0.251 ms | 0.181 ms | 0.72배 |
| ML-DSA-87 서명, 32바이트 메시지 | 1.410 ms | 1.024 ms | 0.73배 |
| ML-DSA-87 검증, 32바이트 메시지 | 0.461 ms | 0.287 ms | 0.64배 |

EC 행도 같은 3회 실행 중앙값 방법을 사용합니다. 아래의 압축 표는
`certpp / OpenSSL` 성능 비율을 나타내며 `examples/06_openssl_compare.cpp`가 양쪽의
절대 지연시간을 출력합니다. `CEcdsa2`는 서명만 구현하므로 이진 곡선 ECDH는 사용
불가로 표시합니다.

| 곡선 | 키 생성 | ECDSA 서명 | ECDSA 검증 | ECDH 유도 |
|---|---:|---:|---:|---:|
| P-192 | 0.08배 | 0.22배 | 0.24배 | 0.23배 |
| P-224 | 0.09배 | 0.24배 | 0.25배 | 0.24배 |
| P-256 | <0.01배 | 0.01배 | 0.04배 | 0.03배 |
| P-384 | 0.07배 | 0.22배 | 0.21배 | 0.23배 |
| P-521 | 0.08배 | 0.25배 | 0.22배 | 0.23배 |
| secp256k1 | 0.08배 | 0.23배 | 0.25배 | 0.23배 |
| brainpoolP160r1 | 0.10배 | 0.24배 | 0.27배 | 0.25배 |
| brainpoolP192r1 | 0.08배 | 0.21배 | 0.24배 | 0.21배 |
| brainpoolP224r1 | 0.08배 | 0.23배 | 0.26배 | 0.24배 |
| brainpoolP256r1 | 0.07배 | 0.21배 | 0.25배 | 0.21배 |
| brainpoolP320r1 | 0.08배 | 0.22배 | 0.23배 | 0.22배 |
| brainpoolP384r1 | 0.07배 | 0.22배 | 0.22배 | 0.21배 |
| brainpoolP512r1 | 0.05배 | 0.15배 | 0.16배 | 0.15배 |
| brainpoolP160t1 | 0.09배 | 0.24배 | 0.27배 | 0.24배 |
| brainpoolP192t1 | 0.08배 | 0.21배 | 0.24배 | 0.21배 |
| brainpoolP224t1 | 0.09배 | 0.23배 | 0.25배 | 0.24배 |
| brainpoolP256t1 | 0.07배 | 0.21배 | 0.22배 | 0.22배 |
| brainpoolP320t1 | 0.08배 | 0.22배 | 0.22배 | 0.22배 |
| brainpoolP384t1 | 0.07배 | 0.22배 | 0.21배 | 0.21배 |
| brainpoolP512t1 | 0.05배 | 0.15배 | 0.15배 | 0.15배 |
| B-163 | 0.09배 | 0.34배 | 0.39배 | 사용 불가 |
| K-163 | 0.08배 | 0.35배 | 0.35배 | 사용 불가 |
| B-233 | 0.09배 | 0.38배 | 0.41배 | 사용 불가 |
| K-233 | 0.10배 | 0.39배 | 0.41배 | 사용 불가 |
| B-283 | 0.11배 | 0.43배 | 0.47배 | 사용 불가 |
| K-283 | 0.10배 | 0.45배 | 0.47배 | 사용 불가 |
| B-409 | 0.14배 | 0.61배 | 0.66배 | 사용 불가 |
| K-409 | 0.14배 | 0.62배 | 0.63배 | 사용 불가 |
| B-571 | 0.16배 | 0.74배 | 0.77배 | 사용 불가 |
| K-571 | 0.16배 | 0.72배 | 0.76배 | 사용 불가 |

ECDSA와 GOST 검증은 이제 private-scalar ladder 두 개와 아핀 덧셈 대신 공개 스칼라용
`linearCombination()` 하나를 사용합니다. 대표적인 certpp 검증 지연시간은 P-256에서
3.171→1.315 ms, P-521에서 15.847→6.776 ms, B-571에서 7.648→4.048 ms,
K-571에서 7.270→3.745 ms로 줄었습니다. 두 검증 스칼라는 모두 공개값이므로 새 연산은
의도적으로 variable-time입니다. 서명, 키 생성, ECDH는 기존 private-scalar 경로를 계속
사용합니다.

Ed448 검증은 이제 untwisted Edwards 전용 배가 공식, 부분군 검사용 공개 4비트 window,
그리고 `S*B - k*A`를 위한 공개 스칼라 Straus loop 하나를 사용합니다. 전체 하네스를
세 번 실행한 certpp 검증 지연시간은 7.433, 6.055, 5.994 ms였고, 중앙값 6.055 ms는
이전 11.454 ms 행보다 약 47% 낮습니다. 실행별 OpenSSL 대비 비율 중앙값은 0.02배에서
0.03배로 올랐습니다. RFC 8032 TEST 1과 잘못된 점, 항등원 점, 변경된 메시지·서명,
다른 키 네거티브 검사는 계속 통과합니다. window와 Straus 분기는 공개된 위수, 서명
스칼라, challenge hash만 처리하며 개인 스칼라 곱은 기존 ladder를 유지합니다.

X25519 키 생성은 새로 유도한 공개값에 cofactor를 곱하던 두 번째 255단계 ladder를
더는 실행하지 않습니다. 개인 스칼라는 표준 기준점과 곱하기 전에 8의 배수로
clamp되므로 결과는 이미 소수 위수 부분군에 있고, 유지한 전부 0 검사가 유도 결과의
유일한 잘못된 경우를 다룹니다. 세 번의 대상 비교에서 certpp 키 생성은 0.136,
0.141, 0.139 ms였고 실행별 OpenSSL 비율은 0.24배, 0.24배, 0.25배였습니다. 중앙값
0.139 ms는 이전 0.270 ms 행보다 약 49% 낮습니다. RFC 7748 벡터와 낮은 위수 상대
거부 테스트는 계속 통과합니다.

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
지수 두 개를 결합해 현재 3회 중앙값을 위 수치까지 줄였습니다. 키 생성은 무작위 소수
후보를 얼마나 빨리 찾는지에 따라 편차가 있지만, 반복 서명과 검증의 개선은 안정적입니다.
남은 격차는 [성능 로드맵](../roadmap/performance.ko.md#openssl-90-프로그램)이 추적합니다.

### 현재 Ed25519 비교

위 점 연산 최적화 뒤 2026-10-16에 Ed25519 행을 다시 측정했습니다. MSYS2 MinGW64의
GCC 16.2.0과 OpenSSL 3.6.4를 사용하는 네이티브 Windows Release 빌드입니다. 전체
하네스를 세 번 실행했고, 각 실행은 워밍업 뒤 양쪽을 독립적으로 측정하여 연산 200회
배치 다섯 개 중 가장 빠른 값을 택했습니다.

| 연산 | certpp | OpenSSL EVP | certpp / OpenSSL 성능 |
|---|---:|---:|---:|
| Ed25519 서명, 32바이트 메시지 | 0.059 ms | **0.040 ms** | **0.67배** |
| Ed25519 검증, 32바이트 메시지 | 0.430 ms | **0.107 ms** | **0.25배** |

세 실행의 certpp/OpenSSL 지연시간 비율은 서명이 1.46배, 1.49배, 1.42배였고,
검증은 3.97배, 3.99배, 4.03배였습니다. OpenSSL의 지연시간이 여전히 낮지만,
현재의 동일 세션 서명 비교는
이전 4.5배 행보다 훨씬 가까워졌습니다. 예전 결과는 컴파일러와 OpenSSL 세션이
다르므로, 비율 변화는 현재 격차를 보여 주지만 전체 향상을 특정 컴파일러 효과와
분리해 설명하지는 않습니다. 검증 행은 고립된 군 방정식 벤치마크가 아니라 API의
종단 간 동작입니다. certpp는 서명 방정식 검사에 더해 서명 점에 대한 엄격한 전체
`L·R` 부분군 검사를 유지합니다.

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
