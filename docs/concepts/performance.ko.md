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

## 현재 하드웨어 가속 확인

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

## OpenSSL과 비교

숫자는 혼자서는 아무 뜻이 없으므로, 같은 알고리즘을 같은 머신에서 OpenSSL 3.0.13과
비교해 측정했습니다.

**양쪽 모두 단독으로, 각자의 루프에서 측정했습니다.** 두 구현을 한 루프에서 번갈아
돌리는 것은 — 공정을 지키는 뻔한 방법처럼 보이지만 — 알고 보면 둘 다 망칩니다.
certpp의 SHA-256이 1523에서 765 MiB/s로 떨어지고 OpenSSL의 것도 거의 절반으로
떨어집니다. 번갈아 실행하면 캐시와 분기 예측기가 서로를 방해해서, 교차 수치는 암호
연산의 비교가 아니라 측정 방법의 비교가 됩니다. OpenSSL은 이 라이브러리의
래퍼가 아니라 EVP를 직접 호출했는데, 이것은 `certpp`를 통해 오는 호출자가 더할
호출당 할당이 아니라 암호 연산 자체를 측정합니다. 양쪽 모두 먼저 워밍업합니다.
OpenSSL은 생성자를 게으르게 해석해서 64 KiB SHA-256 첫 호출이 워밍업 후
38.9 µs 대비 963 µs가 들므로, 차갑게 비교하면 실속의 4분의 1로 보고됩니다.

각 수치는 조용한 머신에서 하네스를 세 번 실행한 것 중 최선이므로, 단독으로 잰 쪽의
실행 간 편차는 1~3%입니다 — 비율은 성립하지만 단일 실행의 절대값은 그 알고리즘의
속도가 아닙니다.

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
| Ed25519 서명 | 0.163 ms | 0.037 ms | 4.5배 느림 |

SHA-256이 동률인 것은 양쪽이 모두 같은 SHA-NI를 부르기 때문이고, SHA-512의 0.56배는
둘 다 그렇지 못한 가장 분명한 행입니다.

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
