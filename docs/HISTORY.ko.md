# 프로젝트 변경 이력

[English](HISTORY.md)

이 저장소의 git 역사는 늦게 시작합니다. 최초 소스 커밋까지의 모든 것이 커밋되지
않은 작업 트리 상태로 개발되었으므로, `git log`는 그중 무엇이 어떻게 생겨났는지
아무것도 말해 주지 않습니다. 이 파일이 대신 그 기록이며, 역사보다 앞서는 작업의
(그리고 커밋 메시지가 너무 짧게만 말한 것의) 근거를 찾을 곳으로 남아 있습니다.
각 장은 프로젝트의 발전 순서를 따릅니다. 라이브러리가 *지금* 어떤 모습인지는
[`docs/CONCEPTS.ko.md`](CONCEPTS.ko.md)를 보십시오. 이 변경 이력은 그 모습에
이르기까지의 과정을 설명합니다.

## 최근 신뢰성과 통합 계획

1.1.0 작업은 이력을 더 잘게 나누지 않고 하나의 연속된 계획으로 완료했습니다.
명시적인 신뢰 저장소를 쓰는 X.509 경로 validator, sanitizer를 적용한 파서 퍼저
다섯 개, mask 기반 소수 곡선 ladder 교환과 ML-DSA 타이밍 검토 도구, 소유형 출력
overload와 중앙 생성 정책, RFC 9215 GOST 인증서/CSR·RFC 9558 DNSSEC 알고리즘
23·RFC 9935 ML-KEM SPKI 지원, SemVer/ABI 계약과 설치 패키지 소비자 테스트를
추가했습니다. 새 wire format은 공개 RFC 산출물과 잘못된 입력으로 검증합니다.
후속 하드웨어 작업에서는 16블록 AVX-512F ChaCha20 경로를 추가하고, 기존 가속
경로가 Clang의 Windows ABI에서도 컴파일되게 했으며, GFNI 기능 감지를 바로잡고,
Poly1305의 AVX-512 벡터 인자 ABI 경계를 없앴습니다. 검토 장비의 64 KiB record에서
완전한 AVX-512 ChaCha20-Poly1305 경로는 1979.7 MiB/s, 두 AVX-512 단계를 모두
끈 구성은 494.8 MiB/s였습니다. 이어 OpenSSL 3.6 비교 프로그램을 전체 해시/CBC
목록과 AEAD, X25519, ML-KEM, EdDSA, ML-DSA까지 확장했습니다. 순환 SHA-512
스케줄과 회전된 라운드 인자는 중앙 처리량을 36% 높였고, 병렬 AES-CTR, VAES,
4블록 GHASH는 짧은 레코드 경로를 보존하면서 64 KiB AES-256-GCM을 517에서
2953 MiB/s로 높였습니다. 이어 OpenSSL 목록을 소수체 ECDSA/ECDH 곡선 20개와 이진
ECDSA 곡선 10개 모두로 확장했습니다. 공개 스칼라 동시 곱은 대표 소수 곡선 ECDSA 검증을 약
2.3배, 이진 곡선 검증을 약 1.9--2.0배 줄였고 같은 소수체 경로가 GOST 검증도
가속합니다. 이어 스택 상주 고정 폭 Montgomery 체, 전체 스캔 private window, 공개 검증용
signed window, 고정 기저 comb 표가 소수체 키 생성·서명·검증·ECDH 80개 행 중 72개를
먼저 OpenSSL의 0.90배 이상으로 높였습니다. 이어 고정 count 체 kernel과 키 바인딩 폭 6
affine 검증 표가 P-256 이외의 모든 행을 문턱 위로 높였습니다. 압축한 7비트 P-256 기저
표, 한쪽 방향 mask 선택, Montgomery limb를 직접 보관하는 폭 8 검증 표가 P-256의 5회
키 생성/서명/검증/ECDH 비율을 0.403/0.345/0.315/0.302배에서
0.614/0.434/0.361/0.318배로 높였습니다. 이어 고정 폭 체 선택기와 희소 P-256 곱셈을
점 공식 안으로 강제 inline하여 단일 CPU 15회 지연시간을 5.2--15.6% 줄였고 비율은
0.797/0.477/0.406/0.322배가 됐습니다. 이어 위치별 4비트 P-256 공개 검증 comb가 점 배가
256회를 제거했습니다. 기저 표는 프로세스 전체에서 공유하고 각 바인딩 공개키는 60 KiB 표
하나를 보관합니다. 21회 교대 실행에서 검증은 0.142 ms에서 0.058 ms로 줄었고 OpenSSL
비율은 0.999배가 됐습니다. 이어 AVX-512F private comb 선택기가 64바이트 affine 항목을
모두 읽고 mask로 요청한 점을 남겨 전체 행 스캔을 보존하면서 직전 바이너리보다 키 생성과
서명을 15.8%와 8.3% 개선했습니다. 비교 하네스는 이제 양쪽을 준비한 뒤 독립 batch 순서를
번갈아 실행합니다. batch마다 1,000회 연산하고 단일 CPU에서 7회 실행한 P-256
키 생성/서명/검증/ECDH 중앙 비율은 0.838/0.497/1.007/0.322배였습니다. 소수체 80개 중
당시 77개 행이 통과했습니다. 이어 unsigned 7비트 기저 comb를 33행 signed radix-256으로
바꾸어 표를 약 296 KiB에서 266 KiB로, 예상 mixed 덧셈을 36.7회에서 32.4회로 줄였습니다.
변경 전후를 7회 번갈아 실행한 certpp 키 생성/서명 중앙값은 0.027/0.039 ms에서
0.025/0.037 ms로 줄었고 현재 OpenSSL 비율은 0.959/0.535/0.971/0.311배입니다. 키 생성도
통과해 소수체 통과 행은 80개 중 78개가 됐습니다.
이어 현재 P-256 ECDH peer를 위해 context에 캐시한 위치별 4비트 comb가 점 배가 256회와 일반
덧셈 64회를 private digit마다 후보 15개를 모두 스캔하는 mixed 덧셈 64회로 바꿨습니다.
변경 전후를 7회 번갈아 실행한 certpp 반복 유도는 0.140 ms에서 0.039 ms로 줄었고 OpenSSL
비율은 0.315배에서 1.164배로 높아졌습니다. 현재 P-256 비율은
0.959/0.543/0.994/1.164배이므로 소수체 80개 중 79개 행이 통과하고 서명만 남았습니다.
이어 반복 서명 P-256 context는 일반 one-shot 첫 서명을 보존한 뒤 무작위 nonce 8개를 함께
준비하기 시작했습니다. Batch normalization이 projective `k*G` 좌표의 field 역원 하나를
공유하고 Montgomery batch 방식이 `k^-1` 값들의 order 역원 하나를 공유합니다. 쓰지 않은
비밀 역원은 키 reset과 context 파괴 시 안전하게 지웁니다. 단일 CPU에서 변경 전후를 7회
번갈아 실행한 반복 서명 중앙값은 0.037 ms에서 0.020 ms로 줄었고 OpenSSL 비율은
0.531배에서 0.990배로 높아졌습니다. 갱신한 키 생성/서명/검증/ECDH 중앙값은
0.980/0.990/0.983/1.168배이므로 소수체 80개 행이 모두 통과합니다.
이어 고정 count PCLMUL 곱·제곱 kernel과 높은 word부터 접는 축약이 공유 GF(2^m)
병목을 제거했습니다. 혼합 Lopez-Dahab 덧셈과 방금 생성한 키의 중복 검증 제거까지
적용해 이진 곡선 키 생성/서명/검증 30개 행 모두 OpenSSL 문턱을 넘었고, 단일 코어 고정
5회 중앙값은 1.12--1.83배입니다. 이어 RSA와 DSA 상호운용 비교를 추가했습니다. Montgomery 기반 소수
판정, sliding-window 지수승, 결합 DSA 검증은 첫 직접 측정 대비 RSA 키 생성/서명을
약 5.7배/1.3배, DSA 키 생성/서명/검증을 약 3.7배/3.4배/5.5배 줄였습니다. 시험한
OpenSSL provider는 GOST 서명을 제공하지 않습니다. 이어 각 RSA 키의 공개 modulus context를
캐시하고 짧은 공개 지수를 하나의 packed 64비트 Montgomery 체인에 유지해, Windows에서
한 코어에 고정한 RSA 검증을 OpenSSL의 0.11배에서 0.54배로 높였습니다. 이어 긴 지수승과
두 밑수 DSA 검증을 packed 64비트 형식에 유지하고 홀수 모듈러스에 binary 모듈러 역원을
적용해 나머지 연산을 크게 높였습니다. 개인 CRT `p`, `q`의 Montgomery context도 캐시해
서명마다 발생하던 context 설정 나눗셈을 제거했습니다. 이어 통합 CIOS 곱셈과 2비트 동시 DSA window로
새 단일 코어 고정 비율이 키 생성/서명/검증 기준 RSA 0.36/0.27/0.61배, DSA
0.61/0.65/0.48배가 됐으며 CRT fault 검사와 portable fallback을 보존했습니다.
이어 작은 소수 시험 제수를 32비트 곱으로 묶어 고정 2048비트 최악 체 사례의 9회 중앙값을
호출당 86.687마이크로초에서 16.790마이크로초로 줄였습니다. 새 단일 코어 고정 11회 비율은
RSA 0.41/0.27/0.61배, DSA 0.75/0.65/0.48배이며 키 생성 비율에는 무작위 소수 탐색의 큰
편차가 남아 있습니다. 이어 최대 32-way loop 전개를 적용한 별도 16-limb·32-limb CIOS kernel이
RSA 서명/검증을 0.948/0.027 ms에서 0.805/0.025 ms로, DSA 서명/검증을
0.514/0.616 ms에서 0.471/0.558 ms로 줄였습니다. 쌍별 비율은 각각
0.316/0.668배와 0.720/0.535배로 높아졌고 키 생성 비율은 계속 무작위 소수 탐색 편차의
영향이 큽니다.
X25519와 packed Montgomery의 BMI2/ADX gate는 compiler별 기능 문자열 대신 직접 CPUID
검사로 전환했고, X25519는 AVX2 body에 들어가기 전에 OSXSAVE/XCR0도 확인합니다. 이로써
cached dispatch와 portable fallback을 보존하면서 Clang 18에서도 최적화 경로를 빌드할 수
있습니다. 이어 AES VAES dispatch도 같은 방식으로 전환해 AVX2/AVX-512F, VAES 비트와 필요한
XCR0 상태를 직접 해석하므로 전체 가속 빌드도 Clang 18에서 컴파일됩니다. 프로파일은 RSA
전체 비교 self cycle의 35.85%를 16-limb kernel에 귀속했습니다.
명시적인 `_mulx_u64`/`_addcarryx_u64` 재작성은 Montgomery 단언 914,917개를 통과했지만
안정적인 RSA/DSA 연산을 5--8% 늦춰 기각했습니다. 이어 고정 count 제곱 wrapper가 기존 통합
CIOS 산술은 그대로 두고 공유 피연산자를 compiler에 노출했습니다. WSL에서 기준과 변경
바이너리를 번갈아 7회 실행한 RSA 서명/검증과 DSA 서명/검증 중앙값은 2.5--4.2%
개선됐고, 가속 전체 suite와 SIMD 비활성 Montgomery/RSA/DSA 테스트는 같은 응답을
유지했습니다. 이어 DSA 키 바인딩 시 준비하는 위치별 4비트 Montgomery 표가 반복 서명
지수승을 최대 곱 64회로, 검증을 표 평가 두 번과 마지막 곱 한 번으로 바꿨습니다. 서명
선택기는 행마다 0이 아닌 후보 15개를 모두 훑고 공개 검증은 직접 조회합니다. 한 코어 고정
7회 실행에서 DSA 서명/검증 중앙값은 이전 snapshot의 0.471/0.558 ms에서 0.196/0.263 ms로
줄고 OpenSSL의 1.667/1.103배에 도달해 반복 DSA 행을 완료했으며, 무작위 키 생성은 남았습니다.
이어 소수 생성은 후보마다 새로운 전체 폭 값을 뽑아 trial division하지 않습니다. 이제 seed
하나를 뽑아 묶음 작은 소수 나머지를 한 번 계산하고, 그 나머지를 조정하면서 가까운 홀수 후보를
순회한 뒤 기존 20회 Miller--Rabin 판정을 수행합니다. 변경 전 `HEAD` 별도 빌드와 새 바이너리를
각각 WSL Clang 18에서 한 코어에 고정해 15회 측정한 결과 certpp RSA-2048 키 생성 중앙값은
63.937 ms에서 54.471 ms로 14.8% 줄었습니다. 정확한 비트 길이와 probable-prime 검사는 작은
소수 순회 경계의 양쪽을 모두 다룹니다.
이어 여러 RSA 실험을 측정하고 기각했습니다. AVX-512 IFMA full-product Montgomery 시제품은
RSA 기지 응답과 단위 테스트를 통과했지만 scratch product 메모리 접근 비용이 더 적은 곱셈 수를
상쇄해 서명을 약 0.8 ms에서 4.0 ms로, 검증을 약 0.024 ms에서 0.105 ms로 늦췄습니다. 두 CRT
지수승을 `std::async`로 실행하는 방법은 단일 CPU 기준에서 손해였고, CRT 재결합을 캐시한
Montgomery context로 보내는 방법은 기존 나눗셈 경로보다 약 4% 느렸으며, 긴 지수의 6비트
window도 5비트 기준을 개선하지 못했습니다.
채택한 다음 변경은 통합 CIOS를 유지하면서 두 1024비트 RSA CRT branch를 하나의 고정 5비트
schedule로 함께 진행합니다. paired kernel이 한 thread에서 서로 독립인 product·reduction carry
chain을 교차 배치합니다. WSL Clang 18에서 한 코어에 고정해 변경 전후를 번갈아 15회 실행한 결과
RSA-2048 서명 중앙값은 0.811에서 0.772 ms로 4.8% 줄었고 OpenSSL 대비 비율 중앙값은
0.324배였습니다. KAT, RSA 단위 테스트, Montgomery 단언 914,917개, SIMD 비활성 fallback은
같은 결과를 유지했습니다.
이어 짧은 지수 chain의 마지막 홀수 base 곱과 Montgomery domain 이탈을 합쳤습니다. 마지막
Montgomery residue에 ordinary-domain base를 곱하면 ordinary 결과가 바로 나옵니다. 한 코어에
고정한 11회 교대 실행에서 RSA-2048 검증 중앙값은 0.024에서 0.023 ms로 줄었고 OpenSSL 비율
중앙값은 0.640배에서 0.676배로 올랐습니다. 같은 재암호화를 CRT fault 검사에 쓰는 서명도
0.793에서 0.782 ms로 줄었습니다. 별도 7회 현재 snapshot의 서명/검증 비율은
0.328/0.673배였고 같은 Montgomery·RSA 검사를 통과했습니다.
이어 DSA 파라미터 생성은 제한된 `p += 2q` 진행식을 순회하면서 새로운 2048비트 후보를
매번 뽑아 나누는 대신 묶음 작은 소수 나머지를 재사용합니다. 컴파일 시 생성하는 sieve는
4096 미만 소수를 다루고, 채택한 `p`로 만든 Montgomery context는 생성자 구성, 공개키 유도,
두 키 객체, 생성 키 검증에서 재사용합니다. 생성의 Miller--Rabin 20회와 독립적인 키 검사의
20회는 그대로입니다. 변경 전/현재 바이너리를 번갈아 실행한 WSL 21회에서 certpp 중앙값은
225.673 ms에서 178.276 ms로 21.0% 줄었습니다. 현재 바이너리 추가 15회의 중앙값은
158.894 ms였고, 현재 표본 36개 전체의 certpp 중앙값은 164.646 ms, OpenSSL 대비 실행별 비율
중앙값은 0.9015배였습니다. 2048과 8192 상한은 15회 중앙값이 각각 187.664와 204.667 ms로,
4096의 대응 중앙값 158.894와 171.999 ms보다 느려 기각했습니다. Miller--Rabin 결과를
Montgomery 형식에 유지하는 실험도 고정 RFC 3526 소수에서 0.3%만 줄어 기각했습니다. 이
무작위 행은 계속 재측정에 민감합니다. 다음 RSA 산술 방향은 생성한 ADCX/ADOX dual-carry
kernel입니다.
이어 더 좁은 RSA kernel 실험 네 가지로 생성 kernel이 피해야 할 형태를 확인했습니다. inline
assembly 열마다 CF/OF를 초기화한 경로는 검증 중앙값을 0.023 ms에서 0.032 ms로 늦췄습니다.
통합 radix-52 AVX-512 IFMA 시제품은 Montgomery 정답을 유지했지만 scalar carry 정규화와
겹친 vector 접근 비용 때문에 같은 행을 0.044 ms로 늦췄습니다. compiler 전개를 4-limb로
제한한 결과 서명/검증 중앙값은 0.774/0.023 ms에서 0.781/0.024 ms가 됐습니다. 지속되는
dual-carry schedule이 없는 compact 및 완전 전개 BMI2 assembly kernel은 서명을 각각
0.772에서 0.979 ms로, 0.780에서 0.895 ms로 늦췄습니다. 네 경로를 모두 제거했습니다. 유효한
assembly 경로는 limb마다 carry를 정수화하거나 초기화하지 않고 여러 열에 걸쳐 두 ADX flag
chain을 유지해야 합니다.
채택한 다음 변경은 두 1024비트 RSA CRT branch에서 그 구조를 구현합니다. 첫 전체 폭 pass는
scalar product와 accumulator carry를 CF와 OF에 유지하고, reduction pass는 modulus product와
shifted accumulator에 두 flag를 다시 사용합니다. 기존 5비트 paired exponent schedule과 CRT
fault 검사는 그대로입니다. 한 코어에 고정한 11회 교대 실행에서 RSA-2048 서명 중앙값은
0.778에서 0.626 ms로 19.5% 줄었고 OpenSSL 대비 비율 중앙값은 0.330배에서 0.396배로
높아졌습니다.
같은 지속 dual-carry schedule을 일반 고정 폭 Montgomery 경로의 16 및 32 limb에도
적용했습니다. RSA-2048 공개 연산은 전체 폭 kernel을 사용하며, runtime BMI2/ADX dispatch와
기존 portable fallback은 유지됩니다. 한 코어에 고정한 7회 교대 실행에서 검증 중앙값은
0.024에서 0.017 ms로 29.2% 줄고 OpenSSL 대비 비율 중앙값은 0.678배에서 0.913배로
높아졌습니다. 공개 재암호화 검사를 수행하는 개인키 연산의 서명 중앙값도 0.689에서
0.646 ms로 6.2% 줄었습니다.
이어 edwards448 전용 배가,
공개 부분군 검사 window, 결합 `S*B - k*A` 검증을 적용해 Ed448 검증 중앙 지연시간을
먼저 11.454에서 6.055 ms로 줄였습니다. 이어 고정 폭 Fe448 구현과 10열 comb 표로
동일 조건 WSL 비교의 서명/검증을 0.139/0.191 ms까지 줄여 OpenSSL의
1.48/0.99배에 도달했고, portable 16-limb fallback도 MSVC에서 같은 필드·RFC 테스트를
통과했습니다. X25519
키 생성의 중복 유도점 cofactor ladder도 제거해 중앙값을 0.270에서 0.139 ms로
줄였습니다. 테스트 프로세스는 이제 Windows 오류 대화상자 없이 assertion과 충돌을
콘솔 진단으로 보냅니다. 자동 CI와 플랫폼 매트릭스는 의도적으로
[로드맵](PLANS.ko.md)에 남겨 두었습니다. 이어 4-lane SSE2 BLAKE2s 압축 경로가
64 KiB 중앙 처리량을 406에서 512 MiB/s로, 동일 조건 OpenSSL 비율을 0.74에서
0.96으로 높였습니다. SIMD 비활성 scalar 경로도 같은 RFC 및 keyed 참조 응답을
유지했습니다. 이어 압축 kernel을 완전히 전개하고 입력마다 한 번만 dispatch하여 MD4를
OpenSSL의 0.61배에서 0.90배로, MD5를 0.81배에서 0.90배로 높였습니다. MD4는
AVX-512VL ternary logic과 rotate를 사용하고, MD5는 더 느리게 측정된 BMI2 RORX 대신
scalar ROL과 BMI1 ANDN을 사용합니다. 가속 및 SIMD 비활성 기지 응답 테스트는 같은
결과를 유지했습니다.
이어 AVX-512VL SHA-384/SHA-512 경로가 메시지 스케줄 네 개를 함께 생성하고 준비한
블록의 라운드 사슬에서 덧셈 하나를 제거해 OpenSSL 비율을 0.90배와 0.91배로 높였습니다.
AVX-512VL Keccak permutation도 lane 25개를 모두 register에 유지하고 theta와
chi를 ternary logic으로 접었습니다. OpenSSL 대비 5회 중앙값은 SHA3-256 1.40배,
SHA3-512 1.35배, 두 SHAKE 변형 모두 1.38배로 높아졌고 portable permutation도 같은
FIPS 및 독립 참조 응답을 유지했습니다.
이어 안전한 완전 CBC 입력을 AES-NI bulk loop에 직접 넘겨 `CbcTransformer`의 입력 크기
staging 복사와 빈 buffer 할당을 제거했습니다. OpenSSL 대비 7회 중앙값은 AES-128/192-CBC
0.97배, AES-256-CBC 0.98배로 높아졌으며 buffered 겹침과 부분 출력 의미를 유지했습니다.
이어 DES는 비트 단위 라운드 permutation을 생성된 S/P table과 회전 조회 키 워드 두 개로
바꾸고, DES/TripleDES bulk CBC는 chaining을 지역 변수에 유지하며 EDE 단계 사이에 permuted
값을 보존했습니다. DES/2-key TripleDES의 OpenSSL 대비 7회 중앙값은 0.07/0.06배에서
1.04/1.01배로 높아졌고 공개 2-key·3-key 벡터 결과는 그대로 유지됐습니다.
이어 ARIA는 바이트 단위 substitution과 diffusion을 확장 32비트 S-box, word diffusion,
inline CBC bulk loop로 바꿨습니다. 128/192/256비트의 OpenSSL 대비 7회 중앙값은 약
0.31배에서 1.04/1.03/1.03배로 높아졌고 RFC 5794 벡터 결과는 그대로 유지됐습니다.
이어 생성된 Fe25519 제곱, 혼합 precomputed 점 덧셈, 단일 지수승 점 복구, 결합 공개
검증, 공개키별 홀수 배수 표가 Ed25519 서명/검증의 11회 중앙값을 0.94/0.97배로
높였으며 RFC 8032와 저차수 점 검사를 유지했습니다. 이어 5-limb radix-51 경로를 64비트
GCC/Clang 기본값으로 삼고 unsigned loose 범위를 명시적으로 유지하며 X25519 ladder를
flatten하여 동일 조건 WSL 비교에서 Ed25519를 OpenSSL의 1.53/1.28배로, X25519
키 생성/유도를 0.24/0.21배에서 0.77/0.62배로 높였습니다. portable 10-limb 경로는
MSVC 및 네이티브 wide product가 없는 대상의 fallback으로 남아 있습니다. 이후
radix-51 개선은 두 독립 carry chain, 전용 10-product 제곱, 더 짧은 ladder live range,
런타임 AVX2/BMI2/ADX 및 정확한 Tiger Lake tuning, 바인딩 키 cache를 적용했습니다.
논리 processor 하나에 고정한 동일 조건 Windows 실행 15회의 X25519 키 생성/유도 중앙
비율은 OpenSSL 3.6.4 대비 1.035/0.909배였습니다.
이어 ML-KEM은 비트 단위 codec과 CBD 샘플링을 word 단위 경로로 바꾸고, NTT에 제한 범위
Barrett reduction을 사용하며, context에 키를 바인딩할 때 디코드·확장한 키 재료를
준비했습니다. 동일 조건 Windows 비교 7회에서 ML-KEM 키 생성/캡슐화/디캡슐화 9개 행의
중앙값은 OpenSSL 3.6.4의 1.07--1.25배에 도달했고 NIST ACVP와 교차 구현 검사는 같은
결과를 유지했습니다.
이어 ML-DSA는 NTT의 계수별 modular 나눗셈을 고정 modulus Montgomery 곱으로 바꾸고,
비트 패킹을 reservoir로 옮기며, SHAKE 거부 스트림을 rate block 단위로 소비했습니다.
동일 조건 Windows 비교 7회에서 서명/검증 6개 행의 중앙값은 모두 OpenSSL 3.6.4의
1.17--1.38배에 도달했고 공식 서명·검증 벡터와 산술 참조 검사는 같은 결과를 유지했습니다.

## 장별 기록

- [기반 구축과 초기 강화](history/01-foundations.ko.md)
- [감사, 문서화 및 계획](history/02-audit-and-planning.ko.md)
- [검증과 산술 성능](history/03-verification-and-performance.ko.md)
- [ML-KEM 구현](history/04-ml-kem.ko.md)
- [보안 메모리와 ML-DSA 기반](history/05-secure-memory-and-ml-dsa.ko.md)
- [ML-DSA 내부 구조와 이식성](history/06-ml-dsa-and-portability.ko.md)
- [프로토콜 암호 프리미티브](history/07-protocol-primitives.ko.md)
- [Curve25519와 성능](history/08-curve25519-and-performance.ko.md)
- [필드 산술과 AEAD](history/09-field-and-aead.ko.md)
- [GOST와 DNSSEC](history/10-gost-and-dnssec.ko.md)
- [통합과 실제 인증서](history/11-integration-and-certificates.ko.md)
- [Fe25519 기반 Ed25519](history/12-ed25519.ko.md)
- [ML-DSA와 최초의 PQ 인증서](history/13-ml-dsa.ko.md)
- [모듈러 산술과 인증서 요청](history/14-modular-arithmetic-and-csr.ko.md)
- [PEM 인증서 체인](history/15-pem-chains.ko.md)
- [PKCS#12와 PBKDF2](history/16-pkcs12.ko.md)
- [API 공백, 키 검증 및 측정](history/17-api-and-measurement.ko.md)
- [RSA 프로파일링과 Montgomery 산술](history/18-rsa-profiling.ko.md)
- [AES-CBC 레지스터 체이닝](history/19-aes-cbc.ko.md)
- [OID와 정확성 수정](history/20-oids-and-correctness.ko.md)
- [해시와 MAC 최적화](history/21-hash-and-mac-optimization.ko.md)
