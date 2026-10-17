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
가속합니다. 이어 RSA와 DSA 상호운용 비교를 추가했습니다. Montgomery 기반 소수
판정, sliding-window 지수승, 결합 DSA 검증은 첫 직접 측정 대비 RSA 키 생성/서명을
약 5.7배/1.3배, DSA 키 생성/서명/검증을 약 3.7배/3.4배/5.5배 줄였습니다. 시험한
OpenSSL provider는 GOST 서명을 제공하지 않습니다. 이어 edwards448 전용 배가,
공개 부분군 검사 window, 결합 `S*B - k*A` 검증을 적용해 비밀 스칼라 ladder를
유지하면서 Ed448 검증 중앙 지연시간을 11.454에서 6.055 ms로 줄였습니다. X25519
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
