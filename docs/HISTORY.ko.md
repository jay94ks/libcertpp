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
끈 구성은 494.8 MiB/s였습니다. 테스트 프로세스는 이제 Windows 오류 대화상자 없이
assertion과 충돌을 콘솔 진단으로 보냅니다. 자동 CI와 플랫폼 매트릭스는 의도적으로
[로드맵](PLANS.ko.md)에 남겨 두었습니다.

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
