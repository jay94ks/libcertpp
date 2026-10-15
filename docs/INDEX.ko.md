# 문서 인덱스

[English](INDEX.md)

이 문서는 저장소에서 유지 보수하는 Markdown 문서의 전체 인덱스입니다. 각 행은
영문 원본과 한국어 짝 문서를 함께 나열합니다. `examples/wiki/snippets/` 아래의
생성된 API 조각, 벤더 문서, 빌드 결과물은 의도적으로 제외합니다.

## 진입점

| 영문 | 한국어 |
| --- | --- |
| [프로젝트 README](../README.md) | [프로젝트 README](../README.ko.md) |
| [기여 가이드](../CONTRIB.md) | [기여 가이드](../CONTRIB.ko.md) |
| [문서 안내](README.md) | [문서 안내](README.ko.md) |
| [문서 인덱스](INDEX.md) | [문서 인덱스](INDEX.ko.md) |

번역 짝이 없는 운영 지침:

- [AI 에이전트 지침](../AGENTS.md)(영문)
- [Claude 호환 진입점](../CLAUDE.md)(영문)

## 상위 유지보수 문서

| 영문 | 한국어 |
| --- | --- |
| [아키텍처와 개념](CONCEPTS.md) | [아키텍처와 개념](CONCEPTS.ko.md) |
| [코딩 규칙](RULES.md) | [코딩 규칙](RULES.ko.md) |
| [빌드와 검증](BUILDING.md) | [빌드와 검증](BUILDING.ko.md) |
| [계획](PLANS.md) | [계획](PLANS.ko.md) |
| [프로젝트 변경 이력](HISTORY.md) | [프로젝트 변경 이력](HISTORY.ko.md) |
| [포스트퀀텀 암호](PQC.md) | [포스트퀀텀 암호](PQC.ko.md) |

## 개념

| 영문 | 한국어 |
| --- | --- |
| [프로젝트 구조](concepts/structure.md) | [프로젝트 구조](concepts/structure.ko.md) |
| [개발 모델](concepts/development.md) | [개발 모델](concepts/development.ko.md) |
| [코어와 유틸리티](concepts/foundations.md) | [코어와 유틸리티](concepts/foundations.ko.md) |
| [I/O와 ASN.1](concepts/data-encoding.md) | [I/O와 ASN.1](concepts/data-encoding.ko.md) |
| [해시와 대칭키 암호](concepts/symmetric.md) | [해시와 대칭키 암호](concepts/symmetric.ko.md) |
| [MAC, KDF, AEAD 및 난수](concepts/protocols.md) | [MAC, KDF, AEAD 및 난수](concepts/protocols.ko.md) |
| [고전 비대칭키 암호](concepts/classical.md) | [고전 비대칭키 암호](concepts/classical.ko.md) |
| [비대칭키 인터페이스와 현대 곡선](concepts/asymmetric.md) | [비대칭키 인터페이스와 현대 곡선](concepts/asymmetric.ko.md) |
| [포스트퀀텀 내부 구조](concepts/post-quantum.md) | [포스트퀀텀 암호 내부 구조](concepts/post-quantum.ko.md) |
| [인증서와 컨테이너](concepts/certificates.md) | [인증서와 컨테이너](concepts/certificates.ko.md) |
| [확장과 폐지](concepts/validation.md) | [확장과 폐지](concepts/validation.ko.md) |
| [범위, 통합 및 DNSSEC](concepts/scope.md) | [범위, 통합 및 DNSSEC](concepts/scope.ko.md) |
| [성능](concepts/performance.md) | [성능](concepts/performance.ko.md) |

## 빌드, 규칙, 계획 및 PQC 세부 문서

| 영문 | 한국어 |
| --- | --- |
| [구성과 설치](building/configuration.md) | [구성과 설치](building/configuration.ko.md) |
| [테스트와 예제](building/verification.md) | [테스트와 예제](building/verification.ko.md) |
| [API 설계 규칙](rules/api.md) | [API 설계 규칙](rules/api.ko.md) |
| [소스와 문서 스타일](rules/style.md) | [소스와 문서 스타일](rules/style.ko.md) |
| [버전 관리와 테스트](rules/maintenance.md) | [버전 관리와 테스트](rules/maintenance.ko.md) |
| [Constant-time 및 성능 로드맵](roadmap/performance.md) | [Constant-time 및 성능 로드맵](roadmap/performance.ko.md) |
| [계획에 없음](roadmap/not-planned.md) | [계획에 없음](roadmap/not-planned.ko.md) |
| [PQC 동기, 표준 및 인터페이스](pqc/design.md) | [PQC 동기, 표준 및 인터페이스](pqc/design.ko.md) |
| [PQC 공유 엔지니어링과 위험](pqc/engineering.md) | [PQC 공유 엔지니어링과 위험](pqc/engineering.ko.md) |
| [남은 PQC 작업](pqc/implementation.md) | [남은 PQC 작업](pqc/implementation.ko.md) |

## 프로젝트 변경 이력 장

| 영문 | 한국어 |
| --- | --- |
| [01. 기반 구축과 초기 강화](history/01-foundations.md) | [01. 기반 구축과 초기 강화](history/01-foundations.ko.md) |
| [02. 감사, 문서화 및 계획](history/02-audit-and-planning.md) | [02. 감사, 문서화 및 계획](history/02-audit-and-planning.ko.md) |
| [03. 검증과 산술 성능](history/03-verification-and-performance.md) | [03. 검증과 산술 성능](history/03-verification-and-performance.ko.md) |
| [04. ML-KEM 구현](history/04-ml-kem.md) | [04. ML-KEM 구현](history/04-ml-kem.ko.md) |
| [05. 보안 메모리와 ML-DSA 기반](history/05-secure-memory-and-ml-dsa.md) | [05. 보안 메모리와 ML-DSA 기반](history/05-secure-memory-and-ml-dsa.ko.md) |
| [06. ML-DSA 내부 구조와 이식성](history/06-ml-dsa-and-portability.md) | [06. ML-DSA 내부 구조와 이식성](history/06-ml-dsa-and-portability.ko.md) |
| [07. 프로토콜 암호 프리미티브](history/07-protocol-primitives.md) | [07. 프로토콜 암호 프리미티브](history/07-protocol-primitives.ko.md) |
| [08. Curve25519와 성능](history/08-curve25519-and-performance.md) | [08. Curve25519와 성능](history/08-curve25519-and-performance.ko.md) |
| [09. 필드 산술과 AEAD](history/09-field-and-aead.md) | [09. 필드 산술과 AEAD](history/09-field-and-aead.ko.md) |
| [10. GOST와 DNSSEC](history/10-gost-and-dnssec.md) | [10. GOST와 DNSSEC](history/10-gost-and-dnssec.ko.md) |
| [11. 통합과 실제 인증서](history/11-integration-and-certificates.md) | [11. 통합과 실제 인증서](history/11-integration-and-certificates.ko.md) |
| [12. Fe25519 기반 Ed25519](history/12-ed25519.md) | [12. Fe25519 기반 Ed25519](history/12-ed25519.ko.md) |
| [13. ML-DSA와 최초의 PQ 인증서](history/13-ml-dsa.md) | [13. ML-DSA와 최초의 PQ 인증서](history/13-ml-dsa.ko.md) |
| [14. 모듈러 산술과 인증서 요청](history/14-modular-arithmetic-and-csr.md) | [14. 모듈러 산술과 인증서 요청](history/14-modular-arithmetic-and-csr.ko.md) |
| [15. PEM 인증서 체인](history/15-pem-chains.md) | [15. PEM 인증서 체인](history/15-pem-chains.ko.md) |
| [16. PKCS#12와 PBKDF2](history/16-pkcs12.md) | [16. PKCS#12와 PBKDF2](history/16-pkcs12.ko.md) |
| [17. API 공백, 키 검증 및 측정](history/17-api-and-measurement.md) | [17. API 공백, 키 검증 및 측정](history/17-api-and-measurement.ko.md) |
| [18. RSA 프로파일링과 Montgomery 산술](history/18-rsa-profiling.md) | [18. RSA 프로파일링과 Montgomery 산술](history/18-rsa-profiling.ko.md) |
| [19. AES-CBC 레지스터 체이닝](history/19-aes-cbc.md) | [19. AES-CBC 레지스터 체이닝](history/19-aes-cbc.ko.md) |
| [20. OID와 정확성 수정](history/20-oids-and-correctness.md) | [20. OID와 정확성 수정](history/20-oids-and-correctness.ko.md) |
| [21. 해시와 MAC 최적화](history/21-hash-and-mac-optimization.md) | [21. 해시와 MAC 최적화](history/21-hash-and-mac-optimization.ko.md) |

## 호출자 명세와 예제

| 영문 | 한국어 |
| --- | --- |
| [명세 안내](../specs/README.md) | [명세 안내](../specs/README.ko.md) |
| [API 지도](../specs/api-map.md) | [API 지도](../specs/api-map.ko.md) |
| [레시피](../specs/recipes.md) | [레시피](../specs/recipes.ko.md) |
| [함정](../specs/pitfalls.md) | [함정](../specs/pitfalls.ko.md) |
| [예제 안내](../examples/README.md) | [예제 안내](../examples/README.ko.md) |
| [위키 생성 안내](../examples/wiki/README.md) | [위키 생성 안내](../examples/wiki/README.ko.md) |

타입별 생성 API 조각은 유지 보수하는 원본 문서가 아니라 다시 생성하는 결과물이므로
개별 파일 대신 [`examples/wiki/snippets/`](../examples/wiki/snippets) 디렉터리로
표시합니다.
