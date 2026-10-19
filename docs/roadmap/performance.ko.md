# 보안 및 성능 작업

[English](performance.md)

이 문서에는 아직 남은 작업만 둡니다. 현재 벤치마크 결과와 방법론은
[성능](../concepts/performance.ko.md)에, 완료된 최적화·조사·부정적 결과는
[변경 이력](../HISTORY.ko.md)과 [계획에 없음](not-planned.ko.md)에 기록합니다.

## 보안 작업

### 비밀 메모리 페이지 잠금

현재 `CSecure::zero()`는 명시적인 영점화를 컴파일러가 제거하지 못하게 하지만, 그
메모리가 속한 페이지가 swap 또는 Windows page file에 기록되는 것은 막지 않습니다.
개인키와 비밀 중간값도 일반 `COctet`, `TArray`, `CBigNum` 할당에 들어갑니다. 따라서
호출자가 제공한 임의 span에 `lock()`과 `unlock()`을 적용하는 방식은 안전한 소유권
경계를 만들지 못합니다. 메모리 잠금은 페이지 전체에 적용되고 서로 무관한 할당이 같은
페이지를 공유할 수 있으며, 운영체제의 잠금 횟수로 독립적인 객체 수명을 안전하게 표현할
수 없기 때문입니다.

임의 버퍼에 잠금 호출을 추가하는 대신 전용 페이지 기반 보안 할당 계층을 조사합니다.
Windows에서는 `VirtualAlloc` 다음 `VirtualLock`, Linux에서는 익명 `mmap` 다음
`mlock`을 사용하는 형태를 목표로 합니다. Linux mapping에는 `MADV_DONTDUMP`와 지원되는
경우 `MADV_WIPEONFORK`도 적용합니다. 파괴할 때는 전체 할당을 먼저 영점화한 뒤 잠금을
해제하고 mapping을 반환해야 합니다. 복사는 금지하거나 다른 보호된 할당으로 직접 깊은
복사해야 하며, 크기를 늘릴 때 일반 heap buffer를 중간 경유지로 사용해서는 안 됩니다.

보호 계약은 실패를 호출자에게 드러내야 합니다. best-effort 모드는 호환성을 위해 일반
메모리로 계속 진행할 수 있지만 해당 할당이 잠기지 않았다는 상태를 알려야 합니다.
required 모드는 플랫폼 API, Windows working-set 제한, Linux `RLIMIT_MEMLOCK` 때문에
잠글 수 없으면 키 생성 또는 가져오기를 실패시켜야 합니다. 잠금 호출이 성공한 할당에
대해서만 page-out되지 않는다고 문서화합니다.

다음 단계로 적용합니다.

1. Ed25519, Ed448, X25519, ML-DSA, ML-KEM 키처럼 장기간 유지되는 byte 기반 개인
   자료를 보호된 buffer로 옮깁니다.
2. 공개 산술까지 보안 allocator로 보내지 않으면서 RSA, DSA, ECDSA, GOST의 장기 보관
   private `CBigNum` 구성 요소에 보호된 limb 저장소를 추가합니다.
3. nonce, seed, 파생 비밀, private 산술 임시값을 위한 연산 단위 secure arena를
   검토합니다. arena 또는 키 저장소를 한 번 준비해 재사용함으로써 page 잠금을 hot loop
   밖에 둡니다.

테스트에서는 주입 가능한 플랫폼 backend를 사용해 복사 전 잠금, 잠금 해제 전 영점화,
이동 및 크기 변경 동작, required 모드 실패, best-effort 상태 보고를 확인해야 합니다.
Linux 통합 검증은 잠긴 byte 집계와 fork 동작을, Windows 검증은 대응하는 할당·잠금·잠금
해제·반환 순서를 확인해야 합니다.

이 기능만으로 비밀 byte가 영구 저장소에 절대 도달하지 않는다고 보장할 수는 없습니다.
호출자가 가진 사본, 보호 mapping 밖으로 나온 compiler spill, 최대 절전 이미지, 전체 메모리
dump, debugger, 가상 머신 snapshot, buffer가 라이브러리에 들어오기 전에 만들어진 저장소는
할당 계층이 통제하지 못합니다. Linux dump 제외와 Windows Error Reporting 메모리 제외는
dump 노출을 줄일 수 있지만, 전체 dump, 최대 절전, 암호화된 swap 또는 page file에 대한
host 정책을 대신하지는 않습니다.

플랫폼 참고 자료: Microsoft는 [`VirtualLock`](https://learn.microsoft.com/windows/win32/api/memoryapi/nf-memoryapi-virtuallock)의
page file 제외 보장과 자원 제한, 그리고 더 좁은 Windows Error Reporting 범위인
[`WerRegisterExcludedMemoryBlock`](https://learn.microsoft.com/windows/win32/api/werapi/nf-werapi-werregisterexcludedmemoryblock)을
문서화합니다. Linux man-pages의 [`mlock`](https://man7.org/linux/man-pages/man2/mlock2.2.html)은
`RLIMIT_MEMLOCK`과 최대 절전 한계를, [`madvise`](https://man7.org/linux/man-pages/man2/madvise.2.html)는
`MADV_DONTDUMP`와 `MADV_WIPEONFORK`를 설명합니다.

## 성능 작업

- **Windows Clang 전체 목록의 격차를 해소합니다.** OpenSSL 3.6.4를 상대로 한
  2026-10-19 Release 갱신에서 RSA-2048 키 생성/서명/검증은
  0.398/0.875/0.700배, P-256 키 생성은 0.676배, SHA-384는 0.88배였습니다.
  각 행을 논리 프로세서 하나에 고정한 집중 실행으로 재현하고, 선택된 Windows kernel과
  ABI code generation을 더 빠른 WSL 구성과 비교하여 직접 비교 가능한 모든 행을 다시
  0.90배 이상으로 올립니다. 무작위 RSA 키 생성 결과는 반복 연산 결론과 분리합니다.

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
