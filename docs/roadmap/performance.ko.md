# 보안 및 성능 작업

[English](performance.md)

이 문서에는 아직 남은 작업만 둡니다. 현재 벤치마크 결과와 방법론은
[성능](../concepts/performance.ko.md)에, 완료된 최적화·조사·부정적 결과는
[변경 이력](../HISTORY.ko.md)과 [계획에 없음](not-planned.ko.md)에 기록합니다.

## 보안 작업

### 비밀 메모리 페이지 잠금

이제 `CSecure::alloc()`이 전용 페이지 기반 계층을 제공합니다. 정렬된 작은 할당들은
보호된 OS mapping을 나눠 씁니다. 기본값에서는 먼저 OS large-page 크기(Windows의
`MEM_LARGE_PAGES`, Linux의 `MAP_HUGETLB`)로 요청하고, 필요한 권한이나 예약 페이지가
없으면 `VirtualLock` 또는 `mlock`으로 보호한 표준 페이지로 폴백합니다.
`CERTPP_DISABLE_LARGE_PAGE=ON`이면 처음부터 표준 페이지를 사용합니다. Linux에서는
kernel이 제공할 때 `MADV_DONTDUMP`도 적용합니다.
반환된 블록은 재사용 전에 지우고 마지막 블록을 반환할 때 mapping 전체를 지웁니다.
풀은 영점화한 표준 페이지를 최대 하나만 잠긴 상태로 보관해 재사용하며, 나머지 표준
페이지와 large-page mapping은 mapping을 해제하기 직전에 전체를 지우고 필요에 따라
잠금을 풉니다. best-effort 일반 heap
fallback은 없습니다. 잠금 실패는
`ERET_NOMEM`이고 키 생성 또는 가져오기 경로가 그 실패를 전달합니다. 모든 비대칭 및 KEM
개인키 객체 본체도 이제 이 allocator를 사용합니다.

첫 간접 소유자들도 보호 저장소로 옮겼습니다. ML-DSA와 ML-KEM은 인코딩된 개인키를
`CSecureOctet`에 보관하고, 대칭키 객체도 원시 키 바이트에 같은 타입을 사용합니다.
생성 buffer, 평문을 보관할 수 있는 CBC/RSA 변환 buffer와 그 밖의 바이트 기반 비밀
작업공간은 `CSecureBuffer`를 사용합니다. AES/ARIA key schedule과 ML-DSA 다항식
임시값은 `TSecureArray<T>`를 사용합니다. 복사와 확장은 선택된 allocator 안에서
이루어지며 `wrap()`은 계속 호출자 소유 저장소입니다.

남은 작업은 일반 container가 여전히 소유하는 저장소입니다. `CBigNum`, `COctet`, 기본
allocator의 `TArray` 인스턴스는 payload를 일반 heap에 할당합니다. 객체 본체만 잠가서는
이 동적 바이트를 보호할 수 없습니다. `CERTPP_DISABLE_SECURE_MEM=ON`은 의도적으로 모든
`CSecure` 할당을 page 잠금과 해제 시 영 소거가 없는 일반 정렬 heap 저장소로 되돌립니다.
이 호환 모드는 `GetLibraryVersion().isSecureMemory()`로 확인할 수 있습니다.

다음 단계로 적용합니다.

1. 비밀을 담는 나머지 `COctet`, `CBuffer`, 기본 `TArray` 인스턴스를 감사하고, 장기
   보관하거나 재사용하는 각 소유자를 역할에 따라 `CSecureOctet`, `CSecureBuffer`,
   `TSecureArray`로 옮깁니다.
2. 공개 산술까지 보안 allocator로 보내지 않으면서 RSA, DSA, ECDSA, GOST의 장기 보관
   private `CBigNum` 구성 요소에 보호된 limb 저장소를 추가합니다.
3. nonce, seed, 파생 비밀, private 산술 임시값을 위한 연산 단위 secure arena를
   검토합니다. arena 또는 키 저장소를 한 번 준비해 재사용함으로써 page 잠금을 hot loop
   밖에 둡니다.

주입 가능한 플랫폼 backend를 추가하여 host 잠금 제한에 의존하지 않고 사용 전 잠금,
잠금 해제 전 영점화, required-mode 실패를 확인해야 합니다. Linux 통합 검증은 잠긴 byte
집계와 fork 동작을, Windows 검증은 대응하는 할당·잠금·잠금 해제·반환 순서를 확인해야
합니다.

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

- **Windows thread 의존성을 CMake에 반영합니다.** 현재 벤치마크 빌드는
  `SecurePool`의 `std::mutex` 때문에 실행 파일과 공유 라이브러리 링크 단계에
  `-lwinpthread`를 명시적으로 제공합니다. 다음 전체 목록 갱신 전에 이 의존성을
  유지 보수하는 CMake 구성에 반영합니다.

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
