# 위키 예제

[English](README.md)

[GitHub 위키의 API 레퍼런스](https://github.com/jay94ks/libcertpp/wiki/API-Reference)에
실리는 예제 코드입니다. 공개 클래스·구조체·enum 하나마다 예제 하나씩, 모두
173개입니다.

이 코드가 위키에만 있지 않고 빌드 안에 들어와 있는 이유는 하나입니다.
**한 번도 컴파일해 본 적 없는 예제는 추측일 뿐입니다.** 이 디렉터리는 빌드
타깃이므로, 컴파일되지 않게 된 예제는 조용히 독자를 오해시키는 대신 빌드를
실패시킵니다.

## 구성

| | |
| --- | --- |
| `core.cpp` | 최상위 `certpp` 헤더들, 그리고 `io/`, `utils/` |
| `asn1.cpp` | `certpp::asn1` |
| `crypto_core.cpp` | `certpp::crypto` 자체 헤더들 — hasher 인터페이스, MAC, KDF, RNG, 곡선, AEAD |
| `crypto_hashers.cpp` | `crypto/hashers/`의 구체적인 해시 구현들 |
| `crypto_syms.cpp` | `crypto/syms/`의 블록·스트림 암호 |
| `crypto_asyms.cpp` | `crypto/asyms/`의 서명·키 합의 알고리즘과 KEM |
| `x509_core.cpp` | `certpp::x509` 자체 헤더들 — 인증서, CRL, OCSP, CSR, 컬렉션, 컨테이너 |
| `x509_exts.cpp` | `x509/exts/`의 확장 10종 |
| `dnssec.cpp` | `certpp::dnssec` |
| `main.cpp` | 빈 `main()`. 전체가 링크되도록 하기 위한 것입니다 |
| `snippets/` | 생성물. 예제마다 `<Type>.md` 하나씩이고, 위키 페이지가 이를 끼워 넣습니다 |

## 예제를 작성하는 방식

```cpp
// === CCert ===
// One or two sentences of prose, shown above the snippet on the wiki page.
void exampleCCert(const COctet& der) {
    CCert cert;
    if (cert.importDer(der) != ERET_OK) {
        return;
    }
    // ...
}
```

- `// === <TypeName> ===` 마커가 타입 이름을 지정합니다. 헤더에 적힌 그대로
  써야 하며, 이 이름이 예제와 위키 페이지를 짝지어 줍니다.
- 함수 이름은 `example<TypeName>`입니다.
- **발행되는 것은 함수 본문**이며, 들여쓰기를 한 단계 걷어낸 형태입니다. 테스트가
  아니라 호출하는 쪽이 실제로 쓸 코드로 작성합니다. assert도, `doctest`도
  쓰지 않습니다.
- **예제가 스스로 만들어낼 수 없는 값은 매개변수로 받습니다.** DER 바이트열이나
  상대방의 공개키가 필요한 예제는 그것을 매개변수로 받고,
  `tools/exsplit.py`가 매개변수 목록을 `// given: ...` 줄로 코드 위에
  발행합니다. `/* file contents */` 같은 자리표시자 표현식은 컴파일되지 않으므로,
  이 디렉터리의 존재 이유 자체를 무너뜨립니다.
- 각 예제는 해당 타입에서 호출하는 쪽이 틀리기 쉬운 지점을 담습니다. 해당하는
  내용이 있다면 [`specs/pitfalls.md`](../../specs/pitfalls.ko.md)를 참고하세요.
  거의 똑같이 생긴 parse/build 쌍 20개에 서로 바꿔 써도 되는 예제 20개를 붙이면
  아무것도 문서화하지 못합니다.

## 위키 재생성

```sh
cmake --build build --config Debug --target certpp_example_wiki   # 먼저 통과해야 합니다
python tools/exsplit.py                                           # -> snippets/*.md
python tools/wikigen.py emit <위키 클론 경로>
```

`tools/wikigen.py`는 각 페이지의 레퍼런스 부분을 헤더의 Javadoc에서 읽어옵니다.
다시 타이핑하는 내용은 없습니다. 그리고 짝이 되는 snippet을 끼워 넣습니다. 각
페이지에는 생성 시점의 커밋이 기록되는데, 이것이 낡은 위키 페이지를 그저 틀린
페이지가 아니라 *낡았음을 알 수 있는* 페이지로 만들어 줍니다.

공개 타입 중 아직 예제가 없는 것이 있으면 생성기가 알려 줍니다. 라이브러리가
커지는 동안 이 디렉터리가 빠진 것 없이 유지되는 방법입니다.

## 위쪽의 둘러보기 예제와는 다릅니다

한 단계 위의 `examples/*.cpp`는 실행되는 프로그램입니다.
`01_issue_ca_root.cpp`부터 `04_sign_verify.cpp`까지가 실제 root/intermediate/leaf
계층을 발급하고 그것으로 서명하며, 각 프로그램이 앞 프로그램의 출력을 읽어
이어집니다. 조각들이 어떻게 맞물리는지 보려면 그쪽을 보세요. 여기 있는 snippet은
*이 타입 하나를 어떻게 호출하는가*라는 더 좁은 질문에 답하며, 모든 타입이 하나씩
갖도록 타입 단위로 나뉘어 있습니다.
