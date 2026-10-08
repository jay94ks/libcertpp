# 레시피

[English](recipes.md)

호출자가 실제로 하는 작업들의 동작하는 코드입니다. 모든 서명은 헤더에서 직접
읽어 확인했으며, 인증서 관련 관용구는 빌드가 함께 컴파일하는 `examples/`를
따릅니다 — 둘이 어긋나면 `examples/` 쪽이 더 강한 근거입니다.

오류 처리는 첫 레시피에서 한 번 제대로 보여주고 이후에는 분량 때문에
생략합니다. **실제 코드에서는 생략하지 마세요** — `ERET_OK`은 0이고, `bool`을
반환하는 호출은 실패 이유를 알려주지 않으므로, 여기서 검사하지 않은 호출은
운영 환경에서도 검사되지 않은 호출입니다.

```cpp
#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;
using namespace certpp::x509;
```

## JSON 파싱과 직렬화

```cpp
CJsonPtr value = parseJson(R"({"enabled":true,"labels":["cert","json"]})");
if (!value) {
    return; // 입력이 완전하고 유효한 JSON 값 하나가 아닙니다.
}

CJson::KeyedValue enabled = value->byKey("enabled");
if (enabled.value && enabled.value->asBool()) {
    std::string encoded = value->toString();
}
```

`parseJson()`은 루트 primitive를 포함해 완전한 JSON 값 하나를 받습니다.
유효한 JSON `null`과 파싱 실패를 구분하려면 `value->isNull()`을 사용하십시오.
유효한 `null`의 반환값은 null이 아닌 `CJsonPtr`입니다.

```cpp
CJsonPtr document = parseJson(R"({"enabled":true,"count":3})");
if (!document) {
    return;
}

CBuffer bson;
if (!document->toBson(bson)) {
    return;
}

CJsonPtr decoded = parseBson(bson.toSpan());
```

BSON 루트는 document이므로 `toBson()`은 JSON object와 array만 받습니다.
`parseBson(span, true)`는 루트 document를 array로 해석하며 `"0"`, `"1"`처럼
연속된 문자열 키를 요구합니다. BSON 정수 타입은 JSON `double` 값으로 변환되며,
지원하지 않는 BSON 타입은 파싱에 실패합니다.

## 인증서를 파싱하고 읽기

```cpp
COctet der = /* 파일 내용 */;

CCert cert;
ERetCode rc = cert.importDer(der);
if (rc != ERET_OK) {
    // 참고: 이 라이브러리가 해석할 수 없는 알고리즘을 쓰는 인증서도
    // importDer()는 성공합니다 -- 그 경우 keyAlgo()/signAlgo()가 원시 OID
    // 문자열을 담고 publicKey()를 쓸 수 없게 됩니다. 여기서의 실패는 구조
    // 자체가 거부되었다는 뜻입니다.
    return rc;
}

CName cn;
if (cert.subject().tryGet(ENAME_CN, cn) == true) {
    // cn이 common name을 담고 있습니다
}

const SDateTime& from = cert.notBefore();
const SDateTime& to   = cert.notAfter();
const COctet& serial  = cert.serialNumber();
```

`importPem()`은 PEM 형식을 받으며, PEM 파일에 개인키가 들어 있으면 그것도
함께 가져옵니다.

## 한 인증서가 다른 인증서에 의해 발급되었는지 검증

```cpp
// 링크 하나뿐입니다: 서명을 확인하고 그 외에는 아무것도 확인하지 않습니다.
// 유효 기간, basicConstraints, 키 용도, 이름 제약, 폐기 여부를 보지 않습니다.
ERetCode rc = leaf.verifyBy(issuer);
```

## 인증서의 키로 데이터 서명·검증

```cpp
const char* msg = "payload";
SReadOnlyByteSpan message(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg));

uint8_t buf[512];
SByteSpan signature(buf, sizeof(buf));

// 개인키가 붙어 있어야 합니다 -- importPem()이 파싱해 왔거나,
// cert.privateKey(key)로 붙입니다.
cert.signData(message, signature);

// signature.size가 실제 길이로 좁혀졌습니다. sizeof(buf)가 아니라 이것을 쓰세요.
cert.verifyData(message, SReadOnlyByteSpan(signature.data, signature.size));
```

`verifyData()`는 공개키만 필요하며, 파싱된 인증서는 언제나 공개키를 가집니다.

## 인증서 발급

전체 과정은 `examples/01_issue_ca_root.cpp`부터 `03_issue_leaf.cpp`까지의
컴파일되는 예제를 보세요: 루트, 그 아래 중간 CA, 그리고 리프를 각각 계층
구조가 유효해지는 확장과 함께 발급합니다. 시작점은 `CCertBuilder`입니다. 그
파일들이 여기서의 기준인 이유는 바로 **빌드되기 때문**입니다.

## 인증서 서명 요청(CSR) 만들기와 읽기

```cpp
// 요청자 쪽: 키 쌍 하나만 넘깁니다. 공개키를 개인키와 따로 지정할 방법이
// 없는 것은 의도된 설계입니다 -- 그럴 수 있다면 서명은 subjectPKInfo에 담긴
// 키가 아니라 개인키 자신의 공개 짝에 대해 검증되어 버립니다.
CCertRequestBuilder builder;
CDistinguishedName::tryParse(builder.subject, CString("CN=example.com"));
builder.subjectKeyPair = myKeyPair;

CCertRequest request;
builder.build(request);
```

```cpp
// CA 쪽: import가 자기 서명을 검증하며, 검증 없이는 ERET_OK를 반환하지
// 않습니다. 인증서와 달리 CSR의 필드는 서명이 성립할 때까지 인증되지 않은
// 주장일 뿐이고, 개인키 소유 증명이 CSR의 존재 이유 전부입니다.
CCertRequest incoming;
if (incoming.importDer(csrDer) != ERET_OK) {
    return;     // 서명이 맞지 않거나 구조가 잘못되었습니다
}

CCertBuilder issuing;
issuing.subjectFrom(incoming);      // subject와 공개키만 복사합니다
```

`subjectFrom()`에는 **요청된 확장을 복사하는 대응물이 의도적으로 없습니다.**
원하는 확장이 있으면 CA가 그것을 읽고, 검사하고, 직접 `extensions`에
넣습니다 — 확장 하나하나가 명시적인 결정이 됩니다. 일괄 복사는 "요청자가
요구했으니 CA 인증서를 발급해 주는" 경로입니다.

## 해시 계산

```cpp
IHasherPtr hasher;
IHasher::create(EHASH_SHA256, hasher);

hasher->reset();
hasher->push(SReadOnlyByteSpan(data, length));

uint8_t digest[32];                       // hasher->byteWidth() 바이트
hasher->finish(SByteSpan(digest, sizeof(digest)));
```

`push()`는 여러 번 호출할 수 있고, 결과는 입력을 어떻게 쓪았는지에 의존하지
않습니다. `finish()`는 *조회*입니다. 상태의 사본을 마무리하기 때문에 원본
상태는 그대로 남아 이후에도 `push()`가 동작합니다. 진행 중인 다이제스트가
가능한 이유가 이것입니다 — 앞부분을 해싱해서 읽어보고, 계속 해싱하면 됩니다.
`reset()`은 `finish()`를 안전하게 만들기 위해서가 아니라, *새* 메시지를
시작할 때 호출합니다.

## HMAC과 HKDF

```cpp
uint8_t tag[32];
CHmac::compute(EHASH_SHA256, key, message, SByteSpan(tag, sizeof(tag)));

// constant-time 비교이며, 태그를 직접 비교하지 않고 verify()를 쓰는 이유가
// 바로 이것입니다.
bool ok = CHmac::verify(EHASH_SHA256, key, message, receivedTag);
```

```cpp
uint8_t keys[64];
CHkdf::derive(EHASH_SHA256, salt, inputKeyMaterial, info,
              SByteSpan(keys, sizeof(keys)));
```

인자 순서를 보세요: **salt가 입력 키 재료보다 먼저** 옵니다. 두 단계가 서로
다른 시점에 일어나는 경우를 위해 `CHkdf::extract()`와 `expand()`가 따로
있으며, `maxExpandBytes()`가 해시별 상한을 알려줍니다.

## AEAD로 레코드 암호화

```cpp
CChaCha20Poly1305 aead;
aead.reset(key);                       // 키마다 한 번, 레코드마다가 아닙니다

// seal(nonce, aad, in, out, tag) -- out은 in과 정확히 같은 버퍼여도 되며,
// 그것이 제자리 암호화 방법입니다.
uint8_t tag[16];
aead.seal(nonce, aad,
          SReadOnlyByteSpan(buffer, length),
          SByteSpan(buffer, length),            // 제자리
          SByteSpan(tag, sizeof(tag)));
```

```cpp
// open(nonce, aad, in, tag, out) -- 여기서는 tag가 out보다 먼저 옵니다.
// 태그가 검증되지 않으면 평문을 한 바이트도 쓰지 않으며, 태그를
// constant-time으로 비교합니다. 실패하면 버퍼는 도착한 그대로의 암호문으로
// 남습니다.
bool ok = aead.open(nonce, aad,
                    SReadOnlyByteSpan(buffer, length),
                    SReadOnlyByteSpan(tag, sizeof(tag)),
                    SByteSpan(buffer, length));
```

여기서 nonce는 96비트인데 이는 무작위로 고르기에는 너무 짧으므로 카운터를
쓰세요. 무작위 nonce가 필요하면 그것이 `CXChaCha20Poly1305`의 192비트 nonce가
있는 이유이고, `CAesGcm`도 같은 모양입니다.

## 키 쌍 생성과 서명

```cpp
IAsymmetricPtr algo = IAsymmetric::builtIn(EASYM_P256);

SKeyPair pair;
algo->generateKeyPair(SKeySize(256), pair);

IAsymmetricContextPtr ctx = algo->createContext();
ctx->keyPair(pair);

uint8_t sig[160];
SByteSpan signature(sig, sizeof(sig));
ctx->sign(digest, signature);           // ECDSA는 다이제스트에 서명합니다

// 검증에는 공개키 쪽만 필요합니다.
IAsymmetricContextPtr verifier = algo->createContext();
verifier->keyPair(pair.publicKey, nullptr);
verifier->verify(digest, SReadOnlyByteSpan(signature.data, signature.size));
```

`generateKeyPair()`는 비트 단위 크기에 엄격합니다: Ed448은 448이 아니라
456을 요구합니다.

Ed25519, Ed448, ML-DSA에서는 `digest` 매개변수가 다이제스트가 아니라
**메시지**를 담습니다 — 이 방식들은 내부에서 해시를 수행합니다.
`ctx->sizeOfDigest() == 0`이 그 신호이고, 인증서 수준의 대응물은
`CCert::signsMessageDirectly()`입니다.

## 공유 비밀 합의

```cpp
IAsymmetricPtr x = IAsymmetric::builtIn(EASYM_X25519);

SKeyPair mine;
x->generateKeyPair(SKeySize(256), mine);

IAsymmetricContextPtr ctx = x->createContext();
ctx->keyPair(mine);

uint8_t secret[32];
SByteSpan out(secret, sizeof(secret));
ctx->deriveSharedSecret(peerPublicKey, out);

// 원시 비밀을 키로 바로 쓰지 마세요. KDF를 통과시키세요.
uint8_t sessionKeys[64];
CHkdf::derive(EHASH_SHA256, transcriptHash,
              SReadOnlyByteSpan(secret, out.size), info,
              SByteSpan(sessionKeys, sizeof(sessionKeys)));
```

같은 호출이 `EASYM_P256`/`EASYM_P384`로 소수체 곡선에서도 동작하며(RFC 5903),
이때 비밀은 x 좌표 하나뿐입니다. 그쪽은 **constant-time이 아니고** X25519는
맞습니다.

## 양자내성 키 캡슐화

```cpp
IKemPtr kem = IKem::builtIn(EKEM_MLKEM768);

SKemKeyPair pair;
kem->generateKeyPair(SKeySize(768), pair);

// 보내는 쪽:
uint8_t ct[1088], ss[32];
SByteSpan ciphertext(ct, sizeof(ct));
SByteSpan sharedSecret(ss, sizeof(ss));
senderCtx->encapsulate(ciphertext, sharedSecret);

// 받는 쪽:
uint8_t ss2[32];
SByteSpan recovered(ss2, sizeof(ss2));
receiverCtx->decapsulate(SReadOnlyByteSpan(ciphertext.data, ciphertext.size),
                         recovered);
```

ML-KEM은 암묵적 거부(implicit rejection) 방식입니다: 손상된 암호문은 오류가
아니라 **다른** 공유 비밀을 내놓으며, 이는 설계된 동작입니다.
`decapsulate()`의 성공을 인증으로 취급하지 말고, 비밀을 트랜스크립트에
묶으세요.

## 인증서 컬렉션과 체인

```cpp
CCertCollection col;
size_t idx = 0;
col.add(leafCert, leafPrivateKey, idx);
col.add(intermediateCert, idx);
col.add(rootCert, idx);

// 누가 누구를 발급했는지로 순서를 정합니다. AuthorityKeyIdentifier가 있으면
// 그것을 이름 매칭보다 우선하는데, CA가 키를 교체하면 같은 subject에 다른
// 키를 가진 인증서가 둘 생기기 때문입니다.
TArray<size_t> chain;
if (col.buildChain(0, chain) == ECHAINRES_OK) {
    // chain은 리프부터 자기 발급 루트까지의 인덱스입니다
}

// 순서를 정하는 것은 검증이 아닙니다. 이것은 각 링크의 서명만 확인하며,
// 유효 기간·basicConstraints·이름 제약·폐기 여부·신뢰 앵커 선택은 여전히
// 호출자의 몫입니다.
col.verifyLinks(chain);

// 개인키가 정말 그 인증서의 것인지 확인 -- 직렬화된 키 비교가 아니라
// 서명으로 확인합니다. 비교는 일부 알고리즘에서만 통합니다.
col.checkKeyPairing(0);
```

불완전한 체인은 `ECHAINRES_PARTIAL`을 반환하며 **찾은 부분을 버리지
않습니다** — 빠진 발급자를 가져오려면 그것이 필요합니다. 순환은
`ECHAINRES_TOO_DEEP`이 아니라 `ECHAINRES_CYCLE`로 보고되는데, 전자는 입력에
대해 참인 사실을 알려주고 후자는 포기했다는 말만 하기 때문입니다.

## 난수

```cpp
uint8_t nonce[12];
CRng::fill(SByteSpan(nonce, sizeof(nonce)));   // OS CSPRNG
```

## Constant-time 비교와 메모리 지우기

```cpp
bool equal = CSecure::equals(receivedTag, computedTag);   // 조기 종료 없음
CSecure::zero(SByteSpan(secret, sizeof(secret)));         // /O2에서도 남습니다
```

비밀에 해당하는 것에는 `memcmp`와 `memset` 대신 이것들을 쓰세요: `memcmp`는
일치하는 접두사 길이를 타이밍으로 누출하고, 결과를 읽지 않는 `memset`은
옵티마이저가 지워 버릴 수 있는 죽은 저장(dead store)입니다.

비교 결과 자체가 비밀인 경우에는 `equalsMask()`와 `select()`를 쓰세요 —
`equals()`는 마스크를 bool로 좁히는 과정에서 그 결과를 분기 가능한 값으로
만듭니다.

## DNSSEC: 키 태그와 DS 레코드

```cpp
SDnskey key;
key.flags = SDnskey::FLAG_ZONE_KEY | SDnskey::FLAG_SECURE_ENTRY_POINT;
key.algorithm = EDNSALG_ECDSAP256SHA256;
key.publicKey = /* 64바이트: x || y */;

uint16_t tag = 0;
key.keyTag(tag);

SDsRecord ds;
SDsRecord::fromDnskey(CString("example.net."), key, EDNSDIG_SHA256, ds);

// 다이제스트를 다시 계산해 constant-time으로 비교합니다.
bool vouchesFor = ds.matches(CString("example.net."), key);
```

DNSSEC의 인코딩과 이 라이브러리의 키·서명 사이를 변환하는 것은
`CDnssecKeys`의 일입니다 — 직접 구현하면 어디서 틀어지는지는
[`pitfalls.ko.md`](pitfalls.ko.md)를 보세요.
