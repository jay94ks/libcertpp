# Recipes

[한국어](recipes.ko.md)

Working code for the things callers actually do. Signatures were read out of
the headers; the certificate idioms follow `examples/`, which the build
compiles and which is therefore the stronger reference if the two ever
disagree.

Error handling is shown once, properly, in the first recipe and then elided for
brevity. **Do not elide it in real code** — `ERET_OK` is 0 and a `bool`-returning
call reports no reason for its failure, so an unchecked call here is an
unchecked call in production.

```cpp
#include <certpp.hpp>

using namespace certpp;
using namespace certpp::crypto;
using namespace certpp::x509;
```

## Parse and serialize JSON

```cpp
CJsonPtr value = parseJson(R"({"enabled":true,"labels":["cert","json"]})");
if (!value) {
    return; // The input was not one complete, valid JSON value.
}

CJson::KeyedValue enabled = value->byKey("enabled");
if (enabled.value && enabled.value->asBool()) {
    std::string encoded = value->toString();
}
```

`parseJson()` accepts one complete JSON value, including a root primitive.
Use `value->isNull()` to distinguish a valid JSON `null` from a parse failure:
the valid `null` result is a non-null `CJsonPtr`.

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

BSON's root is a document, so `toBson()` accepts only JSON objects and arrays.
`parseBson(span, true)` interprets the root document as an array and requires
its keys to be the sequential strings `"0"`, `"1"`, and so on. BSON integer
types become JSON `double` values; unsupported BSON types fail parsing.

## Parse a certificate and read it

```cpp
COctet der = /* file contents */;

CCert cert;
ERetCode rc = cert.importDer(der);
if (rc != ERET_OK) {
    // Note: importDer() succeeds for a certificate whose algorithm this
    // library cannot resolve -- keyAlgo()/signAlgo() then hold the raw OID
    // text and publicKey() is unavailable. A failure here means the
    // structure itself was rejected.
    return rc;
}

CName cn;
if (cert.subject().tryGet(ENAME_CN, cn) == true) {
    // cn holds the common name
}

const SDateTime& from = cert.notBefore();
const SDateTime& to   = cert.notAfter();
const COctet& serial  = cert.serialNumber();
```

`importPem()` takes the PEM form, and will also pick up a private key if the
PEM file carries one.

## Verify that one certificate was issued by another

```cpp
// One link only: this checks the signature and nothing else. It does not look
// at dates, basicConstraints, key usage, name constraints or revocation.
ERetCode rc = leaf.verifyBy(issuer);
```

## Sign and verify data with a certificate's key

```cpp
const char* msg = "payload";
SReadOnlyByteSpan message(reinterpret_cast<const uint8_t*>(msg), std::strlen(msg));

uint8_t buf[512];
SByteSpan signature(buf, sizeof(buf));

// Needs a private key attached -- importPem() may have parsed one, or
// cert.privateKey(key) attaches one.
cert.signData(message, signature);

// signature.size has been narrowed to the real length. Use it, not sizeof(buf).
cert.verifyData(message, SReadOnlyByteSpan(signature.data, signature.size));
```

`verifyData()` needs only the public key, which every parsed certificate has.

## Issue a certificate

See `examples/01_issue_ca_root.cpp` through `03_issue_leaf.cpp` for the full,
compiled walkthrough: a root, an intermediate under it, and a leaf, each with
the extensions that make the hierarchy valid. `CCertBuilder` is the entry
point. Those files are the reference here precisely because they are built.

## Hash something

```cpp
IHasherPtr hasher;
IHasher::create(EHASH_SHA256, hasher);

hasher->reset();
hasher->push(SReadOnlyByteSpan(data, length));

uint8_t digest[32];                       // hasher->byteWidth() bytes
hasher->finish(SByteSpan(digest, sizeof(digest)));
```

`push()` may be called repeatedly; the result does not depend on how the input
was chunked. `finish()` is a *query*: it finalizes a copy, so the live state
survives and `push()` still works afterwards. That is what makes a running
digest possible — hash a prefix, read it, keep hashing. Call `reset()` to start
a *new* message, not to make `finish()` safe.

## HMAC and HKDF

```cpp
uint8_t tag[32];
CHmac::compute(EHASH_SHA256, key, message, SByteSpan(tag, sizeof(tag)));

// Constant-time comparison, which is the point of using verify() rather than
// comparing the tag yourself.
bool ok = CHmac::verify(EHASH_SHA256, key, message, receivedTag);
```

```cpp
uint8_t keys[64];
CHkdf::derive(EHASH_SHA256, salt, inputKeyMaterial, info,
              SByteSpan(keys, sizeof(keys)));
```

Note the order: **salt before input key material**. `CHkdf::extract()` and
`expand()` are available separately when the two phases happen at different
times, and `maxExpandBytes()` gives the per-hash ceiling.

## Encrypt a record with an AEAD

```cpp
CChaCha20Poly1305 aead;
aead.reset(key);                       // once per key, not per record

// seal(nonce, aad, in, out, tag) -- out may alias in exactly, which is how you
// encrypt in place.
uint8_t tag[16];
aead.seal(nonce, aad,
          SReadOnlyByteSpan(buffer, length),
          SByteSpan(buffer, length),            // in place
          SByteSpan(tag, sizeof(tag)));
```

```cpp
// open(nonce, aad, in, tag, out) -- note tag comes before out here.
// Writes no plaintext unless the tag verifies, and compares it in constant
// time. A failure leaves the buffer as the ciphertext it arrived as.
bool ok = aead.open(nonce, aad,
                    SReadOnlyByteSpan(buffer, length),
                    SReadOnlyByteSpan(tag, sizeof(tag)),
                    SByteSpan(buffer, length));
```

The nonce is 96 bits here, which is too short to choose at random — use a
counter. `CXChaCha20Poly1305` has the same shape with a 192-bit nonce if you
need random ones, and `CAesGcm` the same again.

## Generate a key pair and sign

```cpp
IAsymmetricPtr algo = IAsymmetric::builtIn(EASYM_P256);

SKeyPair pair;
algo->generateKeyPair(SKeySize(256), pair);

IAsymmetricContextPtr ctx = algo->createContext();
ctx->keyPair(pair);

uint8_t sig[160];
SByteSpan signature(sig, sizeof(sig));
ctx->sign(digest, signature);           // ECDSA signs a digest

// Verification needs only the public half.
IAsymmetricContextPtr verifier = algo->createContext();
verifier->keyPair(pair.publicKey, nullptr);
verifier->verify(digest, SReadOnlyByteSpan(signature.data, signature.size));
```

`generateKeyPair()` is strict about the size in bits: Ed448 wants 456, not 448.

For Ed25519, Ed448 and ML-DSA the `digest` parameter carries the **message**,
not a digest — those schemes hash internally. `ctx->sizeOfDigest() == 0` is the
signal, and `CCert::signsMessageDirectly()` is the predicate for the
certificate-level equivalent.

## Agree a shared secret

```cpp
IAsymmetricPtr x = IAsymmetric::builtIn(EASYM_X25519);

SKeyPair mine;
x->generateKeyPair(SKeySize(256), mine);

IAsymmetricContextPtr ctx = x->createContext();
ctx->keyPair(mine);

uint8_t secret[32];
SByteSpan out(secret, sizeof(secret));
ctx->deriveSharedSecret(peerPublicKey, out);

// Never use the raw secret as a key. Run it through a KDF.
uint8_t sessionKeys[64];
CHkdf::derive(EHASH_SHA256, transcriptHash,
              SReadOnlyByteSpan(secret, out.size), info,
              SByteSpan(sessionKeys, sizeof(sessionKeys)));
```

The same call works on the prime curves via `EASYM_P256`/`EASYM_P384`
(RFC 5903), where the secret is the x-coordinate alone. Those are **not**
constant-time; X25519 is.

## Post-quantum key encapsulation

```cpp
IKemPtr kem = IKem::builtIn(EKEM_MLKEM768);

SKemKeyPair pair;
kem->generateKeyPair(SKeySize(768), pair);

// Sender:
uint8_t ct[1088], ss[32];
SByteSpan ciphertext(ct, sizeof(ct));
SByteSpan sharedSecret(ss, sizeof(ss));
senderCtx->encapsulate(ciphertext, sharedSecret);

// Receiver:
uint8_t ss2[32];
SByteSpan recovered(ss2, sizeof(ss2));
receiverCtx->decapsulate(SReadOnlyByteSpan(ciphertext.data, ciphertext.size),
                         recovered);
```

ML-KEM is implicitly rejecting: a corrupted ciphertext yields a *different*
shared secret rather than an error, by design. Do not treat
`decapsulate()` succeeding as authentication — bind the secret to a transcript.

## Make and read a certificate-signing request

```cpp
// Requester side: one key pair, and only one. There is deliberately no way to
// name a public key separately from the private key signing for it -- if there
// were, the signature would verify against the private key's own public half
// rather than the one in subjectPKInfo.
CCertRequestBuilder builder;
CDistinguishedName::tryParse(builder.subject, CString("CN=example.com"));
builder.subjectKeyPair = myKeyPair;

CCertRequest request;
builder.build(request);
```

```cpp
// CA side: import verifies the self-signature and will not return ERET_OK
// without it. Unlike a certificate's, a CSR's fields are an unauthenticated
// claim until the signature holds -- proving possession of the private key is
// the only thing a CSR is for.
CCertRequest incoming;
if (incoming.importDer(csrDer) != ERET_OK) {
    return;     // signature did not hold, or the structure was malformed
}

CCertBuilder issuing;
issuing.subjectFrom(incoming);      // the subject name and public key, nothing else
```

There is deliberately **no counterpart that copies requested extensions.** A CA
that wants one reads it, checks it, and pushes it onto `extensions` itself, so
every extension is an explicit decision. Copying wholesale is how a CA issues a
CA certificate because the requester asked for one.

## Hold a set of certificates and order them into a chain

```cpp
CCertCollection col;
size_t idx = 0;
col.add(leafCert, leafPrivateKey, idx);
col.add(intermediateCert, idx);
col.add(rootCert, idx);

// Orders by who issued whom. Where an AuthorityKeyIdentifier is present it is
// preferred over the name match, because a CA that re-keys has two
// certificates with one subject and two keys.
TArray<size_t> chain;
if (col.buildChain(0, chain) == ECHAINRES_OK) {
    // chain holds indices from the leaf up to a self-issued root
}

// Ordering is not validating. This checks each link's signature and nothing
// else -- validity periods, basicConstraints, name constraints, revocation and
// trust-anchor selection remain yours.
col.verifyLinks(chain);

// Confirm a private key really belongs to its certificate -- by signing, not by
// comparing serialized keys, which only works for some algorithms.
col.checkKeyPairing(0);
```

An incomplete chain returns `ECHAINRES_PARTIAL` and **keeps what it found** --
that is what you need in order to go and fetch the missing issuer. A cycle is
reported as `ECHAINRES_CYCLE` rather than `ECHAINRES_TOO_DEEP`, because the
first says something true about your data and the second only says the walk
gave up.

## Random bytes

```cpp
uint8_t nonce[12];
CRng::fill(SByteSpan(nonce, sizeof(nonce)));   // OS CSPRNG
```

## Constant-time comparison and wiping

```cpp
bool equal = CSecure::equals(receivedTag, computedTag);   // no early exit
CSecure::zero(SByteSpan(secret, sizeof(secret)));         // survives /O2
```

Use these rather than `memcmp` and `memset` on anything secret: `memcmp` leaks
the matching-prefix length through timing, and a `memset` whose result is
unread is a dead store the optimizer may delete.

Where the comparison's outcome is itself a secret, use `equalsMask()` with
`select()` instead — `equals()` narrows the mask to a `bool`, which makes that
outcome something the caller can branch on.

## DNSSEC: key tag and DS record

```cpp
SDnskey key;
key.flags = SDnskey::FLAG_ZONE_KEY | SDnskey::FLAG_SECURE_ENTRY_POINT;
key.algorithm = EDNSALG_ECDSAP256SHA256;
key.publicKey = /* 64 bytes: x || y */;

uint16_t tag = 0;
key.keyTag(tag);

SDsRecord ds;
SDsRecord::fromDnskey(CString("example.net."), key, EDNSDIG_SHA256, ds);

// Recomputes and compares the digest in constant time.
bool vouchesFor = ds.matches(CString("example.net."), key);
```

Converting between DNSSEC's encodings and this library's keys and signatures is
`CDnssecKeys`' job — see [`pitfalls.md`](pitfalls.md) for why hand-rolling it
goes wrong.
