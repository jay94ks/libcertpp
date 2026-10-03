Issues a leaf certificate signed by a CA's key pair. subjectKey is only the key being certified; issuerKeyPair is what signs. build() never attaches a private key to the certificate it hands back, so the subject's own private half has to be set separately.

```cpp
// given: const CCert& caCert, const SKeyPair& caKeyPair, const IPublicKeyPtr& subjectKey, const COctet& serial
CCertBuilder builder;
builder.issuer = caCert.subject();
if (!CDistinguishedName::tryParse(builder.subject, CString("CN=leaf.example.com"))) {
    return;
}

builder.serialNumber = serial;
builder.notBefore = SDateTime::now(true);
builder.notAfter = builder.notBefore;
builder.notAfter.year += 1;

builder.subjectKey = subjectKey;
builder.issuerKeyPair = caKeyPair;
builder.digestAlgo = EHASH_SHA256;

CBasicConstraintsExtensionBuilder bc;
bc.setIsCa(false);

IExtensionPtr bcExt = bc.build();
if (!bcExt) {
    return; // build() reports an unencodable extension with null, and a null entry fails below
}
builder.extensions.add(bcExt);

CCert leaf;
if (builder.build(leaf) != ERET_OK) {
    return;
}
// leaf.verifyBy(caCert) now holds -- which is a statement about one signature and no more
```
