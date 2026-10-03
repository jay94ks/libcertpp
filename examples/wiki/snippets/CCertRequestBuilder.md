Produces a CSR on the requester's side. The key is set as a whole key pair -- subjectKeyPair, never a public key on its own -- because build() signs with the private half to prove it is the match for the public half it embeds, and refuses a mismatched pair with ERET_KEY_ERROR.

```cpp
// given: const SKeyPair& myKeyPair, CCertRequest& out
CCertRequestBuilder builder;
if (!CDistinguishedName::tryParse(builder.subject, CString("CN=example.com"))) {
    return;
}

builder.subjectKeyPair = myKeyPair;
builder.digestAlgo = EHASH_SHA256;

// These are what the CA is *asked* for, carried in a PKCS#9 extensionRequest attribute.
CSanExtensionBuilder san;
san.addName(CGeneralName(EGNAME_DNS, CString("example.com")));

IExtensionPtr sanExt = san.build();
if (!sanExt) {
    return;
}
builder.extensions.add(sanExt);

if (builder.build(out) != ERET_OK) {
    return;
}
// build() handed the result through importDer(), so out's signature has already been checked
```
