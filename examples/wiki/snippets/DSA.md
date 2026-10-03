Generates a 2048-bit DSA key pair, stores the private half, and reloads it. generateKeyPair() produces fresh domain parameters too, and the serialized private key carries p, q and g with it, so nothing else has to be kept alongside it.

```cpp
DSA dsa;

SKeyPair pair;
if (dsa.generateKeyPair(SKeySize(2048), pair) != ERET_OK) {
    return;         // ERET_AGAIN here means only "call it again"
}

COctet stored;
if (pair.privateKey->serialize(stored) != ERET_OK) {
    return;
}

// .toSpan() is needed here: IAsymmetric's COctet overload is hidden by DSA's own
// override of the span one, so it is reachable only through an IAsymmetricPtr.
IPrivateKeyPtr reloaded = dsa.createPrivateKey(stored.toSpan());
if (!reloaded) {
    return;
}

// createPrivateKey() only parses. checkPrivateKey() is what says the domain parameters and
// the key material agree, and -- unlike generateKeyPair() -- it reports why when they do
// not, since retrying a deserialized key is not a coherent response.
if (dsa.checkPrivateKey(reloaded) != ERET_OK) {
    return;
}
```
