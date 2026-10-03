Obtains a built-in KEM from the factory and generates a decapsulation key pair. ML-KEM's "key size" is its parameter-set label -- 768 means ML-KEM-768, not a modulus width -- and nothing between the three names is accepted.

```cpp
crypto::IKemPtr kem = crypto::IKem::builtIn(crypto::EKEM_MLKEM768);
if (!kem) {
    return;
}

crypto::SKemKeyPair pair;
if (kem->generateKeyPair(768, pair) != ERET_OK) {
    return; // ERET_AGAIN means retry; ERET_KEY_SIZE means the wrong label
}

if (kem->checkPrivateKey(pair.privateKey) != ERET_OK) {
    return;
}

crypto::IKemContextPtr ctx = kem->createContext();
ctx->keyPair(pair);
```
