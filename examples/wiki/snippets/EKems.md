Selects the ML-KEM parameter set. The three values are *names*, not scalable sizes: the SKeySize generateKeyPair() wants is that same number, and an instance built for one set rejects the other two outright.

```cpp
// given: crypto::EKems which, crypto::SKeySize label
crypto::IKemPtr kem = crypto::IKem::builtIn(which);
if (!kem) {
    return; // EKEM_MAX and EKEM_UNKNOWN land here
}

crypto::SKemKeyPair pair;
if (kem->generateKeyPair(label, pair) != ERET_OK) {
    return; // ERET_KEY_SIZE unless label is this instance's own parameter-set label
}

if (pair.publicKey->algorithm() != which) {
    return;
}
```
