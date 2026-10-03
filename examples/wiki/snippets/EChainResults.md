ECHAINRES_PARTIAL is the case worth writing code for: the walk ran out of issuers, and the output keeps what it found so the caller can go and fetch the missing one. Only ECHAINRES_OK means the walk reached a self-issued certificate held in the collection.

```cpp
// given: const CCertCollection& col, const CCert& leaf
TArray<size_t> chain;
EChainResults res = col.buildChainFor(leaf, chain);

if (res == ECHAINRES_PARTIAL) {
    SCertEntry topMost;
    if (chain.size() && col.at(chain[chain.size() - 1], topMost) == ERET_OK) {
        // topMost.cert.issuer() names the certificate still to be fetched
    }
    return;
}

if (res != ECHAINRES_OK) {
    return; // ECHAINRES_CYCLE or ECHAINRES_TOO_DEEP: the collection itself is the problem
}
// chain holds the issuers above leaf, nearest first -- leaf has no index in col
```
