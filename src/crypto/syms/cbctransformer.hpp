#ifndef __SRC_CRYPTO_SYMS_CBCTRANSFORMER_HPP__
#define __SRC_CRYPTO_SYMS_CBCTRANSFORMER_HPP__

#include <certpp/crypto/sym.hpp>
#include <certpp/io/buffer.hpp>
#include <functional>

namespace certpp {
namespace crypto {

    /* CBC-mode, PKCS#7-padded block cipher transformer shared by AES/DES/3DES's
     * ISymmetricContext implementations -- the only thing that differs between them is the
     * per-block encrypt/decrypt function and the block size, both supplied by the caller, so
     * none of them need their own copy of this buffering/chaining/padding logic.
     *
     * Decrypting always holds back the most recently completed block rather than emitting it
     * immediately, since that block might turn out to be the final one (requiring its PKCS#7
     * padding to be located and stripped) -- it's only emitted, unpadded, once transformFinal()
     * confirms it really is the last block. Encrypting has no such ambiguity (padding is only
     * ever added in transformFinal(), after which the transformer is no longer usable), so
     * every complete block is encrypted and emitted as soon as it's buffered. */
    class CbcTransformer : public ISymmetricTransformer {
    public:
        /* Encrypts/decrypts exactly one block (in and out may alias the same buffer). */
        using BlockFn = std::function<void(const uint8_t* in, uint8_t* out)>;

    private:
        bool _encrypting;
        size_t _blockBytes;
        BlockFn _blockFn;
        CBuffer _chain;      // --> current chaining value; IV until the first block.
        CBuffer _buffer;     // --> input not yet consumed.
        CBuffer _scratch;    // --> one block of scratch space, reused per block.

        ERetCode processBuffered(bool final, SByteSpan& output);

    public:
        /**
         * @param ctx The context this transformer was created from.
         * @param encrypting true to encrypt (pad on finalize); false to decrypt (strip padding
         * on finalize).
         * @param blockBytes The cipher's block size, in bytes.
         * @param iv The initialization vector; must be exactly blockBytes long.
         * @param blockFn Encrypts (if encrypting) or decrypts (otherwise) one raw blockBytes-long
         * block, with no chaining/padding of its own -- this transformer applies CBC chaining and
         * PKCS#7 padding around it.
         */
        CbcTransformer(
            const ISymmetricContextPtr& ctx, bool encrypting, size_t blockBytes,
            SReadOnlyByteSpan iv, BlockFn blockFn
        );

        ERetCode transform(const SReadOnlyByteSpan& input, SByteSpan& output) override;
        ERetCode transformFinal(SByteSpan& output) override;
    };

} // namespace crypto
} // namespace certpp

#endif
