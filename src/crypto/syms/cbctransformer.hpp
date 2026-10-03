#ifndef __SRC_CRYPTO_SYMS_CBCTRANSFORMER_HPP__
#define __SRC_CRYPTO_SYMS_CBCTRANSFORMER_HPP__

#include <certpp/crypto/sym.hpp>
#include <certpp/io/buffer.hpp>
#include <functional>

namespace certpp {
namespace crypto {

    /* CBC-mode block cipher transformer shared by AES/DES/3DES's ISymmetricContext
     * implementations -- the only thing that differs between them is the per-block
     * encrypt/decrypt function and the block size, both supplied by the caller, so none of them
     * need their own copy of this buffering/chaining/padding logic.
     *
     * Padding is PKCS#7 or none, per the ESymPaddings the caller passes (which every caller takes
     * from its context's padding(), so it is the context's choice, defaulting to PKCS#7 and
     * therefore unchanged for anyone who never asks).
     *
     * With PKCS#7, decrypting always holds back the most recently completed block rather than
     * emitting it immediately, since that block might turn out to be the final one (requiring its
     * padding to be located and stripped) -- it's only emitted, unpadded, once transformFinal()
     * confirms it really is the last block. Encrypting has no such ambiguity (padding is only
     * ever added in transformFinal(), after which the transformer is no longer usable), so
     * every complete block is encrypted and emitted as soon as it's buffered.
     *
     * With ESYMPAD_NONE neither direction has anything to hold back or strip: every whole block
     * is emitted as soon as it is buffered, and transformFinal() produces nothing, failing with
     * ERET_BADREQ if a partial block is left over -- unpadded CBC cannot represent a length that
     * isn't a multiple of the block size, so a caller feeding one has made a mistake that must
     * not be silently rounded up. */
    class CbcTransformer : public ISymmetricTransformer {
    public:
        /* Encrypts/decrypts exactly one block (in and out may alias the same buffer). */
        using BlockFn = std::function<void(const uint8_t* in, uint8_t* out)>;

    private:
        bool _encrypting;
        size_t _blockBytes;
        ESymPaddings _padding;
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
         * @param padding ESYMPAD_PKCS7 to pad/strip the final block, ESYMPAD_NONE to require the
         * input to be a whole number of blocks already.
         * @param blockFn Encrypts (if encrypting) or decrypts (otherwise) one raw blockBytes-long
         * block, with no chaining/padding of its own -- this transformer applies CBC chaining and
         * whatever padding `padding` selects around it.
         */
        CbcTransformer(
            const ISymmetricContextPtr& ctx, bool encrypting, size_t blockBytes,
            SReadOnlyByteSpan iv, ESymPaddings padding, BlockFn blockFn
        );

        ERetCode transform(const SReadOnlyByteSpan& input, SByteSpan& output) override;
        ERetCode transformFinal(SByteSpan& output) override;
    };

} // namespace crypto
} // namespace certpp

#endif
