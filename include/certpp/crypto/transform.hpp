#ifndef __INCLUDE_CERTPP_CRYPTO_TRANSFORM_HPP__
#define __INCLUDE_CERTPP_CRYPTO_TRANSFORM_HPP__

#include <certpp/common.hpp>
#include <certpp/io/span.hpp>

namespace certpp {
namespace crypto {

    /**
     * Forward declaration of the ITransformer interface.
     */
    class ITransformer;

    /**
     * Shared pointer type for the ITransformer interface.
     */
    using ITransformerPtr = std::shared_ptr<ITransformer>;

    /**
     * Interface for a generic cryptographic transformer.
     */
    class CERTPP_API ITransformer  {
    private:
        size_t _blockSize;                  // --> Block size for this transformer's operation.
        
    protected:
        /**
         * Sets the block size for this transformer's operation.
         * @param blockSize The block size to set.
         */
        inline void blockSize(size_t blockSize) {
            _blockSize = blockSize;
        }

    public:
        /**
         * Default constructor.
         */
        ITransformer() : _blockSize(0) { }
        
        /**
         * Virtual destructor.
         */
        virtual ~ITransformer() = default;
        
        /**
         * @return The block size for this transformer's operation.
         */
        inline size_t blockSize() const {
            return _blockSize;
        }

        /**
         * Feeds more input into this operation, producing however much output that input
         * completes. Call transformFinal() once all input has been fed in.
         *
         * @param input The next chunk of input (plaintext when encrypting, ciphertext when
         * decrypting).
         * @param output The buffer to receive whatever output this call produces.
         * @return ERET_OK on success; another ERetCode describing the failure otherwise.
         */
        virtual ERetCode transform(const SReadOnlyByteSpan& input, SByteSpan& output) = 0;

        /**
         * Finalizes this operation once all input has been fed in via transform(), producing
         * any remaining output. Not usable again afterward.
         *
         * @param output The buffer to receive the final output.
         * @return ERET_OK on success; another ERetCode describing the failure otherwise.
         */
        virtual ERetCode transformFinal(SByteSpan& output) = 0;
    };
}
}

#endif
