#include "crypto_guard_ctx.h"
#include <array>
#include <cstddef>
#include <format>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdexcept>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm
    std::array<unsigned char, KEY_SIZE> key;       // Encryption key
    std::array<unsigned char, IV_SIZE> iv;         // Initialization array
};

using evp_cipher_unique_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

using evp_md_unique_ptr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *mdctx) { EVP_MD_CTX_free(mdctx); })>;

class CryptoGuardCtx::Impl {
public:
    Impl() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    }

    ~Impl() {
        EVP_cleanup();
        ERR_free_strings();
    }
    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    enum class CIPHER_ACTION { DECRYPT, ENCRYPT };

    AesCipherParams createCipherParamsFromPassword(std::string_view password);

    evp_cipher_unique_ptr createCipherCtx(std::string_view password, CIPHER_ACTION whatToDo);
    void readWriteCipherByChunk(std::iostream &inStream, std::iostream &outStream, EVP_CIPHER_CTX *ctx);

    evp_md_unique_ptr createMessageDigestCtx(std::string_view digestName);
    std::string getMmessageDigest(std::iostream &inStream, EVP_MD_CTX *mdctx);

    std::exception runtimeCryptoGuardCtxException(std::string_view msg);
};

std::exception CryptoGuardCtx::Impl::runtimeCryptoGuardCtxException(std::string_view msg) {
    return std::runtime_error{std::format("{}\n{}", msg, ERR_error_string(ERR_get_error(), nullptr))};
}

AesCipherParams CryptoGuardCtx::Impl::createCipherParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'M', 'i', 'k', 'h', 'a', 'i', 'l', '.'};

    int ok = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                            reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                            params.key.data(), params.iv.data());
    if (!ok) {
        throw runtimeCryptoGuardCtxException("Failed to create a key from password");
    }

    return params;
}

evp_cipher_unique_ptr CryptoGuardCtx::Impl::createCipherCtx(std::string_view password, CIPHER_ACTION whatToDo) {
    auto ctx = evp_cipher_unique_ptr(EVP_CIPHER_CTX_new());

    if (!ctx) {
        throw runtimeCryptoGuardCtxException("EVP_CIPHER_CTX_new failed");
    }

    if (password.length() > 0) {
        auto params = createCipherParamsFromPassword(password);
        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                          static_cast<int>(whatToDo));
    }

    return ctx;
}

void CryptoGuardCtx::Impl::readWriteCipherByChunk(std::iostream &inStream, std::iostream &outStream,
                                                  EVP_CIPHER_CTX *ctx) {
    constexpr int chunkSizeInBytes = 1024;

    std::array<char, chunkSizeInBytes> chunk;
    std::array<unsigned char, chunkSizeInBytes + EVP_MAX_BLOCK_LENGTH> workingBuf;

    while (!inStream.eof()) {
        inStream.read(reinterpret_cast<char *>(chunk.data()), chunk.size());

        if (!inStream.eof() && inStream.fail()) {
            throw std::runtime_error{"Error while reading chunk from input stream"};
        }

        std::streamsize inputLen = inStream.gcount();

        int outLen = 0;
        int ok = EVP_CipherUpdate(ctx, workingBuf.data(), &outLen,
                                  reinterpret_cast<const unsigned char *>(chunk.data()), inputLen);

        if (!ok) {
            throw runtimeCryptoGuardCtxException("EVP_CipherUpdate failed");
        }

        outStream.write(reinterpret_cast<const char *>(workingBuf.data()), outLen);

        if (inStream.eof()) {
            EVP_CipherFinal_ex(ctx, workingBuf.data(), &outLen);
            outStream.write(reinterpret_cast<const char *>(workingBuf.data()), outLen);
        }

        if (outStream.fail()) {
            throw std::runtime_error{"Error while writing chunk to output stream"};
        }
    }
}

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    auto ctx = createCipherCtx(password, CIPHER_ACTION::ENCRYPT);
    readWriteCipherByChunk(inStream, outStream, ctx.get());
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    auto ctx = createCipherCtx(password, CIPHER_ACTION::DECRYPT);
    readWriteCipherByChunk(inStream, outStream, ctx.get());
}

evp_md_unique_ptr CryptoGuardCtx::Impl::createMessageDigestCtx(std::string_view digestName) {
    const auto md = EVP_get_digestbyname(digestName.data());
    if (!md) {
        throw runtimeCryptoGuardCtxException("EVP_get_digestbyname failed");
    }

    auto mdctx = evp_md_unique_ptr(EVP_MD_CTX_new());
    if (!mdctx) {
        throw runtimeCryptoGuardCtxException("EVP_MD_CTX_new failed");
    }

    int ok = EVP_DigestInit_ex2(mdctx.get(), md, nullptr);
    if (!ok) {
        throw runtimeCryptoGuardCtxException("EVP_DigestInit_ex2 failed");
    }

    return mdctx;
}

std::string CryptoGuardCtx::Impl::getMmessageDigest(std::iostream &inStream, EVP_MD_CTX *mdctx) {
    constexpr int chunkSizeInBytes = 1024;
    std::array<char, chunkSizeInBytes> chunk;

    while (!inStream.eof()) {
        inStream.read(chunk.data(), chunk.size());

        if (!inStream.eof() && inStream.fail()) {
            throw std::runtime_error{"Error while reading chunk from input stream"};
        }

        std::streamsize inputLen = inStream.gcount();

        int ok = EVP_DigestUpdate(mdctx, chunk.data(), inputLen);

        if (!ok) {
            throw runtimeCryptoGuardCtxException("EVP_DigestUpdate failed");
        }
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> mdValue;
    unsigned int mdLen;

    int ok = EVP_DigestFinal_ex(mdctx, mdValue.data(), &mdLen);

    if (!ok) {
        throw runtimeCryptoGuardCtxException("EVP_DigestFinal_ex failed");
    }

    std::stringstream ss;

    for (int i = 0; i < mdLen; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mdValue[i]);

    return ss.str();
}

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) {
    const std::string digestName = "SHA256";
    auto mdctx = createMessageDigestCtx(digestName);
    return getMmessageDigest(inStream, mdctx.get());
}

CryptoGuardCtx::CryptoGuardCtx() : pImpl_(std::make_unique<Impl>()) {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &in, std::iostream &out, std::string_view password) {
    pImpl_->EncryptFile(in, out, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &in, std::iostream &out, std::string_view password) {
    pImpl_->DecryptFile(in, out, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &in) { return pImpl_->CalculateChecksum(in); }

}  // namespace CryptoGuard
