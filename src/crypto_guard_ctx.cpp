#include "crypto_guard_ctx.h"
#include <array>
#include <cstddef>
#include <iomanip>
#include <openssl/evp.h>
#include <stdexcept>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    static const size_t KEY_SIZE = 32;             // AES-256 key size
    static const size_t IV_SIZE = 16;              // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm
    std::array<unsigned char, KEY_SIZE> key;       // Encryption key
    std::array<unsigned char, IV_SIZE> iv;         // Initialization vector
};

AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'M', 'i', 'k', 'h', 'a', 'i', 'l', '.'};

    int ok = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                            reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                            params.key.data(), params.iv.data());
    if (!ok) {
        throw std::runtime_error{"Failed to create a key from password"};
    }
    return params;
}

using evp_cipher_unique_ptr =
    std::unique_ptr<EVP_CIPHER_CTX, decltype([](EVP_CIPHER_CTX *ctx) { EVP_CIPHER_CTX_free(ctx); })>;

using evp_md_unique_ptr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX *mdctx) { EVP_MD_CTX_free(mdctx); })>;

class CryptoGuardCtx::Impl {
public:
    Impl() { OpenSSL_add_all_algorithms(); }

    ~Impl() { EVP_cleanup(); }
    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
    std::string CalculateChecksum(std::iostream &inStream);

private:
    enum class CIPHER_ACTION { DECRYPT, ENCRYPT };

    evp_cipher_unique_ptr createCipherCtx(std::string_view password, int whatToDo);
    std::string getCipherChunk(std::iostream &in, EVP_CIPHER_CTX *ctx);

    evp_md_unique_ptr createMessageDigestCtx(std::string_view digestName);
    std::string getMmessageDigest(std::iostream &inStream, EVP_MD_CTX *mdctx);
};

evp_cipher_unique_ptr CryptoGuardCtx::Impl::createCipherCtx(std::string_view password, int whatToDo) {
    auto ctx = evp_cipher_unique_ptr(EVP_CIPHER_CTX_new());

    if (!ctx) {
        throw std::runtime_error{"EVP_CIPHER_CTX_new failed"};
    }

    if (password.length() > 0) {
        auto params = CreateCipherParamsFromPassword(password);
        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), whatToDo);
    }

    return std::move(ctx);
}

std::string CryptoGuardCtx::Impl::getCipherChunk(std::iostream &inStream, EVP_CIPHER_CTX *ctx) {
    constexpr int chunkSizeInBytes = 1024;

    std::vector<char> chunk(chunkSizeInBytes, 0);
    std::vector<unsigned char> workingBuf(chunk.size() + EVP_MAX_BLOCK_LENGTH);

    inStream.read(reinterpret_cast<char *>(chunk.data()), chunk.size());
    std::streamsize inputLen = inStream.gcount();

    int outLen = 0;
    int ok = EVP_CipherUpdate(ctx, workingBuf.data(), &outLen, reinterpret_cast<const unsigned char *>(chunk.data()),
                              inputLen);

    if (!ok) {
        throw std::runtime_error{"EVP_EncryptUpdate failed"};
    }

    std::string cipherChunk;
    cipherChunk.insert(cipherChunk.end(), workingBuf.begin(), workingBuf.begin() + outLen);

    if (inStream.eof()) {
        EVP_CipherFinal_ex(ctx, workingBuf.data(), &outLen);
        cipherChunk.insert(cipherChunk.end(), workingBuf.begin(), workingBuf.begin() + outLen);
    }

    return cipherChunk;
}

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    auto ctx = createCipherCtx(password, static_cast<int>(CIPHER_ACTION::ENCRYPT));

    while (!inStream.eof()) {
        const auto chunk = getCipherChunk(inStream, ctx.get());
        outStream << chunk;
    }
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
    auto ctx = createCipherCtx(password, static_cast<int>(CIPHER_ACTION::DECRYPT));

    while (!inStream.eof()) {
        const auto chunk = getCipherChunk(inStream, ctx.get());
        outStream << chunk;
    }
}

evp_md_unique_ptr CryptoGuardCtx::Impl::createMessageDigestCtx(std::string_view digestName) {
    const auto md = EVP_get_digestbyname(digestName.data());
    if (!md) {
        throw std::runtime_error{"EVP_get_digestbyname failed"};
    }

    auto mdctx = evp_md_unique_ptr(EVP_MD_CTX_new());
    if (!mdctx) {
        throw std::runtime_error{"EVP_MD_CTX_new failed"};
    }

    int ok = EVP_DigestInit_ex2(mdctx.get(), md, nullptr);
    if (!ok) {
        throw std::runtime_error{"EVP_DigestInit_ex2 failed"};
    }

    return std::move(mdctx);
}

std::string CryptoGuardCtx::Impl::getMmessageDigest(std::iostream &inStream, EVP_MD_CTX *mdctx) {
    constexpr int chunkSizeInBytes = 1024;

    while (!inStream.eof()) {
        std::vector<char> chunk(chunkSizeInBytes, 0);
        inStream.read(chunk.data(), chunk.size());
        std::streamsize inputLen = inStream.gcount();

        int ok = EVP_DigestUpdate(mdctx, chunk.data(), inputLen);

        if (!ok) {
            throw std::runtime_error{"EVP_DigestUpdate failed"};
        }
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> mdValue;
    unsigned int mdLen;

    int ok = EVP_DigestFinal_ex(mdctx, mdValue.data(), &mdLen);

    if (!ok) {
        throw std::runtime_error{"EVP_DigestFinal_ex failed"};
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
