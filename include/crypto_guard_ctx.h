#pragma once

#include <string>

namespace CryptoGuard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx() {}
    ~CryptoGuardCtx() {}

    CryptoGuardCtx(const CryptoGuardCtx &) = delete;
    CryptoGuardCtx &operator=(const CryptoGuardCtx &) = delete;

    CryptoGuardCtx(CryptoGuardCtx &&) noexcept = default;
    CryptoGuardCtx &operator=(CryptoGuardCtx &&) noexcept = default;

    // API
    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {}
    std::string CalculateChecksum(std::iostream &inStream) { return "NOT_IMPLEMENTED"; }

private:
    class Impl;
    Impl *pImpl_;
};

}  // namespace CryptoGuard

/*
//
        // OpenSSL пример использования:
        //
        std::string input = "01234567890123456789";
        std::string output;

        OpenSSL_add_all_algorithms();

        auto params = CreateChiperParamsFromPassword("12341234");
        params.encrypt = 1;
        auto *ctx = EVP_CIPHER_CTX_new();

        // Инициализируем cipher
        EVP_CipherInit_ex(ctx, params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt);

        std::vector<unsigned char> outBuf(16 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(16);
        int outLen;

        // Обрабатываем первые N символов
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Обрабатываем оставшиеся символы
        EVP_CipherUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), static_cast<int>(16));
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }

        // Заканчиваем работу с cipher
        EVP_CipherFinal_ex(ctx, outBuf.data(), &outLen);
        for (int i = 0; i < outLen; ++i) {
            output.push_back(outBuf[i]);
        }
        EVP_CIPHER_CTX_free(ctx);
        std::print("String encoded successfully. Result: '{}'\n\n", output);
        EVP_cleanup();
        //
        // Конец примера
        //
*/
