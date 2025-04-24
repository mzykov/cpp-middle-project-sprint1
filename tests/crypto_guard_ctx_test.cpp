#include "crypto_guard_ctx.h"
#include <gtest/gtest.h>
#include <iostream>
#include <sstream>

TEST(TestCryptoGuardCtx, TestMainScenario) {
    // given
    std::string givenStr = "My private content to be encrypted\n", password = "My robust password";
    std::string checksumOfGivenStr, encryptedStr, decryptedStr, checksumOfDecryptedStr;

    // when
    {
        std::stringstream inSStream;
        inSStream << givenStr;
        CryptoGuard::CryptoGuardCtx ctx;
        checksumOfGivenStr = ctx.CalculateChecksum(inSStream);
    }
    {
        std::stringstream inSStream, outSStream;
        inSStream << givenStr;
        CryptoGuard::CryptoGuardCtx ctx;
        ctx.EncryptFile(inSStream, outSStream, password);
        encryptedStr = outSStream.str();
    }
    {
        std::stringstream inSStream, outSStream;
        inSStream << encryptedStr;
        CryptoGuard::CryptoGuardCtx ctx;
        ctx.DecryptFile(inSStream, outSStream, password);
        decryptedStr = outSStream.str();
    }
    {
        std::stringstream inSStream;
        inSStream << decryptedStr;
        CryptoGuard::CryptoGuardCtx ctx;
        checksumOfDecryptedStr = ctx.CalculateChecksum(inSStream);
    }

    // then
    EXPECT_EQ(givenStr, decryptedStr);
    EXPECT_EQ(checksumOfGivenStr, checksumOfDecryptedStr);
}
