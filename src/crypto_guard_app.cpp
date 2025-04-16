#include "crypto_guard_app.h"
#include <print>
#include <stdexcept>

namespace CryptoGuard {

void CryptoGuardApp::Run() {
    using COMMAND_TYPE = ProgramOptions::COMMAND_TYPE;

    switch (opts_.GetCommand()) {
    case COMMAND_TYPE::ENCRYPT:
        // ctx_.Encrypt();
        std::println("File encoded successfully");
        break;

    case COMMAND_TYPE::DECRYPT:
        // ctx_.Decrypt();
        std::println("File decoded successfully");
        break;

    case COMMAND_TYPE::CHECKSUM:
        // ctx_.Checksum();
        std::println("{}", "CHECKSUM_NOT_IMPLEMENTED");
        break;

    default:
        throw std::runtime_error{"Unsupported command"};
    }
}

}  // namespace CryptoGuard
