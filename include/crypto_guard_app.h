#pragma once

#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <stdexcept>

namespace CryptoGuard {

class CryptoGuardApp {
public:
    CryptoGuardApp(int argc, char *argv[]) {
        if (!opts_.Parse(argc, argv)) {
            throw std::runtime_error{"Invalid command line options"};
        }
    }
    ~CryptoGuardApp() {}

    CryptoGuardApp(const CryptoGuardApp &) = delete;
    CryptoGuardApp &operator=(const CryptoGuardApp &) = delete;

    CryptoGuardApp(CryptoGuardApp &&) noexcept = delete;
    CryptoGuardApp &operator=(CryptoGuardApp &&) noexcept = delete;

    // API
    void Run();

private:
    ProgramOptions opts_;
    CryptoGuardCtx ctx_;
};

}  // namespace CryptoGuard
