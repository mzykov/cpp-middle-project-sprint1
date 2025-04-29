#pragma once

#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <stdexcept>
#include <string>

namespace CryptoGuard {

class CryptoGuardApp {
public:
    CryptoGuardApp(int ac, char *av[]);
    ~CryptoGuardApp() = default;

    CryptoGuardApp(const CryptoGuardApp &) = delete;
    CryptoGuardApp &operator=(const CryptoGuardApp &) = delete;

    CryptoGuardApp(CryptoGuardApp &&) noexcept = delete;
    CryptoGuardApp &operator=(CryptoGuardApp &&) noexcept = delete;

    // API
    void Run();

private:
    ProgramOptions opts_;
    CryptoGuardCtx ctx_;

    // Helpers
    std::string checksum();
    void decrypt();
    void encrypt();
    std::string help();
};

}  // namespace CryptoGuard
