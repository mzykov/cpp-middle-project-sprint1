#include "crypto_guard_app.h"
#include <iostream>
#include <print>
#include <stdexcept>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::CryptoGuardApp app(argc, argv);
        app.Run();

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}
