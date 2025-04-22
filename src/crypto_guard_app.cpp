#include "crypto_guard_app.h"
#include <iostream>
#include <print>
#include <sstream>
#include <stdexcept>

namespace CryptoGuard {

CryptoGuardApp::CryptoGuardApp(int ac, char *av[]) {
    if (!opts_.Parse(ac, av)) {
        throw std::runtime_error{"Invalid command line options"};
    }
}

void CryptoGuardApp::Run() {
    using COMMAND_TYPE = ProgramOptions::COMMAND_TYPE;
    auto IwouldLikeTo = opts_.GetCommand();

    switch (IwouldLikeTo) {
    case COMMAND_TYPE::CHECKSUM:
        std::println("{}", checksum());
        break;

    case COMMAND_TYPE::DECRYPT:
        decrypt();
        break;

    case COMMAND_TYPE::ENCRYPT:
        encrypt();
        break;

    case COMMAND_TYPE::HELP:
        std::print("{}", help());
        break;

    default:
        throw std::runtime_error{"Application internal error"};
    }
}

std::string checksum() {
    std::ifstream in(opts_.GetInputFile());
    return ctx_.CalculateChecksum(in);
}

void decrypt() {
    std::ifstream in(opts_.GetInputFile());
    std::ofstream out(opts_.GetOutputFile());
    ctx_.DecryptFile(in, out, opts_.GetPassword());
}

void encrypt() {
    std::ifstream in(opts_.GetInputFile());
    std::ofstream out(opts_.GetOutputFile());
    ctx_.EncryptFile(in, out, opts_.GetPassword());
}

std::string help() {
    std::stringstream sout;
    sout << desc_;
    return sout.str();
}

}  // namespace CryptoGuard
