#include "crypto_guard_app.h"
#include <format>
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>

namespace CryptoGuard {

CryptoGuardApp::CryptoGuardApp(int ac, char *av[]) {
    const auto &[ok, err] = opts_.Parse(ac, av);
    if (!ok) {
        throw std::invalid_argument{std::format("Invalid command line options: {}", err)};
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
        throw std::logic_error{"Application internal error"};
    }
}

std::string CryptoGuardApp::checksum() {
    std::fstream in(opts_.GetInputFile(), std::ios::in);
    if (!in.is_open()) {
        throw std::runtime_error{"Cannot open file for reading"};
    }
    return ctx_.CalculateChecksum(in);
}

void CryptoGuardApp::decrypt() {
    std::fstream in(opts_.GetInputFile(), std::ios::in);
    if (!in.is_open()) {
        throw std::runtime_error{"Cannot open file for reading"};
    }
    std::fstream out(opts_.GetOutputFile(), std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        throw std::runtime_error{"Cannot open file for writing"};
    }
    ctx_.DecryptFile(in, out, opts_.GetPassword());
}

void CryptoGuardApp::encrypt() {
    std::fstream in(opts_.GetInputFile(), std::ios::in);
    if (!in.is_open()) {
        throw std::runtime_error{"Cannot open file for reading"};
    }
    std::fstream out(opts_.GetOutputFile(), std::ios::out | std::ios::trunc);
    if (!out.is_open()) {
        throw std::runtime_error{"Cannot open file for writing"};
    }
    ctx_.EncryptFile(in, out, opts_.GetPassword());
}

std::string CryptoGuardApp::help() { return opts_.GetHelp(); }

}  // namespace CryptoGuard
