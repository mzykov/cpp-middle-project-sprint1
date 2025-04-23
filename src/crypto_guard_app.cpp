#include "crypto_guard_app.h"
#include <fstream>
#include <iostream>
#include <print>
#include <sstream>
#include <stdexcept>

namespace CryptoGuard {

CryptoGuardApp::CryptoGuardApp(int ac, char *av[]) {
    if (!opts_.Parse(ac, av)) {
        throw std::invalid_argument{"Invalid command line options"};
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

std::string CryptoGuardApp::checksum() {
    std::fstream in(opts_.GetInputFile(), std::ios::in);
    return ctx_.CalculateChecksum(in);
}

void CryptoGuardApp::decrypt() {
    std::fstream in(opts_.GetInputFile(), std::ios::in);
    std::fstream out(opts_.GetOutputFile(), std::ios::out);
    ctx_.DecryptFile(in, out, opts_.GetPassword());
}

void CryptoGuardApp::encrypt() {
    std::fstream in(opts_.GetInputFile(), std::ios::in);
    std::fstream out(opts_.GetOutputFile(), std::ios::out);
    ctx_.EncryptFile(in, out, opts_.GetPassword());
}

std::string CryptoGuardApp::help() {
    std::stringstream sout;
    sout << opts_.GetHelp();
    return sout.str();
}

}  // namespace CryptoGuard
