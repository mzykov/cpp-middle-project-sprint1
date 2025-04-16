#include "cmd_options.h"

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;
    desc_.add_options()("help", "produce help message")("command", po::value<std::string>(), "command to execute")(
        "input", po::value<std::string>(), "input file path")("output", po::value<std::string>(), "output file path")(
        "password", po::value<std::string>(), "owner password");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    namespace po = boost::program_options;

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, this->desc_), vm);
    po::notify(vm);

    return true;
}

}  // namespace CryptoGuard
