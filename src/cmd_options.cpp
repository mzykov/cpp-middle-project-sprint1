#include "cmd_options.h"

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;
    desc_.add_options()("help", "print help message")("command", po::value<std::string>(), "command to execute")(
        "input", po::value<std::string>(), "input file path")("output", po::value<std::string>(), "output file path")(
        "password", po::value<std::string>(), "owner password");
}

bool ProgramOptions::Parse(int ac, char *av[]) {
    auto vm = parseCommandLine(ac, av);

    if (!optionsAreConsistent(vm)) {
        return false;
    }

    setCommand(vm);
    setInputFile(vm);
    setOutputFile(vm);
    setPasswod(vm);

    return true;
}

boost::program_options::variables_map parseCommandLine(int ac, char *av[]) {
    namespace po = boost::program_options;
    po::variables_map vm;
    auto parsed = po::parse_command_line(ac, av, desc_);
    po::store(parsed, vm);
    po::notify(vm);
    return vm;
}

bool optionsAreConsistent(const boost::program_options::variables_map &vm) const { return true; }

void setCommand(const boost::program_options::variables_map &vm) {
    if (vm.count("help")) {
        command_ = commandMapping_["help"];
    } else {
        command_ = commandMapping_[vm["command"].as<std::string>()];
    }
}

void setInputFile(const boost::program_options::variables_map &vm) {}
void setOutputFile(const boost::program_options::variables_map &vm) {}
void setPassword(const boost::program_options::variables_map &vm) {}

}  // namespace CryptoGuard
