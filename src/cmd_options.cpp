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

    if (!this->optionsAreConsistent(vm)) {
        return false;
    }

    this->setCommand(vm);
    this->setInputFile(vm);
    this->setOutputFile(vm);
    this->setPassword(vm);

    return true;
}

boost::program_options::variables_map ProgramOptions::parseCommandLine(int ac, char *av[]) {
    namespace po = boost::program_options;
    po::variables_map vm;
    auto parsed = po::parse_command_line(ac, av, desc_);
    po::store(parsed, vm);
    po::notify(vm);
    return vm;
}

bool ProgramOptions::optionsAreConsistent(const boost::program_options::variables_map &vm) const { return true; }

void ProgramOptions::setCommand(const boost::program_options::variables_map &vm) {
    if (vm.count("help")) {
        command_ = commandMapping_["help"];
    } else {
        command_ = commandMapping_[vm["command"].as<std::string>()];
    }
}

void ProgramOptions::setInputFile(const boost::program_options::variables_map &vm) {
    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }
}

void ProgramOptions::setOutputFile(const boost::program_options::variables_map &vm) {
    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }
}

void ProgramOptions::setPassword(const boost::program_options::variables_map &vm) {
    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard
