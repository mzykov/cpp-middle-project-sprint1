#include "cmd_options.h"
#include <utility>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    namespace po = boost::program_options;
    desc_.add_options()("help", "print help message")("command", po::value<std::string>(),
                                                      "command to execute: encrypt/decrypt/checksum")(
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
    setPassword(vm);

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

bool ProgramOptions::optionsAreConsistent(const boost::program_options::variables_map &vm) const {
    if (vm.count("help")) {
        return true;
    } else if (vm.count("command") == 1) {
        const auto &cmd = vm["command"].as<std::string>();

        if (!commandMapping_.count(cmd)) {
            return false;
        }

        std::unordered_map<ProgramOptions::COMMAND_TYPE, std::vector<std::pair<std::string, bool>>> consistensyMapping =
            {
                {ProgramOptions::COMMAND_TYPE::CHECKSUM, {{"input", true}, {"output", false}, {"password", false}}},
                {ProgramOptions::COMMAND_TYPE::DECRYPT, {{"input", true}, {"output", true}, {"password", true}}},
                {ProgramOptions::COMMAND_TYPE::ENCRYPT, {{"input", true}, {"output", true}, {"password", true}}},
            };

        const auto cmdType = commandMapping_.at(cmd);

        for (const auto &[opt, musthave] : consistensyMapping[cmdType]) {
            if (!ProgramOptions::optionIsConsistent(vm, opt, musthave))
                return false;
        }

        return true;
    }

    return false;
}

bool ProgramOptions::optionIsConsistent(const boost::program_options::variables_map &vm, const std::string &opt,
                                        bool musthave) const {
    if (vm.contains(opt) != musthave)
        return false;

    if (musthave) {
        const auto &val = vm[opt].as<std::string>();
        if (val.length() == 0) {
            return false;
        }
    }

    return true;
}

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
