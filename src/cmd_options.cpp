#include "cmd_options.h"
#include <array>
#include <utility>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options"), command_(ProgramOptions::COMMAND_TYPE::HELP) {

    namespace po = boost::program_options;
    desc_.add_options()("help, h", "print help message")("command, c", po::value<std::string>(),
                                                         "command to execute: encrypt/decrypt/checksum")(
        "input, i", po::value<std::string>(),
        "input file path")("output, o", po::value<std::string>(),
                           "output file path")("password, p", po::value<std::string>(), "owner password");
}

bool ProgramOptions::Parse(int ac, char *av[]) {
    auto vm = parseCommandLine(ac, av);

    if (vm.contains("help")) {
        return true;
    }
    if (!optionsAreConsistent(vm)) {
        return false;
    }
    if (vm.contains("command")) {
        command_ = commandMapping_[vm["command"].as<std::string>()];
    }
    if (vm.contains("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }
    if (vm.contains("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }
    if (vm.contains("password")) {
        password_ = vm["password"].as<std::string>();
    }

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
    if (!vm.count("command")) {
        return false;
    }

    const auto &cmd = vm["command"].as<std::string>();

    if (!commandMapping_.count(cmd)) {
        return false;
    }

    std::unordered_map<ProgramOptions::COMMAND_TYPE, std::array<std::pair<std::string, bool>, 3>> consistensyMapping = {
        {ProgramOptions::COMMAND_TYPE::CHECKSUM, {{{"input", true}, {"output", false}, {"password", false}}}},
        {ProgramOptions::COMMAND_TYPE::DECRYPT, {{{"input", true}, {"output", true}, {"password", true}}}},
        {ProgramOptions::COMMAND_TYPE::ENCRYPT, {{{"input", true}, {"output", true}, {"password", true}}}},
    };

    const auto cmdType = commandMapping_.at(cmd);

    for (const auto &[opt, musthave] : consistensyMapping[cmdType]) {
        if (!ProgramOptions::optionIsConsistent(vm, opt, musthave))
            return false;
    }

    return true;
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

}  // namespace CryptoGuard
