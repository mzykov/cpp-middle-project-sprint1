#pragma once

#include <boost/program_options.hpp>
#include <sstream>
#include <string>
#include <unordered_map>

namespace CryptoGuard {

class ProgramOptions {
public:
    ProgramOptions();
    ~ProgramOptions() = default;

    bool Parse(int ac, char *av[]);

    enum class COMMAND_TYPE {
        CHECKSUM,
        DECRYPT,
        ENCRYPT,
        HELP,
    };

    COMMAND_TYPE GetCommand() const { return command_; }

    std::string GetInputFile() const { return inputFile_; }
    std::string GetOutputFile() const { return outputFile_; }
    std::string GetPassword() const { return password_; }
    std::string GetHelp() const {
        std::stringstream sout;
        sout << desc_;
        return sout.str();
    }

private:
    COMMAND_TYPE command_;
    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    // Helpers
    std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"checksum", COMMAND_TYPE::CHECKSUM},
        {"decrypt", COMMAND_TYPE::DECRYPT},
        {"encrypt", COMMAND_TYPE::ENCRYPT},
        {"help", COMMAND_TYPE::HELP},
    };
    boost::program_options::options_description desc_;

    boost::program_options::variables_map parseCommandLine(int ac, char *av[]);
    bool optionsAreConsistent(const boost::program_options::variables_map &vm) const;
    bool optionIsConsistent(const boost::program_options::variables_map &vm, const std::string &opt,
                            bool musthave) const;
    void setCommand(const boost::program_options::variables_map &vm);
    void setInputFile(const boost::program_options::variables_map &vm);
    void setOutputFile(const boost::program_options::variables_map &vm);
    void setPassword(const boost::program_options::variables_map &vm);
};

}  // namespace CryptoGuard
