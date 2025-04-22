#pragma once

#include <boost/program_options.hpp>
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

private:
    COMMAND_TYPE command_;
    const std::unordered_map<std::string_view, COMMAND_TYPE> commandMapping_ = {
        {"checksum", ProgramOptions::COMMAND_TYPE::CHECKSUM},
        {"decrypt", ProgramOptions::COMMAND_TYPE::DECRYPT},
        {"encrypt", ProgramOptions::COMMAND_TYPE::ENCRYPT},
        {"help", ProgramOptions::COMMAND_TYPE::HELP},
    };

    std::string inputFile_;
    std::string outputFile_;
    std::string password_;

    boost::program_options::options_description desc_;

    // Helpers
    boost::program_options::variables_map parseCommandLine(int ac, char *av[]);
    bool areConsistent(const boost::program_options::variables_map &vm) const;
    void setCommand(const boost::program_options::variables_map &vm);
    void setInputFile(const boost::program_options::variables_map &vm);
};

}  // namespace CryptoGuard
