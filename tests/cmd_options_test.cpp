#include "cmd_options.h"
#include <gtest/gtest.h>

// 1.
TEST(TestProgramOptions, TestHelp) {
    // given
    int ac = 2;
    const char *av[] = {"./CryptoGuard", "--help"};
    // when
    CryptoGuard::ProgramOptions opts;
    bool ok = opts.Parse(ac, const_cast<char **>(av));
    // then
    EXPECT_EQ(ok, true);
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::HELP);
}

// 2.
TEST(TestProgramOptions, TestChecksum) {
    // given
    int ac = 5;
    const char *av[] = {
        "./CryptoGuard", "--command", "checksum", "--input", "/path/to/file",
    };
    // when
    CryptoGuard::ProgramOptions opts;
    bool ok = opts.Parse(ac, const_cast<char **>(av));
    // then
    EXPECT_EQ(ok, true);
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
    EXPECT_EQ(opts.GetInputFile(), "/path/to/file");
}

// 3.
TEST(TestProgramOptions, TestEncrypt) {
    // given
    int ac = 9;
    const char *av[] = {
        "./CryptoGuard",        "--command",  "encrypt", "--input", "/path/to/input/file", "--output",
        "/path/to/output/file", "--password", "QWERTY",
    };
    // when
    CryptoGuard::ProgramOptions opts;
    bool ok = opts.Parse(ac, const_cast<char **>(av));
    // then
    EXPECT_EQ(ok, true);
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(opts.GetInputFile(), "/path/to/input/file");
    EXPECT_EQ(opts.GetOutputFile(), "/path/to/output/file");
    EXPECT_EQ(opts.GetPassword(), "QWERTY");
}

// 4.
TEST(TestProgramOptions, TestDecrypt) {
    // given
    int ac = 9;
    const char *av[] = {
        "./CryptoGuard",        "--command",  "decrypt", "--input", "/path/to/input/file", "--output",
        "/path/to/output/file", "--password", "QWERTY",
    };
    // when
    CryptoGuard::ProgramOptions opts;
    bool ok = opts.Parse(ac, const_cast<char **>(av));
    // then
    EXPECT_EQ(ok, true);
    EXPECT_EQ(opts.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
    EXPECT_EQ(opts.GetInputFile(), "/path/to/input/file");
    EXPECT_EQ(opts.GetOutputFile(), "/path/to/output/file");
    EXPECT_EQ(opts.GetPassword(), "QWERTY");
}

// 5.
TEST(TestProgramOptions, TestChecksumNoInput) {
    // given
    int ac = 3;
    const char *av[] = {
        "./CryptoGuard",
        "--command",
        "checksum",
    };
    // when
    CryptoGuard::ProgramOptions opts;
    bool ok = opts.Parse(ac, const_cast<char **>(av));
    // then
    EXPECT_EQ(ok, false);
}

// 6.
TEST(TestProgramOptions, TestDecryptNoInputOutput) {
    // given
    int ac = 3;
    const char *av[] = {
        "./CryptoGuard",
        "--command",
        "decrypt",
    };
    // when
    CryptoGuard::ProgramOptions opts;
    bool ok = opts.Parse(ac, const_cast<char **>(av));
    // then
    EXPECT_EQ(ok, false);
}

// 7.
TEST(TestProgramOptions, TestEncryptNoInputOutput) {
    // given
    int ac = 3;
    const char *av[] = {
        "./CryptoGuard",
        "--command",
        "encrypt",
    };
    // when
    CryptoGuard::ProgramOptions opts;
    bool ok = opts.Parse(ac, const_cast<char **>(av));
    // then
    EXPECT_EQ(ok, false);
}
