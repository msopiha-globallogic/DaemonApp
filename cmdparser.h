#ifndef CMDPARSER_H
#define CMDPARSER_H

#include <string>

#include <getopt.h>

class CmdParser
{
public:
    CmdParser(int argc, char** argv);
    std::string getPass();
    std::string getCert();
    std::string getKey();

private:
    const char* const m_short_opts = "k:c:p:h";
    const option m_long_opts[5] = {
            {"key", required_argument, nullptr, 'k'},
            {"cert", required_argument, nullptr, 'c'},
            {"pass", required_argument, nullptr, 'p'},
            {"help", no_argument, nullptr, 'h'},
            {nullptr, no_argument, nullptr, 0}
    };

    std::string m_pass = "";
    std::string m_key = "";
    std::string m_cert = "";

    void printHelp();

};

#endif // CMDPARSER_H
