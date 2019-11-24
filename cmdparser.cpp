#include "cmdparser.h"

#include <iostream>
#include <string>

#include "log.h"

void CmdParser::printHelp() {
    std::cout <<
            "\nUsage:\n\n"
            "-k|--key <file name>:     Key file name\n"
            "-c|--cert <file name>:    Certificate file name\n"
            "-p|--pass:                Password\n"
            "-h|-?|--help:             Show help\n"
            "\n";
}

bool CmdParser::file_exists (const std::string& name) {
    if (FILE *file = fopen(name.c_str(), "r")) {
        fclose(file);
        return true;
    } else {
        return false;
    }
}

CmdParser::CmdParser(int argc, char **argv)
{
    if (argc == 1) {
        printHelp();
        throw std::invalid_argument( "Invalid arguments" );
    }
    while (true)
    {
        const auto opt = getopt_long(argc, argv, m_short_opts, m_long_opts, nullptr);

        LOGI("opt is %d\n", opt);

        if (-1 == opt)
            break;

        switch (opt)
        {
        case 'k':
            m_key = std::string(optarg);
            LOGI("key-file is %s\n", m_key.c_str());
            break;
        case 'c':
            m_cert = std::string(optarg);
            LOGI("cert-file is %s\n", m_cert.c_str());
            break;
        case 'p':
            m_pass = std::string(optarg);
            LOGI("pass is %s\n", m_pass.c_str());
            break;
        case 'h': // -h or --help
        case '?': // Unrecognized option
        default:
            printHelp();
            exit(1);
            break;
        }
    }
    if(m_key.empty() || !file_exists(m_key)) {
        printHelp();
        throw std::invalid_argument( "Key file required" );
    }
    if(m_cert.empty() || !file_exists(m_cert)) {
        printHelp();
        throw std::invalid_argument( "Certificate file required" );
    }
    if(m_pass.empty()) {
        printHelp();
        throw std::invalid_argument( "Pass can't be empty" );
    }

}

std::string CmdParser::getCert() {
    return m_cert;
}

std::string CmdParser::getKey() {
    return m_key;
}

std::string CmdParser::getPass() {
    return m_pass;
}
