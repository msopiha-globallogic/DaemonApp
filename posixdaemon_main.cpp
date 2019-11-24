#include "posixdaemon.h"

#include "cmdparser.h"

#include <iostream>
#include <stdexcept>
// Syslog
#include <syslog.h>

int main(int argc, char** argv){

    setlogmask (LOG_UPTO (LOG_INFO));
    openlog ("sdbg-server", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    try {
        CmdParser cmdParser(argc, argv);
    } catch (const std::invalid_argument& ia) {
        std::cerr << "Invalid argument: " << ia.what() << "\n";
        return 1;
    }

    PosixDaemon daemon{
        "/",
        "/tmp/sdbg-server.pid"
    };

    daemon.init();
    daemon.run();
    return 0;
}
