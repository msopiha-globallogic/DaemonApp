#include "posixdaemon.h"

#include "cmdparser.h"

#include <iostream>
#include <stdexcept>
// Syslog
#include <syslog.h>

int main(int argc, char** argv){

    setlogmask (LOG_UPTO (LOG_INFO));
    openlog ("sdbg-server", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    PosixDaemon daemon{
        "/",
        "/tmp/sdbg-server.pid"
    };

    if (!daemon.init(argc, argv)) {
        std::cout << "The nitialization failed. Daemon was not started.\n"
                     "Check syslog for details\n";
        return -1;
    }
    daemon.run();
    return 0;
}
