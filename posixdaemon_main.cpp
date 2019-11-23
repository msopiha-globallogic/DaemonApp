#include "posixdaemon.h"

// Syslog
#include <syslog.h>

int main(int argc, char** argv){

    setlogmask (LOG_UPTO (LOG_INFO));
    openlog ("sdbg-server", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);

    PosixDaemon daemon{
        "/",
        "/tmp/sdbg-server.pid"
    };

    daemon.init();
    daemon.run();
    return 0;
}
