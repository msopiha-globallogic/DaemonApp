#include "posixdaemon.h"

#include <iostream>
#include <fstream>

#include <csignal>

//------ U*nix only ----//
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "log.h"
#include "token.h"
#include "connection.h"
#include "session.h"

auto PosixDaemon::payload() -> void {
    LOGI("Payload start");
    Connection con(8080);
    if (con.StartListening() != 0) {
        LOGE("Failed to start listening. Err = %s\n", con.GetLastErrorString().c_str());
//        std::cout << "Failed to start listening. Err = " << con.GetLastErrorString()
//                  << std::endl;
    } else {
        while(1) {
            Session s(con.GetNextConnection(), "cert", "key");
            Token t = s.getSessionToken();
            std::cout << "Got token state " << t.getState();
        }
    }
}

auto PosixDaemon::run() -> void {
    // Make child process
    pid_t child_pid = fork();
    if(child_pid < 0){
        std::cerr << "Error: failed to fork this process." << "\n";
        return;
    }
    if(child_pid > 0){
        std::cout << "Process ID of child process = " << child_pid << "\n";
        return;
    }
    // Umask file mode
    ::umask(0);
    // Set new session
    pid_t sid = ::setsid();
    if(sid < 0)
        return;
    //------ Code of Forked Process ---------//
    // Set path of forked process (daemon)
    ::chdir(m_path.c_str());

    // Check whether there is a running process of this program
    auto fs = std::ifstream(m_pidfile);
    if(fs.good()){
        int pid;
        fs >> pid;
        std::cerr << " [LOG] Kill process of PID = " << pid << "\n";
        ::kill(-pid, SIGTERM);
        fs.close();
    }
    auto fo = std::ofstream(m_pidfile);
    if(fo.good()){
        int pid = ::getpid();
        std::cerr << "Child PID = " << pid << "\n";
        fo << pid  << std::flush;
    } else {
        std::cerr << " [LOG] Error: could not open PID file " << m_pidfile << "\n";
        return;
    }
    // Close stdin, stdout and stderr file descriptors.
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    payload();
}
