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
#include "cmdparser.h"

auto PosixDaemon::init(int argc, char **argv) -> bool {

    try {
        CmdParser cmdParser(argc, argv);
        m_con.setPwd(cmdParser.getPass());
        m_con.setKeyFile(cmdParser.getKey());
        m_con.setCertFile(cmdParser.getCert());
    } catch (const std::invalid_argument& ia) {
        LOGE("Invalid argument: %s\n", ia.what());
        return false;
    }

    if (m_con.StartListening() != 0) {
        LOGE("Failed to start listening. Err = %s\n", m_con.GetLastErrorString().c_str());
        return false;
    }

    return true;
}


auto PosixDaemon::payload() -> void {
    LOGI("Payload start");

    while(1) {
        LOGI("Started new listening session");
        Session s(m_con.GetNextConnection(),
                  m_con.getCertFile(),
                  m_con.getKeyFile(),
                  m_con.getPwdFile());
        Token t = s.getSessionToken();
        LOGI("Got token state: %s.", t.getTokenStateStr().c_str());
        if(t.isDebugEnabled()) {
            LOGI("Secure Debug ENABLED!!!\n");
        } else {
            LOGI("Secure Debug disabled\n");
        }
    }
}

auto PosixDaemon::run() -> void {
    // Make child process
    pid_t child_pid = fork();
    if(child_pid < 0){
        LOGE("Error: failed to fork this process.\n");
        return;
    }
    if(child_pid > 0){
        LOGE("Process ID of child process = %d\n", child_pid);
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
        LOGE(" [LOG] Kill process of PID = %d\n", pid);
        ::kill(-pid, SIGTERM);
        fs.close();
    }
    auto fo = std::ofstream(m_pidfile);
    if(fo.good()){
        int pid = ::getpid();
        LOGE("Child PID = %d\n", pid);
        fo << pid  << std::flush;
    } else {
        LOGE(" [LOG] Error: could not open PID file %s\n", m_pidfile.c_str());
        return;
    }
    // Close stdin, stdout and stderr file descriptors.
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    payload();
}
