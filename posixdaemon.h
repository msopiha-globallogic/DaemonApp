#ifndef POSIXDAEMON_H
#define POSIXDAEMON_H

#include <string>

class PosixDaemon{
public:
    PosixDaemon(std::string path, std::string pidfile)
        : m_path(std::move(path)),
          m_pidfile(std::move(pidfile)) { }
    ~PosixDaemon(){}

    // Disable copy constructor in order to forbid copy
    PosixDaemon(const PosixDaemon&) = delete;
    // Disable copy-assignment operator to make the class non-copiable.
    PosixDaemon& operator= (const PosixDaemon&) = delete;

    auto run() -> void;

    auto init() -> bool;

private:
    std::string m_path;
    std::string m_pidfile;

    auto payload() -> void;
};

#endif // POSIXDAEMON_H
